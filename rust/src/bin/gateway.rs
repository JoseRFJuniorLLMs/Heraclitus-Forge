//! Gateway de ingestão (backend do dashboard) — axum + tokio.
//!
//! Rotas:
//!   GET  /healthz          -> "ok"
//!   GET  /stats            -> { head, events, lsn }
//!   GET  /facts?limit=N    -> { facts: [...] }       (N mais recentes)
//!   GET  /query?q=...      -> { results: [...], count: N }  ← HQL nativo
//!   POST /ingest           -> { ok, lsn, fact }  | { drift, line }
//!   GET  /verify           -> { status, facts, root, message }
//!
//! A tarefa de ingestão contínua alimenta o `.hdb` a cada ~1.2s com linhas
//! do PostgreSQL de exemplo (simula stream ao vivo para o dashboard).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderMap, HeaderValue},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use heraclitus::db::{export_facts, FactStore};
use heraclitus::hql;
use heraclitus::quarantine::{key_from_env, QuarantineWriter};
use heraclitus::runner::ReconstitutiveRunner;

fn resolve_latest_artifact(base: &str) -> Option<String> {
    let dir = std::path::Path::new(base);
    if !dir.exists() || !dir.is_dir() {
        return None;
    }
    let mut highest = (0, 0, 0);
    let mut highest_path = None;

    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('v') && name.ends_with(".hcx") {
            let ver_str = &name[1..name.len() - 4];
            let parts: Vec<u32> = ver_str.split('.').filter_map(|s| s.parse().ok()).collect();
            if parts.len() == 3 {
                let tuple = (parts[0], parts[1], parts[2]);
                if tuple >= highest {
                    highest = tuple;
                    highest_path = Some(e.path().to_string_lossy().to_string());
                }
            }
        }
    }
    highest_path
}

const DB_PATH_DEFAULT: &str = "gateway.hdb";
/// Porta distinta do HeraclitusDB de produção (7475 = "panta rhei").
const ADDR_DEFAULT: &str = "127.0.0.1:7480";
const CAP: usize = 200;

const SAMPLES: &[&str] = &[
    "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:07.410 UTC [14804] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:08.560 UTC [14805] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:09.700 UTC [14806] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:11.500 UTC [14808] admin@prod LOG:  connection authorized: user=admin database=prod",
    "2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
];

// ---------------------------------------------------------------------------
// Estado compartilhado
// ---------------------------------------------------------------------------

struct AppState {
    recent: Mutex<VecDeque<Value>>,
    total: AtomicU64,
    db: Mutex<FactStore>,
    runner: Mutex<ReconstitutiveRunner>,
    quarantine: Mutex<QuarantineWriter>,
    db_path: String,
    /// Identidade que este gateway carimba nos Fatos que grava. Configuravel
    /// por ambiente; sem configuracao assume-se DEMO e diz-se em voz alta.
    identity: heraclitus::hfb2::SecurityIdentity,
    /// BLAKE3 da chave publica da ancora — identidade da origem.
    forge_source_id: String,
}

fn cors() -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(origin) = std::env::var("FORGE_CORS_ORIGIN") {
        if origin == "*" {
            return headers;
        }
        if let Ok(value) = HeaderValue::from_str(&origin) {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
        }
    }
    headers
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> impl IntoResponse {
    (cors(), "ok")
}

async fn stats(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let total = st.total.load(Ordering::Relaxed);
    let lsn = st.db.lock().await.current_lsn;
    (
        cors(),
        Json(json!({ "head": total, "events": total, "lsn": lsn })),
    )
}

#[derive(Deserialize)]
struct FactsQ {
    limit: Option<usize>,
}

async fn facts(State(st): State<Arc<AppState>>, Query(q): Query<FactsQ>) -> impl IntoResponse {
    let n = q.limit.unwrap_or(20).min(CAP);
    let rec = st.recent.lock().await;
    let facts: Vec<Value> = rec.iter().take(n).cloned().collect();
    (cors(), Json(json!({ "facts": facts })))
}

// --- HQL: GET /query?q=FROM FACTS ... ------------------------------------

#[derive(Deserialize)]
struct HqlQ {
    q: Option<String>,
}

/// Endpoint de consulta HQL nativo.
///
/// Executa `hql::execute_query` num `spawn_blocking` (I/O síncrono em arquivo)
/// e devolve os Fatos projetados como JSON, com suporte a zero-copy, wildcards
/// e LIMIT N conforme o parser EBNF do `hql.rs`.
async fn query_hql(
    State(st): State<Arc<AppState>>,
    Query(params): Query<HqlQ>,
) -> impl IntoResponse {
    let body = match params.q.filter(|s| !s.is_empty()) {
        None => json!({
            "error": "parâmetro 'q' obrigatório",
            "exemplo": "GET /query?q=FROM FACTS MATCH (actor.id) EXECUTES \"*\" AGAINST \"*\" SELECT * LIMIT 10"
        }),
        Some(qs) => {
            if qs.len() > 16_384 {
                return (cors(), Json(json!({ "error": "consulta excede 16 KiB" })));
            }
            match hql::parse_query(&qs) {
                Ok(plan) if plan.limit.is_some_and(|limit| limit <= CAP) => {}
                Ok(_) => {
                    return (
                        cors(),
                        Json(json!({ "error": format!("consulta deve declarar LIMIT <= {CAP}") })),
                    );
                }
                Err(error) => {
                    return (cors(), Json(json!({ "error": error })));
                }
            }
            let db_path = st.db_path.clone();
            let result = tokio::task::spawn_blocking(move || hql::execute_query(&db_path, &qs))
                .await
                .unwrap_or_else(|e| Err(format!("task panic: {e}")));
            match result {
                Ok(rows) => {
                    let n = rows.len();
                    json!({ "results": rows, "count": n })
                }
                Err(e) => json!({ "error": e }),
            }
        }
    };
    (cors(), Json(body))
}

// --- Ingestão avulsa: POST /ingest  (corpo = 1 linha de log) --------------

/// Ingere uma linha de log raw (texto puro no corpo da requisição HTTP).
///
/// Retorna o Fato selado se a linha casou com alguma regra do artefato,
/// ou `{"drift": true}` se caiu em Schema Drift.
/// Útil para integração com o Probe nativo sem partilha de memória.
async fn ingest_line(State(st): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    let line = body.trim().to_string();
    let body = if line.is_empty() {
        json!({ "error": "body vazio — envie uma linha de log no corpo da requisição" })
    } else {
        // O lock do banco é tomado ANTES do Runner porque o `forge_lsn` do
        // evento canónico é o LSN que este Fato vai ocupar: prevê-lo fora da
        // secção crítica seria uma corrida entre dois pedidos, e a proveniência
        // apontaria para outro ponto do log.
        let mut db = st.db.lock().await;
        let contexto = heraclitus::runner::EmissionContext {
            identity: &st.identity,
            forge_source_id: &st.forge_source_id,
            forge_lsn: db.current_lsn + 1,
            // Um POST avulso não traz sequência de origem própria.
            source_sequence: None,
            source_event_id: None,
        };
        let of = st
            .runner
            .lock()
            .await
            .process_observation_with_context(&line, &contexto);
        let of = match of {
            Ok(of) => of,
            // Violação de contrato do artefato, não desta linha.
            Err(error) => return (cors(), Json(json!({ "error": error.to_string() }))),
        };
        match of {
            None => {
                let fingerprint = blake3::hash(line.as_bytes()).to_hex().to_string();
                match st.quarantine.lock().await.append("gateway-http", &line) {
                    Ok(()) => {
                        warn!("[POST /ingest] Schema Drift: b3:{}", &fingerprint[..16]);
                        json!({
                            "drift": true,
                            "quarantined": true,
                            "fingerprint": format!("b3:{}", &fingerprint[..16]),
                        })
                    }
                    Err(error) => {
                        error!("falha ao cifrar quarentena: {error}");
                        json!({ "error": "falha ao persistir quarentena cifrada" })
                    }
                }
            }
            Some(mut f) => {
                let written = db.write_fact(&mut f);
                match written {
                    Err(e) => json!({ "error": e.to_string() }),
                    Ok(lsn) => {
                        let fact_copy = f.clone();
                        let mut rec = st.recent.lock().await;
                        rec.push_front(fact_copy);
                        while rec.len() > CAP {
                            rec.pop_back();
                        }
                        st.total.fetch_add(1, Ordering::Relaxed);
                        json!({ "ok": true, "lsn": lsn, "fact": f })
                    }
                }
            }
        }
    };
    (cors(), Json(body))
}

// --- Integridade: GET /verify ---------------------------------------------

async fn verify_db(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let r = st.db.lock().await.verify();
    (
        cors(),
        Json(json!({
            "status":  r.status,
            "facts":   r.facts,
            "root":    r.root,
            "message": r.message,
        })),
    )
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr: std::net::SocketAddr = std::env::var("FORGE_GATEWAY_ADDR")
        .unwrap_or_else(|_| ADDR_DEFAULT.into())
        .parse()
        .context("FORGE_GATEWAY_ADDR inválido")?;
    if !addr.ip().is_loopback() {
        anyhow::bail!("gateway sem TLS/RBAC é restrito a loopback; recebido {addr}");
    }
    if std::env::var("FORGE_CORS_ORIGIN").is_ok_and(|origin| origin == "*") {
        anyhow::bail!("FORGE_CORS_ORIGIN='*' é proibido");
    }

    let artifact_dir =
        std::env::var("FORGE_ARTIFACT_DIR").unwrap_or_else(|_| "../registry/postgresql".into());
    let artifact_path = resolve_latest_artifact(&artifact_dir)
        .context("Nenhuma versao do conector postgresql encontrada no registry")?;

    let runner = ReconstitutiveRunner::load(&artifact_path)
        .context("artefato .hcx ausente — rode: python forge_compiler.py")?;
    info!("Runner carregado (plano: {})", runner.plan_str());
    let db_path = std::env::var("FORGE_GATEWAY_DB").unwrap_or_else(|_| DB_PATH_DEFAULT.into());
    let db = FactStore::new(&db_path).context("abrir db íntegro")?;
    let verified = db.verify();
    let mut recent = VecDeque::with_capacity(CAP);
    export_facts(&db_path, 0, |_, fact| {
        recent.push_front(fact);
        if recent.len() > CAP {
            recent.pop_back();
        }
        true
    })
    .context("reconstruir janela recente do gateway")?;
    let quarantine_path =
        std::env::var("FORGE_QUARANTINE_PATH").unwrap_or_else(|_| "gateway.quarantine.hq".into());
    let quarantine = QuarantineWriter::open(
        quarantine_path,
        key_from_env().context("carregar FORGE_QUARANTINE_KEY")?,
    )
    .context("abrir quarentena cifrada")?;

    let identity = match (
        std::env::var("FORGE_GATEWAY_TENANT"),
        std::env::var("FORGE_GATEWAY_DATASOURCE"),
        std::env::var("FORGE_GATEWAY_SENSOR"),
    ) {
        (Ok(tenant), Ok(datasource), Ok(sensor)) => {
            heraclitus::hfb2::SecurityIdentity::new(tenant, datasource, sensor)
                .map_err(|erro| anyhow::anyhow!("identidade do gateway invalida: {erro}"))?
        }
        _ => {
            warn!(
                "sem FORGE_GATEWAY_TENANT/_DATASOURCE/_SENSOR: os Fatos vao ficar                  gravados com identidade de DEMONSTRACAO, nao operacional"
            );
            heraclitus::hfb2::SecurityIdentity::demo("gateway")
        }
    };

    let forge_source_id = blake3::hash(
        std::fs::read_to_string(format!("{db_path}.pub"))
            .context("ler a chave publica da ancora")?
            .trim()
            .as_bytes(),
    )
    .to_hex()
    .to_string();

    let state = Arc::new(AppState {
        identity,
        forge_source_id,
        recent: Mutex::new(recent),
        total: AtomicU64::new(verified.facts as u64),
        db: Mutex::new(db),
        runner: Mutex::new(runner),
        quarantine: Mutex::new(quarantine),
        db_path,
    });

    // Dados sintéticos são exclusivamente demo e nunca entram por omissão.
    if std::env::var("FORGE_DEMO_SAMPLES").is_ok_and(|v| v == "1") {
        let st = state.clone();
        tokio::spawn(async move {
            let mut i = 0usize;
            let mut tick = tokio::time::interval(Duration::from_millis(1200));
            loop {
                tick.tick().await;
                let line = SAMPLES[i % SAMPLES.len()];
                i += 1;
                let mut db = st.db.lock().await;
                let contexto = heraclitus::runner::EmissionContext {
                    identity: &st.identity,
                    forge_source_id: &st.forge_source_id,
                    forge_lsn: db.current_lsn + 1,
                    source_sequence: None,
                    source_event_id: None,
                };
                let of = {
                    st.runner
                        .lock()
                        .await
                        .process_observation_with_context(line, &contexto)
                };
                let of = match of {
                    Ok(of) => of,
                    Err(error) => {
                        error!("normalizacao canonica falhou: {error}");
                        continue;
                    }
                };
                if let Some(mut f) = of {
                    if let Err(e) = db.write_fact(&mut f) {
                        error!("Erro ao escrever fato: {}", e);
                        continue;
                    }
                    drop(db);
                    let mut rec = st.recent.lock().await;
                    rec.push_front(f);
                    while rec.len() > CAP {
                        rec.pop_back();
                    }
                    st.total.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/facts", get(facts))
        .route("/query", get(query_hql)) // HQL nativo
        .route("/ingest", post(ingest_line)) // ingestão avulsa
        .route("/verify", get(verify_db)) // integridade física + criptográfica
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);

    info!("Heraclitus gateway  ->  http://{addr}");
    info!("  GET  /facts?limit=N  GET  /stats  GET  /healthz");
    info!("  GET  /query?q=<HQL>  POST /ingest  GET  /verify");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind falhou")?;
    axum::serve(listener, app).await.context("serve falhou")?;
    Ok(())
}
