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
    extract::{Query, State},
    http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, error, warn};

use heraclitus::db::HeraclitusDB;
use heraclitus::hql;
use heraclitus::runner::ReconstitutiveRunner;

fn resolve_latest_artifact(base: &str) -> Option<String> {
    let dir = std::path::Path::new(base);
    if !dir.exists() || !dir.is_dir() {
        return None;
    }
    let mut highest = (0, 0, 0);
    let mut highest_path = None;

    for entry in std::fs::read_dir(dir).ok()? {
        if let Ok(e) = entry {
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
    }
    highest_path
}

const DB_PATH: &str = "gateway.hdb";
/// Porta distinta do HeraclitusDB de produção (7475 = "panta rhei").
const ADDR: &str = "127.0.0.1:7480";
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
    db: Mutex<HeraclitusDB>,
    runner: Mutex<ReconstitutiveRunner>,
}

fn cors() -> [(axum::http::HeaderName, &'static str); 1] {
    [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")]
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
    (cors(), Json(json!({ "head": total, "events": total, "lsn": lsn })))
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
    State(_st): State<Arc<AppState>>,
    Query(params): Query<HqlQ>,
) -> impl IntoResponse {
    let body = match params.q.filter(|s| !s.is_empty()) {
        None => json!({
            "error": "parâmetro 'q' obrigatório",
            "exemplo": "GET /query?q=FROM FACTS MATCH (actor.id) EXECUTES \"*\" AGAINST \"*\" SELECT * LIMIT 10"
        }),
        Some(qs) => {
            let result = tokio::task::spawn_blocking(move || hql::execute_query(DB_PATH, &qs))
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
async fn ingest_line(
    State(st): State<Arc<AppState>>,
    body: String,
) -> impl IntoResponse {
    let line = body.trim().to_string();
    let body = if line.is_empty() {
        json!({ "error": "body vazio — envie uma linha de log no corpo da requisição" })
    } else {
        let of = st.runner.lock().await.process_observation(&line);
        match of {
            None => {
                // Truncar por CARACTERES, não por bytes: `&line[..80]` num corpo
                // HTTP multibyte (UTF-8) que caísse a meio de um caractere
                // panicava o handler (índice fora de fronteira de char).
                let short: String = line.chars().take(80).collect();
                let short200: String = line.chars().take(200).collect();
                warn!("[POST /ingest] Schema Drift: {}", short);
                json!({ "drift": true, "line": short200 })
            }
            Some(mut f) => {
                match st.db.lock().await.write_fact(&mut f) {
                    Err(e) => json!({ "error": e.to_string() }),
                    Ok(lsn) => {
                        let fact_copy = f.clone();
                        let mut rec = st.recent.lock().await;
                        rec.push_front(fact_copy);
                        while rec.len() > CAP { rec.pop_back(); }
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
    (cors(), Json(json!({
        "status":  r.status,
        "facts":   r.facts,
        "root":    r.root,
        "message": r.message,
    })))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let _ = std::fs::remove_file(DB_PATH);
    let _ = std::fs::remove_file(format!("{DB_PATH}.anchor"));

    let artifact_path = resolve_latest_artifact("../registry/postgresql")
        .context("Nenhuma versao do conector postgresql encontrada no registry")?;

    let runner = ReconstitutiveRunner::load(&artifact_path).context("artefato .hcx ausente — rode: python forge_compiler.py")?;
    info!("Runner carregado (plano: {})", runner.plan_str());
    let db = HeraclitusDB::new(DB_PATH).context("abrir db")?;

    let state = Arc::new(AppState {
        recent: Mutex::new(VecDeque::with_capacity(CAP)),
        total: AtomicU64::new(0),
        db: Mutex::new(db),
        runner: Mutex::new(runner),
    });

    // Tarefa de ingestão contínua (simula stream PostgreSQL)
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut i = 0usize;
            let mut tick = tokio::time::interval(Duration::from_millis(1200));
            loop {
                tick.tick().await;
                let line = SAMPLES[i % SAMPLES.len()];
                i += 1;
                let of = { st.runner.lock().await.process_observation(line) };
                if let Some(mut f) = of {
                    if let Err(e) = st.db.lock().await.write_fact(&mut f) {
                        error!("Erro ao escrever fato: {}", e);
                        continue;
                    }
                    let mut rec = st.recent.lock().await;
                    rec.push_front(f);
                    while rec.len() > CAP { rec.pop_back(); }
                    st.total.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/stats",   get(stats))
        .route("/facts",   get(facts))
        .route("/query",   get(query_hql))    // HQL nativo
        .route("/ingest",  post(ingest_line)) // ingestão avulsa
        .route("/verify",  get(verify_db))    // integridade física + criptográfica
        .with_state(state);

    info!("Heraclitus gateway  ->  http://{ADDR}");
    info!("  GET  /facts?limit=N  GET  /stats  GET  /healthz");
    info!("  GET  /query?q=<HQL>  POST /ingest  GET  /verify   (CORS *)");
    let listener = tokio::net::TcpListener::bind(ADDR).await.context("bind falhou")?;
    axum::serve(listener, app).await.context("serve falhou")?;
    Ok(())
}
