//! Gateway de ingestao (backend do dashboard) — axum + tokio.
//!
//! Le os Fatos do nosso runtime Rust e expoe a API REST que o dashboard
//! (HeraclitusDB/dashboard/index.html) consome no modo Ao Vivo:
//!
//!   GET /facts?limit=N  -> { "facts": [ <OperationalFact>, ... ] }  (mais recentes 1º)
//!   GET /stats          -> { "head", "lsn", "eps" }                 (badge "ao vivo")
//!   GET /healthz        -> "ok"
//!
//! Uma tarefa de ingestao continua simula o stream de log do PostgreSQL: a cada
//! ~1,2s um Fato Operacional novo e processado pelo Runner, selado no HeraclitusDB
//! e publicado no buffer recente — entao o dashboard "respira" em tempo real.
//!
//! Nao toca no heraclitus-server de producao. O Forge (IA/design-time) segue em
//! Python; aqui so roda o runtime determinístico (Runner + DB) sob tokio.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use heraclitus::db::HeraclitusDB;
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT: &str = "../registry/postgresql.hcx";
const DB_PATH: &str = "gateway.hdb";
// 7475 e do HeraclitusDB de producao (responde "panta rhei"); usamos 7480 p/ o gateway.
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

struct AppState {
    recent: Mutex<VecDeque<Value>>,
    total: AtomicU64,
    db: Mutex<HeraclitusDB>,
    runner: Mutex<ReconstitutiveRunner>,
}

fn cors() -> [(axum::http::HeaderName, &'static str); 1] {
    [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")]
}

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

#[tokio::main]
async fn main() {
    let _ = std::fs::remove_file(DB_PATH);
    let _ = std::fs::remove_file(format!("{DB_PATH}.anchor"));

    let runner = ReconstitutiveRunner::load(ARTIFACT).expect("artefato .hcx ausente");
    println!("Runner carregado (plano: {})", runner.plan_str());
    let db = HeraclitusDB::new(DB_PATH).expect("abrir db");

    let state = Arc::new(AppState {
        recent: Mutex::new(VecDeque::with_capacity(CAP)),
        total: AtomicU64::new(0),
        db: Mutex::new(db),
        runner: Mutex::new(runner),
    });

    // Tarefa de ingestao continua (simula o stream do PostgreSQL)
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
                    let _ = st.db.lock().await.write_fact(&mut f);
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
        .with_state(state);

    println!("Heraclitus gateway de ingestao  ->  http://{ADDR}");
    println!("  GET /facts?limit=N | GET /stats | GET /healthz   (CORS *)");
    let listener = tokio::net::TcpListener::bind(ADDR).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
