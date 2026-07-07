//! Demo/teste do HQL nativo: semeia um `.hdb` com o Runner e roda consultas periciais.
//!
//! Demonstra:
//!   - Query específica com filtro EXECUTES + AGAINST + WITHIN + SELECT
//!   - Query com wildcard `*` na ação + LIMIT
//!   - SELECT * (retorna todos os campos do Fato)

use std::fs;

use anyhow::{Context, Result};
use tracing::{info, error};

use heraclitus::db::HeraclitusDB;
use heraclitus::hql;
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT: &str = "../registry/postgresql.hcx";
const DB: &str = "hql_demo.hdb";

const SAMPLES: &[&str] = &[
    "2026-06-26 01:20:00.001 UTC [14801] LOG:  database system is ready to accept connections",
    "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:07.410 UTC [14804] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:08.560 UTC [14805] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:09.700 UTC [14806] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
];

fn run_query(label: &str, q: &str) {
    info!("─────────────────────────────────────────────────────────");
    info!("[HQL] {label}");
    info!("   > {q}");
    match hql::execute_query(DB, q) {
        Ok(rows) => {
            info!("[OK] {} fato(s) retornado(s)", rows.len());
            for (i, row) in rows.iter().enumerate() {
                let json = serde_json::to_string_pretty(row).unwrap_or_else(|_| "{}".into());
                info!("  [{}] {}", i + 1, json);
            }
        }
        Err(e) => error!("[ERRO] {e}"),
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let _ = fs::remove_file(DB);
    let _ = fs::remove_file(format!("{DB}.anchor"));

    // --- Semear o banco com os samples ---
    let mut runner = ReconstitutiveRunner::load(ARTIFACT).context("artefato .hcx (rode o Forge antes)")?;
    let mut db = HeraclitusDB::new(DB).context("abrir db")?;
    let mut sealed = 0usize;
    for s in SAMPLES {
        if let Some(mut f) = runner.process_observation(s) {
            db.write_fact(&mut f).context("gravar")?;
            sealed += 1;
        }
    }
    info!("─────────────────────────────────────────────────────────");
    info!("[Setup] {sealed} Fatos selados no banco (dupla camada: CRC-32C + BLAKE3 Merkle)");

    // --- Verificação de integridade ---
    let vr = db.verify();
    info!("[verify()] status={} fatos={}", vr.status, vr.facts);

    // --- Query 1: Pericial específica com SELECT projetado ---
    let q1 = std::env::args().nth(1).unwrap_or_else(|| {
        concat!(
            "FROM FACTS MATCH (actor.id, actor.name) ",
            "EXECUTES \"authentication.failure\" AGAINST \"postgresql\" ",
            "WITHIN LAST 6 HOURS ",
            "SELECT fact.id, actor.name, risk, lsn, integrity.merkle_root_anchor"
        )
        .to_string()
    });
    run_query("Pericial — autenticações falhas (filtro específico + zero-copy)", &q1);

    // --- Query 2: Wildcard na ação + LIMIT 3 + SELECT * ---
    let q2 = concat!(
        "FROM FACTS MATCH (actor.id) ",
        "EXECUTES \"*\" AGAINST \"postgresql\" ",
        "SELECT * ",
        "LIMIT 3"
    );
    run_query("Wildcard action + SELECT * + LIMIT 3", q2);

    // --- Query 3: Ação específica + wildcard no target ---
    let q3 = concat!(
        "FROM FACTS MATCH (actor.id, actor.name) ",
        "EXECUTES \"authorization.failure\" AGAINST \"*\" ",
        "SELECT actor.name, target.id, risk, lsn, matched_rule"
    );
    run_query("Wildcard target — todas as violações de autorização", q3);

    let _ = fs::remove_file(DB);
    let _ = fs::remove_file(format!("{DB}.anchor"));
    Ok(())
}
