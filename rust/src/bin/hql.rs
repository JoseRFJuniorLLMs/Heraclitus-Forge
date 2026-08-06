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

const ARTIFACT_DIR: &str = "../registry/postgresql";
/// Banco semeado pela demo. Com `HERACLITUS_DB=<ficheiro.hdb>` a demo é
/// SALTADA e as consultas correm sobre um banco JÁ existente — que é o que
/// torna isto uma ferramenta pericial e não apenas um exemplo.
const DB_DEMO: &str = "hql_demo.hdb";

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

fn run_query(db_path: &str, label: &str, q: &str) {
    info!("─────────────────────────────────────────────────────────");
    info!("[HQL] {label}");
    info!("   > {q}");
    match hql::execute_query(db_path, q) {
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

    // Banco EXISTENTE (perícia) ou demo semeada?
    let existing = std::env::var("HERACLITUS_DB").ok();
    let db_path = existing.clone().unwrap_or_else(|| DB_DEMO.to_string());

    let db = if let Some(ref p) = existing {
        info!("─────────────────────────────────────────────────────────");
        info!("[Perícia] a consultar o banco existente {p} (sem semear)");
        HeraclitusDB::new(p).context("abrir db existente")?
    } else {
        let _ = fs::remove_file(&db_path);
        let _ = fs::remove_file(format!("{db_path}.anchor"));
        let artifact = heraclitus::runner::resolve_latest_artifact(ARTIFACT_DIR)
            .context("nenhuma versao do conector no registry (rode o Forge antes)")?;
        let mut runner =
            ReconstitutiveRunner::load(&artifact).context("carregar artefato .hcx")?;
        let mut db = HeraclitusDB::new(&db_path).context("abrir db")?;
        let mut sealed = 0usize;
        for s in SAMPLES {
            if let Some(mut f) = runner.process_observation(s) {
                db.write_fact(&mut f).context("gravar")?;
                sealed += 1;
            }
        }
        info!("─────────────────────────────────────────────────────────");
        info!("[Setup] {sealed} Fatos selados no banco (dupla camada: CRC-32C + BLAKE3 Merkle)");
        db
    };

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
    run_query(&db_path, "Pericial — autenticações falhas (filtro específico + zero-copy)", &q1);

    // --- Query 2: Wildcard na ação + LIMIT 3 + SELECT * ---
    let q2 = concat!(
        "FROM FACTS MATCH (actor.id) ",
        "EXECUTES \"*\" AGAINST \"postgresql\" ",
        "SELECT * ",
        "LIMIT 3"
    );
    run_query(&db_path, "Wildcard action + SELECT * + LIMIT 3", q2);

    // --- Query 3: Ação específica + wildcard no target ---
    let q3 = concat!(
        "FROM FACTS MATCH (actor.id, actor.name) ",
        "EXECUTES \"authorization.failure\" AGAINST \"*\" ",
        "SELECT actor.name, target.id, risk, lsn, matched_rule"
    );
    run_query(&db_path, "Wildcard target — todas as violações de autorização", q3);

    // Só a demo se auto-limpa; um banco de perícia NUNCA é apagado.
    if existing.is_none() {
        let _ = fs::remove_file(&db_path);
        let _ = fs::remove_file(format!("{db_path}.anchor"));
    }
    Ok(())
}
