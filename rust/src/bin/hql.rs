//! Demo/teste do HQL nativo: semeia um `.hdb` com o Runner e roda uma consulta pericial.

use std::fs;

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

fn main() {
    let _ = fs::remove_file(DB);
    let _ = fs::remove_file(format!("{DB}.anchor"));

    let mut runner = ReconstitutiveRunner::load(ARTIFACT).expect("artefato .hcx (rode o Forge antes)");
    let mut db = HeraclitusDB::new(DB).expect("abrir db");
    for s in SAMPLES {
        if let Some(mut f) = runner.process_observation(s) {
            db.write_fact(&mut f).expect("gravar");
        }
    }

    let query = std::env::args().nth(1).unwrap_or_else(|| {
        concat!(
            "FROM FACTS MATCH (actor.id, actor.name) ",
            "EXECUTES \"authentication.failure\" AGAINST \"postgresql\" ",
            "WITHIN LAST 6 HOURS ",
            "SELECT fact.id, actor.name, fact.behavior.class, fact.behavior.risk_level, integrity.merkle_root_anchor"
        )
        .to_string()
    });

    println!("HQL> {query}\n");
    match hql::execute_query(DB, &query) {
        Ok(rows) => {
            println!("[OK] Fatos extraidos: {}", rows.len());
            println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        }
        Err(e) => {
            eprintln!("[ERRO] {e}");
            std::process::exit(1);
        }
    }

    let _ = fs::remove_file(DB);
    let _ = fs::remove_file(format!("{DB}.anchor"));
}
