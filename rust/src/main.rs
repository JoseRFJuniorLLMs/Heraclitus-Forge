//! Conector PostgreSQL — versao Rust (runtime nativo).
//!
//! Le o artefato `.hcx` compilado pelo Forge (Python) e processa o log do PostgreSQL
//! em velocidade nativa, persistindo Fatos Operacionais no HeraclitusDB Rust.

use std::fs;

use heraclitus::db::HeraclitusDB;
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT: &str = "../registry/postgresql.hcx";
const SAMPLE: &str = "../samples/postgresql.log";
const DB_PATH: &str = "storage_rs.hdb";

fn main() {
    let _ = fs::remove_file(DB_PATH);
    let _ = fs::remove_file(format!("{DB_PATH}.anchor"));

    println!("{}", "#".repeat(64));
    println!("#  HERACLITUS (Rust) - CONECTOR POSTGRESQL");
    println!("{}", "#".repeat(64));

    if !std::path::Path::new(ARTIFACT).exists() {
        eprintln!("\n[ERRO] Artefato {ARTIFACT} ausente.");
        eprintln!("       Rode o Forge (Python) primeiro:  python forge_compiler.py");
        std::process::exit(1);
    }

    let mut runner = match ReconstitutiveRunner::load(ARTIFACT) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERRO] Falha ao carregar artefato: {e}");
            std::process::exit(1);
        }
    };
    println!("\n[Runner] Artefato carregado. Plano (Kahn): {}", runner.plan_str());

    let mut db = HeraclitusDB::new(DB_PATH).expect("abrir db");

    println!("\n[Ingestao] Processando {SAMPLE}...\n");
    let content = fs::read_to_string(SAMPLE).expect("ler sample");
    for raw in content.lines().filter(|l| !l.trim().is_empty()) {
        match runner.process_observation(raw) {
            None => println!("  [DRIFT] linha rejeitada: {}", &raw[..raw.len().min(50)]),
            Some(mut f) => {
                let lsn = db.write_fact(&mut f).expect("gravar");
                let b = &f["fact.behavior"];
                let actor = f["fact.identity"]["actor.name"].as_str().unwrap_or("null");
                println!(
                    "  LSN {lsn} | {:<24} | class={:<18} | risk={:<8} | actor={actor}",
                    b["action"].as_str().unwrap_or(""),
                    b["class"].as_str().unwrap_or(""),
                    b["risk_level"].as_str().unwrap_or(""),
                );
            }
        }
    }

    println!("\n[Auditoria] db.verify()");
    let r1 = db.verify();
    println!("  inicial: {} (Fatos: {})", r1.status, r1.facts);

    println!("\n[Ataque] adulterando o ultimo LSN no disco...");
    db.inject_malicious_tamper(db.current_lsn).expect("tamper");
    let r2 = db.verify();
    println!("  pos-ataque: {} ({})", r2.status, r2.message);
    if r2.status != "INTEG_OK" {
        println!("  [ALERTA FORENSE] adulteracao detectada.");
    }

    println!("\n{}", "#".repeat(64));
}
