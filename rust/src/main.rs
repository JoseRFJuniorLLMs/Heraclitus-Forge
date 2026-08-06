//! Conector PostgreSQL — versao Rust (runtime nativo).
//!
//! Le o artefato `.hcx` compilado pelo Forge (Python) e processa o log do PostgreSQL
//! em velocidade nativa, persistindo Fatos Operacionais no HeraclitusDB Rust.

use std::fs;
use anyhow::{Context, Result};
use tracing::{info, warn, error};

use heraclitus::db::HeraclitusDB;
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT_DIR: &str = "../registry/postgresql";
/// Ficheiro de log a ingerir. Sobrepõe-se com a variável de ambiente
/// HERACLITUS_SAMPLE (para testar com outros ficheiros sem recompilar).
const SAMPLE_DEFAULT: &str = "../samples/postgresql.log";
const DB_PATH: &str = "storage_rs.hdb";

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let _ = fs::remove_file(DB_PATH);
    let _ = fs::remove_file(format!("{DB_PATH}.anchor"));

    info!("{}", "#".repeat(64));
    info!("#  HERACLITUS (Rust) - CONECTOR POSTGRESQL");
    info!("{}", "#".repeat(64));

    // O registry é VERSIONADO (`<base>/vX.Y.Z.hcx`); o caminho fixo antigo
    // (`registry/postgresql.hcx`) já não existe e este binário falhava sempre.
    let Some(artifact) = heraclitus::runner::resolve_latest_artifact(ARTIFACT_DIR) else {
        error!("\n[ERRO] Nenhuma versao do conector em {ARTIFACT_DIR}.");
        error!("       Rode o Forge (Python) primeiro:  python forge_compiler.py");
        std::process::exit(1);
    };
    info!("[Runner] Artefato: {artifact}");

    let mut runner = ReconstitutiveRunner::load(&artifact)
        .context("Falha ao carregar artefato")?;

    info!("[Runner] Artefato carregado. Plano (Kahn): {}", runner.plan_str());

    let mut db = HeraclitusDB::new(DB_PATH).context("Falha ao abrir db")?;

    let sample = std::env::var("HERACLITUS_SAMPLE").unwrap_or_else(|_| SAMPLE_DEFAULT.to_string());
    info!("[Ingestao] Processando {sample}...");
    let content = fs::read_to_string(&sample)
        .with_context(|| format!("Falha ao ler o log {sample}"))?;
    for raw in content.lines().filter(|l| !l.trim().is_empty()) {
        match runner.process_observation(raw) {
            None => warn!("[DRIFT] linha rejeitada: {}", &raw[..raw.len().min(50)]),
            Some(mut f) => {
                let lsn = db.write_fact(&mut f).context("Falha ao gravar fato")?;
                let b = &f["fact.behavior"];
                let actor = f["fact.identity"]["actor.name"].as_str().unwrap_or("null");
                info!(
                    "LSN {lsn} | {:<24} | class={:<18} | risk={:<8} | actor={actor}",
                    b["action"].as_str().unwrap_or(""),
                    b["class"].as_str().unwrap_or(""),
                    b["risk_level"].as_str().unwrap_or(""),
                );
            }
        }
    }

    info!("[Auditoria] db.verify()");
    let r1 = db.verify();
    info!("  inicial: {} (Fatos: {})", r1.status, r1.facts);

    info!("[Ataque] adulterando o ultimo LSN no disco...");
    db.inject_malicious_tamper(db.current_lsn).context("Falha ao injetar tamper")?;
    let r2 = db.verify();
    info!("  pos-ataque: {} ({})", r2.status, r2.message);
    if r2.status != "INTEG_OK" {
        warn!("[ALERTA FORENSE] adulteracao detectada.");
    }

    info!("{}", "#".repeat(64));
    Ok(())
}
