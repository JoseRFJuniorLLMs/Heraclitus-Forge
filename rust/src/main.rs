//! Conector PostgreSQL — versao Rust (runtime nativo).
//!
//! Le o artefato `.hcx` compilado pelo Forge (Python) e processa o log do PostgreSQL
//! em velocidade nativa, persistindo Fatos Operacionais no HeraclitusDB Rust.

use anyhow::{Context, Result};
use std::fs;
use tracing::{error, info, warn};

use heraclitus::db::FactStore;
use heraclitus::quarantine::{key_from_env, QuarantineWriter};
use heraclitus::runner::ReconstitutiveRunner;

/// Conector a usar. Sobrepõe-se com `HERACLITUS_ARTIFACT=<dir do conector>`
/// (ex.: `../registry/linux_sshd`) — sem isto só se conseguia ingerir
/// PostgreSQL, por muito que o Forge compilasse outros conectores.
const ARTIFACT_DIR_DEFAULT: &str = "../registry/postgresql";
/// Ficheiro de log a ingerir. Sobrepõe-se com a variável de ambiente
/// HERACLITUS_SAMPLE (para testar com outros ficheiros sem recompilar).
const SAMPLE_DEFAULT: &str = "../samples/postgresql.log";

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} é obrigatório fora do modo --demo"))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let demo = args == ["--demo"];
    if !args.is_empty() && !demo {
        anyhow::bail!("uso: connector_postgresql [--demo]");
    }
    let demo_dir = if demo {
        Some(tempfile::tempdir().context("criar diretório temporário da demo")?)
    } else {
        None
    };

    info!("{}", "#".repeat(64));
    info!("#  HERACLITUS (Rust) - CONECTOR POSTGRESQL");
    info!("{}", "#".repeat(64));

    // O registry é VERSIONADO (`<base>/vX.Y.Z.hcx`); o caminho fixo antigo
    // (`registry/postgresql.hcx`) já não existe e este binário falhava sempre.
    let artifact_dir = if demo {
        ARTIFACT_DIR_DEFAULT.to_string()
    } else {
        required_env("HERACLITUS_ARTIFACT")?
    };
    let Some(artifact) = heraclitus::runner::resolve_latest_artifact(&artifact_dir) else {
        error!("\n[ERRO] Nenhuma versao do conector em {artifact_dir}.");
        error!("       Rode o Forge (Python) primeiro:  python forge_compiler.py");
        std::process::exit(1);
    };
    info!("[Runner] Artefato: {artifact}");

    let mut runner = ReconstitutiveRunner::load(&artifact).context("Falha ao carregar artefato")?;

    info!(
        "[Runner] Artefato carregado. Plano (Kahn): {}",
        runner.plan_str()
    );

    let db_path = if let Some(ref dir) = demo_dir {
        dir.path()
            .join("connector-demo.hdb")
            .to_string_lossy()
            .into_owned()
    } else {
        required_env("HERACLITUS_DB_PATH")?
    };
    let mut db = FactStore::new(&db_path)
        .with_context(|| format!("Falha ao abrir banco íntegro {db_path}"))?;
    let quarantine_path = if let Some(ref dir) = demo_dir {
        dir.path().join("connector-demo.quarantine.hq")
    } else {
        required_env("FORGE_QUARANTINE_PATH")?.into()
    };
    let quarantine_key = if demo {
        [9u8; 32]
    } else {
        key_from_env().context("carregar FORGE_QUARANTINE_KEY")?
    };
    let mut quarantine = QuarantineWriter::open(quarantine_path, quarantine_key)
        .context("abrir quarentena cifrada")?;

    let sample = if demo {
        SAMPLE_DEFAULT.to_string()
    } else {
        required_env("HERACLITUS_SAMPLE")?
    };
    info!("[Ingestao] Processando {sample}...");
    let content =
        fs::read_to_string(&sample).with_context(|| format!("Falha ao ler o log {sample}"))?;
    for raw in content.lines().filter(|l| !l.trim().is_empty()) {
        match runner.process_observation(raw) {
            None => {
                quarantine
                    .append("connector-file", raw)
                    .context("gravar drift na quarentena cifrada")?;
                let fingerprint = blake3::hash(raw.as_bytes()).to_hex();
                warn!(
                    "[DRIFT] linha rejeitada: bytes={} b3:{}",
                    raw.len(),
                    &fingerprint[..16]
                );
            }
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

    info!("{}", "#".repeat(64));
    Ok(())
}
