//! Heraclitus Fabric — orquestrador de borda NATIVO (data plane em Rust).
//!
//! Substitui o antigo `heraclitus_fabric.py`. Executa o "ciclo de Segunda-Feira" em
//! velocidade nativa: Discover -> Deploy Runners (1 por ativo) -> Observe (ingestao)
//! -> Schema Drift -> Quarentena -> handoff para o CKE (Knowledge Cloud / Python) via
//! uma quarentena cifrada.
//!
//! O Forge (compilacao de `.hcx`) permanece em Python/Design-Time: aqui os artefatos
//! ja devem existir no Registry — rode `python forge_compiler.py` antes, ou puxe da nuvem.

use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{error, info, warn};

use heraclitus::db::FactStore;
use heraclitus::quarantine::QuarantineWriter;
use heraclitus::runner::ReconstitutiveRunner;

const REGISTRY: &str = "../registry";

struct Asset {
    ip: &'static str,
    fingerprint: &'static str,
    vendor: &'static str,
}

fn resolve_latest_artifact(base: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(base)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let version = name.strip_prefix('v')?.strip_suffix(".hcx")?;
            let parts: Vec<u32> = version
                .split('.')
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?;
            (parts.len() == 3).then(|| ((parts[0], parts[1], parts[2]), entry.path()))
        })
        .max_by_key(|(version, _)| *version)
        .map(|(_, path)| path)
}

const PG_STREAM: &[&str] = &[
    "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:07.410 UTC [14804] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:08.560 UTC [14805] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:09.700 UTC [14806] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
];

const DRIFT_STREAM: &[&str] = &[
    "<13> TIME=2026-06-26 user=admin EVENT=auth_error platform_target=root",
    "2026-06-26 03:11:01 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.5 action=deny",
    "2026-06-26 03:11:02 UTC FORTI devid=FGT60D type=traffic srcip=10.0.0.9 action=deny",
    "2026-06-26 03:11:05 UTC FORTI devid=FGT61D type=traffic srcip=10.0.0.7 action=accept",
    "SIGRH|user=carlos|op=DELETE|tbl=beneficios|status=erro",
    "SIGRH|user=ana|op=UPDATE|tbl=folha|status=ok",
];

fn monitor(
    runners: &mut HashMap<&'static str, ReconstitutiveRunner>,
    db: &mut FactStore,
    quarantine: &mut QuarantineWriter,
    quarantined: &mut usize,
    ip: &str,
    lines: &[&str],
) -> Result<()> {
    let Some(runner) = runners.get_mut(ip) else {
        warn!("nenhum runner ativo para {ip}");
        return Ok(());
    };
    for raw in lines {
        match runner.process_observation(raw) {
            Some(mut f) => {
                let lsn = db.write_fact(&mut f).context("gravar fato falhou")?;
                let b = &f["fact.behavior"];
                info!(
                    "{} | LSN {} | {:<24} | {:<18} | {}",
                    ip,
                    lsn,
                    b["action"].as_str().unwrap_or(""),
                    b["class"].as_str().unwrap_or(""),
                    b["risk_level"].as_str().unwrap_or("")
                );
            }
            None => {
                quarantine
                    .append(ip, raw)
                    .context("gravar observação na quarentena cifrada")?;
                *quarantined += 1;
                let preview: String = raw.chars().take(56).collect();
                warn!("{} | [SCHEMA DRIFT -> quarentena] {}", ip, preview);
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args != ["--demo"] {
        anyhow::bail!(
            "fabric contém apenas dados sintéticos e só pode ser executado com --demo; \
             para ingestão operacional use o binário probe"
        );
    }

    // A demonstração nunca toca em caminhos operacionais: banco, chave e
    // quarentena vivem num diretório temporário removido no fim do processo.
    let demo_dir = tempfile::tempdir().context("criar diretório temporário da demo")?;
    let db_path = demo_dir.path().join("fabric.hdb");
    let quarantine_path = demo_dir.path().join("fabric.quarantine.hq");
    let mut quarantine_key = [0u8; 32];
    getrandom::getrandom(&mut quarantine_key)
        .map_err(|error| anyhow::anyhow!("gerar chave efêmera da demo: {error}"))?;

    info!("=== Heraclitus Fabric (demo isolada) — ciclo de Segunda-Feira ===");

    let assets = [
        Asset {
            ip: "10.0.4.15",
            fingerprint: "postgresql",
            vendor: "PostgreSQL Cluster",
        },
        Asset {
            ip: "10.0.4.12",
            fingerprint: "linux_sshd",
            vendor: "Linux OS (OpenSSH)",
        },
    ];

    // 1. Discover & Deploy — 1 Runner por ativo (artefato vindo do Registry)
    info!("[1] Discover & Deploy");
    let mut runners: HashMap<&'static str, ReconstitutiveRunner> = HashMap::new();
    for a in &assets {
        let artifact_dir = std::path::Path::new(REGISTRY).join(a.fingerprint);
        let Some(art) = resolve_latest_artifact(&artifact_dir) else {
            warn!(
                "{} ({}): artefato ausente -> rode `python forge_compiler.py` (Design-Time)",
                a.ip, a.fingerprint
            );
            continue;
        };
        let Some(art_text) = art.to_str() else {
            error!("{}: caminho de artefato não é UTF-8", art.display());
            continue;
        };
        match ReconstitutiveRunner::load(art_text) {
            Ok(r) => {
                info!("[OK] {} -> {} ({})", a.ip, a.fingerprint, a.vendor);
                runners.insert(a.ip, r);
            }
            Err(e) => error!("[ERRO] {}: {}", a.ip, e),
        }
    }
    if runners.is_empty() {
        error!("Nenhum runner provisionado. Compile os .hcx: `python forge_compiler.py`.");
        std::process::exit(1);
    }

    let db_path_text = db_path.to_string_lossy();
    let mut db = FactStore::new(&db_path_text).context("Falha ao abrir db temporário")?;
    let mut quarantine = QuarantineWriter::open(&quarantine_path, quarantine_key)
        .context("Falha ao abrir quarentena cifrada temporária")?;
    let mut quarantined = 0usize;

    // 2. Observe — trafego operacional do PostgreSQL (brute force)
    info!("[2] Observe — trafego PostgreSQL (brute force)");
    monitor(
        &mut runners,
        &mut db,
        &mut quarantine,
        &mut quarantined,
        "10.0.4.15",
        PG_STREAM,
    )?;

    // 3. Schema Drift — formatos desconhecidos vao para a quarentena
    info!("[3] Schema Drift — formatos desconhecidos");
    monitor(
        &mut runners,
        &mut db,
        &mut quarantine,
        &mut quarantined,
        "10.0.4.12",
        DRIFT_STREAM,
    )?;

    // 4. Learn — handoff para o CKE (Knowledge Cloud, Python)
    info!("[4] Learn — handoff p/ o CKE (Knowledge Cloud)");
    if quarantined == 0 {
        info!("quarentena vazia.");
    } else {
        info!(
            "{} observacoes cifradas em {} (temporário; demo não faz handoff)",
            quarantined,
            quarantine.path().display()
        );
    }

    // 5. Integridade
    let r = db.verify();
    info!("[5] db.verify(): {} (Fatos: {})", r.status, r.facts);

    Ok(())
}
