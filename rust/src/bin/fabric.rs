//! Heraclitus Fabric — orquestrador de borda NATIVO (data plane em Rust).
//!
//! Substitui o antigo `heraclitus_fabric.py`. Executa o "ciclo de Segunda-Feira" em
//! velocidade nativa: Discover -> Deploy Runners (1 por ativo) -> Observe (ingestao)
//! -> Schema Drift -> Quarentena -> handoff para o CKE (Knowledge Cloud / Python) via
//! `quarantine.log`.
//!
//! O Forge (compilacao de `.hcx`) permanece em Python/Design-Time: aqui os artefatos
//! ja devem existir no Registry — rode `python forge_compiler.py` antes, ou puxe da nuvem.

use std::collections::HashMap;
use std::fs;
use std::io::Write;

use heraclitus::db::HeraclitusDB;
use heraclitus::runner::ReconstitutiveRunner;

const REGISTRY: &str = "../registry";
const DB_PATH: &str = "fabric.hdb";
const QUARANTINE: &str = "quarantine.log";

struct Asset {
    ip: &'static str,
    fingerprint: &'static str,
    vendor: &'static str,
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
    db: &mut HeraclitusDB,
    quarantine: &mut Vec<String>,
    ip: &str,
    lines: &[&str],
) {
    let Some(runner) = runners.get_mut(ip) else {
        println!("   [!] nenhum runner ativo para {ip}");
        return;
    };
    for raw in lines {
        match runner.process_observation(raw) {
            Some(mut f) => {
                let lsn = db.write_fact(&mut f).expect("gravar");
                let b = &f["fact.behavior"];
                println!(
                    "   {ip} | LSN {lsn} | {:<24} | {:<18} | {}",
                    b["action"].as_str().unwrap_or(""),
                    b["class"].as_str().unwrap_or(""),
                    b["risk_level"].as_str().unwrap_or("")
                );
            }
            None => {
                quarantine.push((*raw).to_string());
                println!("   {ip} | [SCHEMA DRIFT -> quarentena] {}", &raw[..raw.len().min(56)]);
            }
        }
    }
}

fn main() {
    let _ = fs::remove_file(DB_PATH);
    let _ = fs::remove_file(format!("{DB_PATH}.anchor"));
    let _ = fs::remove_file(QUARANTINE);

    println!("=== Heraclitus Fabric (nativo) — ciclo de Segunda-Feira ===\n");

    let assets = [
        Asset { ip: "10.0.4.15", fingerprint: "postgresql", vendor: "PostgreSQL Cluster" },
        Asset { ip: "10.0.4.12", fingerprint: "linux_sshd", vendor: "Linux OS (OpenSSH)" },
    ];

    // 1. Discover & Deploy — 1 Runner por ativo (artefato vindo do Registry)
    println!("[1] Discover & Deploy");
    let mut runners: HashMap<&'static str, ReconstitutiveRunner> = HashMap::new();
    for a in &assets {
        let art = format!("{REGISTRY}/{}.hcx", a.fingerprint);
        if !std::path::Path::new(&art).exists() {
            println!("   [!] {} ({}): artefato ausente -> rode `python forge_compiler.py` (Design-Time)",
                     a.ip, a.fingerprint);
            continue;
        }
        match ReconstitutiveRunner::load(&art) {
            Ok(r) => {
                println!("   [OK] {} -> {} ({})", a.ip, a.fingerprint, a.vendor);
                runners.insert(a.ip, r);
            }
            Err(e) => println!("   [ERRO] {}: {e}", a.ip),
        }
    }
    if runners.is_empty() {
        eprintln!("\nNenhum runner provisionado. Compile os .hcx: `python forge_compiler.py`.");
        std::process::exit(1);
    }

    let mut db = HeraclitusDB::new(DB_PATH).expect("abrir db");
    let mut quarantine: Vec<String> = Vec::new();

    // 2. Observe — trafego operacional do PostgreSQL (brute force)
    println!("\n[2] Observe — trafego PostgreSQL (brute force)");
    monitor(&mut runners, &mut db, &mut quarantine, "10.0.4.15", PG_STREAM);

    // 3. Schema Drift — formatos desconhecidos vao para a quarentena
    println!("\n[3] Schema Drift — formatos desconhecidos");
    monitor(&mut runners, &mut db, &mut quarantine, "10.0.4.12", DRIFT_STREAM);

    // 4. Learn — handoff para o CKE (Knowledge Cloud, Python)
    println!("\n[4] Learn — handoff p/ o CKE (Knowledge Cloud)");
    if quarantine.is_empty() {
        println!("   quarentena vazia.");
    } else {
        let mut f = fs::File::create(QUARANTINE).expect("criar quarantine.log");
        for q in &quarantine {
            writeln!(f, "{q}").ok();
        }
        println!("   {} observacoes -> {QUARANTINE}", quarantine.len());
        println!("   rode: python cke.py {QUARANTINE}   (clusteriza e gera sementes de conector)");
    }

    // 5. Integridade
    let r = db.verify();
    println!("\n[5] db.verify(): {} (Fatos: {})", r.status, r.facts);
    let _ = fs::remove_file(DB_PATH);
    let _ = fs::remove_file(format!("{DB_PATH}.anchor"));
}
