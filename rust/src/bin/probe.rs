//! Heraclitus Fabric — Probe de Ingestão de Ponta (syslog UDP real, nativo).
//!
//! Substitui o array estático simulado do `heraclitus_fabric.py` por um listener
//! UDP de verdade: escuta um socket, descasca o prefixo de prioridade syslog
//! (`<NN>`), passa cada linha pelo Runner -> Fato Operacional -> HeraclitusDB e
//! desvia o que falha na validação sintática para a quarentena (Schema Drift).
//!
//!   cargo run --release --bin probe              # listener contínuo em 127.0.0.1:5514
//!   cargo run --release --bin probe -- --selftest  # auto-teste (envia a si mesmo)

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use heraclitus::db::HeraclitusDB;
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT: &str = "../registry/postgresql.hcx";
const DB: &str = "probe.hdb";
const BIND: &str = "127.0.0.1:5514"; // 514 exigiria privilégio; 5514 roda sem admin

const SELFTEST_LINES: &[&str] = &[
    "<13>2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:07.410 UTC [14804] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:08.560 UTC [14805] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:09.700 UTC [14806] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "<13>2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
    "<13>GARBAGE: isto nao e um log do postgres e deve cair na quarentena",
];

/// Remove o prefixo de prioridade syslog `<NN>` se presente.
fn strip_syslog_pri(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('<') {
        if let Some(i) = rest.find('>') {
            return &rest[i + 1..];
        }
    }
    s
}

fn main() -> std::io::Result<()> {
    let selftest = std::env::args().any(|a| a == "--selftest");

    let _ = std::fs::remove_file(DB);
    let _ = std::fs::remove_file(format!("{DB}.anchor"));

    let mut runner = ReconstitutiveRunner::load(ARTIFACT).expect("artefato .hcx (rode o Forge antes)");
    let mut db = HeraclitusDB::new(DB)?;
    let sock = UdpSocket::bind(BIND)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    println!("[Fabric Probe] escutando syslog UDP em {BIND}  (artefato: postgresql.hcx)");
    if selftest {
        println!("[selftest] enviando {} datagramas a si mesmo...\n", SELFTEST_LINES.len());
        std::thread::spawn(|| {
            let s = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            for line in SELFTEST_LINES {
                let _ = s.send_to(line.as_bytes(), BIND);
                std::thread::sleep(Duration::from_millis(40));
            }
        });
    } else {
        println!("Envie linhas (ex.: logger/rsyslog). Ctrl+C para sair.\n");
    }

    let mut buf = [0u8; 65536];
    let mut sealed = 0u64;
    let mut quarantine = 0u64;
    let mut got_any = false;
    let mut last_stats = Instant::now();

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                got_any = true;
                let payload = String::from_utf8_lossy(&buf[..n]).into_owned();
                for line in payload.lines() {
                    let line = strip_syslog_pri(line.trim());
                    if line.is_empty() {
                        continue;
                    }
                    match runner.process_observation(line) {
                        Some(mut f) => {
                            let lsn = db.write_fact(&mut f)?;
                            sealed += 1;
                            let b = &f["fact.behavior"];
                            println!(
                                "[{src}] LSN {lsn} | {:<22} | {:<18} | {}",
                                b["action"].as_str().unwrap_or(""),
                                b["class"].as_str().unwrap_or(""),
                                b["risk_level"].as_str().unwrap_or("")
                            );
                        }
                        None => {
                            quarantine += 1;
                            println!("[{src}] [SCHEMA DRIFT -> quarentena] {}",
                                     &line[..line.len().min(56)]);
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if selftest && got_any {
                    break; // sem mais datagramas: encerra o auto-teste
                }
                if last_stats.elapsed() >= Duration::from_secs(10) {
                    println!("-- stats: selados={sealed} quarentena={quarantine} --");
                    last_stats = Instant::now();
                }
            }
            Err(e) => eprintln!("erro recv: {e}"),
        }
    }

    println!("\n[selftest] resultado: selados={sealed} quarentena={quarantine}");
    let ok = sealed == 7 && quarantine == 1;
    println!("[selftest] {}", if ok { "OK (7 selados, 1 quarentena)" } else { "FALHOU" });
    let _ = std::fs::remove_file(DB);
    let _ = std::fs::remove_file(format!("{DB}.anchor"));
    std::process::exit(if ok { 0 } else { 1 });
}
