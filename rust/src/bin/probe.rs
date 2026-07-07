//! Heraclitus Fabric — Probe de Ingestão de Ponta (UDP + TCP syslog, nativo).
//!
//! Substitui o array estático simulado do `heraclitus_fabric.py` por listeners
//! de rede reais. Suporta dois transportes:
//!
//!   UDP (padrão, RFC 5426): datagramas, sem conexão, alta vazão.
//!   TCP (opt, RFC 6587):   fluxo de conexões, framing por newline.
//!
//! Cada datagrama/linha passa pelo Runner → Fato Operacional → HeraclitusDB.
//! Linhas que falham na validação sintática vão para a quarentena (Schema Drift).
//!
//! ## Arquitetura de canais
//!
//! ```text
//! UDP socket  ─┐
//!              ├─→  mpsc::channel<(src, line)>  ─→  loop principal
//! TCP accept  ─┘                                       │
//!                                                   Runner → DB
//!                                                       │
//!                                                   quarentena
//! ```
//!
//! ## Uso
//!
//! ```sh
//! cargo run --release --bin probe                    # UDP em 127.0.0.1:5514
//! cargo run --release --bin probe -- --tcp           # UDP + TCP em 127.0.0.1:5515
//! cargo run --release --bin probe -- --selftest      # auto-teste UDP
//! cargo run --release --bin probe -- --tcp --selftest # auto-teste UDP + TCP
//! ```

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{info, warn, error};

use heraclitus::db::HeraclitusDB;
use heraclitus::runner::ReconstitutiveRunner;

fn resolve_latest_artifact(base: &str) -> Option<String> {
    let dir = std::path::Path::new(base);
    if !dir.exists() || !dir.is_dir() {
        return None;
    }
    let mut highest = (0, 0, 0);
    let mut highest_path = None;

    for entry in std::fs::read_dir(dir).ok()? {
        if let Ok(e) = entry {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('v') && name.ends_with(".hcx") {
                let ver_str = &name[1..name.len() - 4];
                let parts: Vec<u32> = ver_str.split('.').filter_map(|s| s.parse().ok()).collect();
                if parts.len() == 3 {
                    let tuple = (parts[0], parts[1], parts[2]);
                    if tuple >= highest {
                        highest = tuple;
                        highest_path = Some(e.path().to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    highest_path
}

const DB: &str = "probe.hdb";

/// Porta UDP: 5514 (514 exigiria privilégio root; 5514 funciona sem admin).
const UDP_BIND: &str = "127.0.0.1:5514";
/// Porta TCP: 5515 (RFC 6587 — framing por newline, sem octet-counting).
const TCP_BIND: &str = "127.0.0.1:5515";

/// Linhas de auto-teste: exercitam parse correto + Schema Drift + escalada brute-force.
const SELFTEST_LINES: &[&str] = &[
    "<13>2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:07.410 UTC [14804] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:08.560 UTC [14805] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:09.700 UTC [14806] FATAL:  password authentication failed for user \"admin\"",
    "<13>2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "<13>2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
    "<13>GARBAGE: isto não é um log do postgres e deve cair na quarentena",
];

/// Remove o prefixo de prioridade syslog `<NN>` se presente (RFC 5424 §6.2.1).
fn strip_syslog_pri(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('<') {
        if let Some(i) = rest.find('>') {
            return &rest[i + 1..];
        }
    }
    s
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let selftest = args.iter().any(|a| a == "--selftest");
    let use_tcp  = args.iter().any(|a| a == "--tcp");

    let _ = std::fs::remove_file(DB);
    let _ = std::fs::remove_file(format!("{DB}.anchor"));

    let artifact_path = resolve_latest_artifact("../registry/postgresql")
        .context("Nenhuma versao do conector postgresql encontrada no registry")?;

    let mut runner = ReconstitutiveRunner::load(&artifact_path)
        .context("Falha ao carregar artefato .hcx")?;
    let mut db = HeraclitusDB::new(DB).context("Falha ao abrir db")?;

    // Canal unificado: todas as fontes entregam (src_addr, log_line) aqui.
    let (tx, rx) = mpsc::channel::<(String, String)>();

    // ------------------------------------------------------------------
    // Thread UDP (sempre ativa)
    // ------------------------------------------------------------------
    {
        let sock = UdpSocket::bind(UDP_BIND).context("Falha no bind UDP")?;
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .context("Falha ao setar read_timeout UDP")?;
        info!("[Probe] UDP syslog escutando em {UDP_BIND}");

        let tx_udp = tx.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 65_536];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let payload = String::from_utf8_lossy(&buf[..n]).into_owned();
                        for line in payload.lines() {
                            let line = strip_syslog_pri(line.trim()).to_string();
                            if !line.is_empty() {
                                let _ = tx_udp.send((src.to_string(), line));
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(e) => {
                        error!("[UDP] recv erro: {e}");
                        break;
                    }
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // Thread TCP (RFC 6587, framing por newline) — opcional com --tcp
    // ------------------------------------------------------------------
    if use_tcp {
        let listener = TcpListener::bind(TCP_BIND).context("Falha no bind TCP")?;
        info!("[Probe] TCP syslog escutando em {TCP_BIND}  (RFC 6587, framing=newline)");

        let tx_tcp = tx.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Err(e) => { error!("[TCP] accept erro: {e}"); }
                    Ok(stream) => {
                        let src = stream
                            .peer_addr()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|_| "?".into());
                        let tx = tx_tcp.clone();
                        thread::spawn(move || {
                            let reader = BufReader::new(stream);
                            for line in reader.lines() {
                                match line {
                                    Err(_) => break,
                                    Ok(l) => {
                                        let l = strip_syslog_pri(l.trim()).to_string();
                                        if !l.is_empty() {
                                            let _ = tx.send((src.clone(), l));
                                        }
                                    }
                                }
                            }
                            info!("[TCP] conexão de {src} encerrada");
                        });
                    }
                }
            }
        });
    }

    // ------------------------------------------------------------------
    // Self-test: envia as linhas de teste ao próprio probe via UDP
    // (opcional --selftest)
    // ------------------------------------------------------------------
    if selftest {
        info!("[selftest] enviando {} datagrama(s) via UDP...", SELFTEST_LINES.len());
        thread::spawn(|| {
            let s = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            for line in SELFTEST_LINES {
                let _ = s.send_to(line.as_bytes(), UDP_BIND);
                thread::sleep(Duration::from_millis(40));
            }
        });

        // Se --tcp também, envia as mesmas linhas via TCP
        if use_tcp {
            info!("[selftest] enviando {} linha(s) via TCP...", SELFTEST_LINES.len());
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(200)); // aguarda TCP listener subir
                use std::io::Write;
                use std::net::TcpStream;
                match TcpStream::connect(TCP_BIND) {
                    Err(e) => error!("[selftest TCP] connect: {e}"),
                    Ok(mut s) => {
                        for line in SELFTEST_LINES {
                            let _ = writeln!(s, "{line}");
                            thread::sleep(Duration::from_millis(30));
                        }
                    }
                }
            });
        }
    } else {
        info!("[Probe] aguardando logs. Envie via rsyslog/logger para {UDP_BIND}.");
        if use_tcp {
            info!("[Probe]   ou via TCP syslog para {TCP_BIND}.");
        }
        info!("[Probe] Ctrl+C para sair.");
    }

    // ------------------------------------------------------------------
    // Loop principal de processamento
    // ------------------------------------------------------------------
    let mut sealed: u64 = 0;
    let mut quarantine: u64 = 0;
    let mut got_any = false;
    let mut last_stats = Instant::now();

    // Timeout de receive: curto no selftest (detecta fim rápido), longo em produção.
    let recv_timeout = if selftest {
        Duration::from_millis(700)
    } else {
        Duration::from_secs(10)
    };

    loop {
        match rx.recv_timeout(recv_timeout) {
            Ok((src, line)) => {
                got_any = true;
                match runner.process_observation(&line) {
                    Some(mut f) => {
                        match db.write_fact(&mut f) {
                            Err(e) => error!("Erro ao gravar fato: {e}"),
                            Ok(lsn) => {
                                sealed += 1;
                                let b = &f["fact.behavior"];
                                info!(
                                    "[{src}] LSN {lsn} | {:<22} | {:<18} | {}",
                                    b["action"].as_str().unwrap_or(""),
                                    b["class"].as_str().unwrap_or(""),
                                    b["risk_level"].as_str().unwrap_or("")
                                );
                            }
                        }
                    }
                    None => {
                        quarantine += 1;
                        warn!(
                            "[{src}] [SCHEMA DRIFT → quarentena] {}",
                            &line[..line.len().min(60)]
                        );
                    }
                }
            }

            // Timeout — sem mensagens novas neste período
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if selftest && got_any {
                    // No selftest, timeout após receber pelo menos 1 linha = fim
                    break;
                }
                if last_stats.elapsed() >= Duration::from_secs(10) {
                    info!("-- stats: selados={sealed} quarentena={quarantine} --");
                    last_stats = Instant::now();
                }
            }

            // Canal fechado (todos os threads de entrada terminaram)
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // ------------------------------------------------------------------
    // Resultado do selftest
    // ------------------------------------------------------------------
    if selftest {
        // UDP: espera 7 selados + 1 quarentena
        // TCP (--tcp): dobra os números (mesmas linhas enviadas por ambos)
        let factor: u64 = if use_tcp { 2 } else { 1 };
        let expect_sealed = 7 * factor;
        let expect_quar   = 1 * factor;

        info!(
            "[selftest] resultado: selados={sealed}/{expect_sealed}  quarentena={quarantine}/{expect_quar}"
        );

        let vr = db.verify();
        info!("[selftest] db.verify() → {} (fatos: {})", vr.status, vr.facts);

        let ok = sealed == expect_sealed && quarantine == expect_quar && vr.status == "INTEG_OK";
        info!("[selftest] {}", if ok { "✓ OK" } else { "✗ FALHOU" });

        let _ = std::fs::remove_file(DB);
        let _ = std::fs::remove_file(format!("{DB}.anchor"));

        if !ok {
            std::process::exit(1);
        }
    }

    Ok(())
}
