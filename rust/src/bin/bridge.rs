//! `bridge` — ponte Rust contínua Forge -> HeraclitusDB.
//!
//! Caminho de produção:
//! HDB2/HFB2 -> validação/mapeamento Rust -> gRPC Append -> ACK -> checkpoint.
//!
//! `export_facts` continua disponível para auditoria/offline, mas não participa
//! mais obrigatoriamente do caminho quente.

use anyhow::{bail, Context, Result};
use heraclitus::bridge::{
    load_state, map_fact, map_telemetry, save_state, source_event_identity, state_key,
    telemetry_event_identity, validate_fact, validate_telemetry, Episode, StateLock,
};
use heraclitus::db::ExportedRecord;
use heraclitus::export::VerifiedSnapshot;
use heraclitus::quarantine::{key_from_env, QuarantineWriter};
use heraclitus_client::{AppendOptions, Client};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;

const DEFAULT_HDB: &str = "storage_rs.hdb";
const DEFAULT_STATE: &str = ".bridge_state.json";
const DEFAULT_ADDR: &str = "127.0.0.1:7474";
const DEFAULT_QUARANTINE: &str = ".bridge_quarantine.hq";
const SUBJECT_HMAC_ENV: &str = "FORGE_SUBJECT_HMAC_KEY";

#[derive(Debug)]
struct Args {
    hdb: PathBuf,
    apply: bool,
    addr: String,
    state: PathBuf,
    reset: bool,
    limit: Option<u64>,
    batch: usize,
    quarantine: PathBuf,
    rpc_timeout: Duration,
    max_retries: usize,
    follow: bool,
    poll: Duration,
}

fn usage() -> ! {
    eprintln!(
        "uso: bridge [opções]\n\
         \n\
         --hdb PATH          HDB2 de origem (padrão: {DEFAULT_HDB})\n\
         --apply             envia ao HeraclitusDB; sem isto é dry-run\n\
         --addr HOST:PORT    gRPC (padrão: {DEFAULT_ADDR})\n\
         --state PATH        checkpoint (padrão: {DEFAULT_STATE})\n\
         --reset             ignora checkpoint e parte do LSN 0\n\
         --limit N           máximo de registos por passagem\n\
         --batch N           frequência do progresso (padrão: 500)\n\
         --quarantine PATH   quarentena cifrada de inválidos\n\
         --rpc-timeout SEC   deadline por Append (padrão: 30)\n\
         --max-retries N     retries idempotentes (padrão: 3)\n\
         --follow            fica 24x7, enviando novos LSNs\n\
         --poll-ms N         intervalo do follow (padrão: 1000)"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let raw: Vec<String> = env::args().skip(1).collect();
    if raw.iter().any(|arg| arg == "-h" || arg == "--help") {
        usage();
    }
    let mut args = Args {
        hdb: DEFAULT_HDB.into(),
        apply: false,
        addr: DEFAULT_ADDR.into(),
        state: DEFAULT_STATE.into(),
        reset: false,
        limit: None,
        batch: 500,
        quarantine: DEFAULT_QUARANTINE.into(),
        rpc_timeout: Duration::from_secs(30),
        max_retries: 3,
        follow: false,
        poll: Duration::from_millis(1000),
    };

    let need = |index: usize| raw.get(index + 1).cloned().unwrap_or_else(|| usage());
    let mut index = 0usize;
    while index < raw.len() {
        match raw[index].as_str() {
            "--hdb" => {
                args.hdb = need(index).into();
                index += 1;
            }
            "--apply" => args.apply = true,
            "--addr" => {
                args.addr = need(index);
                index += 1;
            }
            "--state" => {
                args.state = need(index).into();
                index += 1;
            }
            "--reset" => args.reset = true,
            "--limit" => {
                args.limit = Some(need(index).parse().unwrap_or_else(|_| usage()));
                index += 1;
            }
            "--batch" => {
                args.batch = need(index).parse().unwrap_or_else(|_| usage());
                index += 1;
            }
            "--quarantine" => {
                args.quarantine = need(index).into();
                index += 1;
            }
            "--rpc-timeout" => {
                let secs: f64 = need(index).parse().unwrap_or_else(|_| usage());
                args.rpc_timeout = Duration::from_secs_f64(secs.max(0.1));
                index += 1;
            }
            "--max-retries" => {
                args.max_retries = need(index).parse().unwrap_or_else(|_| usage());
                index += 1;
            }
            "--follow" => args.follow = true,
            "--poll-ms" => {
                args.poll = Duration::from_millis(need(index).parse().unwrap_or_else(|_| usage()));
                index += 1;
            }
            other => {
                eprintln!("argumento desconhecido: {other}");
                usage()
            }
        }
        index += 1;
    }
    args.batch = args.batch.max(1);
    args.max_retries = args.max_retries.max(1);
    args
}

fn host_from_addr(addr: &str) -> String {
    let without_scheme = addr
        .strip_prefix("http://")
        .or_else(|| addr.strip_prefix("https://"))
        .unwrap_or(addr);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .to_string()
}

fn is_loopback(addr: &str) -> bool {
    let host = host_from_addr(addr).to_ascii_lowercase();
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.")
}

fn endpoint(addr: &str, tls: bool) -> String {
    if addr.contains("://") {
        addr.to_string()
    } else if tls {
        format!("https://{addr}")
    } else {
        format!("http://{addr}")
    }
}

fn bearer_token() -> Result<Option<String>> {
    if let Ok(token) = env::var("HERACLITUS_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(Some(token));
        }
    }
    if let Ok(path) = env::var("HERACLITUS_TOKEN_FILE") {
        let token = fs::read_to_string(&path)
            .with_context(|| format!("ler HERACLITUS_TOKEN_FILE={path}"))?
            .trim()
            .to_string();
        if token.is_empty() {
            bail!("HERACLITUS_TOKEN_FILE está vazio");
        }
        return Ok(Some(token));
    }
    Ok(None)
}

async fn connect_destination(args: &Args) -> Result<Client> {
    let ca = env::var("HERACLITUS_TLS_CA").ok();
    let cert = env::var("HERACLITUS_TLS_CERT").ok();
    let key = env::var("HERACLITUS_TLS_KEY").ok();
    if cert.is_some() != key.is_some() {
        bail!("HERACLITUS_TLS_CERT e HERACLITUS_TLS_KEY devem vir juntos");
    }
    if !is_loopback(&args.addr) && ca.is_none() {
        bail!(
            "destino não-loopback {} exige HERACLITUS_TLS_CA; plaintext recusado",
            args.addr
        );
    }

    let connect_timeout = Duration::from_secs(10);
    let mut client = if let Some(ca_path) = ca {
        let ca_pem = fs::read(&ca_path).with_context(|| format!("ler CA TLS {ca_path}"))?;
        let identity = match (cert, key) {
            (Some(cert), Some(key)) => Some((
                fs::read(&cert).with_context(|| format!("ler certificado {cert}"))?,
                fs::read(&key).with_context(|| format!("ler chave TLS {key}"))?,
            )),
            _ => None,
        };
        let domain =
            env::var("HERACLITUS_TLS_SERVER_NAME").unwrap_or_else(|_| host_from_addr(&args.addr));
        Client::connect_tls(
            endpoint(&args.addr, true),
            ca_pem,
            domain,
            identity,
            connect_timeout,
        )
        .await
        .context("ligar ao HeraclitusDB com TLS/mTLS")?
    } else {
        Client::connect_with(endpoint(&args.addr, false), connect_timeout)
            .await
            .context("ligar ao HeraclitusDB")?
    };

    client = client.with_request_timeout(args.rpc_timeout);
    if let Some(token) = bearer_token()? {
        client = client
            .with_bearer_token(&token)
            .context("Authorization Bearer inválido")?;
    }
    Ok(client)
}

fn anchor_head_lsn(hdb: &Path) -> Result<u64> {
    let anchor = fs::read_to_string(format!("{}.anchor", hdb.to_string_lossy()))
        .context("ler âncora HDB2")?;
    anchor
        .lines()
        .find_map(|line| line.strip_prefix("lsn="))
        .and_then(|value| value.parse().ok())
        .context("âncora HDB2 sem LSN válido")
}

fn transient(status: &heraclitus_client::tonic::Status) -> bool {
    use heraclitus_client::tonic::Code;
    matches!(
        status.code(),
        Code::Unavailable | Code::DeadlineExceeded | Code::ResourceExhausted | Code::Aborted
    )
}

async fn append_with_retry(
    client: &mut Client,
    episode: &Episode,
    idempotency_key: String,
    max_retries: usize,
) -> Result<heraclitus_client::AppendResult> {
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let options = AppendOptions {
            session_id: episode.session_id.clone(),
            kind: episode.kind.clone(),
            attrs: episode.attrs.clone(),
            parents: episode.parents.clone(),
            idempotency_key: idempotency_key.clone(),
            ..AppendOptions::default()
        };
        match client
            .append_with_result(&episode.agent_id, episode.content.as_bytes(), options)
            .await
        {
            Ok(response) => return Ok(response),
            Err(status) if transient(&status) && attempt < max_retries => {
                let delay = 1u64 << (attempt - 1).min(3);
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            Err(status) => return Err(status).context("Append gRPC"),
        }
    }
}

fn quarantine_invalid(
    writer: &mut Option<QuarantineWriter>,
    lsn: u64,
    errors: &[String],
    payload: &serde_json::Value,
) -> Result<()> {
    let Some(writer) = writer.as_mut() else {
        return Ok(());
    };
    let record = serde_json::json!({
        "lsn": lsn,
        "errors": errors,
        "payload": payload
    });
    writer
        .append("forge-bridge-validation", &record.to_string())
        .context("gravar quarentena cifrada")
}

struct PassOutcome {
    read: u64,
    appended: u64,
    deduplicated: u64,
    last_lsn: u64,
}

async fn bridge_pass(
    args: &Args,
    from_lsn: u64,
    last_event_id: &mut String,
    secret: &[u8],
    client: &mut Option<Client>,
    quarantine: &mut Option<QuarantineWriter>,
) -> Result<PassOutcome> {
    let snapshot = VerifiedSnapshot::open(&args.hdb).context("criar snapshot HDB2 verificado")?;
    let attestation = snapshot.attestation().clone();
    let source_id = snapshot.source_id().to_string();

    // Preflight sem rede: nenhum Append começa se houver um registo íntegro mas
    // semanticamente indecodificável/desconhecido dentro do lote.
    let preflight = snapshot
        .export_records(from_lsn, args.limit, |_, _| true)
        .context("preflight dos registos HDB2")?;
    if preflight.torn > 0 || preflight.undecodable > 0 || preflight.skipped > 0 {
        bail!(
            "preflight recusado: torn={} undecodable={} skipped={}",
            preflight.torn,
            preflight.undecodable,
            preflight.skipped
        );
    }

    let capacity = args.batch.clamp(16, 4096);
    let (tx, mut rx) = mpsc::channel::<(u64, ExportedRecord)>(capacity);
    let limit = args.limit;
    let producer = tokio::task::spawn_blocking(move || {
        snapshot.export_records(from_lsn, limit, |lsn, record| {
            tx.blocking_send((lsn, record)).is_ok()
        })
    });

    let mut read = 0u64;
    let mut appended = 0u64;
    let mut deduplicated = 0u64;
    let mut confirmed_lsn = from_lsn;

    while let Some((lsn, record)) = rx.recv().await {
        read += 1;
        let (mut episode, source_identity, idempotency_key, quarantine_payload) = match record {
            ExportedRecord::Fact(fact) => {
                let errors = validate_fact(lsn, &fact, &attestation);
                if !errors.is_empty() {
                    quarantine_invalid(quarantine, lsn, &errors, &fact)?;
                    bail!("{}", errors.join("; "));
                }
                let episode = map_fact(lsn, &fact, &attestation, secret);
                let (identity, key) = source_event_identity(lsn, &fact, &attestation);
                (episode, identity, key, fact)
            }
            ExportedRecord::TelemetryHealth { identity, envelope } => {
                let errors = validate_telemetry(lsn, &identity, &envelope);
                if !errors.is_empty() {
                    let payload = serde_json::json!({
                        "identity": {
                            "tenant_id": identity.tenant_id,
                            "datasource_id": identity.datasource_id,
                            "sensor_id": identity.sensor_id
                        },
                        "envelope": envelope
                    });
                    quarantine_invalid(quarantine, lsn, &errors, &payload)?;
                    bail!("{}", errors.join("; "));
                }
                let episode =
                    map_telemetry(lsn, &identity, &envelope).map_err(anyhow::Error::msg)?;
                let (identity_key, key) = telemetry_event_identity(lsn, &attestation);
                (
                    episode,
                    identity_key,
                    key,
                    serde_json::json!({"telemetry": true}),
                )
            }
        };
        episode
            .attrs
            .insert("source_event_id".to_string(), source_identity);
        if !last_event_id.is_empty() {
            episode.parents.push(last_event_id.clone());
        }

        if !args.apply {
            if read <= 3 {
                println!(
                    "  LSN {lsn} -> kind={} content={:?}",
                    episode.kind, episode.content
                );
                println!(
                    "           attrs={}\n",
                    serde_json::to_string(&episode.attrs)?
                );
            }
            confirmed_lsn = lsn;
            let _ = quarantine_payload;
            continue;
        }

        let db = client
            .as_mut()
            .context("cliente HeraclitusDB não inicializado")?;
        let response = append_with_retry(db, &episode, idempotency_key, args.max_retries).await?;

        if response.deduplicated {
            deduplicated += 1;
        } else {
            appended += 1;
        }
        confirmed_lsn = lsn;
        *last_event_id = response.event_id;

        save_state(
            &args.state,
            &args.hdb,
            confirmed_lsn,
            u64::from(!response.deduplicated),
            last_event_id,
            &source_id,
        )
        .context("persistir checkpoint após ACK")?;

        if read.is_multiple_of(args.batch as u64) {
            println!("  ... {read} confirmados");
        }
    }

    let stats = producer
        .await
        .context("worker de leitura HDB2 terminou em panic")?
        .context("ler snapshot HDB2")?;
    if stats.torn > 0 || stats.undecodable > 0 || stats.skipped > 0 {
        bail!(
            "exportação terminou inconsistente: torn={} undecodable={} skipped={}",
            stats.torn,
            stats.undecodable,
            stats.skipped
        );
    }

    Ok(PassOutcome {
        read,
        appended,
        deduplicated,
        last_lsn: confirmed_lsn,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();
    if !args.hdb.exists() {
        bail!(".hdb não encontrado: {}", args.hdb.display());
    }

    let secret = match env::var(SUBJECT_HMAC_ENV) {
        Ok(value) if value.as_bytes().len() >= 32 => value.into_bytes(),
        _ if args.apply => {
            bail!("{SUBJECT_HMAC_ENV} é obrigatório em --apply e deve ter ao menos 32 bytes")
        }
        _ => b"forge-insecure-dry-run-only".to_vec(),
    };

    let _lock = if args.apply {
        Some(
            StateLock::acquire(&args.state, Duration::from_secs(30))
                .context("adquirir lock do checkpoint")?,
        )
    } else {
        None
    };

    let mut quarantine = if args.apply {
        Some(
            QuarantineWriter::open(&args.quarantine, key_from_env()?)
                .context("abrir quarentena cifrada")?,
        )
    } else {
        None
    };
    let mut client = if args.apply {
        Some(connect_destination(&args).await?)
    } else {
        None
    };

    let state = load_state(&args.state).context("ler checkpoint")?;
    let previous = state
        .get(&state_key(&args.hdb))
        .cloned()
        .unwrap_or_default();
    let mut from_lsn = if args.reset { 0 } else { previous.last_lsn };
    let mut last_event_id = if args.reset {
        String::new()
    } else {
        previous.last_event_id
    };

    println!("=== bridge Rust Forge -> HeraclitusDB ===");
    println!("  origem : {}", args.hdb.display());
    println!(
        "  destino: {}",
        if args.apply {
            args.addr.as_str()
        } else {
            "DRY-RUN"
        }
    );
    println!("  retoma : LSN > {from_lsn}");
    println!(
        "  modo   : {}\n",
        if args.follow {
            "contínuo"
        } else {
            "uma passagem"
        }
    );

    let mut total_new = 0u64;
    let mut total_dedup = 0u64;

    loop {
        if args.follow && anchor_head_lsn(&args.hdb)? <= from_lsn {
            tokio::time::sleep(args.poll).await;
            continue;
        }

        let outcome = bridge_pass(
            &args,
            from_lsn,
            &mut last_event_id,
            &secret,
            &mut client,
            &mut quarantine,
        )
        .await?;
        total_new += outcome.appended;
        total_dedup += outcome.deduplicated;

        if outcome.read == 0 {
            if !args.follow {
                println!("Nada de novo para exportar.");
                break;
            }
            tokio::time::sleep(args.poll).await;
            continue;
        }

        if !args.apply {
            if outcome.read > 3 {
                println!("  ... e mais {}.", outcome.read - 3);
            }
            println!("Dry-run. Use --apply para escrever no HeraclitusDB.");
            break;
        }

        from_lsn = outcome.last_lsn;
        println!(
            "passagem: {} novo(s), {} retry(s) deduplicado(s), LSN {}",
            outcome.appended, outcome.deduplicated, from_lsn
        );

        if !args.follow {
            break;
        }
    }

    if args.apply {
        println!(
            "\nTotal: {total_new} novo(s), {total_dedup} deduplicado(s). Último LSN: {from_lsn}."
        );
    }
    Ok(())
}
