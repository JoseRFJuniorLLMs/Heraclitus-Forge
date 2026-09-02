//! `export_facts` — a metade Rust da ponte Forge → HeraclitusDB.
//!
//! Lê o `.hdb` do Forge em streaming e emite **JSON Lines** em stdout: uma
//! linha por Fato Operacional, já validada pelo CRC-32C e desserializada do
//! corpo `fbfact`. A outra metade da ponte (`bridge.py`) consome estas linhas e
//! faz `append` no HeraclitusDB via SDK gRPC.
//!
//! A divisão segue a mesma regra do resto do projeto: o Rust decodifica o seu
//! próprio formato (é o único que sabe), o Python fala gRPC (é onde o SDK vive).
//!
//! ```text
//! export_facts storage_rs.hdb --from-lsn 41 | python bridge.py --apply
//! ```
//!
//! Saída (uma por linha):
//! ```json
//! {"lsn":42,"fact":{"fact_id":"019f…","fact.identity":{…},"fact.behavior":{…}}}
//! ```
//!
//! A última linha vai para **stderr**, não stdout, para não contaminar o JSONL:
//! um resumo `{"scanned":…,"exported":…,"torn":…,"last_lsn":…}`.

use std::fs;
use std::io::{BufWriter, Write};
use std::process::ExitCode;

/// Versao do envelope JSONL consumido por `bridge.py`. Alteracoes
/// incompatíveis exigem um novo numero; o consumidor recusa versoes
/// desconhecidas antes de escrever qualquer evento no destino.
/// Versao 2: uma linha do JSONL deixou de ser sempre um Fato. O log passou a
/// carregar tambem eventos de Telemetry Health, e cada linha diz o que e em
/// `record_type`. Mudar a forma do envelope sem mudar o numero seria
/// exatamente o que o numero existe para impedir.
const BRIDGE_CONTRACT_VERSION: &str = "forge-heraclitusdb/2";
const FACT_SCHEMA_VERSION: &str = "operational-fact/1.0";
const DESTINATION_API_VERSION: &str = "heraclitus.v1";

fn usage() -> ! {
    eprintln!(
        "uso: export_facts <ficheiro.hdb> [--from-lsn N] [--limit N]\n\
         \n\
         Emite um JSON por linha em stdout: {{\"lsn\":N,\"fact\":{{…}}}}\n\
         O resumo da exportação vai para stderr.\n\
         \n\
         --from-lsn N   só exporta LSN > N (retoma uma exportação anterior)\n\
         --limit N      pára ao fim de N Fatos (lote)"
    );
    std::process::exit(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        usage()
    }

    let db_path = args[0].clone();
    let mut from_lsn: u64 = 0;
    let mut limit: u64 = u64::MAX;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--from-lsn" => {
                i += 1;
                from_lsn = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--limit" => {
                i += 1;
                limit = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            other => {
                eprintln!("argumento desconhecido: {other}");
                usage()
            }
        }
        i += 1;
    }

    // Faz primeiro uma fotografia privada da origem (dados + sidecars públicos).
    // Se um writer estiver a anexar em paralelo, a cópia fica inconsistente e a
    // verificação abaixo falha fechada; nunca exportamos uma mistura de épocas.
    let snapshot_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("erro ao criar snapshot temporário: {e}");
            return ExitCode::from(1);
        }
    };
    let snapshot_path = snapshot_dir.path().join("source.hdb");
    let snapshot = snapshot_path.to_string_lossy().to_string();
    // No HDB2 a raiz, o LSN e a assinatura vivem num unico `.anchor` atomico:
    // com dois ficheiros existia um estado intermedio em que a raiz era nova e
    // a assinatura velha, e o banco reabria a acusar adulteracao.
    for ext in ["", ".anchor", ".pub"] {
        let src = format!("{db_path}{ext}");
        let dst = format!("{snapshot}{ext}");
        if let Err(e) = fs::copy(&src, &dst) {
            eprintln!(
                "{}",
                serde_json::json!({
                    "status": "INTEGRITY_ERROR",
                    "message": format!("sidecar obrigatório ausente/ilegível {src}: {e}")
                })
            );
            return ExitCode::from(4);
        }
    }

    let verified = heraclitus::db::verify_file(&snapshot);
    if verified.status != "INTEG_OK" {
        eprintln!(
            "{}",
            serde_json::json!({
                "status": verified.status,
                "facts": verified.facts,
                "message": verified.message
            })
        );
        return ExitCode::from(4);
    }
    let public_key = fs::read_to_string(format!("{snapshot}.pub"))
        .unwrap_or_default()
        .trim()
        .to_string();
    // A assinatura Ed25519 e um campo do ficheiro de ancora (`sig=<hex>`).
    let anchor_signature = fs::read_to_string(format!("{snapshot}.anchor"))
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.trim().strip_prefix("sig=").map(str::to_owned))
        .unwrap_or_default();
    let source_id = blake3::hash(public_key.as_bytes()).to_hex().to_string();
    let attestation = serde_json::json!({
        "status": "INTEG_OK",
        "bridge_contract": BRIDGE_CONTRACT_VERSION,
        "fact_schema": FACT_SCHEMA_VERSION,
        "destination_api": DESTINATION_API_VERSION,
        "verified_root": verified.root.clone(),
        "verified_facts": verified.facts,
        "source_id": source_id.clone(),
        "public_key": public_key,
        "anchor_signature": anchor_signature,
        "algorithm": "ed25519+blake3+crc32c"
    });

    // stdout com buffer: um `write!` por Fato sem uma syscall por Fato.
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut emitted: u64 = 0;
    let mut write_err: Option<std::io::Error> = None;

    let stats = match heraclitus::db::export_records(&snapshot, from_lsn, |lsn, record| {
        let mut line = serde_json::json!({
            "contract_version": BRIDGE_CONTRACT_VERSION,
            "lsn": lsn,
            "record_type": record.record_type(),
            "attestation": attestation.clone()
        });
        match record {
            heraclitus::db::ExportedRecord::Fact(fact) => line["fact"] = fact,
            heraclitus::db::ExportedRecord::TelemetryHealth { identity, envelope } => {
                // O envelope viaja como TEXTO, tal como foi gravado e coberto
                // pela folha: reserializar aqui daria outros bytes e a ponte
                // deixaria de poder afirmar que entregou o que estava no disco.
                line["telemetry"] = serde_json::json!({
                    "envelope": envelope,
                    "identity": {
                        "tenant_id": identity.tenant_id,
                        "datasource_id": identity.datasource_id,
                        "sensor_id": identity.sensor_id,
                    }
                });
            }
        }
        // `serde_json::to_writer` + '\n': JSONL estrito, sem indentação.
        if let Err(e) = serde_json::to_writer(&mut out, &line).map_err(std::io::Error::from) {
            write_err = Some(e);
            return false;
        }
        if let Err(e) = out.write_all(b"\n") {
            write_err = Some(e);
            return false;
        }
        emitted += 1;
        emitted < limit
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("erro ao ler {db_path}: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = out.flush() {
        eprintln!("erro ao escrever em stdout: {e}");
        return ExitCode::from(1);
    }
    // Um pipe fechado a jusante (`| head`) não é falha da exportação.
    if let Some(e) = write_err {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("erro ao escrever em stdout: {e}");
            return ExitCode::from(1);
        }
    }

    eprintln!(
        "{}",
        serde_json::json!({
            "scanned":     stats.scanned,
            "exported":    stats.exported,
            "torn":        stats.torn,
            "undecodable": stats.undecodable,
            "skipped":     stats.skipped,
            "last_lsn":    stats.last_lsn,
            "integrity":   "INTEG_OK",
            "contract_version": BRIDGE_CONTRACT_VERSION,
            "source_id":   source_id,
            "verified_root": attestation["verified_root"],
        })
    );

    // Blocos com CRC partido são um sinal de integridade, não um detalhe: saem
    // com código 3 para que um pipeline os apanhe sem ter de parsear o stderr.
    if stats.torn > 0 || stats.undecodable > 0 {
        return ExitCode::from(3);
    }
    // Registos integros de um tipo desconhecido nao sao corrupcao, mas tambem
    // nao foram entregues. Dize-lo em voz alta: perda silenciosa nao existe.
    if stats.skipped > 0 {
        eprintln!(
            "{}",
            serde_json::json!({
                "warning": "registos de tipo desconhecido nao exportados",
                "skipped": stats.skipped
            })
        );
    }
    ExitCode::SUCCESS
}
