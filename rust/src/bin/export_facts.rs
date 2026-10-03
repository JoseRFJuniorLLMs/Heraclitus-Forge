//! `export_facts` — exportador offline/auditoria HDB2 -> JSONL.
//!
//! O caminho de produção usa agora o binário Rust `bridge`, que lê o HDB2
//! diretamente e fala gRPC com o HeraclitusDB. Este utilitário permanece porque
//! JSONL é útil para auditoria, air-gap, depuração e integrações externas.

use std::io::{BufWriter, Write};
use std::process::ExitCode;

use heraclitus::db::ExportedRecord;
use heraclitus::export::{
    VerifiedSnapshot, BRIDGE_CONTRACT_VERSION, DESTINATION_API_VERSION, FACT_SCHEMA_VERSION,
};

fn usage() -> ! {
    eprintln!(
        "uso: export_facts <ficheiro.hdb> [--from-lsn N] [--limit N]\n\
         \n\
         Emite JSONL verificado em stdout; resumo vai para stderr.\n\
         --from-lsn N   só exporta LSN > N\n\
         --limit N      pára ao fim de N registos"
    );
    std::process::exit(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        usage()
    }

    let db_path = args[0].clone();
    let mut from_lsn = 0u64;
    let mut limit = None;

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--from-lsn" => {
                index += 1;
                from_lsn = args
                    .get(index)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--limit" => {
                index += 1;
                limit = Some(
                    args.get(index)
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| usage()),
                );
            }
            other => {
                eprintln!("argumento desconhecido: {other}");
                usage()
            }
        }
        index += 1;
    }

    let snapshot = match VerifiedSnapshot::open(&db_path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({
                    "status": "INTEGRITY_ERROR",
                    "message": error.to_string()
                })
            );
            return ExitCode::from(4);
        }
    };
    let attestation = snapshot.attestation().clone();
    let source_id = snapshot.source_id().to_string();

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut write_error = None;

    let stats = match snapshot.export_records(from_lsn, limit, |lsn, record| {
        let mut line = serde_json::json!({
            "contract_version": BRIDGE_CONTRACT_VERSION,
            "lsn": lsn,
            "record_type": record.record_type(),
            "attestation": attestation
        });
        match record {
            ExportedRecord::Fact(fact) => line["fact"] = fact,
            ExportedRecord::TelemetryHealth { identity, envelope } => {
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

        if let Err(error) =
            serde_json::to_writer(&mut out, &line).map_err(std::io::Error::from)
        {
            write_error = Some(error);
            return false;
        }
        if let Err(error) = out.write_all(b"\n") {
            write_error = Some(error);
            return false;
        }
        true
    }) {
        Ok(stats) => stats,
        Err(error) => {
            eprintln!("erro ao ler {db_path}: {error}");
            return ExitCode::from(1);
        }
    };

    if let Err(error) = out.flush() {
        eprintln!("erro ao escrever em stdout: {error}");
        return ExitCode::from(1);
    }
    if let Some(error) = write_error {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("erro ao escrever em stdout: {error}");
            return ExitCode::from(1);
        }
    }

    eprintln!(
        "{}",
        serde_json::json!({
            "scanned": stats.scanned,
            "exported": stats.exported,
            "torn": stats.torn,
            "undecodable": stats.undecodable,
            "skipped": stats.skipped,
            "last_lsn": stats.last_lsn,
            "integrity": "INTEG_OK",
            "contract_version": BRIDGE_CONTRACT_VERSION,
            "fact_schema": FACT_SCHEMA_VERSION,
            "destination_api": DESTINATION_API_VERSION,
            "source_id": source_id,
            "verified_root": snapshot.verified_root(),
        })
    );

    if stats.torn > 0 || stats.undecodable > 0 {
        return ExitCode::from(3);
    }
    if stats.skipped > 0 {
        eprintln!(
            "{}",
            serde_json::json!({
                "warning": "registos de tipo desconhecido não exportados",
                "skipped": stats.skipped
            })
        );
    }
    ExitCode::SUCCESS
}
