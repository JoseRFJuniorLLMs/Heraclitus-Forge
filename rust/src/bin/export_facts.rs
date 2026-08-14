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

use std::io::{BufWriter, Write};
use std::process::ExitCode;

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
                from_lsn = args.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            }
            "--limit" => {
                i += 1;
                limit = args.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            }
            other => {
                eprintln!("argumento desconhecido: {other}");
                usage()
            }
        }
        i += 1;
    }

    // stdout com buffer: um `write!` por Fato sem uma syscall por Fato.
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut emitted: u64 = 0;
    let mut write_err: Option<std::io::Error> = None;

    let stats = match heraclitus::db::export_facts(&db_path, from_lsn, |lsn, fact| {
        let line = serde_json::json!({ "lsn": lsn, "fact": fact });
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
            "last_lsn":    stats.last_lsn,
        })
    );

    // Blocos com CRC partido são um sinal de integridade, não um detalhe: saem
    // com código 3 para que um pipeline os apanhe sem ter de parsear o stderr.
    if stats.torn > 0 || stats.undecodable > 0 {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}
