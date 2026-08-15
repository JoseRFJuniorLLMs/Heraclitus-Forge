//! `ingest` — o ingestor real (Marco D).
//!
//! Segue um ficheiro de log ao vivo, passa cada linha pelo Runner com um
//! artefato `.hcx` e persiste os Fatos no `.hdb`. Linhas que nenhuma regra casa
//! (Schema Drift) vão para a quarentena cifrada, não para o ecrã.
//!
//! Porque é que isto existe
//! ------------------------
//! O `connector_postgresql` é uma DEMONSTRAÇÃO, não um ingestor: apaga o `.hdb`
//! ao arrancar (`main.rs`) e adultera o último LSN ao sair, para mostrar que o
//! `verify()` deteta. Serve o seu propósito — e é inutilizável em produção. O
//! `gateway` alimenta-se de um array `SAMPLES` fixo num temporizador. Nenhum dos
//! dois lê uma fonte real. Era esse o Marco D em aberto.
//!
//! Este binário:
//!   * **abre** o `.hdb` existente (recupera LSN e cadeia Merkle) — nunca apaga;
//!   * **nunca** adultera nada;
//!   * **retoma** de onde ficou, por deslocamento gravado num sidecar;
//!   * **deteta rotação** do ficheiro (truncado ou substituído) e recomeça;
//!   * só processa linhas **completas** — uma linha ainda a ser escrita espera.
//!
//! Garantia de entrega
//! -------------------
//! **Pelo menos uma vez.** O deslocamento é gravado depois de os Fatos irem para
//! o disco, por isso uma paragem abrupta pode reprocessar as últimas linhas.
//! Preferido ao contrário: num sistema de auditoria, repetir é recuperável,
//! perder não é.
//!
//! ```text
//! ingest /var/log/postgresql.log --artifact ../registry/postgresql --follow
//! ingest amostra.log --artifact ../registry/linux_sshd --from-start --once
//! ```

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use heraclitus::db::HeraclitusDB;
use heraclitus::quarantine::QuarantineWriter;
use heraclitus::runner::{resolve_latest_artifact, ReconstitutiveRunner};

/// Bytes lidos para identificar o ficheiro. Junto com o tamanho, distingue
/// "cresceu" de "foi rodado" sem depender de inode (que o Windows não expõe).
const FINGERPRINT_BYTES: usize = 256;

/// Intervalo de sondagem em `--follow`. Baixo o suficiente para parecer ao vivo,
/// alto o suficiente para não queimar CPU num ficheiro parado.
const POLL: Duration = Duration::from_millis(400);

struct Args {
    source: PathBuf,
    artifact_dir: String,
    db_path: String,
    quarantine: PathBuf,
    state_path: PathBuf,
    follow: bool,
    from_start: bool,
    once: bool,
}

fn usage() -> ! {
    eprintln!(
        "uso: ingest <ficheiro.log> [opcoes]\n\
         \n\
         Le um ficheiro de log real, produz Fatos Operacionais e persiste-os.\n\
         Abre o .hdb existente (nunca apaga) e nunca adultera nada.\n\
         \n\
         --artifact <dir>    pasta do conector no registry (default ../registry/postgresql)\n\
         --db <ficheiro>     .hdb de destino (default ingest.hdb)\n\
         --quarantine <f>    quarentena cifrada (default quarantine.hq)\n\
         --state <f>         ficheiro de retoma (default <db>.ingest-state)\n\
         --follow            fica a seguir o ficheiro (tail -f)\n\
         --from-start        comeca no inicio do ficheiro (default: retoma, ou fim se novo)\n\
         --once              processa o que ha e sai (default sem --follow)\n\
         \n\
         FORGE_QUARANTINE_KEY (64 hex) e obrigatoria: a quarentena guarda\n\
         observacoes que podem conter dados pessoais e e sempre cifrada."
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() || raw[0] == "-h" || raw[0] == "--help" {
        usage()
    }
    let source = PathBuf::from(&raw[0]);
    let mut a = Args {
        source,
        artifact_dir: "../registry/postgresql".into(),
        db_path: "ingest.hdb".into(),
        quarantine: PathBuf::from("quarantine.hq"),
        state_path: PathBuf::new(),
        follow: false,
        from_start: false,
        once: false,
    };
    let mut i = 1;
    while i < raw.len() {
        let need = |i: usize| -> String {
            raw.get(i + 1).cloned().unwrap_or_else(|| usage())
        };
        match raw[i].as_str() {
            "--artifact" => { a.artifact_dir = need(i); i += 1; }
            "--db" => { a.db_path = need(i); i += 1; }
            "--quarantine" => { a.quarantine = PathBuf::from(need(i)); i += 1; }
            "--state" => { a.state_path = PathBuf::from(need(i)); i += 1; }
            "--follow" => a.follow = true,
            "--from-start" => a.from_start = true,
            "--once" => a.once = true,
            other => {
                eprintln!("argumento desconhecido: {other}");
                usage()
            }
        }
        i += 1;
    }
    if a.state_path.as_os_str().is_empty() {
        a.state_path = PathBuf::from(format!("{}.ingest-state", a.db_path));
    }
    a
}

// ---------------------------------------------------------------------------
// Estado de retoma
// ---------------------------------------------------------------------------

/// Identidade do ficheiro: hash de um prefixo da região **já consumida**.
///
/// A escolha do `upto` é o cerne da correção. A primeira versão hasheava sempre
/// os primeiros 256 bytes do ficheiro — e num log com menos de 256 bytes cada
/// linha nova caía dentro da janela, mudava o hash, e o ingestor lia "rotação".
/// Resultado: reprocessava o ficheiro inteiro a cada passagem e duplicava todos
/// os Fatos, precisamente no caso mais comum — um log acabado de criar.
///
/// Num log append-only, a região que já lemos é imutável por definição. Hashear
/// `min(256, offset)` bytes dá uma identidade que **não muda quando o ficheiro
/// cresce** e muda de facto quando o ficheiro é substituído. Com `offset = 0`
/// não há nada consumido, logo não há rotação possível — estamos a começar.
fn fingerprint(path: &Path, offset: u64) -> std::io::Result<String> {
    let upto = offset.min(FINGERPRINT_BYTES as u64) as usize;
    if upto == 0 {
        return Ok("novo".into());
    }
    let mut f = std::fs::File::open(path)?;
    let mut head = vec![0u8; upto];
    let n = f.read(&mut head)?;
    head.truncate(n);
    if n < upto {
        // O ficheiro encolheu abaixo do que já tínhamos lido: é rotação, e o
        // valor devolvido nunca pode casar com o guardado.
        return Ok(format!("curto:{n}"));
    }
    Ok(blake3::hash(&head).to_hex()[..16].to_string())
}

fn load_state(path: &Path) -> Option<(u64, String)> {
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    Some((
        v["offset"].as_u64()?,
        v["fingerprint"].as_str()?.to_string(),
    ))
}

fn save_state(path: &Path, offset: u64, fp: &str, source: &Path) -> std::io::Result<()> {
    let body = serde_json::json!({
        "source": source.to_string_lossy(),
        "offset": offset,
        "fingerprint": fp,
    });
    // Escrita atómica: um corte de energia a meio nunca deixa um estado
    // meio-escrito que faria a retoma saltar ou repetir um bloco inteiro.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&body)?)?;
    std::fs::rename(&tmp, path)
}

// ---------------------------------------------------------------------------
// Ingestão
// ---------------------------------------------------------------------------

struct Stats {
    facts: u64,
    drift: u64,
}

/// Lê de `offset` até ao fim, processando apenas linhas COMPLETAS. Devolve o
/// deslocamento até onde consumiu — uma linha final sem `\n` fica por ler, para
/// ser apanhada inteira na próxima passagem.
fn drain(
    source: &Path,
    offset: u64,
    runner: &mut ReconstitutiveRunner,
    db: &mut HeraclitusDB,
    quarantine: &mut QuarantineWriter,
    stats: &mut Stats,
) -> std::io::Result<u64> {
    let mut file = std::fs::File::open(source)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file);
    let mut consumed = offset;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // EOF
        }
        if !line.ends_with('\n') {
            // Linha incompleta: o produtor ainda está a escrevê-la. Não avança
            // o deslocamento — na próxima passagem lê-se do princípio dela.
            break;
        }
        consumed += n as u64;
        let raw = line.trim_end_matches(['\n', '\r']);
        if raw.trim().is_empty() {
            continue;
        }
        match runner.process_observation(raw) {
            Some(mut fact) => {
                db.write_fact(&mut fact)?;
                stats.facts += 1;
            }
            None => {
                // Schema Drift: a observação não casa com nenhuma regra do
                // artefato. Vai cifrada para a quarentena — nunca para o ecrã
                // nem para uma log em claro: pode conter dados pessoais.
                quarantine.append(&source.to_string_lossy(), raw)?;
                stats.drift += 1;
            }
        }
    }
    Ok(consumed)
}

fn run(a: &Args) -> anyhow::Result<Stats> {
    let key = heraclitus::quarantine::key_from_env()?;

    let artifact = resolve_latest_artifact(&a.artifact_dir).ok_or_else(|| {
        anyhow::anyhow!(
            "nenhuma versao de conector em {} — corra `python forge_compiler.py` primeiro",
            a.artifact_dir
        )
    })?;
    let mut runner = ReconstitutiveRunner::load(&artifact)?;
    eprintln!("[ingest] artefato : {artifact}");
    eprintln!("[ingest] plano    : {}", runner.plan_str());

    // Abre o .hdb EXISTENTE. O `new` recupera LSN e raiz Merkle do disco; um
    // ingestor que apagasse aqui perdia o histórico a cada reinício.
    let mut db = HeraclitusDB::new(&a.db_path)?;
    eprintln!("[ingest] destino  : {} (LSN atual {})", a.db_path, db.current_lsn);

    let mut quarantine = QuarantineWriter::open(&a.quarantine, key)?;
    eprintln!("[ingest] quarentena: {}", quarantine.path().display());

    let size = std::fs::metadata(&a.source)?.len();

    let mut offset = match (a.from_start, load_state(&a.state_path)) {
        (true, _) => 0,
        // A impressão é calculada sobre a região que o estado diz já ter sido
        // consumida — comparar contra a mesma janela que foi gravada.
        (false, Some((saved, saved_fp)))
            if saved <= size && fingerprint(&a.source, saved)? == saved_fp =>
        {
            eprintln!("[ingest] retoma   : byte {saved}");
            saved
        }
        (false, Some((saved, saved_fp))) => {
            let agora = fingerprint(&a.source, saved).unwrap_or_else(|_| "ilegivel".into());
            eprintln!(
                "[ingest] ROTACAO detetada (impressao {saved_fp} -> {agora}); a recomecar do inicio"
            );
            0
        }
        // Ficheiro novo sem estado: começa no FIM. Um ingestor que arrancasse a
        // ler um log de meses inundaria o banco com histórico que ninguém pediu.
        // `--from-start` é explícito para quem quer isso.
        (false, None) => {
            eprintln!("[ingest] sem estado; a comecar no fim ({size}). Use --from-start para o historico.");
            size
        }
    };

    let mut stats = Stats { facts: 0, drift: 0 };
    loop {
        let size = std::fs::metadata(&a.source)?.len();
        if size < offset {
            eprintln!("[ingest] ficheiro TRUNCADO ({size} < {offset}); a recomecar do inicio");
            offset = 0;
        }
        let before = (stats.facts, stats.drift);
        offset = drain(&a.source, offset, &mut runner, &mut db, &mut quarantine, &mut stats)?;
        if (stats.facts, stats.drift) != before {
            // Estado gravado DEPOIS dos Fatos: entrega pelo menos uma vez.
            // A impressão é recalculada sobre o NOVO offset: o estado guarda
            // sempre a identidade da região consumida até àquele ponto.
            let fp = fingerprint(&a.source, offset)?;
            save_state(&a.state_path, offset, &fp, &a.source)?;
            eprintln!(
                "[ingest] {} fato(s), {} drift(s) · offset {}",
                stats.facts, stats.drift, offset
            );
            std::io::stderr().flush().ok();
        }
        if !a.follow || a.once {
            break;
        }
        std::thread::sleep(POLL);
    }
    Ok(stats)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    let a = parse_args();
    if !a.source.exists() {
        eprintln!("[ERRO] ficheiro nao existe: {}", a.source.display());
        return ExitCode::from(1);
    }
    match run(&a) {
        Ok(s) => {
            eprintln!("[ingest] fim: {} fato(s), {} em quarentena", s.facts, s.drift);
            // Drift é sinal, não erro: um conector desatualizado manifesta-se
            // assim. Código 3 deixa um agendador distinguir "correu e havia
            // linhas que nao casaram" de "correu limpo".
            if s.drift > 0 { ExitCode::from(3) } else { ExitCode::SUCCESS }
        }
        Err(e) => {
            eprintln!("[ERRO] {e:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);

    fn tmp(tag: &str) -> PathBuf {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("ingest_{tag}_{}_{n}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn fingerprint_is_stable_for_the_same_content() {
        let p = tmp("fp_estavel");
        std::fs::write(&p, b"linha um\nlinha dois\n").unwrap();
        assert_eq!(fingerprint(&p, 20).unwrap(), fingerprint(&p, 20).unwrap());
    }

    /// REGRESSAO do bug que este teste apanhou na primeira versao.
    ///
    /// A impressao hasheava sempre os primeiros 256 bytes do ficheiro. Num log
    /// com MENOS de 256 bytes, cada linha nova caia dentro da janela, mudava o
    /// hash, e o ingestor lia "rotacao" -- reprocessando o ficheiro inteiro a
    /// cada passagem e duplicando todos os Fatos. Acontecia precisamente no caso
    /// mais comum: um log acabado de criar.
    ///
    /// Hasheando `min(256, offset)` -- a regiao JA CONSUMIDA, imutavel num log
    /// append-only -- crescer deixa de mexer na identidade.
    #[test]
    fn growing_a_short_file_is_not_mistaken_for_rotation() {
        let p = tmp("fp_curto_cresce");
        std::fs::write(&p, b"log novo\n").unwrap(); // 9 bytes, MUITO abaixo de 256
        let consumido = 9u64;
        let antes = fingerprint(&p, consumido).unwrap();

        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"segunda linha\nterceira linha\n").unwrap();
        drop(f);

        assert_eq!(
            fingerprint(&p, consumido).unwrap(),
            antes,
            "crescer nao pode mudar a identidade da regiao ja lida"
        );
    }

    #[test]
    fn appending_does_not_change_the_fingerprint() {
        let p = tmp("fp_append");
        let base = vec![b'x'; 400];
        std::fs::write(&p, &base).unwrap();
        let antes = fingerprint(&p, 400).unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"linha nova\n").unwrap();
        drop(f);
        assert_eq!(fingerprint(&p, 400).unwrap(), antes);
    }

    /// Substituir o ficheiro por outro conteudo TEM de mudar a impressao — e o
    /// unico sinal de rotacao que funciona sem inode (o Windows nao o expoe).
    #[test]
    fn replacing_the_file_changes_the_fingerprint() {
        let p = tmp("fp_rotacao");
        std::fs::write(&p, b"conteudo original do log, com tamanho suficiente\n").unwrap();
        let antes = fingerprint(&p, 40).unwrap();
        std::fs::write(&p, b"log completamente novo depois da rotacao xxxxx\n").unwrap();
        assert_ne!(fingerprint(&p, 40).unwrap(), antes);
    }

    /// Um ficheiro que encolheu abaixo do que ja tinhamos lido e rotacao, e a
    /// impressao nunca pode casar com a guardada.
    #[test]
    fn truncated_below_offset_never_matches() {
        let p = tmp("fp_truncado");
        std::fs::write(&p, vec![b'a'; 300]).unwrap();
        let antes = fingerprint(&p, 300).unwrap();
        std::fs::write(&p, b"minusculo\n").unwrap();
        assert_ne!(fingerprint(&p, 300).unwrap(), antes);
    }

    /// Offset 0 = nada consumido = nao ha rotacao possivel.
    #[test]
    fn offset_zero_is_always_new() {
        let p = tmp("fp_zero");
        std::fs::write(&p, b"seja o que for\n").unwrap();
        assert_eq!(fingerprint(&p, 0).unwrap(), "novo");
    }

    #[test]
    fn state_round_trips() {
        let p = tmp("estado");
        save_state(&p, 4242, "abc123", Path::new("origem.log")).unwrap();
        let (off, fp) = load_state(&p).unwrap();
        assert_eq!(off, 4242);
        assert_eq!(fp, "abc123");
    }

    /// Estado ausente ou ilegivel nao pode rebentar: devolve None e o ingestor
    /// decide (comeca no fim, ou no inicio com --from-start).
    #[test]
    fn missing_or_corrupt_state_is_none_not_panic() {
        assert!(load_state(Path::new("nao_existe_de_todo.state")).is_none());
        let p = tmp("estado_partido");
        std::fs::write(&p, b"{ isto nao e json").unwrap();
        assert!(load_state(&p).is_none());
    }

    /// A gravacao do estado e atomica: nunca fica um ficheiro meio-escrito que
    /// faria a retoma saltar ou repetir um bloco.
    #[test]
    fn state_write_leaves_no_temp_behind() {
        let p = tmp("estado_atomico");
        save_state(&p, 1, "f", Path::new("x")).unwrap();
        assert!(p.exists());
        assert!(!p.with_extension("tmp").exists(), "o ficheiro temporario tem de desaparecer");
    }
}
