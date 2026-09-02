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

use heraclitus::db::FactStore;
use heraclitus::quarantine::QuarantineWriter;
use heraclitus::runner::{resolve_latest_artifact, ReconstitutiveRunner};

/// Bytes lidos para identificar o ficheiro. Junto com o tamanho, distingue
/// "cresceu" de "foi rodado" sem depender de inode (que o Windows não expõe).
const FINGERPRINT_BYTES: usize = 256;

/// Intervalo de sondagem em `--follow`. Baixo o suficiente para parecer ao vivo,
/// alto o suficiente para não queimar CPU num ficheiro parado.
const POLL: Duration = Duration::from_millis(400);

/// Nome do serviço do Windows. O install script usa o mesmo.
pub const SERVICE_NAME: &str = "HeraclitusForgeIngest";

/// Janela de ingestão reportada ao Telemetry Health. Longa o suficiente para
/// não encher o log com um evento por sondagem, curta o suficiente para que
/// "esta fonte calou-se" seja uma afirmação recente.
const DEFAULT_WINDOW_SECS: u64 = 60;
/// Tolerância de atraso declarada. Faz parte do estado DESEJADO: é o que
/// permite ao consumidor distinguir uma fonte atrasada de uma fonte morta.
const DEFAULT_MAX_LATENESS_SECS: u64 = 300;

fn numero_env(chave: &str, omissao: u64) -> Result<u64, String> {
    match std::env::var(chave) {
        Err(_) => Ok(omissao),
        Ok(texto) => texto
            .parse()
            .map_err(|_| format!("{chave} tem de ser um inteiro, e {texto:?}")),
    }
}

struct Args {
    source: PathBuf,
    artifact_dir: String,
    db_path: String,
    quarantine: PathBuf,
    state_path: PathBuf,
    /// Identidade de seguranca do datasource. Nao tem valor por omissao: o
    /// registo HFB2 autentica-a, e um tenant adivinhado e uma falha de
    /// isolamento gravada de forma indelevel na cadeia de custodia.
    identity: heraclitus::hfb2::SecurityIdentity,
    /// Duracao da janela de ingestao reportada ao Telemetry Health.
    window_secs: u64,
    /// Tolerancia de atraso declarada (estado DESEJADO, SPEC-0071 5.3).
    max_lateness_secs: u64,
    follow: bool,
    from_start: bool,
    once: bool,
}

impl Args {
    /// Configuração para o modo serviço.
    ///
    /// O SCM lança o binário **sem argumentos** — não há linha de comando onde
    /// pôr o ficheiro a seguir. Por isso o serviço lê o ambiente, exatamente
    /// como o `heraclitus-service` faz. Falhar aqui com uma mensagem clara vale
    /// mais do que arrancar a seguir o ficheiro errado em silêncio.
    fn from_env() -> Result<Self, String> {
        let obrigatoria = |k: &str| -> Result<String, String> {
            std::env::var(k).map_err(|_| format!("{k} e obrigatoria no modo servico"))
        };
        let source = PathBuf::from(obrigatoria("FORGE_INGEST_SOURCE")?);
        let identity = heraclitus::hfb2::SecurityIdentity::new(
            obrigatoria("FORGE_INGEST_TENANT")?,
            obrigatoria("FORGE_INGEST_DATASOURCE")?,
            obrigatoria("FORGE_INGEST_SENSOR")?,
        )
        .map_err(|erro| erro.to_string())?;
        let db_path = std::env::var("FORGE_INGEST_DB")
            .unwrap_or_else(|_| r"D:\HeraclitusForge\data\ingest.hdb".into());
        Ok(Self {
            state_path: PathBuf::from(format!("{db_path}.ingest-state")),
            source,
            artifact_dir: obrigatoria("FORGE_INGEST_ARTIFACT")?,
            identity,
            window_secs: numero_env("FORGE_INGEST_WINDOW_SECS", DEFAULT_WINDOW_SECS)?,
            max_lateness_secs: numero_env(
                "FORGE_INGEST_MAX_LATENESS_SECS",
                DEFAULT_MAX_LATENESS_SECS,
            )?,
            db_path,
            quarantine: PathBuf::from(
                std::env::var("FORGE_INGEST_QUARANTINE")
                    .unwrap_or_else(|_| r"D:\HeraclitusForge\data\quarantine.hq".into()),
            ),
            // Um serviço segue o ficheiro: essa é a razão de existir.
            follow: true,
            from_start: false,
            once: false,
        })
    }
}

fn usage() -> ! {
    eprintln!(
        "uso: ingest <ficheiro.log> [opcoes]\n\
         \n\
         Le um ficheiro de log real, produz Fatos Operacionais e persiste-os.\n\
         Abre o .hdb existente (nunca apaga) e nunca adultera nada.\n\
         \n\
         --tenant <id>       OBRIGATORIO: tenant a que a fonte pertence\n\
         --datasource <id>   OBRIGATORIO: identidade da fonte (nao e o caminho)\n\
         --sensor <id>       OBRIGATORIO: identidade desta instancia do Forge\n\
         --window-secs <n>   janela de saude reportada (default 60)\n\
         --max-lateness-secs <n>  tolerancia de atraso declarada (default 300)\n\
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
    let mut tenant = String::new();
    let mut datasource = String::new();
    let mut sensor = String::new();
    let mut a = Args {
        source,
        artifact_dir: "../registry/postgresql".into(),
        // Substituida no fim de `parse_args`; nunca chega assim ao disco.
        identity: heraclitus::hfb2::SecurityIdentity::demo("placeholder"),
        window_secs: DEFAULT_WINDOW_SECS,
        max_lateness_secs: DEFAULT_MAX_LATENESS_SECS,
        db_path: "ingest.hdb".into(),
        quarantine: PathBuf::from("quarantine.hq"),
        state_path: PathBuf::new(),
        follow: false,
        from_start: false,
        once: false,
    };
    let mut i = 1;
    while i < raw.len() {
        let need = |i: usize| -> String { raw.get(i + 1).cloned().unwrap_or_else(|| usage()) };
        match raw[i].as_str() {
            "--tenant" => {
                tenant = need(i);
                i += 1;
            }
            "--datasource" => {
                datasource = need(i);
                i += 1;
            }
            "--sensor" => {
                sensor = need(i);
                i += 1;
            }
            "--window-secs" => {
                a.window_secs = need(i).parse().unwrap_or_else(|_| usage());
                i += 1;
            }
            "--max-lateness-secs" => {
                a.max_lateness_secs = need(i).parse().unwrap_or_else(|_| usage());
                i += 1;
            }
            "--artifact" => {
                a.artifact_dir = need(i);
                i += 1;
            }
            "--db" => {
                a.db_path = need(i);
                i += 1;
            }
            "--quarantine" => {
                a.quarantine = PathBuf::from(need(i));
                i += 1;
            }
            "--state" => {
                a.state_path = PathBuf::from(need(i));
                i += 1;
            }
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
    match heraclitus::hfb2::SecurityIdentity::new(tenant, datasource, sensor) {
        Ok(identity) => a.identity = identity,
        Err(erro) => {
            eprintln!(
                "[ERRO] identidade do datasource incompleta: {erro}
                 --tenant, --datasource e --sensor sao obrigatorios: o registo                  HFB2 autentica-os e nao ha valor por omissao para eles."
            );
            std::process::exit(2)
        }
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
    // `write` + `rename` protege contra torn-write mas NAO contra corte de
    // energia: sem o fsync do temporario o rename pode chegar ao disco antes do
    // conteudo. E este checkpoint que o `CheckpointAdvanced` diz estar
    // verificado — se nao for duravel, o evento estaria a mentir.
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(&body)?)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(handle) = std::fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    Ok(())
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
#[allow(clippy::too_many_arguments)]
fn drain(
    source: &Path,
    offset: u64,
    runner: &mut ReconstitutiveRunner,
    db: &mut FactStore,
    quarantine: &mut QuarantineWriter,
    identity: &heraclitus::hfb2::SecurityIdentity,
    forge_source_id: &str,
    counters: &mut heraclitus::telemetry::WindowCounters,
    stats: &mut Stats,
) -> anyhow::Result<u64> {
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
        // Deslocamento do INÍCIO da linha: é a sequência estável desta fonte e
        // entra na chave de idempotência a jusante (SPEC-0071 §5.4).
        let inicio = consumed;
        consumed += n as u64;
        let raw = line.trim_end_matches(['\n', '\r']);
        if raw.trim().is_empty() {
            continue;
        }
        counters.observed();
        let sequencia = inicio.to_string();
        let evento = format!("{}:{inicio}", source.to_string_lossy());
        let contexto = heraclitus::runner::EmissionContext {
            identity,
            forge_source_id,
            // O LSN que este Fato VAI ocupar. Confirmado a seguir à escrita.
            forge_lsn: db.current_lsn + 1,
            source_sequence: Some(&sequencia),
            source_event_id: Some(&evento),
        };
        match runner.process_observation_with_context(raw, &contexto)? {
            Some(mut fact) => {
                let lsn = db.write_fact(&mut fact)?;
                // Se o LSN previsto não for o gravado, a proveniência do evento
                // canónico aponta para outro ponto do log. Falha fechado em vez
                // de gravar uma cadeia de custódia que não se sustenta.
                anyhow::ensure!(
                    lsn == contexto.forge_lsn,
                    "LSN previsto {} mas gravado {lsn}; proveniência canónica inválida",
                    contexto.forge_lsn
                );
                counters.accepted(fact.get("fact.security").is_some());
                stats.facts += 1;
            }
            None => {
                // Schema Drift: a observação não casa com nenhuma regra do
                // artefato. Vai cifrada para a quarentena — nunca para o ecrã
                // nem para uma log em claro: pode conter dados pessoais.
                quarantine.append(&source.to_string_lossy(), raw)?;
                counters.drifted();
                stats.drift += 1;
            }
        }
    }
    Ok(consumed)
}

/// Grava um evento de saude no MESMO log dos Fatos.
///
/// Partilhar o log e o ponto: a saude do sensor entra na mesma cadeia Merkle e
/// na mesma ancora que a evidencia, portanto um sensor nao consegue esconder
/// que esteve cego sem partir a cadeia.
/// Fecha a janela: batimento, contadores, drift e a barreira de tempo de evento.
///
/// A ordem importa para quem le: o batimento prova vida, a janela diz o que
/// aconteceu nela, e o tick e a barreira explicita que permite derivar silencio
/// sem ninguem ler o relogio de parede.
fn fechar_janela(
    db: &mut FactStore,
    identity: &heraclitus::hfb2::SecurityIdentity,
    connector_digest: &str,
    inicio: i64,
    fim: i64,
    counters: &heraclitus::telemetry::WindowCounters,
) -> anyhow::Result<()> {
    use heraclitus::telemetry as th;
    emitir(
        db,
        identity,
        th::Event::SensorHeartbeat(th::SensorHeartbeat {
            observed_at_micros: fim.max(0) as u64,
        }),
    )?;
    emitir(
        db,
        identity,
        th::Event::IngestionWindowClosed(Box::new(counters.close(
            inicio,
            fim,
            connector_digest.to_owned(),
        ))),
    )?;
    if counters.quarantined > 0 {
        emitir(
            db,
            identity,
            th::Event::SchemaDriftObserved(th::SchemaDriftObserved {
                count: counters.quarantined,
                field: None,
            }),
        )?;
    }
    emitir(
        db,
        identity,
        th::Event::HealthEvaluationTick(th::HealthEvaluationTick {
            evaluated_at_micros: fim.max(0) as u64,
        }),
    )
}

fn emitir(
    db: &mut FactStore,
    identity: &heraclitus::hfb2::SecurityIdentity,
    evento: heraclitus::telemetry::Event,
) -> anyhow::Result<()> {
    let agora = heraclitus::fact::now_micros()?;
    let envelope = heraclitus::telemetry::Envelope::new(identity, agora, evento);
    db.write_health_event(identity, agora, &envelope.to_json()?)?;
    Ok(())
}

/// `parar` permite ao SCM interromper o laco entre passagens. Em modo consola
/// e `None` e o comportamento e o de sempre.
fn run(a: &Args, parar: Option<&std::sync::mpsc::Receiver<()>>) -> anyhow::Result<Stats> {
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
    let mut db = FactStore::new(&a.db_path)?;
    eprintln!(
        "[ingest] destino  : {} (LSN atual {})",
        a.db_path, db.current_lsn
    );

    let mut quarantine = QuarantineWriter::open(&a.quarantine, key)?;
    eprintln!("[ingest] quarentena: {}", quarantine.path().display());

    // Identidade da ORIGEM: BLAKE3 do texto da chave publica da ancora. Tem de
    // ser calculada exatamente como o `export_facts` a calcula, senao a
    // proveniencia do evento canonico e a atestacao da ponte apontam para
    // origens diferentes.
    let forge_source_id = blake3::hash(std::fs::read_to_string(db.pub_path())?.trim().as_bytes())
        .to_hex()
        .to_string();
    eprintln!(
        "[ingest] tenant   : {} · datasource {}",
        a.identity.tenant_id, a.identity.datasource_id
    );
    match runner.mapping_version() {
        Some(mapping) => eprintln!("[ingest] canonico : {mapping}"),
        None => eprintln!("[ingest] canonico : conector legado (sem bloco security:)"),
    }

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

    // --- Telemetry Health: estado desejado e conector ativo ---------------
    // Sem a expectativa declarada, o consumidor nao consegue distinguir "fonte
    // calada porque morreu" de "fonte calada porque e assim que ela e".
    use heraclitus::telemetry as th;
    let connector_digest = heraclitus::hfb2::model_hex(&runner.connector_digest());
    emitir(
        &mut db,
        &a.identity,
        th::Event::ExpectationConfigured(th::ExpectationConfigured {
            heartbeat_cadence_micros: Some(a.window_secs * 1_000_000),
            max_lateness_micros: a.max_lateness_secs * 1_000_000,
            minimum_events_per_window: None,
            duplicate_storm_basis_points: 0,
        }),
    )?;
    emitir(
        &mut db,
        &a.identity,
        th::Event::ConnectorActivated(th::ConnectorActivated {
            connector_digest: connector_digest.clone(),
            approved: true,
        }),
    )?;

    let mut stats = Stats { facts: 0, drift: 0 };
    let mut counters = th::WindowCounters::default();
    let mut window_start = heraclitus::fact::now_micros()?;
    loop {
        let size = std::fs::metadata(&a.source)?.len();
        if size < offset {
            eprintln!("[ingest] ficheiro TRUNCADO ({size} < {offset}); a recomecar do inicio");
            offset = 0;
        }
        let before = (stats.facts, stats.drift);
        offset = drain(
            &a.source,
            offset,
            &mut runner,
            &mut db,
            &mut quarantine,
            &a.identity,
            &forge_source_id,
            &mut counters,
            &mut stats,
        )?;
        if (stats.facts, stats.drift) != before {
            // Estado gravado DEPOIS dos Fatos: entrega pelo menos uma vez.
            // A impressão é recalculada sobre o NOVO offset: o estado guarda
            // sempre a identidade da região consumida até àquele ponto.
            let fp = fingerprint(&a.source, offset)?;
            save_state(&a.state_path, offset, &fp, &a.source)?;
            // O checkpoint so e anunciado DEPOIS de os Fatos estarem no disco e
            // de o proprio offset estar duravel — por isso `Verified`.
            emitir(
                &mut db,
                &a.identity,
                th::Event::CheckpointAdvanced(th::CheckpointAdvanced {
                    source_sequence: Some(offset),
                    source_watermark: None,
                    integrity: th::CheckpointIntegrity::Verified,
                }),
            )?;
            eprintln!(
                "[ingest] {} fato(s), {} drift(s) · offset {}",
                stats.facts, stats.drift, offset
            );
            std::io::stderr().flush().ok();
        }

        let agora = heraclitus::fact::now_micros()?;
        let fim_de_ciclo = !a.follow || a.once;
        if fim_de_ciclo || agora - window_start >= (a.window_secs * 1_000_000) as i64 {
            fechar_janela(
                &mut db,
                &a.identity,
                &connector_digest,
                window_start,
                agora,
                &counters,
            )?;
            counters = th::WindowCounters::default();
            window_start = agora;
        }
        if fim_de_ciclo {
            break;
        }
        // Dorme ate ao proximo ciclo OU ate o SCM mandar parar -- o que vier
        // primeiro. Sem isto, um `Stop` esperava o POLL inteiro e o Windows
        // podia declarar o servico como nao-responsivo.
        match parar {
            Some(rx) => match rx.recv_timeout(POLL) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    tracing::info!("paragem pedida; a terminar o ciclo");
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            },
            None => std::thread::sleep(POLL),
        }
    }
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Modo servico do Windows
// ---------------------------------------------------------------------------

/// Pasta do log rotativo. Um serviço não tem consola: sem isto, uma falha no
/// arranque é invisível e o operador vê apenas "o serviço parou".
#[cfg(windows)]
fn log_dir() -> PathBuf {
    std::env::var("FORGE_INGEST_LOGDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
                .join("HeraclitusForge")
                .join("logs")
        })
}

#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    pub fn start() -> windows_service::Result<()> {
        service_dispatcher::start(super::SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_args: Vec<OsString>) {
        // O log tem de estar vivo ANTES de qualquer coisa poder falhar.
        let dir = super::log_dir();
        let _ = std::fs::create_dir_all(&dir);
        let appender = tracing_appender::rolling::daily(&dir, "forge-ingest.log");
        let (writer, _guard) = tracing_appender::non_blocking(appender);
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(writer)
            .try_init();

        if let Err(e) = run() {
            tracing::error!(erro = %e, "servico terminou com erro");
        }
    }

    fn run() -> Result<(), Box<dyn std::error::Error>> {
        let (parar_tx, parar_rx) = mpsc::channel::<()>();
        let handler = move |control| -> ServiceControlHandlerResult {
            match control {
                ServiceControl::Stop | ServiceControl::Preshutdown => {
                    let _ = parar_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status = service_control_handler::register(super::SERVICE_NAME, handler)?;
        let set = |estado: ServiceState, aceita: ServiceControlAccept, codigo: u32| {
            status.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: estado,
                controls_accepted: aceita,
                exit_code: ServiceExitCode::Win32(codigo),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
        };

        let args = match super::Args::from_env() {
            Ok(a) => a,
            Err(e) => {
                // Configuração em falta é erro de instalação, não transitório.
                // Sai com código != 0 para o SCM NÃO ficar a reiniciar em ciclo
                // um serviço que nunca vai conseguir arrancar.
                tracing::error!("configuracao invalida: {e}");
                set(ServiceState::Stopped, ServiceControlAccept::empty(), 1)?;
                return Ok(());
            }
        };

        set(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
            0,
        )?;
        tracing::info!(
            origem = %args.source.display(),
            artefato = %args.artifact_dir,
            destino = %args.db_path,
            "ingestor a arrancar"
        );

        let resultado = super::run(&args, Some(&parar_rx));
        let codigo = match resultado {
            Ok(s) => {
                tracing::info!(fatos = s.facts, quarentena = s.drift, "ingestor parado");
                0
            }
            Err(e) => {
                tracing::error!(erro = %format!("{e:#}"), "ingestor falhou");
                1
            }
        };
        set(ServiceState::Stopped, ServiceControlAccept::empty(), codigo)?;
        Ok(())
    }
}

fn main() -> ExitCode {
    // O SCM lança o binário com o argumento `service`. Tem de ser a PRIMEIRA
    // coisa: o dispatcher precisa de responder ao SCM em segundos, antes de
    // qualquer inicialização mais lenta.
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("service") {
        if let Err(e) = service::start() {
            eprintln!("[ERRO] dispatcher do servico: {e}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    tracing_subscriber::fmt::init();
    let a = parse_args();
    if !a.source.exists() {
        eprintln!("[ERRO] ficheiro nao existe: {}", a.source.display());
        return ExitCode::from(1);
    }
    match run(&a, None) {
        Ok(s) => {
            eprintln!(
                "[ingest] fim: {} fato(s), {} em quarentena",
                s.facts, s.drift
            );
            // Drift é sinal, não erro: um conector desatualizado manifesta-se
            // assim. Código 3 deixa um agendador distinguir "correu e havia
            // linhas que nao casaram" de "correu limpo".
            if s.drift > 0 {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
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
        assert!(
            !p.with_extension("tmp").exists(),
            "o ficheiro temporario tem de desaparecer"
        );
    }
}
