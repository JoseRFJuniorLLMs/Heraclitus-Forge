//! SPEC-0071 §5.2 P0 #7 — o adapter `auditd`.
//!
//! ## Porque é que isto não é um `file-tail` com outro nome
//!
//! O `/var/log/audit/audit.log` é um ficheiro de texto, e a tentação é apontar-
//! lhe o `file-tail`. Seria errado, porque **um evento do auditd não é uma
//! linha**. É um conjunto de linhas que partilham o mesmo serial:
//!
//! ```text
//! type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 ...
//! type=CWD msg=audit(1364481363.243:24287): cwd="/home/shadowman"
//! type=PATH msg=audit(1364481363.243:24287): item=0 name="/etc/ssh/sshd_config"
//! ```
//!
//! Entregar estas três linhas como três observações separadas parte o evento:
//! quem correlaciona a seguir vê um `SYSCALL` sem caminho e um `PATH` sem
//! processo. A perda não dá erro nenhum — é o pior tipo, o silencioso.
//!
//! Por isso este adapter agrupa por serial e entrega **um evento por
//! observação**, com as linhas separadas por `\n`.
//!
//! ## O grupo do fim do ficheiro
//!
//! O último grupo lido pode estar incompleto: o kernel ainda pode estar a
//! escrever as linhas seguintes do mesmo serial. Entregá-lo já é partir o
//! evento; segurá-lo para sempre é nunca entregar o último.
//!
//! O compromisso é [`AuditdAdapter::atraso_de_agrupamento`]: o grupo do fim
//! fica retido enquanto o ficheiro tiver crescido há menos desse tempo. Custa
//! latência no último evento; poupa eventos partidos, que é o que não se
//! consegue reparar depois.
//!
//! ## O serial é uma sequência a sério
//!
//! Ao contrário do syslog, aqui há uma sequência da FONTE: o serial que o
//! kernel atribui. Entra em `source_sequence` e serve de chave de idempotência
//! (§5.4) sem depender de quando o adapter leu.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::source::{
    AdapterError, DatasourceIdentity, DatasourceState, Observation, ObservationBatch, SourceAck,
    SourceAdapter, SourceCapabilities, SourceCounters, SourceHealthSample,
};

/// Quanto tempo o grupo do fim do ficheiro fica retido à espera de mais linhas.
pub const ATRASO_DE_AGRUPAMENTO_OMISSAO: std::time::Duration = std::time::Duration::from_secs(2);

/// Extrai o serial de uma linha do auditd.
///
/// O formato é `msg=audit(<epoch>.<ms>:<serial>)`. Uma linha sem isto não é do
/// auditd — e não se inventa um serial para ela: fica com `None` e é tratada
/// como um grupo só dela, para não ser costurada ao evento do vizinho.
pub fn serial_da_linha(linha: &str) -> Option<u64> {
    let inicio = linha.find("msg=audit(")? + "msg=audit(".len();
    let resto = &linha[inicio..];
    let fim = resto.find(')')?;
    let dentro = &resto[..fim];
    let (_, serial) = dentro.rsplit_once(':')?;
    serial.trim().parse().ok()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CheckpointAuditd {
    ficheiro: PathBuf,
    offset: u64,
    geracao: u64,
}

/// Um evento completo: as linhas de um serial.
#[derive(Debug, Clone)]
struct Grupo {
    serial: Option<u64>,
    linhas: Vec<String>,
    /// Offset no ficheiro logo a seguir à última linha deste grupo. É o que
    /// pode ser confirmado quando o consumidor persistir até aqui.
    fim_offset: u64,
}

impl Grupo {
    fn corpo(&self) -> String {
        self.linhas.join("\n")
    }
}

/// Lê `/var/log/audit/audit.log` agrupando por serial.
pub struct AuditdAdapter {
    identity: DatasourceIdentity,
    ficheiro: PathBuf,
    checkpoint_path: PathBuf,
    offset: u64,
    geracao: u64,
    /// Grupos completos, prontos a entregar.
    prontos: VecDeque<Grupo>,
    /// O grupo do fim, ainda a poder crescer.
    retido: Option<Grupo>,
    /// Quando o ficheiro cresceu pela última vez.
    ultimo_crescimento: std::time::Instant,
    pub atraso_de_agrupamento: std::time::Duration,
    observadas: u64,
    confirmadas: u64,
    ultimo_offset_entregue: Option<u64>,
    ultimo_erro: Option<String>,
}

impl AuditdAdapter {
    /// Abre o log do auditd.
    ///
    /// `desde_o_inicio` decide o que fazer sem checkpoint: `false` (o normal em
    /// produção) salta o histórico e só apanha o que vier a seguir, porque um
    /// `audit.log` de meses reprocessado no arranque afogaria o pipeline.
    pub fn abrir(
        identity: DatasourceIdentity,
        ficheiro: impl Into<PathBuf>,
        checkpoint_path: impl Into<PathBuf>,
        desde_o_inicio: bool,
    ) -> Result<Self, AdapterError> {
        identity.validate()?;
        let ficheiro = ficheiro.into();
        let checkpoint_path = checkpoint_path.into();
        let tamanho = std::fs::metadata(&ficheiro)?.len();

        let guardado = std::fs::read_to_string(&checkpoint_path)
            .ok()
            .and_then(|texto| serde_json::from_str::<CheckpointAuditd>(&texto).ok())
            .filter(|c| c.ficheiro == ficheiro && c.offset <= tamanho);

        let (offset, geracao) = match guardado {
            Some(c) => (c.offset, c.geracao),
            None if desde_o_inicio => (0, 0),
            None => (tamanho, 0),
        };

        Ok(Self {
            identity,
            ficheiro,
            checkpoint_path,
            offset,
            geracao,
            prontos: VecDeque::new(),
            retido: None,
            ultimo_crescimento: std::time::Instant::now(),
            atraso_de_agrupamento: ATRASO_DE_AGRUPAMENTO_OMISSAO,
            observadas: 0,
            confirmadas: 0,
            ultimo_offset_entregue: None,
            ultimo_erro: None,
        })
    }

    /// Detecta rotação ou truncamento.
    ///
    /// O auditd roda o ficheiro quando ele chega ao tamanho configurado. Se o
    /// tamanho actual for MENOR que o offset guardado, o ficheiro no caminho já
    /// não é o mesmo — continuar a ler do offset antigo daria lixo a meio de uma
    /// linha, que é pior do que recomeçar.
    fn detectar_rotacao(&mut self) -> Result<(), AdapterError> {
        let tamanho = std::fs::metadata(&self.ficheiro)?.len();
        if tamanho < self.offset {
            self.offset = 0;
            self.geracao = self.geracao.saturating_add(1);
            // Um grupo retido pertencia ao ficheiro anterior; entregá-lo agora
            // misturaria duas gerações no mesmo evento.
            self.retido = None;
            self.ultimo_erro = Some("rotacao_detectada".into());
        }
        Ok(())
    }

    /// Lê tudo o que há de novo e agrupa.
    fn absorver(&mut self) -> Result<(), AdapterError> {
        self.detectar_rotacao()?;
        let tamanho = std::fs::metadata(&self.ficheiro)?.len();
        if tamanho > self.offset {
            self.ultimo_crescimento = std::time::Instant::now();
        }

        let mut leitor = BufReader::new(std::fs::File::open(&self.ficheiro)?);
        leitor.seek(SeekFrom::Start(self.offset))?;

        let mut cursor = self.offset;
        let mut linha = Vec::new();
        loop {
            linha.clear();
            let lidos = leitor.read_until(b'\n', &mut linha)?;
            // Uma linha sem `\n` no fim está a meio de ser escrita. Parar aqui
            // e voltar a lê-la inteira no próximo poll é o que impede entregar
            // meia linha como se fosse um evento.
            if lidos == 0 || !linha.ends_with(b"\n") {
                break;
            }
            cursor = cursor.saturating_add(lidos as u64);
            let texto = String::from_utf8_lossy(&linha).trim_end().to_string();
            if texto.is_empty() {
                continue;
            }
            let serial = serial_da_linha(&texto);

            match &mut self.retido {
                // Mesmo serial: é a continuação do mesmo evento.
                Some(g) if g.serial == serial && serial.is_some() => {
                    g.linhas.push(texto);
                    g.fim_offset = cursor;
                }
                // Serial diferente: o grupo anterior fechou.
                Some(_) => {
                    let fechado = self.retido.take().expect("acabado de verificar");
                    self.prontos.push_back(fechado);
                    self.retido = Some(Grupo {
                        serial,
                        linhas: vec![texto],
                        fim_offset: cursor,
                    });
                }
                None => {
                    self.retido = Some(Grupo {
                        serial,
                        linhas: vec![texto],
                        fim_offset: cursor,
                    });
                }
            }
        }
        self.offset = cursor;

        // O grupo do fim só sai quando o ficheiro estiver quieto há tempo
        // suficiente. Uma linha sem serial nunca cresce, por isso sai já.
        let quieto = self.ultimo_crescimento.elapsed() >= self.atraso_de_agrupamento;
        let sem_serial = self.retido.as_ref().is_some_and(|g| g.serial.is_none());
        if quieto || sem_serial {
            if let Some(g) = self.retido.take() {
                self.prontos.push_back(g);
            }
        }
        Ok(())
    }
}

impl SourceAdapter for AuditdAdapter {
    fn identity(&self) -> &DatasourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            // Um ficheiro lê-se por ordem, e o auditd escreve por ordem.
            ordered: true,
            reliable_transport: true,
            // O serial vem da FONTE, não da recepção — é uma sequência a sério.
            source_sequence: true,
            // O timestamp está no `msg=audit(<epoch>...)`, mas extraí-lo é
            // parsing, e parsing é da camada de cima.
            source_timestamp: false,
            backpressure: true,
        }
    }

    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
        self.absorver()?;
        let quantos = limit.min(self.prontos.len());
        if quantos == 0 {
            return Ok(ObservationBatch {
                observations: Vec::new(),
                ack: None,
            });
        }
        let mut observations = Vec::with_capacity(quantos);
        let mut fim = self.offset;
        for grupo in self.prontos.iter().take(quantos) {
            fim = grupo.fim_offset;
            observations.push(Observation {
                payload: grupo.corpo().into_bytes(),
                // `geracao:serial` e não só o serial: depois de uma rotação o
                // kernel pode reiniciar a numeração, e dois eventos diferentes
                // com a mesma chave seriam fundidos num pela idempotência.
                source_sequence: Some(match grupo.serial {
                    Some(s) => format!("{}:{s}", self.geracao),
                    None => format!("{}:offset{}", self.geracao, grupo.fim_offset),
                }),
                source_event_id: Some(format!(
                    "{}:{}:{}",
                    self.ficheiro.display(),
                    self.geracao,
                    grupo.fim_offset
                )),
                observed_at_micros: None,
            });
        }
        self.observadas = self.observadas.saturating_add(quantos as u64);
        self.ultimo_offset_entregue = Some(fim);
        Ok(ObservationBatch {
            observations,
            ack: Some(SourceAck {
                cursor: fim.to_string(),
            }),
        })
    }

    /// Só aqui o progresso fica durável (§5.4).
    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
        let ate: u64 = ack.cursor.parse().map_err(|_| {
            AdapterError::InvalidAck(format!("cursor nao numerico: {}", ack.cursor))
        })?;
        if self.ultimo_offset_entregue != Some(ate) {
            // Confirmar um offset que não foi o do último lote entregue é um
            // erro do chamador: ou salta eventos que ninguém persistiu, ou
            // reentrega o que já foi.
            return Err(AdapterError::InvalidAck(format!(
                "cursor {ate} nao corresponde ao ultimo lote entregue ({:?})",
                self.ultimo_offset_entregue
            )));
        }
        while let Some(g) = self.prontos.front() {
            if g.fim_offset > ate {
                break;
            }
            self.prontos.pop_front();
            self.confirmadas = self.confirmadas.saturating_add(1);
        }
        let estado = CheckpointAuditd {
            ficheiro: self.ficheiro.clone(),
            offset: ate,
            geracao: self.geracao,
        };
        let texto =
            serde_json::to_string(&estado).map_err(|e| AdapterError::InvalidAck(e.to_string()))?;
        escrever_atomico(&self.checkpoint_path, texto.as_bytes())?;
        self.ultimo_offset_entregue = None;
        Ok(())
    }

    fn health(&self) -> SourceHealthSample {
        let state = if self.observadas == 0 {
            DatasourceState::Starting
        } else {
            DatasourceState::Healthy
        };
        SourceHealthSample {
            state,
            last_observed_at_micros: None,
            last_checkpoint: (self.confirmadas > 0).then(|| self.offset.to_string()),
            counters: SourceCounters {
                observed: self.observadas,
                acknowledged: self.confirmadas,
                backpressure_events: 0,
                // Um ficheiro não descarta: o que não coube fica lá para o
                // próximo poll. É a vantagem de uma fonte com retenção.
                dropped: 0,
            },
            last_error_code: self.ultimo_erro.clone(),
        }
    }
}

/// Escreve por ficheiro temporário e renomeia.
///
/// Um checkpoint escrito por cima do antigo pode ficar a meio se a máquina cair
/// durante a escrita — e um checkpoint truncado é lido como um offset errado no
/// arranque seguinte.
fn escrever_atomico(destino: &Path, dados: &[u8]) -> Result<(), AdapterError> {
    let temporario = destino.with_extension("tmp");
    std::fs::write(&temporario, dados)?;
    std::fs::rename(&temporario, destino)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn identidade() -> DatasourceIdentity {
        DatasourceIdentity {
            tenant_id: "tenant-a".into(),
            datasource_id: "ds-auditd".into(),
            sensor_id: "auditd-1".into(),
        }
    }

    const EVENTO_24287: &str = concat!(
        "type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no\n",
        "type=CWD msg=audit(1364481363.243:24287): cwd=\"/home/shadowman\"\n",
        "type=PATH msg=audit(1364481363.243:24287): item=0 name=\"/etc/ssh/sshd_config\"\n",
    );
    const EVENTO_24288: &str =
        "type=SYSCALL msg=audit(1364481364.000:24288): arch=c000003e syscall=59 success=yes\n";

    struct Bancada {
        _dir: tempfile::TempDir,
        log: PathBuf,
        checkpoint: PathBuf,
    }

    fn bancada(conteudo: &str) -> Bancada {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.log");
        std::fs::write(&log, conteudo).unwrap();
        let checkpoint = dir.path().join("audit.ckpt");
        Bancada {
            _dir: dir,
            log,
            checkpoint,
        }
    }

    fn abrir(b: &Bancada) -> AuditdAdapter {
        let mut a = AuditdAdapter::abrir(identidade(), &b.log, &b.checkpoint, true).expect("abrir");
        // Sem atraso: o teste quer o grupo do fim ja.
        a.atraso_de_agrupamento = std::time::Duration::ZERO;
        a
    }

    fn acrescentar(b: &Bancada, texto: &str) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&b.log)
            .unwrap();
        f.write_all(texto.as_bytes()).unwrap();
    }

    /// O ponto todo do adapter: tres linhas, UM evento.
    #[test]
    fn tres_linhas_do_mesmo_serial_sao_um_evento() {
        let b = bancada(EVENTO_24287);
        let mut a = abrir(&b);
        let lote = a.poll(10).unwrap();
        assert_eq!(lote.observations.len(), 1, "tres linhas; um evento");

        let corpo = String::from_utf8_lossy(&lote.observations[0].payload).to_string();
        assert!(corpo.contains("SYSCALL"));
        assert!(corpo.contains("CWD"));
        assert!(corpo.contains("PATH"), "o caminho nao pode ficar de fora");
        assert_eq!(corpo.lines().count(), 3);
    }

    #[test]
    fn seriais_diferentes_sao_eventos_diferentes() {
        let b = bancada(&format!("{EVENTO_24287}{EVENTO_24288}"));
        let mut a = abrir(&b);
        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].source_sequence.as_deref(), Some("0:24287"));
        assert_eq!(obs[1].source_sequence.as_deref(), Some("0:24288"));
    }

    /// O evento do fim pode ainda estar a ser escrito. Com atraso, segura-se.
    #[test]
    fn o_grupo_do_fim_fica_retido_enquanto_o_ficheiro_cresce() {
        let b = bancada(EVENTO_24287);
        let mut a = AuditdAdapter::abrir(identidade(), &b.log, &b.checkpoint, true).unwrap();
        a.atraso_de_agrupamento = std::time::Duration::from_secs(3600);

        // O unico grupo e o do fim: fica retido, e nada sai.
        assert!(
            a.poll(10).unwrap().observations.is_empty(),
            "entregar ja partiria o evento ao meio"
        );

        // Chega a linha que faltava do MESMO serial.
        acrescentar(
            &b,
            "type=PROCTITLE msg=audit(1364481363.243:24287): proctitle=sshd\n",
        );
        assert!(a.poll(10).unwrap().observations.is_empty());

        // Chega outro serial: o grupo anterior fecha e sai inteiro, com quatro
        // linhas — nao tres.
        acrescentar(&b, EVENTO_24288);
        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 1);
        let corpo = String::from_utf8_lossy(&obs[0].payload).to_string();
        assert_eq!(corpo.lines().count(), 4, "a quarta linha tinha de entrar");
        assert!(corpo.contains("PROCTITLE"));
    }

    /// Uma linha a meio de ser escrita nao pode sair como evento.
    #[test]
    fn uma_linha_sem_fim_de_linha_nao_e_entregue() {
        let b = bancada(EVENTO_24287);
        let mut a = abrir(&b);
        assert_eq!(a.poll(10).unwrap().observations.len(), 1);
        let ack = SourceAck {
            cursor: a.offset.to_string(),
        };
        a.ultimo_offset_entregue = Some(a.offset);
        a.checkpoint(ack).unwrap();

        // Meia linha, sem `\n`.
        acrescentar(&b, "type=SYSCALL msg=audit(1364481365.000:24289): arch=c00");
        assert!(
            a.poll(10).unwrap().observations.is_empty(),
            "meia linha nao e um evento"
        );

        // Agora completa-se.
        acrescentar(&b, "0003e syscall=2\n");
        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 1);
        let corpo = String::from_utf8_lossy(&obs[0].payload).to_string();
        assert!(
            corpo.contains("arch=c000003e"),
            "a linha veio inteira: {corpo}"
        );
    }

    /// O `poll` nao consome; o `checkpoint` e que consome e persiste (§5.4).
    #[test]
    fn o_progresso_so_fica_duravel_no_checkpoint() {
        let b = bancada(&format!("{EVENTO_24287}{EVENTO_24288}"));
        let mut a = abrir(&b);
        let lote = a.poll(10).unwrap();
        assert_eq!(lote.observations.len(), 2);

        // Sem checkpoint, um adapter novo volta ao principio.
        let mut outro = abrir(&b);
        assert_eq!(outro.poll(10).unwrap().observations.len(), 2, "repete");

        a.checkpoint(lote.ack.unwrap()).unwrap();
        assert!(b.checkpoint.exists(), "o checkpoint tem de ficar em disco");

        // Um adapter novo agora retoma e nao repete.
        let mut terceiro = AuditdAdapter::abrir(identidade(), &b.log, &b.checkpoint, true).unwrap();
        terceiro.atraso_de_agrupamento = std::time::Duration::ZERO;
        assert!(terceiro.poll(10).unwrap().observations.is_empty());
    }

    #[test]
    fn um_cursor_que_nao_e_o_do_ultimo_lote_e_recusado() {
        let b = bancada(EVENTO_24287);
        let mut a = abrir(&b);
        let lote = a.poll(10).unwrap();
        assert!(a
            .checkpoint(SourceAck {
                cursor: "999999".into()
            })
            .is_err());
        assert!(a
            .checkpoint(SourceAck {
                cursor: "abc".into()
            })
            .is_err());
        a.checkpoint(lote.ack.unwrap()).unwrap();
    }

    /// Depois de uma rotacao o kernel pode reiniciar a numeracao. Sem a geracao
    /// na chave, dois eventos diferentes seriam fundidos num.
    #[test]
    fn a_rotacao_muda_a_geracao_e_a_chave() {
        let b = bancada(&format!("{EVENTO_24287}{EVENTO_24288}"));
        let mut a = abrir(&b);
        let lote = a.poll(10).unwrap();
        assert_eq!(
            lote.observations[0].source_sequence.as_deref(),
            Some("0:24287")
        );
        a.checkpoint(lote.ack.unwrap()).unwrap();

        // O ficheiro roda: fica mais pequeno do que o offset guardado.
        std::fs::write(&b.log, EVENTO_24287).unwrap();
        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 1);
        assert_eq!(
            obs[0].source_sequence.as_deref(),
            Some("1:24287"),
            "mesmo serial, geracao nova: chaves diferentes"
        );
        assert_eq!(
            a.health().last_error_code.as_deref(),
            Some("rotacao_detectada")
        );
    }

    /// Uma linha que nao e do auditd nao pode ser costurada ao evento vizinho.
    #[test]
    fn uma_linha_sem_serial_fica_sozinha() {
        let b = bancada("uma linha qualquer sem formato\n");
        let mut a = abrir(&b);
        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 1);
        assert!(obs[0]
            .source_sequence
            .as_deref()
            .is_some_and(|s| s.contains("offset")));
    }

    #[test]
    fn o_serial_sai_da_linha_e_nao_de_um_palpite() {
        assert_eq!(
            serial_da_linha("type=SYSCALL msg=audit(1364481363.243:24287): arch=x"),
            Some(24287)
        );
        assert_eq!(serial_da_linha("msg=audit(1.2:1)"), Some(1));
        assert_eq!(serial_da_linha("sem audit nenhum"), None);
        assert_eq!(serial_da_linha("msg=audit(sem-dois-pontos)"), None);
        assert_eq!(serial_da_linha("msg=audit(1.2:nao-numero)"), None);
        assert_eq!(serial_da_linha("msg=audit(1.2:3"), None, "sem fechar");
    }

    /// Em producao arranca-se do FIM: um audit.log de meses reprocessado no
    /// arranque afogaria o pipeline.
    #[test]
    fn sem_checkpoint_e_sem_desde_o_inicio_arranca_do_fim() {
        let b = bancada(&format!("{EVENTO_24287}{EVENTO_24288}"));
        let mut a = AuditdAdapter::abrir(identidade(), &b.log, &b.checkpoint, false).unwrap();
        a.atraso_de_agrupamento = std::time::Duration::ZERO;
        assert!(a.poll(10).unwrap().observations.is_empty());

        acrescentar(&b, "type=SYSCALL msg=audit(1364481365.000:24289): novo\n");
        assert_eq!(a.poll(10).unwrap().observations.len(), 1);
    }

    #[test]
    fn as_capacidades_dizem_que_a_sequencia_e_da_fonte() {
        let b = bancada(EVENTO_24287);
        let a = abrir(&b);
        let caps = a.capabilities();
        assert!(caps.ordered, "um ficheiro le-se por ordem");
        assert!(caps.source_sequence, "o serial vem do kernel");
        assert!(!caps.source_timestamp, "extrair o timestamp e parsing");
        assert_eq!(a.health().counters.dropped, 0);
    }
}
