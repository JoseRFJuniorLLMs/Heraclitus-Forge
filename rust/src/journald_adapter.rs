//! SPEC-0071 §5.2 P0 #6 — o adapter `journald`.
//!
//! ## O único adapter com um cursor a sério
//!
//! O syslog não tem retenção e o seu "cursor" é uma contagem de recepção. O
//! `file-tail` tem um offset, que se estraga numa rotação. O journald tem
//! aquilo que a §5.4 realmente quer: um **cursor opaco atribuído pela fonte**,
//! que sobrevive a restarts, a rotações e a reinícios da máquina. Guardá-lo e
//! voltar a apresentá-lo devolve exactamente a posição de onde se ficou.
//!
//! É por isso que este é o único destes adapters em que "restart pode repetir,
//! nunca perder" se cumpre nos dois lados.
//!
//! ## O `-n` do `journalctl` serve para uma coisa e estraga a outra
//!
//! **A retomar, o `-n` está errado.** `journalctl --after-cursor=X -n 100`
//! devolve as ÚLTIMAS 100 entradas do conjunto, não as 100 primeiras. Com mais
//! de 100 por ler, as mais antigas desaparecem sem erro nenhum — perda
//! silenciosa, que é o que a §5.4 proíbe pelo nome. Por isso, com cursor, o
//! comando não é limitado: lê-se o fluxo e para-se ao fim de `limit` linhas, e
//! o que sobra vem no `poll` seguinte.
//!
//! **No primeiro arranque, o `-n` é a única coisa que serve.** Sem cursor
//! guardado é preciso um ponto de partida, e "as N mais recentes" é exactamente
//! isso. A alternativa que estava aqui antes — `--since=now` — não devolve nada
//! sem `--follow`, e o adapter nunca chegava a ter um primeiro cursor: ficava
//! calado para sempre a reportar `Starting`.
//!
//! Os argumentos vivem em [`argumentos`], separados do processo, porque foi
//! nessa construção que o defeito viveu e nenhum teste lá chegava.
//!
//! ## Parsing
//!
//! O adapter lê dois campos do JSON — `__CURSOR` e `__REALTIME_TIMESTAMP` — e
//! entrega o resto tal e qual. São metadados de transporte, não conteúdo: sem o
//! cursor não há checkpoint nenhum. A interpretação da `MESSAGE` e dos campos
//! do serviço continua a ser da camada de cima.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::source::{
    AdapterError, DatasourceIdentity, DatasourceState, Observation, ObservationBatch, SourceAck,
    SourceAdapter, SourceCapabilities, SourceCounters, SourceHealthSample,
};

/// De onde vêm as entradas do jornal.
///
/// É um trait e não uma chamada directa ao `journalctl` para que a lógica de
/// cursor possa ser testada sem systemd — que não existe em Windows nem em
/// contentores sem journal. Um adapter que só se pudesse testar na máquina
/// certa não seria testado.
pub trait LeitorDeJornal: Send {
    /// Devolve até `limite` linhas JSON depois de `apos_cursor`.
    ///
    /// `None` em `apos_cursor` significa "desde o princípio do que está a ser
    /// pedido" — quem chama decide se isso é o início do jornal ou o fim.
    fn ler(
        &mut self,
        apos_cursor: Option<&str>,
        limite: usize,
    ) -> Result<Vec<String>, AdapterError>;
}

/// O leitor real: invoca `journalctl`.
pub struct JournalctlCli {
    /// Argumentos extra de filtragem (`-u sshd`, `_TRANSPORT=audit`, ...).
    pub filtros: Vec<String>,
    /// Sem cursor guardado, começar pelo fim em vez de reprocessar o jornal
    /// inteiro. Um jornal de meses no arranque afogaria o pipeline.
    pub desde_o_fim_sem_cursor: bool,
}

impl Default for JournalctlCli {
    fn default() -> Self {
        Self {
            filtros: Vec::new(),
            desde_o_fim_sem_cursor: true,
        }
    }
}

/// Os argumentos do `journalctl`, isolados para poderem ser testados sem
/// systemd.
///
/// Foi aqui que viveu o defeito mais caro deste adapter: sem cursor guardado, o
/// código punha `--since=now`, que **não devolve nada** sem `--follow`. O
/// adapter nunca obtinha um primeiro cursor e ficava calado para sempre, a
/// reportar `Starting`. Não havia teste que o apanhasse porque o jornal falso
/// dos testes nunca viu um argumento.
pub fn argumentos(
    filtros: &[String],
    apos_cursor: Option<&str>,
    limite: usize,
    desde_o_fim_sem_cursor: bool,
) -> Vec<String> {
    let mut args = vec!["--output=json".to_string(), "--no-pager".to_string()];
    args.extend(filtros.iter().cloned());
    match apos_cursor {
        Some(c) => {
            // A retomar: SEM `-n`. O `-n` devolve as ÚLTIMAS N do conjunto e
            // não as N primeiras — com mais de N por ler, as mais antigas
            // desapareciam sem erro nenhum.
            args.push(format!("--after-cursor={c}"));
        }
        None if desde_o_fim_sem_cursor => {
            // `-n` é seguro AQUI e só aqui: o que se quer é justamente as mais
            // recentes, para haver um ponto de partida. A partir do primeiro
            // checkpoint passa-se ao ramo de cima.
            args.push(format!("-n{}", limite.max(1)));
        }
        None => {}
    }
    args
}

impl LeitorDeJornal for JournalctlCli {
    fn ler(
        &mut self,
        apos_cursor: Option<&str>,
        limite: usize,
    ) -> Result<Vec<String>, AdapterError> {
        use std::io::BufRead;

        let mut cmd = std::process::Command::new("journalctl");
        for a in argumentos(
            &self.filtros,
            apos_cursor,
            limite,
            self.desde_o_fim_sem_cursor,
        ) {
            cmd.arg(a);
        }
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut filho = cmd.spawn()?;
        let saida = filho
            .stdout
            .take()
            .ok_or_else(|| AdapterError::InvalidConfig("journalctl sem stdout".into()))?;

        let mut linhas = Vec::new();
        let mut atingiu_limite = false;
        // O erro de leitura NÃO pode sair daqui com um `?` directo: isso
        // devolveria antes do `kill`/`wait`, e cada poll falhado deixava um
        // `journalctl` zombie até os descritores acabarem.
        let mut erro_de_leitura: Option<std::io::Error> = None;
        for linha in std::io::BufReader::new(saida).lines() {
            match linha {
                Ok(l) => {
                    if l.trim().is_empty() {
                        continue;
                    }
                    linhas.push(l);
                    if linhas.len() >= limite {
                        atingiu_limite = true;
                        break;
                    }
                }
                Err(e) => {
                    erro_de_leitura = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = erro_de_leitura {
            let _ = filho.kill();
            let _ = filho.wait();
            return Err(e.into());
        }

        if atingiu_limite {
            // Parar de ler não termina o processo. Matá-lo é o que impede um
            // `journalctl` por poll a acumular até esgotar os descritores. Aqui
            // o código de saída é o do sinal e não diz nada.
            let _ = filho.kill();
            let _ = filho.wait();
            return Ok(linhas);
        }

        // Chegou-se ao fim do stdout sem interromper: agora o código de saída
        // significa alguma coisa.
        //
        // Ignorá-lo era o segundo defeito grave deste adapter: um `journalctl`
        // em falta, sem permissões, ou com um filtro inválido produz stdout
        // vazio e sai com erro — indistinguível de "o jornal não tem nada de
        // novo". O datasource ficava cego a reportar `Healthy`.
        let estado = filho.wait()?;
        if !estado.success() {
            let mut erro = String::new();
            if let Some(mut e) = filho.stderr.take() {
                use std::io::Read;
                let _ = e.read_to_string(&mut erro);
            }
            return Err(AdapterError::InvalidConfig(format!(
                "journalctl saiu com {estado}: {}",
                erro.trim()
            )));
        }
        Ok(linhas)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CheckpointJornal {
    cursor: String,
}

/// Extrai o cursor de uma linha JSON do journald.
///
/// Uma entrada sem `__CURSOR` não é utilizável: sem ele não há como retomar, e
/// entregá-la significaria avançar sem saber para onde. É recusada em vez de
/// ser entregue com um cursor inventado.
pub fn cursor_da_linha(linha: &str) -> Option<String> {
    let valor: serde_json::Value = serde_json::from_str(linha).ok()?;
    valor.get("__CURSOR")?.as_str().map(str::to_owned)
}

/// Extrai `__REALTIME_TIMESTAMP` (microssegundos desde a época).
pub fn timestamp_da_linha(linha: &str) -> Option<u64> {
    let valor: serde_json::Value = serde_json::from_str(linha).ok()?;
    let bruto = valor.get("__REALTIME_TIMESTAMP")?;
    // O journald escreve-o como string; aceita-se número por robustez.
    bruto
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| bruto.as_u64())
}

/// Lê o journal do systemd.
pub struct JournaldAdapter {
    identity: DatasourceIdentity,
    leitor: Box<dyn LeitorDeJornal>,
    checkpoint_path: PathBuf,
    /// O cursor durável: o último que foi confirmado.
    cursor_confirmado: Option<String>,
    /// O cursor do último lote entregue, ainda por confirmar.
    cursor_pendente: Option<String>,
    observadas: u64,
    confirmadas: u64,
    invalidas: u64,
    ultimo_micros: Option<u64>,
    ultimo_erro: Option<String>,
}

impl JournaldAdapter {
    pub fn novo(
        identity: DatasourceIdentity,
        leitor: Box<dyn LeitorDeJornal>,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, AdapterError> {
        identity.validate()?;
        let checkpoint_path = checkpoint_path.into();
        let (cursor_confirmado, aviso) =
            match crate::checkpoint::carregar::<CheckpointJornal>(&checkpoint_path) {
                crate::checkpoint::EstadoDoCheckpoint::Carregado(c) => (Some(c.cursor), None),
                crate::checkpoint::EstadoDoCheckpoint::Ausente => (None, None),
                // Recomecar em silencio a partir de um ficheiro corrompido e
                // uma decisao grande tomada sem ninguem saber: num jornal com
                // retencao reprocessa, e o operador tem de poder ver porque.
                crate::checkpoint::EstadoDoCheckpoint::Ilegivel(motivo) => {
                    tracing::warn!(%motivo, "journald: checkpoint ilegivel; a recomecar");
                    (None, Some("checkpoint_ilegivel".to_string()))
                }
            };
        Ok(Self {
            identity,
            leitor,
            checkpoint_path,
            cursor_confirmado,
            cursor_pendente: None,
            observadas: 0,
            confirmadas: 0,
            invalidas: 0,
            ultimo_micros: None,
            ultimo_erro: aviso,
        })
    }

    /// Atalho para o caso normal: `journalctl` real.
    pub fn com_journalctl(
        identity: DatasourceIdentity,
        checkpoint_path: impl Into<PathBuf>,
        filtros: Vec<String>,
    ) -> Result<Self, AdapterError> {
        Self::novo(
            identity,
            Box::new(JournalctlCli {
                filtros,
                desde_o_fim_sem_cursor: true,
            }),
            checkpoint_path,
        )
    }

    /// O cursor durável actual. É o que sobrevive a um restart.
    pub fn cursor_confirmado(&self) -> Option<&str> {
        self.cursor_confirmado.as_deref()
    }
}

impl SourceAdapter for JournaldAdapter {
    fn identity(&self) -> &DatasourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            ordered: true,
            reliable_transport: true,
            // O `__CURSOR` é da fonte, opaco e retomável.
            source_sequence: true,
            // Aqui SIM: o `__REALTIME_TIMESTAMP` vem do journald, não da
            // recepção. É o único destes adapters que o pode declarar.
            source_timestamp: true,
            backpressure: true,
        }
    }

    /// Lê a partir do último cursor CONFIRMADO, não do último entregue.
    ///
    /// É isto que faz o restart repetir em vez de saltar: se o consumidor caiu
    /// entre o `poll` e a persistência, o mesmo lote volta a sair.
    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
        if limit == 0 {
            return Ok(ObservationBatch {
                observations: Vec::new(),
                ack: None,
            });
        }
        let desde = self.cursor_confirmado.clone();
        let linhas = match self.leitor.ler(desde.as_deref(), limit) {
            Ok(l) => l,
            Err(erro) => {
                self.ultimo_erro = Some("journalctl_falhou".into());
                return Err(erro);
            }
        };
        self.ultimo_erro = None;

        let mut observations = Vec::with_capacity(linhas.len());
        let mut ultimo_cursor = None;
        for linha in linhas {
            let Some(cursor) = cursor_da_linha(&linha) else {
                // Sem `__CURSOR` não há como retomar depois desta entrada.
                // Contá-la e saltar é melhor do que avançar às cegas — mas
                // conta-se, porque saltar em silêncio é o que a §5.4 proíbe.
                self.invalidas = self.invalidas.saturating_add(1);
                self.ultimo_erro = Some("entrada_sem_cursor".into());
                continue;
            };
            let ts = timestamp_da_linha(&linha);
            if let Some(t) = ts {
                self.ultimo_micros = Some(t);
            }
            observations.push(Observation {
                payload: linha.into_bytes(),
                source_sequence: Some(cursor.clone()),
                source_event_id: Some(cursor.clone()),
                observed_at_micros: ts,
            });
            ultimo_cursor = Some(cursor);
        }

        if observations.is_empty() {
            return Ok(ObservationBatch {
                observations,
                ack: None,
            });
        }
        self.observadas = self.observadas.saturating_add(observations.len() as u64);
        self.cursor_pendente = ultimo_cursor.clone();
        Ok(ObservationBatch {
            observations,
            ack: Some(SourceAck {
                cursor: ultimo_cursor.unwrap_or_default(),
            }),
        })
    }

    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
        if self.cursor_pendente.as_deref() != Some(ack.cursor.as_str()) {
            // Confirmar um cursor que não foi o do último lote entregue saltaria
            // entradas que ninguém persistiu.
            return Err(AdapterError::InvalidAck(format!(
                "cursor {:?} nao corresponde ao ultimo lote entregue",
                ack.cursor
            )));
        }
        let texto = serde_json::to_string(&CheckpointJornal {
            cursor: ack.cursor.clone(),
        })
        .map_err(|e| AdapterError::InvalidAck(e.to_string()))?;
        crate::checkpoint::escrever_atomico(&self.checkpoint_path, texto.as_bytes())?;
        self.cursor_confirmado = Some(ack.cursor);
        self.cursor_pendente = None;
        self.confirmadas = self.confirmadas.saturating_add(1);
        Ok(())
    }

    fn health(&self) -> SourceHealthSample {
        let state = if self.ultimo_erro.as_deref() == Some("journalctl_falhou") {
            DatasourceState::Degraded
        } else if self.invalidas > 0 {
            DatasourceState::Drifted
        } else if self.observadas == 0 {
            DatasourceState::Starting
        } else {
            DatasourceState::Healthy
        };
        SourceHealthSample {
            state,
            last_observed_at_micros: self.ultimo_micros,
            last_checkpoint: self.cursor_confirmado.clone(),
            counters: SourceCounters {
                observed: self.observadas,
                acknowledged: self.confirmadas,
                backpressure_events: 0,
                // O jornal retém: o que não coube neste lote sai no seguinte.
                dropped: 0,
            },
            last_error_code: self.ultimo_erro.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn identidade() -> DatasourceIdentity {
        DatasourceIdentity {
            tenant_id: "tenant-a".into(),
            datasource_id: "ds-journald".into(),
            sensor_id: "journald-1".into(),
        }
    }

    fn entrada(cursor: &str, ts: u64, msg: &str) -> String {
        format!(r#"{{"__CURSOR":"{cursor}","__REALTIME_TIMESTAMP":"{ts}","MESSAGE":"{msg}"}}"#)
    }

    /// Um jornal falso com as mesmas regras do verdadeiro: entrega o que vem
    /// DEPOIS do cursor dado, por ordem, ate ao limite.
    /// O que o falso regista de cada chamada: o cursor pedido e o limite.
    type PedidosRegistados = Arc<Mutex<Vec<(Option<String>, usize)>>>;

    #[derive(Clone, Default)]
    struct JornalFalso {
        entradas: Arc<Mutex<Vec<String>>>,
        pedidos: PedidosRegistados,
        falhar: Arc<Mutex<bool>>,
    }

    impl JornalFalso {
        fn com(entradas: Vec<String>) -> Self {
            Self {
                entradas: Arc::new(Mutex::new(entradas)),
                pedidos: Arc::new(Mutex::new(Vec::new())),
                falhar: Arc::new(Mutex::new(false)),
            }
        }
        fn acrescentar(&self, linha: String) {
            self.entradas.lock().unwrap().push(linha);
        }
    }

    impl LeitorDeJornal for JornalFalso {
        fn ler(
            &mut self,
            apos_cursor: Option<&str>,
            limite: usize,
        ) -> Result<Vec<String>, AdapterError> {
            self.pedidos
                .lock()
                .unwrap()
                .push((apos_cursor.map(str::to_owned), limite));
            if *self.falhar.lock().unwrap() {
                return Err(AdapterError::InvalidConfig("journalctl em falta".into()));
            }
            let entradas = self.entradas.lock().unwrap();
            let inicio = match apos_cursor {
                None => 0,
                Some(c) => entradas
                    .iter()
                    .position(|e| cursor_da_linha(e).as_deref() == Some(c))
                    .map(|i| i + 1)
                    .unwrap_or(0),
            };
            Ok(entradas[inicio.min(entradas.len())..]
                .iter()
                .take(limite)
                .cloned()
                .collect())
        }
    }

    struct Bancada {
        _dir: tempfile::TempDir,
        checkpoint: PathBuf,
        jornal: JornalFalso,
    }

    fn bancada(entradas: Vec<String>) -> Bancada {
        let dir = tempfile::tempdir().unwrap();
        Bancada {
            checkpoint: dir.path().join("journal.ckpt"),
            _dir: dir,
            jornal: JornalFalso::com(entradas),
        }
    }

    fn adapter(b: &Bancada) -> JournaldAdapter {
        JournaldAdapter::novo(
            identidade(),
            Box::new(b.jornal.clone()),
            b.checkpoint.clone(),
        )
        .expect("novo")
    }

    #[test]
    fn entrega_entradas_com_o_cursor_e_o_timestamp_da_fonte() {
        let b = bancada(vec![
            entrada("c1", 1000, "primeira"),
            entrada("c2", 2000, "segunda"),
        ]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        assert_eq!(lote.observations.len(), 2);
        assert_eq!(lote.observations[0].source_sequence.as_deref(), Some("c1"));
        assert_eq!(lote.observations[0].observed_at_micros, Some(1000));
        assert_eq!(lote.ack.unwrap().cursor, "c2");
        // O `__REALTIME_TIMESTAMP` e da FONTE: e o unico destes adapters que
        // pode declarar `source_timestamp`.
        assert!(a.capabilities().source_timestamp);
    }

    /// O que faz o restart REPETIR em vez de saltar: le-se do cursor
    /// CONFIRMADO, nao do ultimo entregue.
    #[test]
    fn sem_checkpoint_o_mesmo_lote_volta_a_sair() {
        let b = bancada(vec![entrada("c1", 1, "a"), entrada("c2", 2, "b")]);
        let mut a = adapter(&b);
        let primeiro = a.poll(10).unwrap();
        let segundo = a.poll(10).unwrap();
        assert_eq!(
            primeiro.observations, segundo.observations,
            "sem checkpoint, repete"
        );

        a.checkpoint(segundo.ack.unwrap()).unwrap();
        assert!(a.poll(10).unwrap().observations.is_empty());
    }

    /// O cursor sobrevive a um adapter novo — que e o que um restart e.
    #[test]
    fn o_cursor_sobrevive_a_um_restart() {
        let b = bancada(vec![entrada("c1", 1, "a"), entrada("c2", 2, "b")]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        a.checkpoint(lote.ack.unwrap()).unwrap();
        drop(a);

        let mut novo = adapter(&b);
        assert_eq!(novo.cursor_confirmado(), Some("c2"));
        assert!(novo.poll(10).unwrap().observations.is_empty());

        b.jornal.acrescentar(entrada("c3", 3, "c"));
        let obs = novo.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].source_sequence.as_deref(), Some("c3"));
    }

    /// O limite e aplicado a LEITURA e nao ao comando: as entradas que sobram
    /// ficam no jornal e saem no poll seguinte, por ordem.
    #[test]
    fn o_limite_nao_salta_as_entradas_mais_antigas() {
        let b = bancada(vec![
            entrada("c1", 1, "a"),
            entrada("c2", 2, "b"),
            entrada("c3", 3, "c"),
        ]);
        let mut a = adapter(&b);

        let primeiro = a.poll(2).unwrap();
        assert_eq!(primeiro.observations.len(), 2);
        assert_eq!(
            primeiro.observations[0].source_sequence.as_deref(),
            Some("c1"),
            "as mais ANTIGAS primeiro; um `-n 2` daria c2 e c3"
        );
        a.checkpoint(primeiro.ack.unwrap()).unwrap();

        let segundo = a.poll(2).unwrap();
        assert_eq!(segundo.observations.len(), 1);
        assert_eq!(
            segundo.observations[0].source_sequence.as_deref(),
            Some("c3")
        );
    }

    /// Uma entrada sem `__CURSOR` nao pode ser entregue com um cursor
    /// inventado — mas tambem nao pode desaparecer sem se ver.
    #[test]
    fn uma_entrada_sem_cursor_e_saltada_e_contada() {
        let b = bancada(vec![
            entrada("c1", 1, "boa"),
            r#"{"MESSAGE":"sem cursor"}"#.to_string(),
            entrada("c2", 2, "boa"),
        ]);
        let mut a = adapter(&b);
        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 2, "a do meio nao entra");
        let saude = a.health();
        assert_eq!(
            saude.state,
            DatasourceState::Drifted,
            "saltar uma entrada nao e estar saudavel"
        );
        assert_eq!(saude.last_error_code.as_deref(), Some("entrada_sem_cursor"));
    }

    #[test]
    fn um_cursor_que_nao_e_o_do_ultimo_lote_e_recusado() {
        let b = bancada(vec![entrada("c1", 1, "a")]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        assert!(a
            .checkpoint(SourceAck {
                cursor: "cX".into()
            })
            .is_err());
        a.checkpoint(lote.ack.unwrap()).unwrap();
        // Confirmar duas vezes o mesmo tambem e recusado: ja nao ha pendente.
        assert!(a
            .checkpoint(SourceAck {
                cursor: "c1".into()
            })
            .is_err());
    }

    #[test]
    fn o_journalctl_em_falta_deixa_o_datasource_degraded() {
        let b = bancada(vec![entrada("c1", 1, "a")]);
        let mut a = adapter(&b);
        *b.jornal.falhar.lock().unwrap() = true;
        assert!(a.poll(10).is_err());
        let saude = a.health();
        assert_eq!(saude.state, DatasourceState::Degraded);
        assert_eq!(saude.last_error_code.as_deref(), Some("journalctl_falhou"));
    }

    #[test]
    fn le_se_sempre_a_partir_do_cursor_confirmado() {
        let b = bancada(vec![entrada("c1", 1, "a"), entrada("c2", 2, "b")]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        a.checkpoint(lote.ack.unwrap()).unwrap();
        let _ = a.poll(10);

        let pedidos = b.jornal.pedidos.lock().unwrap().clone();
        assert_eq!(pedidos[0].0, None, "o primeiro poll nao tem cursor");
        assert_eq!(
            pedidos[1].0.as_deref(),
            Some("c2"),
            "o segundo parte do confirmado"
        );
    }

    #[test]
    fn extrair_cursor_e_timestamp_nao_adivinha() {
        let linha = entrada("abc", 42, "x");
        assert_eq!(cursor_da_linha(&linha).as_deref(), Some("abc"));
        assert_eq!(timestamp_da_linha(&linha), Some(42));
        assert_eq!(cursor_da_linha("nao e json"), None);
        assert_eq!(cursor_da_linha(r#"{"MESSAGE":"x"}"#), None);
        assert_eq!(timestamp_da_linha(r#"{"__CURSOR":"a"}"#), None);
        // Numero em vez de string tambem serve.
        assert_eq!(
            timestamp_da_linha(r#"{"__CURSOR":"a","__REALTIME_TIMESTAMP":7}"#),
            Some(7)
        );
    }

    /// O defeito mais caro deste adapter viveu na construcao dos argumentos, e
    /// nenhum teste o podia apanhar porque o jornal falso nunca ve um
    /// argumento. Agora ve-se.
    #[test]
    fn os_argumentos_do_journalctl_nao_calam_o_adapter() {
        // Sem cursor: TEM de pedir as ultimas N. Um `--since=now` sem
        // `--follow` nao devolve nada, e o adapter ficava calado para sempre.
        let a = argumentos(&[], None, 50, true);
        assert!(
            a.iter().any(|x| x == "-n50"),
            "sem cursor tem de haver um ponto de partida: {a:?}"
        );
        assert!(
            !a.iter().any(|x| x.contains("--since")),
            "`--since=now` sem `--follow` nao devolve nada: {a:?}"
        );

        // A retomar: `--after-cursor` e NUNCA `-n`. O `-n` devolveria as
        // ULTIMAS N e as mais antigas desapareciam sem erro.
        let b = argumentos(&[], Some("c123"), 50, true);
        assert!(b.iter().any(|x| x == "--after-cursor=c123"), "{b:?}");
        assert!(
            !b.iter().any(|x| x.starts_with("-n")),
            "com cursor, o `-n` saltaria as entradas mais antigas: {b:?}"
        );

        // Um limite de 0 nao pode virar `-n0`, que nao devolve nada.
        let c = argumentos(&[], None, 0, true);
        assert!(c.iter().any(|x| x == "-n1"), "{c:?}");

        // Os filtros do orgao passam.
        let d = argumentos(&["-u".into(), "sshd".into()], None, 10, true);
        assert!(d.contains(&"sshd".to_string()));
        assert!(d.contains(&"--output=json".to_string()));
    }

    #[test]
    fn um_limite_de_zero_nao_chama_o_jornal() {
        let b = bancada(vec![entrada("c1", 1, "a")]);
        let mut a = adapter(&b);
        assert!(a.poll(0).unwrap().observations.is_empty());
        assert!(b.jornal.pedidos.lock().unwrap().is_empty());
    }
}
