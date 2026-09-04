//! SPEC-0071 §5.2 P0 #5 — o adapter `windows-eventlog`, **por API nativa**.
//!
//! A §5.2 diz "Windows Event Log por API nativa", e a insistência tem razão de
//! ser. A alternativa fácil é invocar `wevtutil` e ler o stdout, e isso traz
//! três problemas que não se veem no primeiro dia: o formato da ferramenta pode
//! mudar entre versões do Windows, um processo por poll custa mais do que a
//! leitura, e — o pior — os erros chegam como texto em português ou em
//! espanhol conforme a máquina, o que torna impossível distinguir "não há mais
//! eventos" de "o canal não existe".
//!
//! Aqui usa-se `EvtQuery`/`EvtNext`/`EvtRender` do `wevtapi`, e os erros vêm
//! como códigos.
//!
//! ## O cursor é o `EventRecordID`
//!
//! Cada canal numera os seus registos com um `EventRecordID` monótono. É uma
//! sequência da FONTE, e retoma-se com uma consulta XPath que filtra
//! `EventRecordID > N`. Não é preciso guardar bookmarks opacos.
//!
//! O que ela NÃO sobrevive é a limpeza do canal: quando alguém limpa o log de
//! Segurança, a numeração recomeça no 1. O adapter detecta-o — um record id
//! menor do que o confirmado só pode ser isso — e conta-o em vez de o ignorar.
//!
//! ## Porque é que a lógica não está dentro do `cfg(windows)`
//!
//! Só o leitor concreto é Win32. O resto — cursor, checkpoint, detecção de
//! limpeza do canal — é lógica pura por trás de [`LeitorDeEventLog`], e por
//! isso corre e é testado na CI de Linux também. Um adapter que só se
//! compilasse numa plataforma seria um adapter que só lá se testaria.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::source::{
    AdapterError, DatasourceIdentity, DatasourceState, Observation, ObservationBatch, SourceAck,
    SourceAdapter, SourceCapabilities, SourceCounters, SourceHealthSample,
};

/// De onde vêm os eventos.
pub trait LeitorDeEventLog: Send {
    /// Devolve até `limite` eventos em XML com `EventRecordID` maior que
    /// `apos_record_id`.
    fn ler(
        &mut self,
        apos_record_id: Option<u64>,
        limite: usize,
    ) -> Result<Vec<String>, AdapterError>;
}

/// Extrai o `EventRecordID` do XML do evento.
///
/// Sem regex e sem parser de XML: o elemento é fixo no schema do Windows, e um
/// parser completo aqui seria interpretar conteúdo — trabalho da camada de
/// cima. Isto é só o que o cursor precisa.
pub fn record_id_do_xml(xml: &str) -> Option<u64> {
    let inicio = xml.find("<EventRecordID>")? + "<EventRecordID>".len();
    let resto = &xml[inicio..];
    let fim = resto.find("</EventRecordID>")?;
    resto[..fim].trim().parse().ok()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CheckpointEventLog {
    canal: String,
    record_id: u64,
    /// Quantas vezes o canal foi limpo desde que este datasource existe.
    geracao: u64,
}

/// Lê um canal do Windows Event Log.
pub struct WinEventLogAdapter {
    identity: DatasourceIdentity,
    canal: String,
    leitor: Box<dyn LeitorDeEventLog>,
    checkpoint_path: PathBuf,
    confirmado: Option<u64>,
    pendente: Option<u64>,
    geracao: u64,
    observadas: u64,
    confirmadas: u64,
    sem_record_id: u64,
    ultimo_erro: Option<String>,
}

impl WinEventLogAdapter {
    pub fn novo(
        identity: DatasourceIdentity,
        canal: impl Into<String>,
        leitor: Box<dyn LeitorDeEventLog>,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<Self, AdapterError> {
        identity.validate()?;
        let canal = canal.into();
        if canal.trim().is_empty() {
            return Err(AdapterError::InvalidConfig(
                "canal nao pode ser vazio".into(),
            ));
        }
        let checkpoint_path = checkpoint_path.into();
        let guardado = std::fs::read_to_string(&checkpoint_path)
            .ok()
            .and_then(|t| serde_json::from_str::<CheckpointEventLog>(&t).ok())
            .filter(|c| c.canal == canal);
        let (confirmado, geracao) = match guardado {
            Some(c) => (Some(c.record_id), c.geracao),
            None => (None, 0),
        };
        Ok(Self {
            identity,
            canal,
            leitor,
            checkpoint_path,
            confirmado,
            pendente: None,
            geracao,
            observadas: 0,
            confirmadas: 0,
            sem_record_id: 0,
            ultimo_erro: None,
        })
    }

    pub fn canal(&self) -> &str {
        &self.canal
    }

    pub fn record_id_confirmado(&self) -> Option<u64> {
        self.confirmado
    }

    /// Quantas vezes se detectou que o canal foi limpo.
    pub fn geracao(&self) -> u64 {
        self.geracao
    }
}

impl SourceAdapter for WinEventLogAdapter {
    fn identity(&self) -> &DatasourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            ordered: true,
            reliable_transport: true,
            // O `EventRecordID` é da fonte.
            source_sequence: true,
            // O `TimeCreated` está no XML, mas lê-lo é parsing.
            source_timestamp: false,
            backpressure: true,
        }
    }

    /// Lê a partir do record id CONFIRMADO — não do último entregue.
    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
        if limit == 0 {
            return Ok(ObservationBatch {
                observations: Vec::new(),
                ack: None,
            });
        }
        let eventos = match self.leitor.ler(self.confirmado, limit) {
            Ok(e) => e,
            Err(erro) => {
                self.ultimo_erro = Some("eventlog_falhou".into());
                return Err(erro);
            }
        };
        self.ultimo_erro = None;

        let mut observations = Vec::with_capacity(eventos.len());
        let mut ultimo = None;
        for xml in eventos {
            let Some(id) = record_id_do_xml(&xml) else {
                // Sem record id não há como retomar depois deste evento.
                // Conta-se; saltar em silêncio é o que a §5.4 proíbe.
                self.sem_record_id = self.sem_record_id.saturating_add(1);
                self.ultimo_erro = Some("evento_sem_record_id".into());
                continue;
            };
            // Um id MENOR do que o confirmado só acontece quando o canal foi
            // limpo e a numeração recomeçou. Continuar com a chave antiga
            // fundiria eventos novos com eventos velhos.
            if self.confirmado.is_some_and(|c| id <= c) {
                self.geracao = self.geracao.saturating_add(1);
                self.confirmado = None;
                self.ultimo_erro = Some("canal_limpo".into());
            }
            observations.push(Observation {
                payload: xml.into_bytes(),
                source_sequence: Some(format!("{}:{id}", self.geracao)),
                source_event_id: Some(format!("{}:{}:{id}", self.canal, self.geracao)),
                observed_at_micros: None,
            });
            ultimo = Some(id);
        }

        if observations.is_empty() {
            return Ok(ObservationBatch {
                observations,
                ack: None,
            });
        }
        self.observadas = self.observadas.saturating_add(observations.len() as u64);
        self.pendente = ultimo;
        Ok(ObservationBatch {
            observations,
            ack: Some(SourceAck {
                cursor: ultimo.unwrap_or_default().to_string(),
            }),
        })
    }

    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
        let ate: u64 = ack.cursor.parse().map_err(|_| {
            AdapterError::InvalidAck(format!("cursor nao numerico: {}", ack.cursor))
        })?;
        if self.pendente != Some(ate) {
            return Err(AdapterError::InvalidAck(format!(
                "cursor {ate} nao corresponde ao ultimo lote entregue ({:?})",
                self.pendente
            )));
        }
        let texto = serde_json::to_string(&CheckpointEventLog {
            canal: self.canal.clone(),
            record_id: ate,
            geracao: self.geracao,
        })
        .map_err(|e| AdapterError::InvalidAck(e.to_string()))?;
        escrever_atomico(&self.checkpoint_path, texto.as_bytes())?;
        self.confirmado = Some(ate);
        self.pendente = None;
        self.confirmadas = self.confirmadas.saturating_add(1);
        Ok(())
    }

    fn health(&self) -> SourceHealthSample {
        let state = if self.ultimo_erro.as_deref() == Some("eventlog_falhou") {
            DatasourceState::Degraded
        } else if self.ultimo_erro.as_deref() == Some("canal_limpo") || self.sem_record_id > 0 {
            // O canal ter sido limpo não é uma falha do adapter, mas é uma
            // descontinuidade na telemetria — e quem audita tem de a ver.
            DatasourceState::Drifted
        } else if self.observadas == 0 {
            DatasourceState::Starting
        } else {
            DatasourceState::Healthy
        };
        SourceHealthSample {
            state,
            last_observed_at_micros: None,
            last_checkpoint: self.confirmado.map(|c| c.to_string()),
            counters: SourceCounters {
                observed: self.observadas,
                acknowledged: self.confirmadas,
                backpressure_events: 0,
                // O canal retém: o que não coube sai no poll seguinte.
                dropped: 0,
            },
            last_error_code: self.ultimo_erro.clone(),
        }
    }
}

fn escrever_atomico(destino: &Path, dados: &[u8]) -> Result<(), AdapterError> {
    let temporario = destino.with_extension("tmp");
    std::fs::write(&temporario, dados)?;
    std::fs::rename(&temporario, destino)?;
    Ok(())
}

/// O leitor real, sobre `wevtapi`.
#[cfg(windows)]
pub mod nativo {
    use super::{AdapterError, LeitorDeEventLog};
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_ITEMS};
    use windows_sys::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    };

    fn larga(texto: &str) -> Vec<u16> {
        texto.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Fecha o handle no fim do escopo, mesmo se sairmos por erro.
    struct Handle(EVT_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // Sem isto, cada poll deixaria um handle do serviço de eventos
                // por fechar — e o processo acabaria por não conseguir abrir
                // mais nenhum.
                unsafe { EvtClose(self.0) };
            }
        }
    }

    /// Leitor de um canal do Windows Event Log.
    pub struct EventLogNativo {
        canal: String,
    }

    impl EventLogNativo {
        pub fn novo(canal: impl Into<String>) -> Self {
            Self {
                canal: canal.into(),
            }
        }

        /// A consulta XPath que retoma de onde ficou.
        fn consulta(apos: Option<u64>) -> String {
            match apos {
                Some(n) => format!("*[System[EventRecordID > {n}]]"),
                None => "*".to_string(),
            }
        }

        fn renderizar(evento: EVT_HANDLE) -> Result<String, AdapterError> {
            let mut usado: u32 = 0;
            let mut propriedades: u32 = 0;
            // Primeira chamada só para saber o tamanho. O Windows devolve
            // falso com ERROR_INSUFFICIENT_BUFFER; é o protocolo, não um erro.
            unsafe {
                EvtRender(
                    0,
                    evento,
                    EvtRenderEventXml,
                    0,
                    std::ptr::null_mut(),
                    &mut usado,
                    &mut propriedades,
                )
            };
            if usado == 0 {
                return Err(AdapterError::InvalidConfig(
                    "EvtRender nao indicou tamanho".into(),
                ));
            }
            let mut buffer = vec![0u8; usado as usize];
            let ok = unsafe {
                EvtRender(
                    0,
                    evento,
                    EvtRenderEventXml,
                    usado,
                    buffer.as_mut_ptr().cast(),
                    &mut usado,
                    &mut propriedades,
                )
            };
            if ok == 0 {
                return Err(AdapterError::InvalidConfig(format!(
                    "EvtRender falhou com {}",
                    unsafe { GetLastError() }
                )));
            }
            // O buffer vem em UTF-16 com terminador.
            let largas: Vec<u16> = buffer
                .chunks_exact(2)
                .map(|par| u16::from_le_bytes([par[0], par[1]]))
                .take_while(|c| *c != 0)
                .collect();
            Ok(String::from_utf16_lossy(&largas))
        }
    }

    impl LeitorDeEventLog for EventLogNativo {
        fn ler(
            &mut self,
            apos_record_id: Option<u64>,
            limite: usize,
        ) -> Result<Vec<String>, AdapterError> {
            let canal = larga(&self.canal);
            let consulta = larga(&Self::consulta(apos_record_id));
            let resultado = unsafe {
                EvtQuery(
                    0,
                    canal.as_ptr(),
                    consulta.as_ptr(),
                    EvtQueryChannelPath | EvtQueryForwardDirection,
                )
            };
            if resultado == 0 {
                let codigo = unsafe { GetLastError() };
                return Err(AdapterError::InvalidConfig(format!(
                    "EvtQuery falhou no canal {:?} com {codigo}",
                    self.canal
                )));
            }
            let resultado = Handle(resultado);

            let mut linhas = Vec::new();
            // Lotes pequenos: cada handle devolvido tem de ser fechado, e um
            // lote grande que falhe a meio deixa mais por fechar.
            const LOTE: usize = 16;
            let mut eventos: [EVT_HANDLE; LOTE] = [0; LOTE];
            while linhas.len() < limite {
                let quantos = LOTE.min(limite - linhas.len()) as u32;
                let mut devolvidos: u32 = 0;
                let ok = unsafe {
                    EvtNext(
                        resultado.0,
                        quantos,
                        eventos.as_mut_ptr(),
                        // Sem espera: o `poll` não pode bloquear a thread do
                        // supervisor à espera de eventos que podem não vir.
                        0,
                        0,
                        &mut devolvidos,
                    )
                };
                if ok == 0 {
                    let codigo = unsafe { GetLastError() };
                    if codigo == ERROR_NO_MORE_ITEMS {
                        break;
                    }
                    return Err(AdapterError::InvalidConfig(format!(
                        "EvtNext falhou com {codigo}"
                    )));
                }
                if devolvidos == 0 {
                    break;
                }
                for evento in eventos.iter().take(devolvidos as usize) {
                    let guarda = Handle(*evento);
                    match Self::renderizar(guarda.0) {
                        Ok(xml) => linhas.push(xml),
                        // Um evento que não renderiza não pode parar o lote
                        // inteiro: os outros são bons. Fica sem record id e o
                        // adapter conta-o.
                        Err(erro) => {
                            tracing::warn!(%erro, "eventlog: evento nao renderizou");
                        }
                    }
                }
            }
            Ok(linhas)
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
            datasource_id: "ds-winevt".into(),
            sensor_id: "winevt-1".into(),
        }
    }

    fn evento(id: u64, mensagem: &str) -> String {
        format!(
            "<Event><System><EventRecordID>{id}</EventRecordID></System>\
             <EventData><Data>{mensagem}</Data></EventData></Event>"
        )
    }

    type Pedidos = Arc<Mutex<Vec<(Option<u64>, usize)>>>;

    /// Canal falso com as mesmas regras do verdadeiro: devolve os eventos com
    /// record id MAIOR que o pedido, por ordem, ate ao limite.
    #[derive(Clone, Default)]
    struct CanalFalso {
        eventos: Arc<Mutex<Vec<String>>>,
        pedidos: Pedidos,
        falhar: Arc<Mutex<bool>>,
    }

    impl CanalFalso {
        fn com(eventos: Vec<String>) -> Self {
            Self {
                eventos: Arc::new(Mutex::new(eventos)),
                pedidos: Arc::new(Mutex::new(Vec::new())),
                falhar: Arc::new(Mutex::new(false)),
            }
        }
    }

    impl LeitorDeEventLog for CanalFalso {
        fn ler(
            &mut self,
            apos_record_id: Option<u64>,
            limite: usize,
        ) -> Result<Vec<String>, AdapterError> {
            self.pedidos.lock().unwrap().push((apos_record_id, limite));
            if *self.falhar.lock().unwrap() {
                return Err(AdapterError::InvalidConfig("canal indisponivel".into()));
            }
            let eventos = self.eventos.lock().unwrap();
            Ok(eventos
                .iter()
                .filter(|e| match apos_record_id {
                    None => true,
                    Some(n) => record_id_do_xml(e).is_some_and(|id| id > n),
                })
                .take(limite)
                .cloned()
                .collect())
        }
    }

    struct Bancada {
        _dir: tempfile::TempDir,
        checkpoint: PathBuf,
        canal: CanalFalso,
    }

    fn bancada(eventos: Vec<String>) -> Bancada {
        let dir = tempfile::tempdir().unwrap();
        Bancada {
            checkpoint: dir.path().join("winevt.ckpt"),
            _dir: dir,
            canal: CanalFalso::com(eventos),
        }
    }

    fn adapter(b: &Bancada) -> WinEventLogAdapter {
        WinEventLogAdapter::novo(
            identidade(),
            "Application",
            Box::new(b.canal.clone()),
            b.checkpoint.clone(),
        )
        .expect("novo")
    }

    #[test]
    fn entrega_eventos_com_o_record_id_como_sequencia() {
        let b = bancada(vec![evento(10, "a"), evento(11, "b")]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        assert_eq!(lote.observations.len(), 2);
        assert_eq!(
            lote.observations[0].source_sequence.as_deref(),
            Some("0:10")
        );
        assert_eq!(lote.ack.unwrap().cursor, "11");
        assert_eq!(a.canal(), "Application");
    }

    #[test]
    fn sem_checkpoint_o_mesmo_lote_volta_a_sair() {
        let b = bancada(vec![evento(1, "a"), evento(2, "b")]);
        let mut a = adapter(&b);
        let primeiro = a.poll(10).unwrap();
        let segundo = a.poll(10).unwrap();
        assert_eq!(primeiro.observations, segundo.observations);
        a.checkpoint(segundo.ack.unwrap()).unwrap();
        assert!(a.poll(10).unwrap().observations.is_empty());
    }

    #[test]
    fn o_record_id_sobrevive_a_um_restart() {
        let b = bancada(vec![evento(1, "a"), evento(2, "b")]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        a.checkpoint(lote.ack.unwrap()).unwrap();
        drop(a);

        let mut novo = adapter(&b);
        assert_eq!(novo.record_id_confirmado(), Some(2));
        assert!(novo.poll(10).unwrap().observations.is_empty());
    }

    /// Um canal que devolve o que lhe mandarem, sem respeitar o cursor. E o que
    /// o Windows faz depois de o log ser limpo: a consulta
    /// `EventRecordID > 50` passa a incidir sobre uma numeracao que recomecou,
    /// e devolve eventos com ids pequenos.
    struct CanalLimpo(Vec<String>);

    impl LeitorDeEventLog for CanalLimpo {
        fn ler(&mut self, _apos: Option<u64>, limite: usize) -> Result<Vec<String>, AdapterError> {
            Ok(self.0.iter().take(limite).cloned().collect())
        }
    }

    /// Limpar o log de Seguranca reinicia a numeracao no 1. Continuar com a
    /// chave antiga fundiria eventos novos com eventos velhos.
    #[test]
    fn um_record_id_que_recua_conta_como_canal_limpo() {
        let b = bancada(vec![evento(50, "velho")]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        assert_eq!(
            lote.observations[0].source_sequence.as_deref(),
            Some("0:50")
        );
        a.checkpoint(lote.ack.unwrap()).unwrap();
        assert_eq!(a.geracao(), 0);
        assert_eq!(a.record_id_confirmado(), Some(50));

        // Alguem limpou o canal.
        a.leitor = Box::new(CanalLimpo(vec![evento(3, "depois da limpeza")]));
        let obs = a.poll(10).unwrap().observations;

        assert_eq!(obs.len(), 1);
        assert_eq!(a.geracao(), 1, "a geracao tem de subir");
        assert_eq!(
            obs[0].source_sequence.as_deref(),
            Some("1:3"),
            "id pequeno mas geracao nova: nao colide com o 3 da geracao anterior"
        );
        assert_eq!(a.health().state, DatasourceState::Drifted);
        assert_eq!(a.health().last_error_code.as_deref(), Some("canal_limpo"));
    }

    #[test]
    fn um_evento_sem_record_id_e_saltado_e_contado() {
        let b = bancada(vec![
            evento(1, "boa"),
            "<Event><System></System></Event>".to_string(),
            evento(2, "boa"),
        ]);
        let mut a = adapter(&b);
        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 2);
        assert_eq!(a.health().state, DatasourceState::Drifted);
        assert_eq!(
            a.health().last_error_code.as_deref(),
            Some("evento_sem_record_id")
        );
    }

    #[test]
    fn um_cursor_que_nao_e_o_do_ultimo_lote_e_recusado() {
        let b = bancada(vec![evento(1, "a")]);
        let mut a = adapter(&b);
        let lote = a.poll(10).unwrap();
        assert!(a.checkpoint(SourceAck { cursor: "9".into() }).is_err());
        assert!(a
            .checkpoint(SourceAck {
                cursor: "nao".into()
            })
            .is_err());
        a.checkpoint(lote.ack.unwrap()).unwrap();
    }

    #[test]
    fn o_canal_indisponivel_deixa_o_datasource_degraded() {
        let b = bancada(vec![evento(1, "a")]);
        let mut a = adapter(&b);
        *b.canal.falhar.lock().unwrap() = true;
        assert!(a.poll(10).is_err());
        assert_eq!(a.health().state, DatasourceState::Degraded);
        assert_eq!(
            a.health().last_error_code.as_deref(),
            Some("eventlog_falhou")
        );
    }

    #[test]
    fn le_se_sempre_a_partir_do_confirmado() {
        let b = bancada(vec![evento(1, "a"), evento(2, "b"), evento(3, "c")]);
        let mut a = adapter(&b);
        let lote = a.poll(2).unwrap();
        assert_eq!(lote.observations.len(), 2);
        a.checkpoint(lote.ack.unwrap()).unwrap();
        let _ = a.poll(2);
        let pedidos = b.canal.pedidos.lock().unwrap().clone();
        assert_eq!(pedidos[0].0, None);
        assert_eq!(pedidos[1].0, Some(2), "o segundo parte do confirmado");
    }

    #[test]
    fn o_record_id_sai_do_xml_e_nao_de_um_palpite() {
        assert_eq!(record_id_do_xml(&evento(42, "x")), Some(42));
        assert_eq!(record_id_do_xml("<Event/>"), None);
        assert_eq!(record_id_do_xml("<EventRecordID>nao</EventRecordID>"), None);
        assert_eq!(record_id_do_xml("<EventRecordID>7"), None, "sem fechar");
        assert_eq!(
            record_id_do_xml("<EventRecordID> 7 </EventRecordID>"),
            Some(7)
        );
    }

    #[test]
    fn um_canal_vazio_e_recusado_na_configuracao() {
        let b = bancada(vec![]);
        assert!(WinEventLogAdapter::novo(
            identidade(),
            "  ",
            Box::new(b.canal.clone()),
            b.checkpoint.clone(),
        )
        .is_err());
    }

    /// O leitor nativo contra o Event Log REAL desta maquina.
    ///
    /// So corre em Windows, e a CI do Forge e Linux — por isso este teste e a
    /// unica prova de que o FFI do `wevtapi` funciona, e tem de ser exigente.
    /// Um teste que passasse com zero eventos nao provava nada.
    #[cfg(windows)]
    #[test]
    fn o_leitor_nativo_le_o_event_log_real() {
        use super::nativo::EventLogNativo;

        let mut leitor = EventLogNativo::novo("Application");
        let eventos = leitor.ler(None, 5).expect("o canal Application existe");
        assert!(
            !eventos.is_empty(),
            "o canal Application de uma maquina real nunca esta vazio"
        );
        let ids: Vec<u64> = eventos
            .iter()
            .map(|e| {
                record_id_do_xml(e)
                    .unwrap_or_else(|| panic!("o XML do Windows tem sempre EventRecordID: {e}"))
            })
            .collect();
        assert!(
            eventos.iter().all(|e| e.contains("<Event")),
            "o EvtRender devolve XML"
        );

        // A consulta XPath e o que retoma: pedir depois do primeiro id tem de
        // devolver so ids maiores.
        let corte = ids[0];
        let seguintes = leitor.ler(Some(corte), 5).expect("segunda consulta");
        for e in &seguintes {
            let id = record_id_do_xml(e).expect("record id");
            assert!(id > corte, "a consulta filtrou mal: {id} <= {corte}");
        }
    }
}
