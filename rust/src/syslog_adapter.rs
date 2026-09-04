//! SPEC-0071 §5.2 P0 #2 — o adapter `syslog-udp` / `syslog-tcp`.
//!
//! A §5.2 diz "extrair do `probe`", e é isso: o `probe.rs` já recebia syslog em
//! UDP e TCP, mas como binário solto — sem identidade de datasource, sem
//! checkpoint e sem saúde. Aqui a mesma recepção passa a ser um
//! [`SourceAdapter`] que o [`crate::source::SourceSupervisor`] gere ao lado dos
//! outros.
//!
//! ## Porque é que este adapter é diferente do `file-tail`
//!
//! Um ficheiro pode ser relido: o cursor é um offset, e um restart continua de
//! onde parou. **O syslog não.** Um datagrama que chega enquanto o processo
//! está em baixo desaparece — não há onde o ir buscar. Isso muda o que o
//! checkpoint pode prometer, e o adapter declara-o em vez de o esconder:
//!
//! - [`SourceCapabilities::reliable_transport`] é `false` para UDP;
//! - o cursor é uma contagem monótona de recepção, não uma posição relegível.
//!
//! A §5.4 exige "restart pode repetir; nunca perder silenciosamente". Num
//! transporte sem retenção, a parte que se pode honrar é o **silenciosamente**:
//! o que se perde é contado em [`SourceCounters::dropped`], muda o estado do
//! datasource e sai como `TelemetryDropRecorded`.
//!
//! ## Backpressure em vez de descarte invisível (§5.4)
//!
//! A fila tem tecto em BYTES e não em número de linhas — uma fila de 10 000
//! mensagens de 8 KiB é 80 MiB, e um tecto em linhas não diz nada sobre a
//! memória, que é o recurso que realmente acaba.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::buffer_fonte::FilaLimitada;
use crate::source::{
    AdapterError, DatasourceIdentity, DatasourceState, Observation, ObservationBatch, SourceAck,
    SourceAdapter, SourceCapabilities, SourceCounters, SourceHealthSample,
};

/// Tamanho máximo de um datagrama syslog aceite.
///
/// A RFC 5426 recomenda que um receptor aceite pelo menos 2048 bytes; 64 KiB é
/// o máximo de um datagrama UDP e é o que se reserva. Aceitar menos truncaria
/// mensagens legítimas — e uma mensagem truncada é pior do que nenhuma, porque
/// parece completa.
const MAX_DATAGRAMA: usize = 65_535;

/// Transporte do adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogTransport {
    Udp,
    Tcp,
}

impl SyslogTransport {
    /// O nome do tipo de datasource na §5.2.
    pub fn etiqueta(&self) -> &'static str {
        match self {
            Self::Udp => "syslog-udp",
            Self::Tcp => "syslog-tcp",
        }
    }
}

/// Recebe syslog em background e entrega por `poll`.
pub struct SyslogAdapter {
    identity: DatasourceIdentity,
    transport: SyslogTransport,
    endereco: SocketAddr,
    fila: Arc<Mutex<FilaLimitada>>,
    /// Contagem monótona de tudo o que entrou. É o cursor: num transporte sem
    /// retenção, "quantas vi" é a única posição que significa alguma coisa.
    recebidas: Arc<AtomicU64>,
    confirmadas: u64,
    parar: Arc<AtomicBool>,
    ultimo_observado_micros: Arc<AtomicU64>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl SyslogAdapter {
    /// Liga o adapter a um endereço.
    ///
    /// O bind acontece AQUI e não dentro da thread: um endereço ocupado tem de
    /// falhar no arranque do datasource, com erro. Se o bind fosse na thread,
    /// isto "arrancava" e nunca receberia nada — a diferença entre "não
    /// arrancou" e "arrancou e está calado", que é o pior modo de falha que uma
    /// plataforma de telemetria pode ter.
    pub fn ligar(
        identity: DatasourceIdentity,
        transport: SyslogTransport,
        addr: &str,
        limite_bytes: usize,
    ) -> Result<Self, AdapterError> {
        identity.validate()?;
        if limite_bytes == 0 {
            return Err(AdapterError::InvalidConfig(
                "buffer_limit_bytes tem de ser > 0".into(),
            ));
        }
        let fila = Arc::new(Mutex::new(FilaLimitada::nova(limite_bytes)));
        let recebidas = Arc::new(AtomicU64::new(0));
        let parar = Arc::new(AtomicBool::new(false));
        let ultimo = Arc::new(AtomicU64::new(0));
        let mut threads = Vec::new();

        let endereco = match transport {
            SyslogTransport::Udp => {
                let socket = UdpSocket::bind(addr)?;
                let endereco = socket.local_addr()?;
                // O timeout é o que permite ver a bandeira de paragem sem
                // bloquear para sempre num `recv_from`.
                socket.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
                threads.push(Self::receber_udp(
                    socket,
                    fila.clone(),
                    recebidas.clone(),
                    parar.clone(),
                    ultimo.clone(),
                ));
                endereco
            }
            SyslogTransport::Tcp => {
                let listener = TcpListener::bind(addr)?;
                let endereco = listener.local_addr()?;
                listener.set_nonblocking(true)?;
                threads.push(Self::receber_tcp(
                    listener,
                    fila.clone(),
                    recebidas.clone(),
                    parar.clone(),
                    ultimo.clone(),
                ));
                endereco
            }
        };

        Ok(Self {
            identity,
            transport,
            endereco,
            fila,
            recebidas,
            confirmadas: 0,
            parar,
            ultimo_observado_micros: ultimo,
            threads,
        })
    }

    /// O endereço a que ficou efectivamente ligado.
    ///
    /// Necessário quando se pede porto 0: quem configura precisa de saber o que
    /// o sistema escolheu, e os testes ligam-se a ele em vez de fixarem portos
    /// que colidem em CI.
    pub fn endereco_local(&self) -> SocketAddr {
        self.endereco
    }

    pub fn transporte(&self) -> SyslogTransport {
        self.transport
    }

    fn agora_micros() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }

    fn observacao(payload: Vec<u8>, sequencia: u64) -> Observation {
        Observation {
            payload,
            // §5.4: "source sequence, quando disponível, participa da chave de
            // idempotência". O syslog não traz sequência própria, e a de
            // recepção é o mais próximo que existe — é monótona por receptor e
            // distingue duas mensagens byte-a-byte iguais seguidas, que é
            // exactamente o caso que uma chave só de conteúdo fundiria numa.
            source_sequence: Some(sequencia.to_string()),
            source_event_id: None,
            observed_at_micros: Some(Self::agora_micros()),
        }
    }

    fn receber_udp(
        socket: UdpSocket,
        fila: Arc<Mutex<FilaLimitada>>,
        recebidas: Arc<AtomicU64>,
        parar: Arc<AtomicBool>,
        ultimo: Arc<AtomicU64>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_DATAGRAMA];
            while !parar.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((n, _)) if n > 0 => {
                        let seq = recebidas.fetch_add(1, Ordering::SeqCst) + 1;
                        ultimo.store(Self::agora_micros(), Ordering::Relaxed);
                        let obs = Self::observacao(buf[..n].to_vec(), seq);
                        if let Ok(mut f) = fila.lock() {
                            f.empurrar(obs);
                        }
                    }
                    // Timeout é o funcionamento normal deste laço.
                    _ => continue,
                }
            }
        })
    }

    fn receber_tcp(
        listener: TcpListener,
        fila: Arc<Mutex<FilaLimitada>>,
        recebidas: Arc<AtomicU64>,
        parar: Arc<AtomicBool>,
        ultimo: Arc<AtomicU64>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut sessoes: Vec<std::thread::JoinHandle<()>> = Vec::new();
            while !parar.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let fila = fila.clone();
                        let recebidas = recebidas.clone();
                        let parar_sessao = parar.clone();
                        let ultimo = ultimo.clone();
                        sessoes.push(std::thread::spawn(move || {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream
                                .set_read_timeout(Some(std::time::Duration::from_millis(200)));
                            let leitor = BufReader::new(stream);
                            // Uma linha por mensagem: é o enquadramento de
                            // syslog sobre TCP mais usado (RFC 6587,
                            // non-transparent framing). O octet-counting da
                            // mesma RFC precisa de outro parser e fica para
                            // quando um órgão real o exigir.
                            for linha in leitor.lines() {
                                if parar_sessao.load(Ordering::Relaxed) {
                                    break;
                                }
                                let Ok(linha) = linha else { break };
                                if linha.trim().is_empty() {
                                    continue;
                                }
                                let seq = recebidas.fetch_add(1, Ordering::SeqCst) + 1;
                                ultimo.store(Self::agora_micros(), Ordering::Relaxed);
                                let obs = Self::observacao(linha.into_bytes(), seq);
                                if let Ok(mut f) = fila.lock() {
                                    f.empurrar(obs);
                                }
                            }
                        }));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
            for s in sessoes {
                let _ = s.join();
            }
        })
    }
}

impl Drop for SyslogAdapter {
    fn drop(&mut self) {
        self.parar.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl SourceAdapter for SyslogAdapter {
    fn identity(&self) -> &DatasourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            // O syslog não garante ordem entre remetentes, e em UDP nem entre
            // datagramas do mesmo. Declarar `ordered: true` seria prometer o
            // que o transporte não dá.
            ordered: false,
            reliable_transport: matches!(self.transport, SyslogTransport::Tcp),
            // Sequência de RECEPÇÃO — não da fonte, mas participa na chave de
            // idempotência, que é o que a §5.4 pede.
            source_sequence: true,
            // O syslog traz timestamp no corpo, mas o parsing é do connector e
            // não do adapter: aqui só se sabe quando CHEGOU.
            source_timestamp: false,
            backpressure: true,
        }
    }

    /// Entrega o que está na fila **sem a esvaziar**.
    ///
    /// A fila só encolhe no `checkpoint`, e é isso que cumpre a §5.4
    /// ("checkpoint só avança depois da persistência"). Se o `poll` removesse,
    /// um crash entre o `poll` e o append perderia o lote — e perdia-o em
    /// silêncio, que é precisamente o que a §5.4 proíbe.
    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
        let fila = self.fila.lock().map_err(|_| {
            AdapterError::InvalidConfig("fila de syslog envenenada por um pânico".into())
        })?;
        let observations: Vec<Observation> = fila.primeiros(limit);
        if observations.is_empty() {
            return Ok(ObservationBatch {
                observations,
                ack: None,
            });
        }
        // O cursor é a última sequência do lote: confirmá-lo significa "já
        // persisti tudo até aqui".
        let cursor = observations
            .last()
            .and_then(|o| o.source_sequence.clone())
            .unwrap_or_default();
        Ok(ObservationBatch {
            observations,
            ack: Some(SourceAck { cursor }),
        })
    }

    /// Só aqui a fila encolhe (§5.4).
    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
        let ate: u64 = ack.cursor.parse().map_err(|_| {
            AdapterError::InvalidAck(format!("cursor nao numerico: {}", ack.cursor))
        })?;
        if ate < self.confirmadas {
            // Um cursor que recua é um erro do chamador, não uma instrução.
            // Aceitá-lo faria o adapter reentregar o que já foi persistido —
            // duplicação silenciosa, que é tão invisível quanto a perda.
            return Err(AdapterError::InvalidAck(format!(
                "cursor recuou de {} para {ate}",
                self.confirmadas
            )));
        }
        let recebidas = self.recebidas.load(Ordering::SeqCst);
        if ate > recebidas {
            // Confirmar o que nunca se entregou apagaria da fila mensagens que
            // ainda ninguém persistiu.
            return Err(AdapterError::InvalidAck(format!(
                "cursor {ate} ultrapassa as {recebidas} observacoes recebidas"
            )));
        }
        let mut fila = self.fila.lock().map_err(|_| {
            AdapterError::InvalidConfig("fila de syslog envenenada por um pânico".into())
        })?;
        while let Some(frente) = fila.frente() {
            let seq: u64 = frente
                .source_sequence
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if seq > ate {
                break;
            }
            fila.remover_frente();
        }
        self.confirmadas = ate;
        Ok(())
    }

    fn health(&self) -> SourceHealthSample {
        let descartadas = self.fila.lock().map(|f| f.descartadas()).unwrap_or(0);
        let recebidas = self.recebidas.load(Ordering::SeqCst);
        let ultimo = self.ultimo_observado_micros.load(Ordering::Relaxed);

        // O estado sai do que se observou, não de uma suposição.
        //
        // `Degraded` quando houve descarte: a §5.4 chama-lhe "descarte
        // autorizado", e autorizado não é o mesmo que saudável — quem opera tem
        // de ver que o buffer não chega para o caudal.
        let state = if descartadas > 0 {
            DatasourceState::Degraded
        } else if recebidas == 0 {
            DatasourceState::Starting
        } else {
            DatasourceState::Healthy
        };

        SourceHealthSample {
            state,
            last_observed_at_micros: (ultimo > 0).then_some(ultimo),
            last_checkpoint: (self.confirmadas > 0).then(|| self.confirmadas.to_string()),
            counters: SourceCounters {
                observed: recebidas,
                acknowledged: self.confirmadas,
                backpressure_events: descartadas,
                dropped: descartadas,
            },
            last_error_code: (descartadas > 0).then(|| "buffer_cheio".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn identidade(id: &str) -> DatasourceIdentity {
        DatasourceIdentity {
            tenant_id: "tenant-a".into(),
            datasource_id: id.into(),
            sensor_id: "syslog-1".into(),
        }
    }

    /// Porto 0 sempre: portos fixos colidem quando a CI corre testes em
    /// paralelo, e um teste que falha por colisao nao diz nada sobre o codigo.
    fn ligar(id: &str, t: SyslogTransport, limite: usize) -> SyslogAdapter {
        SyslogAdapter::ligar(identidade(id), t, "127.0.0.1:0", limite).expect("bind")
    }

    fn esperar_recebidas(adapter: &SyslogAdapter, quantas: u64) {
        let prazo = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while adapter.health().counters.observed < quantas {
            assert!(
                std::time::Instant::now() < prazo,
                "so chegaram {} de {quantas}",
                adapter.health().counters.observed
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn recebe_datagramas_udp_e_entrega_os_por_poll() {
        let mut adapter = ligar("ds-udp", SyslogTransport::Udp, 1 << 20);
        let destino = adapter.endereco_local();

        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..5 {
            cliente
                .send_to(format!("<34>mensagem {i}").as_bytes(), destino)
                .unwrap();
        }
        esperar_recebidas(&adapter, 5);

        let lote = adapter.poll(1000).unwrap();
        assert_eq!(lote.observations.len(), 5);
        assert!(lote.observations[0].source_sequence.is_some());
        assert!(lote.observations[0].observed_at_micros.is_some());
        assert_eq!(lote.ack.unwrap().cursor, "5");
    }

    /// §5.4 — o `poll` NAO esvazia. Se esvaziasse, um crash entre o poll e o
    /// append perderia o lote, e perdia-o em silencio.
    #[test]
    fn o_poll_nao_consome_so_o_checkpoint_consome() {
        let mut adapter = ligar("ds-udp2", SyslogTransport::Udp, 1 << 20);
        let destino = adapter.endereco_local();
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..3 {
            cliente
                .send_to(format!("linha {i}").as_bytes(), destino)
                .unwrap();
        }
        esperar_recebidas(&adapter, 3);

        let primeiro = adapter.poll(1000).unwrap();
        assert_eq!(primeiro.observations.len(), 3);

        // Sem checkpoint, o mesmo lote continua la — repeticao, nao perda.
        let segundo = adapter.poll(1000).unwrap();
        assert_eq!(segundo.observations.len(), 3, "o poll nao pode consumir");
        assert_eq!(segundo.observations, primeiro.observations);

        adapter.checkpoint(segundo.ack.clone().unwrap()).unwrap();
        assert!(adapter.poll(1000).unwrap().observations.is_empty());
        assert_eq!(adapter.health().counters.acknowledged, 3);
    }

    /// Um checkpoint parcial so apaga o que foi confirmado.
    #[test]
    fn um_checkpoint_parcial_deixa_o_resto_na_fila() {
        let mut adapter = ligar("ds-udp-parcial", SyslogTransport::Udp, 1 << 20);
        let destino = adapter.endereco_local();
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..4 {
            cliente
                .send_to(format!("m{i}").as_bytes(), destino)
                .unwrap();
        }
        esperar_recebidas(&adapter, 4);

        // O chamador so conseguiu persistir as duas primeiras.
        let parcial = adapter.poll(2).unwrap();
        assert_eq!(parcial.observations.len(), 2);
        adapter.checkpoint(parcial.ack.unwrap()).unwrap();

        let resto = adapter.poll(1000).unwrap();
        assert_eq!(resto.observations.len(), 2, "as outras duas tem de ficar");
        assert_eq!(resto.observations[0].source_sequence.as_deref(), Some("3"));
    }

    /// Um cursor que recua — ou que salta a frente do que se recebeu — e um
    /// erro do chamador, nao uma instrucao.
    #[test]
    fn um_cursor_invalido_e_recusado() {
        let mut adapter = ligar("ds-udp3", SyslogTransport::Udp, 1 << 20);
        let destino = adapter.endereco_local();
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..10 {
            cliente.send_to(b"x", destino).unwrap();
        }
        esperar_recebidas(&adapter, 10);

        adapter
            .checkpoint(SourceAck {
                cursor: "10".into(),
            })
            .unwrap();

        let recuo = adapter
            .checkpoint(SourceAck { cursor: "5".into() })
            .unwrap_err();
        assert!(matches!(recuo, AdapterError::InvalidAck(_)));

        // Confirmar o que nunca se entregou apagaria o que ninguem persistiu.
        assert!(adapter
            .checkpoint(SourceAck {
                cursor: "999".into()
            })
            .is_err());

        assert!(adapter
            .checkpoint(SourceAck {
                cursor: "nao-numerico".into()
            })
            .is_err());
    }

    /// §5.4 — "nunca descarte invisivel". O descarte conta-se, muda o estado e
    /// deixa um codigo de erro.
    #[test]
    fn o_buffer_cheio_descarta_o_mais_antigo_e_conta() {
        // Tecto minusculo para forcar o descarte com poucas mensagens.
        let mut adapter = ligar("ds-udp4", SyslogTransport::Udp, 120);
        let destino = adapter.endereco_local();
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..20 {
            cliente
                .send_to(format!("mensagem numero {i:03}").as_bytes(), destino)
                .unwrap();
        }
        esperar_recebidas(&adapter, 20);

        let saude = adapter.health();
        assert!(
            saude.counters.dropped > 0,
            "20 mensagens com 120 bytes de tecto tinham de descartar"
        );
        assert_eq!(
            saude.state,
            DatasourceState::Degraded,
            "descarte autorizado NAO e o mesmo que saudavel"
        );
        assert_eq!(saude.last_error_code.as_deref(), Some("buffer_cheio"));
        assert_eq!(saude.counters.backpressure_events, saude.counters.dropped);

        // O que sobrou e o MAIS RECENTE: numa deteccao, a mensagem de agora
        // vale mais do que a de ha um minuto.
        let restantes = adapter.poll(1000).unwrap().observations;
        let ultima = String::from_utf8_lossy(&restantes.last().unwrap().payload).to_string();
        assert!(ultima.contains("019"), "ficou {ultima}");
    }

    /// As capacidades DECLARAM o que o transporte da, e nao mais.
    #[test]
    fn as_capacidades_nao_prometem_o_que_o_transporte_nao_da() {
        let udp = ligar("ds-cap-udp", SyslogTransport::Udp, 1 << 20);
        let caps = udp.capabilities();
        assert!(!caps.ordered, "syslog nao garante ordem");
        assert!(!caps.reliable_transport, "UDP nao e fiavel");
        assert!(
            !caps.source_timestamp,
            "o timestamp e do corpo; nao do adapter"
        );
        assert!(caps.source_sequence);
        assert!(caps.backpressure);

        let tcp = ligar("ds-cap-tcp", SyslogTransport::Tcp, 1 << 20);
        assert!(tcp.capabilities().reliable_transport, "TCP e fiavel");
        assert_eq!(tcp.transporte().etiqueta(), "syslog-tcp");
        assert_eq!(udp.transporte().etiqueta(), "syslog-udp");
    }

    #[test]
    fn recebe_linhas_por_tcp() {
        let mut adapter = ligar("ds-tcp", SyslogTransport::Tcp, 1 << 20);
        let destino = adapter.endereco_local();

        let mut cliente = std::net::TcpStream::connect(destino).unwrap();
        cliente.write_all(b"<34>primeira\n<34>segunda\n").unwrap();
        cliente.flush().unwrap();
        esperar_recebidas(&adapter, 2);

        let obs = adapter.poll(1000).unwrap().observations;
        assert_eq!(obs.len(), 2);
        assert_eq!(String::from_utf8_lossy(&obs[0].payload), "<34>primeira");
        assert_eq!(String::from_utf8_lossy(&obs[1].payload), "<34>segunda");
    }

    /// Duas mensagens byte-a-byte iguais tem de continuar a ser duas: e por
    /// isso que a sequencia de recepcao entra na chave de idempotencia.
    #[test]
    fn duas_mensagens_iguais_nao_se_fundem_numa() {
        let mut adapter = ligar("ds-dup", SyslogTransport::Udp, 1 << 20);
        let destino = adapter.endereco_local();
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        cliente.send_to(b"<34>falha de login", destino).unwrap();
        cliente.send_to(b"<34>falha de login", destino).unwrap();
        esperar_recebidas(&adapter, 2);

        let obs = adapter.poll(1000).unwrap().observations;
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].payload, obs[1].payload);
        assert_ne!(obs[0].source_sequence, obs[1].source_sequence);
    }

    #[test]
    fn um_endereco_ocupado_falha_no_arranque_e_nao_em_silencio() {
        let primeiro = ligar("ds-ocupado", SyslogTransport::Tcp, 1 << 20);
        let ocupado = primeiro.endereco_local().to_string();

        // O segundo TEM de falhar aqui, com erro.
        assert!(SyslogAdapter::ligar(
            identidade("ds-ocupado-2"),
            SyslogTransport::Tcp,
            &ocupado,
            1 << 20,
        )
        .is_err());
    }

    #[test]
    fn uma_configuracao_invalida_e_recusada() {
        assert!(
            SyslogAdapter::ligar(identidade("ds"), SyslogTransport::Udp, "127.0.0.1:0", 0).is_err(),
            "um tecto de 0 bytes descartaria tudo"
        );

        let mau = DatasourceIdentity {
            tenant_id: "".into(),
            datasource_id: "ds".into(),
            sensor_id: "s".into(),
        };
        assert!(SyslogAdapter::ligar(mau, SyslogTransport::Udp, "127.0.0.1:0", 1 << 20).is_err());
    }
}
