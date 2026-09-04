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
//! - o cursor é uma contagem de recepção, não uma posição relegível.
//!
//! A §5.4 exige "restart pode repetir; nunca perder silenciosamente". Num
//! transporte sem retenção, a parte que se pode honrar é o **silenciosamente**:
//! o que se perde é contado, muda o estado do datasource e sai como
//! `TelemetryDropRecorded`.
//!
//! ## A chave de idempotência tem de sobreviver a um restart
//!
//! A contagem de recepção recomeça em 1 a cada arranque. Se ela fosse a chave,
//! a mensagem número 7 de hoje e a número 7 de amanhã teriam a MESMA chave, e a
//! deduplicação a jusante deitaria fora a segunda — perda silenciosa causada
//! precisamente pelo mecanismo que existe para a evitar.
//!
//! Por isso a chave é `<arranque>:<n>`, onde `<arranque>` é o instante em que
//! este adapter subiu. Dois processos diferentes não partilham chaves.
//!
//! ## Backpressure em vez de descarte invisível (§5.4)
//!
//! A fila tem tecto em BYTES e não em número de linhas — uma fila de 10 000
//! mensagens de 8 KiB é 80 MiB, e um tecto em linhas não diz nada sobre a
//! memória, que é o recurso que realmente acaba.

use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::buffer_fonte::FilaLimitada;
use crate::enquadramento::{consumir_linhas, MAX_LINHA};
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

/// Tecto de ligações TCP simultâneas.
///
/// Cada ligação custa uma thread do sistema operativo. Sem tecto, quem se ligar
/// mil vezes esgota as threads do processo inteiro — e faz isso a partir da
/// rede. Ao tecto, a ligação nova é fechada e contada, o que é visível; ficar
/// sem threads não é.
pub const MAX_SESSOES: usize = 256;

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

/// O estado partilhado entre os receptores e o `poll`.
pub(crate) struct Recepcao {
    pub(crate) fila: Mutex<FilaLimitada>,
    /// Quantas entraram desde que o adapter subiu.
    pub(crate) recebidas: AtomicU64,
    /// Identificador deste arranque, para as chaves não colidirem entre
    /// processos.
    pub(crate) arranque: u64,
    pub(crate) ultimo_micros: AtomicU64,
    /// Linhas deitadas fora por passarem o tecto por linha.
    pub(crate) linhas_gigantes: AtomicU64,
    /// Ligações recusadas por o tecto de sessões estar cheio.
    pub(crate) sessoes_recusadas: AtomicU64,
    /// Erros de socket que não são timeouts.
    pub(crate) erros_de_socket: AtomicU64,
    /// Um `Mutex` envenenado por um pânico torna a fila inutilizável. Sem esta
    /// bandeira o adapter continuaria a dizer `Healthy` enquanto deitava fora
    /// tudo o que recebia.
    pub(crate) envenenada: AtomicBool,
}

impl Recepcao {
    pub(crate) fn nova(limite_bytes: usize) -> Self {
        Self {
            fila: Mutex::new(FilaLimitada::nova(limite_bytes)),
            recebidas: AtomicU64::new(0),
            arranque: agora_micros(),
            ultimo_micros: AtomicU64::new(0),
            linhas_gigantes: AtomicU64::new(0),
            sessoes_recusadas: AtomicU64::new(0),
            erros_de_socket: AtomicU64::new(0),
            envenenada: AtomicBool::new(false),
        }
    }

    /// Enfileira uma mensagem, atribuindo-lhe a sequência **sob o lock da
    /// fila**.
    ///
    /// A ordem importa: se a sequência fosse atribuída antes de pegar no lock,
    /// duas sessões TCP concorrentes podiam ficar com números 5 e 6 e entrar na
    /// fila pela ordem 6, 5. O `checkpoint` percorre a fila da frente para trás
    /// e pára no primeiro que ultrapassa o cursor — com a ordem trocada,
    /// apagaria a mensagem 6 ao confirmar a 5.
    pub(crate) fn enfileirar(&self, payload: Vec<u8>) {
        let Ok(mut fila) = self.fila.lock() else {
            self.envenenada.store(true, Ordering::Relaxed);
            return;
        };
        let n = self.recebidas.fetch_add(1, Ordering::SeqCst) + 1;
        let agora = agora_micros();
        self.ultimo_micros.store(agora, Ordering::Relaxed);
        fila.empurrar(Observation {
            payload,
            source_sequence: Some(format!("{}:{n}", self.arranque)),
            source_event_id: None,
            observed_at_micros: Some(agora),
        });
    }
}

pub(crate) fn agora_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Recebe syslog em background e entrega por `poll`.
pub struct SyslogAdapter {
    identity: DatasourceIdentity,
    transport: SyslogTransport,
    endereco: SocketAddr,
    recepcao: Arc<Recepcao>,
    /// Quantas observações foram CONFIRMADAS. É uma contagem, não um número de
    /// sequência: `acknowledged` num painel ao lado de `observed` só faz
    /// sentido se as duas contarem a mesma coisa.
    confirmadas: u64,
    /// O cursor do último lote entregue, à espera de confirmação.
    cursor_pendente: Option<String>,
    parar: Arc<AtomicBool>,
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
        let recepcao = Arc::new(Recepcao::nova(limite_bytes));
        let parar = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        let endereco = match transport {
            SyslogTransport::Udp => {
                let socket = UdpSocket::bind(addr)?;
                let endereco = socket.local_addr()?;
                // Sem este timeout o `recv_from` bloqueia para sempre e o
                // `Drop` nunca conseguiria juntar a thread.
                socket.set_read_timeout(Some(std::time::Duration::from_millis(200)))?;
                threads.push(Self::receber_udp(socket, recepcao.clone(), parar.clone()));
                endereco
            }
            SyslogTransport::Tcp => {
                let listener = TcpListener::bind(addr)?;
                let endereco = listener.local_addr()?;
                listener.set_nonblocking(true)?;
                threads.push(Self::aceitar_tcp(listener, recepcao.clone(), parar.clone()));
                endereco
            }
        };

        Ok(Self {
            identity,
            transport,
            endereco,
            recepcao,
            confirmadas: 0,
            cursor_pendente: None,
            parar,
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

    fn receber_udp(
        socket: UdpSocket,
        recepcao: Arc<Recepcao>,
        parar: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_DATAGRAMA];
            while !parar.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((n, _)) if n > 0 => recepcao.enfileirar(buf[..n].to_vec()),
                    Ok(_) => continue,
                    // O timeout é o silêncio normal entre datagramas.
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue
                    }
                    // Um erro a sério NÃO pode ser tratado como timeout: o laço
                    // giraria a 100% de CPU sem ninguém saber. Conta-se e
                    // espera-se, para que a saúde o mostre.
                    Err(_) => {
                        recepcao.erros_de_socket.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        })
    }

    fn aceitar_tcp(
        listener: TcpListener,
        recepcao: Arc<Recepcao>,
        parar: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut sessoes: Vec<std::thread::JoinHandle<()>> = Vec::new();
            while !parar.load(Ordering::Relaxed) {
                // Limpar as sessões já terminadas antes de aceitar: sem isto o
                // vector cresce para sempre num servidor de vida longa, mesmo
                // com poucas ligações simultâneas.
                sessoes.retain(|s| !s.is_finished());

                match listener.accept() {
                    Ok((stream, _)) => {
                        if sessoes.len() >= MAX_SESSOES {
                            recepcao.sessoes_recusadas.fetch_add(1, Ordering::Relaxed);
                            // Fechar já: aceitar e não ler deixaria o emissor a
                            // escrever para um buraco.
                            drop(stream);
                            continue;
                        }
                        // Sem timeout de leitura a sessão bloqueia para sempre
                        // e o `Drop` do adapter nunca a consegue juntar. Se não
                        // se conseguir pôr, mais vale não aceitar a ligação do
                        // que ficar com uma thread presa até ao fim do processo.
                        if preparar_sessao(&stream).is_err() {
                            recepcao.erros_de_socket.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let recepcao = recepcao.clone();
                        let parar_sessao = parar.clone();
                        sessoes.push(std::thread::spawn(move || {
                            sessao_de_linhas(stream, &recepcao, &parar_sessao);
                        }));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => {
                        // `EMFILE` e companhia entram aqui. Sem contador, o
                        // datasource ficava calado sem nada a explicar porquê.
                        recepcao.erros_de_socket.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                }
            }
            for s in sessoes {
                let _ = s.join();
            }
        })
    }
}

/// Lê uma ligação TCP até ela acabar.
///
/// Partilhada com o [`crate::syslog_tls_adapter`] através do genérico: o que
/// muda entre os dois é o que está por baixo do `Read`, não o enquadramento.
pub(crate) fn sessao_de_linhas<R: std::io::Read>(
    fonte: R,
    recepcao: &Recepcao,
    parar: &AtomicBool,
) -> crate::enquadramento::FimDeSessao {
    consumir_linhas(
        fonte,
        MAX_LINHA,
        parar,
        |linha| recepcao.enfileirar(linha),
        || {
            recepcao.linhas_gigantes.fetch_add(1, Ordering::Relaxed);
        },
    )
}

/// Prepara um socket aceite para leitura com timeout.
pub(crate) fn preparar_sessao(stream: &TcpStream) -> Result<(), std::io::Error> {
    stream.set_nonblocking(false)?;
    // O timeout NÃO fecha a ligação — ver `crate::enquadramento`. Serve só para
    // o laço poder ver a bandeira de paragem.
    stream.set_read_timeout(Some(std::time::Duration::from_millis(200)))
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
        let observations = {
            let fila = self.recepcao.fila.lock().map_err(|_| {
                self.recepcao.envenenada.store(true, Ordering::Relaxed);
                AdapterError::InvalidConfig("fila de syslog envenenada por um panico".into())
            })?;
            fila.primeiros(limit)
        };
        if observations.is_empty() {
            self.cursor_pendente = None;
            return Ok(ObservationBatch {
                observations,
                ack: None,
            });
        }
        let cursor = observations
            .last()
            .and_then(|o| o.source_sequence.clone())
            .unwrap_or_default();
        self.cursor_pendente = Some(cursor.clone());
        Ok(ObservationBatch {
            observations,
            ack: Some(SourceAck { cursor }),
        })
    }

    /// Só aqui a fila encolhe (§5.4).
    ///
    /// O cursor tem de ser EXACTAMENTE o do último lote entregue. Aceitar
    /// qualquer cursor "plausível" — como aceitar qualquer número menor ou igual
    /// ao total recebido — apagaria da fila observações que nunca chegaram a ser
    /// entregues a ninguém.
    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
        if self.cursor_pendente.as_deref() != Some(ack.cursor.as_str()) {
            return Err(AdapterError::InvalidAck(format!(
                "cursor {:?} nao corresponde ao ultimo lote entregue ({:?})",
                ack.cursor, self.cursor_pendente
            )));
        }
        let mut fila = self.recepcao.fila.lock().map_err(|_| {
            self.recepcao.envenenada.store(true, Ordering::Relaxed);
            AdapterError::InvalidConfig("fila de syslog envenenada por um panico".into())
        })?;
        // Remove-se por IDENTIDADE e não por comparação numérica: a chave é
        // `<arranque>:<n>` e comparar strings de números daria ordens erradas.
        let mut removidas = 0u64;
        while let Some(frente) = fila.frente() {
            let e_o_ultimo = frente.source_sequence.as_deref() == Some(ack.cursor.as_str());
            fila.remover_frente();
            removidas += 1;
            if e_o_ultimo {
                break;
            }
        }
        self.confirmadas = self.confirmadas.saturating_add(removidas);
        self.cursor_pendente = None;
        Ok(())
    }

    fn health(&self) -> SourceHealthSample {
        let descartadas = self
            .recepcao
            .fila
            .lock()
            .map(|f| f.descartadas())
            .unwrap_or_else(|_| {
                self.recepcao.envenenada.store(true, Ordering::Relaxed);
                0
            });
        let recebidas = self.recepcao.recebidas.load(Ordering::SeqCst);
        let gigantes = self.recepcao.linhas_gigantes.load(Ordering::Relaxed);
        let recusadas = self.recepcao.sessoes_recusadas.load(Ordering::Relaxed);
        let erros = self.recepcao.erros_de_socket.load(Ordering::Relaxed);
        let ultimo = self.recepcao.ultimo_micros.load(Ordering::Relaxed);
        let envenenada = self.recepcao.envenenada.load(Ordering::Relaxed);

        // A ordem desta escada é a ordem pela qual quem opera quer saber das
        // coisas. Uma fila envenenada engole tudo o que chega, por isso vem
        // primeiro; um `Healthy` nesse estado seria uma mentira completa.
        let (state, codigo) = if envenenada {
            (DatasourceState::Degraded, Some("fila_envenenada"))
        } else if erros > 0 {
            (DatasourceState::Degraded, Some("erro_de_socket"))
        } else if descartadas > 0 {
            (DatasourceState::Degraded, Some("buffer_cheio"))
        } else if gigantes > 0 {
            (DatasourceState::Degraded, Some("linha_acima_do_tecto"))
        } else if recusadas > 0 {
            (DatasourceState::Degraded, Some("sessoes_no_tecto"))
        } else if recebidas == 0 {
            (DatasourceState::Starting, None)
        } else {
            (DatasourceState::Healthy, None)
        };

        SourceHealthSample {
            state,
            last_observed_at_micros: (ultimo > 0).then_some(ultimo),
            last_checkpoint: self
                .cursor_pendente
                .is_none()
                .then(|| self.confirmadas.to_string()),
            counters: SourceCounters {
                observed: recebidas,
                acknowledged: self.confirmadas,
                // Tudo o que representa pressão: fila cheia, linhas
                // descartadas, ligações recusadas.
                backpressure_events: descartadas + gigantes + recusadas,
                // `dropped` conta só o que se perdeu DEPOIS de entrar: o que
                // foi recusado à porta nunca chegou a ser uma observação.
                dropped: descartadas + gigantes,
            },
            last_error_code: codigo.map(str::to_owned),
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
        let prazo = std::time::Instant::now() + std::time::Duration::from_secs(15);
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
        assert_eq!(
            adapter.health().counters.acknowledged,
            3,
            "`acknowledged` conta observacoes; nao e um numero de sequencia"
        );
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
        assert_eq!(adapter.health().counters.acknowledged, 2);

        let resto = adapter.poll(1000).unwrap();
        assert_eq!(resto.observations.len(), 2, "as outras duas tem de ficar");
    }

    /// O defeito que a revisao apanhou: um cursor que nenhum `poll` produziu
    /// apagava da fila observacoes que ninguem tinha visto.
    #[test]
    fn um_cursor_que_nenhum_poll_produziu_e_recusado() {
        let mut adapter = ligar("ds-udp3", SyslogTransport::Udp, 1 << 20);
        let destino = adapter.endereco_local();
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..10 {
            cliente.send_to(b"x", destino).unwrap();
        }
        esperar_recebidas(&adapter, 10);

        // Confirmar sem ter feito poll nenhum.
        let arranque = adapter.recepcao.arranque;
        let erro = adapter
            .checkpoint(SourceAck {
                cursor: format!("{arranque}:5"),
            })
            .unwrap_err();
        assert!(matches!(erro, AdapterError::InvalidAck(_)));
        assert_eq!(
            adapter.poll(1000).unwrap().observations.len(),
            10,
            "nada pode ter sido apagado"
        );

        // Um cursor de outro formato tambem nao passa.
        assert!(adapter
            .checkpoint(SourceAck {
                cursor: "abc".into()
            })
            .is_err());

        // E confirmar duas vezes o mesmo lote tambem nao.
        let lote = adapter.poll(1000).unwrap();
        let ack = lote.ack.unwrap();
        adapter.checkpoint(ack.clone()).unwrap();
        assert!(adapter.checkpoint(ack).is_err(), "ja nao ha pendente");
    }

    /// A chave tem de sobreviver a um restart, senao a mensagem numero 7 de
    /// hoje e a numero 7 de amanha deduplicam uma contra a outra.
    #[test]
    fn a_chave_nao_colide_entre_arranques() {
        let mut primeiro = ligar("ds-arranque", SyslogTransport::Udp, 1 << 20);
        let destino = primeiro.endereco_local();
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        cliente.send_to(b"evento", destino).unwrap();
        esperar_recebidas(&primeiro, 1);
        let chave_um = primeiro.poll(1).unwrap().observations[0]
            .source_sequence
            .clone()
            .unwrap();
        drop(primeiro);

        // Um segundo adapter e o que um restart e.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut segundo = ligar("ds-arranque", SyslogTransport::Udp, 1 << 20);
        let cliente2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        cliente2
            .send_to(b"evento", segundo.endereco_local())
            .unwrap();
        esperar_recebidas(&segundo, 1);
        let chave_dois = segundo.poll(1).unwrap().observations[0]
            .source_sequence
            .clone()
            .unwrap();

        assert_ne!(
            chave_um, chave_dois,
            "as duas sao a primeira mensagem do seu processo; as chaves NAO podem ser iguais"
        );
    }

    /// §5.4 — "nunca descarte invisivel". O descarte conta-se, muda o estado e
    /// deixa um codigo de erro.
    #[test]
    fn o_buffer_cheio_descarta_o_mais_antigo_e_conta() {
        // Tecto minusculo para forcar o descarte com poucas mensagens.
        let mut adapter = ligar("ds-udp4", SyslogTransport::Udp, 200);
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
            "20 mensagens com 200 bytes de tecto tinham de descartar"
        );
        assert_eq!(
            saude.state,
            DatasourceState::Degraded,
            "descarte autorizado NAO e o mesmo que saudavel"
        );
        assert_eq!(saude.last_error_code.as_deref(), Some("buffer_cheio"));

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

    /// O defeito mais grave que a revisao apanhou: um emissor de syslog fica
    /// calado entre mensagens, e o timeout de leitura fechava-lhe a ligacao.
    /// Isto derrubava TODOS os emissores reais.
    #[test]
    fn uma_ligacao_tcp_inactiva_nao_e_derrubada() {
        let mut adapter = ligar("ds-tcp-inactiva", SyslogTransport::Tcp, 1 << 20);
        let mut cliente = std::net::TcpStream::connect(adapter.endereco_local()).unwrap();

        cliente.write_all(b"<34>antes\n").unwrap();
        cliente.flush().unwrap();
        esperar_recebidas(&adapter, 1);

        // Muito mais do que o timeout de 200 ms do socket.
        std::thread::sleep(std::time::Duration::from_millis(700));

        // A MESMA ligacao continua a servir.
        cliente.write_all(b"<34>depois\n").unwrap();
        cliente.flush().unwrap();
        esperar_recebidas(&adapter, 2);

        let obs = adapter.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 2);
        assert_eq!(String::from_utf8_lossy(&obs[1].payload), "<34>depois");
    }

    /// Uma linha entregue em pedacos, com pausas maiores que o timeout, nao
    /// pode perder os bytes de antes da pausa.
    #[test]
    fn uma_linha_partida_por_uma_pausa_chega_inteira() {
        let mut adapter = ligar("ds-tcp-parcial", SyslogTransport::Tcp, 1 << 20);
        let mut cliente = std::net::TcpStream::connect(adapter.endereco_local()).unwrap();

        cliente.write_all(b"<34>primeira ").unwrap();
        cliente.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        cliente.write_all(b"metade\n").unwrap();
        cliente.flush().unwrap();
        esperar_recebidas(&adapter, 1);

        let obs = adapter.poll(10).unwrap().observations;
        assert_eq!(
            String::from_utf8_lossy(&obs[0].payload),
            "<34>primeira metade"
        );
    }

    /// Sem tecto por linha, quem se ligar esgota a memoria a partir da rede.
    #[test]
    fn uma_linha_gigante_e_descartada_contada_e_nao_para_a_sessao() {
        let mut adapter = ligar("ds-tcp-gigante", SyslogTransport::Tcp, 1 << 20);
        let mut cliente = std::net::TcpStream::connect(adapter.endereco_local()).unwrap();

        let gigante = vec![b'x'; MAX_LINHA + 1000];
        cliente.write_all(&gigante).unwrap();
        cliente.write_all(b"\n<34>boa\n").unwrap();
        cliente.flush().unwrap();
        esperar_recebidas(&adapter, 1);

        let saude = adapter.health();
        assert!(saude.counters.dropped >= 1, "o descarte tem de ser contado");
        assert_eq!(
            saude.last_error_code.as_deref(),
            Some("linha_acima_do_tecto")
        );

        // A sessao continua viva e a linha seguinte entra inteira.
        let obs = adapter.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 1);
        assert_eq!(String::from_utf8_lossy(&obs[0].payload), "<34>boa");
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

    /// Vale para os DOIS transportes: um bind que falha tem de falhar no
    /// arranque, e nao numa thread que ninguem observa.
    #[test]
    fn um_endereco_ocupado_falha_no_arranque_e_nao_em_silencio() {
        for transporte in [SyslogTransport::Tcp, SyslogTransport::Udp] {
            let primeiro = ligar("ds-ocupado", transporte, 1 << 20);
            let ocupado = primeiro.endereco_local().to_string();
            assert!(
                SyslogAdapter::ligar(identidade("ds-ocupado-2"), transporte, &ocupado, 1 << 20,)
                    .is_err(),
                "{transporte:?}: o segundo bind tinha de falhar"
            );
        }
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
