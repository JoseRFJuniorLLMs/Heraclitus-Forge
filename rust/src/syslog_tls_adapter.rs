//! SPEC-0071 §5.2 P0 #3 — `syslog-tls`, com mTLS opcional.
//!
//! O enquadramento é o mesmo do [`crate::syslog_adapter`] em TCP: uma linha por
//! mensagem (RFC 6587, non-transparent framing). O que muda é quem pode falar.
//!
//! ## O que o TLS resolve aqui, e o que não resolve
//!
//! Resolve duas coisas concretas. **Confidencialidade**: o syslog em claro leva
//! nomes de utilizador, caminhos e endereços internos por uma rede onde
//! qualquer um os lê. E, com mTLS, **autenticidade**: sem certificado de
//! cliente assinado pela CA do órgão, o emissor nem chega a enviar uma linha.
//!
//! Não resolve a durabilidade. Um restart continua a perder o que estiver em
//! voo, porque o syslog não tem retenção — ver o cabeçalho do
//! [`crate::syslog_adapter`]. As `capabilities` dizem-no na mesma.
//!
//! ## O mTLS é uma escolha com nome
//!
//! Como no webhook, "sem autenticação de cliente" não é o valor por omissão de
//! um `Option`: é [`AutenticacaoDeCliente::Qualquer`], que quem configura tem
//! de escrever. Um receptor de syslog que aceita qualquer ligação aceita
//! telemetria forjada, e telemetria forjada envenena as detecções.
//!
//! ## Um handshake recusado é um evento operacional
//!
//! Quando um certificado expira num emissor, o sintoma é o datasource ficar
//! calado — e "calado" é indistinguível de "não houve nada a reportar". Por
//! isso os handshakes recusados são CONTADOS e passam o datasource a
//! `Degraded`, com `handshake_recusado` no código de erro.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

use crate::buffer_fonte::FilaLimitada;
use crate::source::{
    AdapterError, DatasourceIdentity, DatasourceState, Observation, ObservationBatch, SourceAck,
    SourceAdapter, SourceCapabilities, SourceCounters, SourceHealthSample,
};

/// Quem pode ligar-se.
#[derive(Debug, Clone)]
pub enum AutenticacaoDeCliente {
    /// mTLS: só emissores com certificado assinado por esta CA (PEM).
    CaObrigatoria(Vec<u8>),
    /// Qualquer cliente. Tem de ser escrito com este nome — ninguém abre um
    /// receptor de syslog ao mundo por distração.
    Qualquer,
}

/// O material criptográfico do servidor.
pub struct MateriaisTls {
    pub cadeia_pem: Vec<u8>,
    pub chave_pem: Vec<u8>,
    pub clientes: AutenticacaoDeCliente,
}

impl std::fmt::Debug for MateriaisTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A chave privada NUNCA aparece num `Debug`. Uma chave que passou por um
        // log deixou de ser privada, e um `Debug` derivado imprimiria os bytes.
        f.debug_struct("MateriaisTls")
            .field("cadeia_pem", &format!("{} bytes", self.cadeia_pem.len()))
            .field("chave_pem", &"<oculta>")
            .field("clientes", &self.clientes)
            .finish()
    }
}

impl MateriaisTls {
    /// Lê o material de ficheiros PEM.
    pub fn de_ficheiros(
        cadeia: impl AsRef<std::path::Path>,
        chave: impl AsRef<std::path::Path>,
        ca_clientes: Option<&std::path::Path>,
    ) -> Result<Self, AdapterError> {
        let clientes = match ca_clientes {
            Some(caminho) => AutenticacaoDeCliente::CaObrigatoria(std::fs::read(caminho)?),
            None => AutenticacaoDeCliente::Qualquer,
        };
        Ok(Self {
            cadeia_pem: std::fs::read(cadeia)?,
            chave_pem: std::fs::read(chave)?,
            clientes,
        })
    }

    fn construir(&self) -> Result<ServerConfig, AdapterError> {
        let mut leitor = std::io::Cursor::new(&self.cadeia_pem);
        let certificados: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut leitor)
            .collect::<Result<_, _>>()
            .map_err(|e| AdapterError::InvalidConfig(format!("cadeia PEM invalida: {e}")))?;
        if certificados.is_empty() {
            return Err(AdapterError::InvalidConfig(
                "a cadeia PEM nao contem certificados".into(),
            ));
        }
        let mut leitor = std::io::Cursor::new(&self.chave_pem);
        let chave: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut leitor)
            .map_err(|e| AdapterError::InvalidConfig(format!("chave PEM invalida: {e}")))?
            .ok_or_else(|| AdapterError::InvalidConfig("a chave PEM esta vazia".into()))?;

        // O provider é indicado explicitamente: com `default-features = false`
        // não há um instalado por omissão, e um `builder()` normal entraria em
        // pânico no arranque em vez de dar erro.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let base = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| AdapterError::InvalidConfig(format!("versoes TLS: {e}")))?;

        let config = match &self.clientes {
            AutenticacaoDeCliente::Qualquer => base.with_no_client_auth(),
            AutenticacaoDeCliente::CaObrigatoria(pem) => {
                let mut leitor = std::io::Cursor::new(pem);
                let mut raizes = rustls::RootCertStore::empty();
                let mut quantas = 0usize;
                for cert in rustls_pemfile::certs(&mut leitor) {
                    let cert = cert.map_err(|e| {
                        AdapterError::InvalidConfig(format!("CA de clientes invalida: {e}"))
                    })?;
                    raizes.add(cert).map_err(|e| {
                        AdapterError::InvalidConfig(format!("CA de clientes recusada: {e}"))
                    })?;
                    quantas += 1;
                }
                if quantas == 0 {
                    // Uma CA vazia aceitaria zero clientes, e o sintoma seria um
                    // datasource permanentemente calado. Falhar aqui diz porquê.
                    return Err(AdapterError::InvalidConfig(
                        "a CA de clientes nao contem certificados".into(),
                    ));
                }
                let verificador = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(raizes),
                    provider,
                )
                .build()
                .map_err(|e| {
                    AdapterError::InvalidConfig(format!("verificador de clientes: {e}"))
                })?;
                base.with_client_cert_verifier(verificador)
            }
        };
        config
            .with_single_cert(certificados, chave)
            .map_err(|e| AdapterError::InvalidConfig(format!("certificado/chave: {e}")))
    }
}

struct Contadores {
    recebidas: AtomicU64,
    handshakes_recusados: AtomicU64,
    ultimo_micros: AtomicU64,
}

/// Distingue "o TLS recusou este cliente" de "a rede caiu".
///
/// A diferença importa porque só a primeira é um evento de segurança. O rustls
/// devolve os seus erros — certificado em falta, de outra CA, expirado — como
/// [`std::io::ErrorKind::InvalidData`], e um alerta fatal recebido a meio como
/// [`std::io::ErrorKind::UnexpectedEof`]. Um `ConnectionAborted` ou
/// `ConnectionReset` é o socket a morrer, o que acontece a emissores legítimos
/// que fecham mal a ligação.
///
/// Contar tudo como recusa faria um emissor desajeitado parecer um intruso, e
/// o alerta que interessa perder-se-ia no meio.
fn e_recusa_de_tls(erro: &std::io::Error) -> bool {
    matches!(
        erro.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
    )
}

/// Recebe syslog sobre TLS.
pub struct SyslogTlsAdapter {
    identity: DatasourceIdentity,
    endereco: SocketAddr,
    exige_certificado_de_cliente: bool,
    fila: Arc<Mutex<FilaLimitada>>,
    contadores: Arc<Contadores>,
    confirmadas: u64,
    parar: Arc<AtomicBool>,
    aceitador: Option<std::thread::JoinHandle<()>>,
}

impl SyslogTlsAdapter {
    pub fn ligar(
        identity: DatasourceIdentity,
        addr: &str,
        limite_bytes: usize,
        materiais: MateriaisTls,
    ) -> Result<Self, AdapterError> {
        identity.validate()?;
        if limite_bytes == 0 {
            return Err(AdapterError::InvalidConfig(
                "buffer_limit_bytes tem de ser > 0".into(),
            ));
        }
        let exige_certificado_de_cliente =
            matches!(materiais.clientes, AutenticacaoDeCliente::CaObrigatoria(_));
        // O material é validado ANTES do bind: um certificado mal formado tem de
        // falhar a configurar o datasource, não na primeira ligação — que pode
        // ser dali a horas, quando já ninguém está a olhar.
        let config = Arc::new(materiais.construir()?);

        let ouvinte = TcpListener::bind(addr)?;
        let endereco = ouvinte.local_addr()?;
        ouvinte.set_nonblocking(true)?;

        let fila = Arc::new(Mutex::new(FilaLimitada::nova(limite_bytes)));
        let contadores = Arc::new(Contadores {
            recebidas: AtomicU64::new(0),
            handshakes_recusados: AtomicU64::new(0),
            ultimo_micros: AtomicU64::new(0),
        });
        let parar = Arc::new(AtomicBool::new(false));

        let aceitador = Self::aceitar(
            ouvinte,
            config,
            fila.clone(),
            contadores.clone(),
            parar.clone(),
        );

        Ok(Self {
            identity,
            endereco,
            exige_certificado_de_cliente,
            fila,
            contadores,
            confirmadas: 0,
            parar,
            aceitador: Some(aceitador),
        })
    }

    pub fn endereco_local(&self) -> SocketAddr {
        self.endereco
    }

    /// Se este receptor exige certificado de cliente (mTLS).
    pub fn exige_certificado_de_cliente(&self) -> bool {
        self.exige_certificado_de_cliente
    }

    fn agora_micros() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }

    fn aceitar(
        ouvinte: TcpListener,
        config: Arc<ServerConfig>,
        fila: Arc<Mutex<FilaLimitada>>,
        contadores: Arc<Contadores>,
        parar: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut sessoes: Vec<std::thread::JoinHandle<()>> = Vec::new();
            while !parar.load(Ordering::Relaxed) {
                match ouvinte.accept() {
                    Ok((tcp, _)) => {
                        let config = config.clone();
                        let fila = fila.clone();
                        let contadores = contadores.clone();
                        let parar_sessao = parar.clone();
                        sessoes.push(std::thread::spawn(move || {
                            let _ = tcp.set_nonblocking(false);
                            let _ =
                                tcp.set_read_timeout(Some(std::time::Duration::from_millis(200)));
                            let conexao = match rustls::ServerConnection::new(config) {
                                Ok(c) => c,
                                Err(erro) => {
                                    tracing::warn!(%erro, "syslog-tls: sessao nao arrancou");
                                    contadores
                                        .handshakes_recusados
                                        .fetch_add(1, Ordering::Relaxed);
                                    return;
                                }
                            };
                            let fluxo = rustls::StreamOwned::new(conexao, tcp);
                            let leitor = BufReader::new(fluxo);
                            let mut linhas = 0u64;
                            for linha in leitor.lines() {
                                if parar_sessao.load(Ordering::Relaxed) {
                                    break;
                                }
                                let linha = match linha {
                                    Ok(l) => l,
                                    Err(erro) => {
                                        // Só uma recusa DE TLS conta como
                                        // handshake recusado. Um socket
                                        // abortado pela rede é outra coisa, e
                                        // contá-lo faria um emissor que fecha
                                        // mal a ligação parecer um intruso.
                                        if linhas == 0 && e_recusa_de_tls(&erro) {
                                            contadores
                                                .handshakes_recusados
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        break;
                                    }
                                };
                                if linha.trim().is_empty() {
                                    continue;
                                }
                                linhas += 1;
                                let seq = contadores.recebidas.fetch_add(1, Ordering::SeqCst) + 1;
                                contadores
                                    .ultimo_micros
                                    .store(Self::agora_micros(), Ordering::Relaxed);
                                if let Ok(mut f) = fila.lock() {
                                    f.empurrar(Observation {
                                        payload: linha.into_bytes(),
                                        source_sequence: Some(seq.to_string()),
                                        source_event_id: None,
                                        observed_at_micros: Some(Self::agora_micros()),
                                    });
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

impl Drop for SyslogTlsAdapter {
    fn drop(&mut self) {
        self.parar.store(true, Ordering::Relaxed);
        if let Some(t) = self.aceitador.take() {
            let _ = t.join();
        }
    }
}

impl SourceAdapter for SyslogTlsAdapter {
    fn identity(&self) -> &DatasourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            // Vários emissores continuam a chegar em qualquer ordem. O TLS
            // garante a ordem DENTRO de uma ligação, não entre ligações.
            ordered: false,
            reliable_transport: true,
            source_sequence: true,
            source_timestamp: false,
            backpressure: true,
        }
    }

    /// Entrega sem consumir; só o `checkpoint` consome (§5.4).
    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
        let fila = self.fila.lock().map_err(|_| {
            AdapterError::InvalidConfig("fila de syslog-tls envenenada por um panico".into())
        })?;
        let observations = fila.primeiros(limit);
        if observations.is_empty() {
            return Ok(ObservationBatch {
                observations,
                ack: None,
            });
        }
        let cursor = observations
            .last()
            .and_then(|o| o.source_sequence.clone())
            .unwrap_or_default();
        Ok(ObservationBatch {
            observations,
            ack: Some(SourceAck { cursor }),
        })
    }

    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
        let ate: u64 = ack.cursor.parse().map_err(|_| {
            AdapterError::InvalidAck(format!("cursor nao numerico: {}", ack.cursor))
        })?;
        if ate < self.confirmadas {
            return Err(AdapterError::InvalidAck(format!(
                "cursor recuou de {} para {ate}",
                self.confirmadas
            )));
        }
        let recebidas = self.contadores.recebidas.load(Ordering::SeqCst);
        if ate > recebidas {
            return Err(AdapterError::InvalidAck(format!(
                "cursor {ate} ultrapassa as {recebidas} observacoes recebidas"
            )));
        }
        let mut fila = self.fila.lock().map_err(|_| {
            AdapterError::InvalidConfig("fila de syslog-tls envenenada por um panico".into())
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
        let recebidas = self.contadores.recebidas.load(Ordering::SeqCst);
        let recusados = self.contadores.handshakes_recusados.load(Ordering::Relaxed);
        let ultimo = self.contadores.ultimo_micros.load(Ordering::Relaxed);

        // Um certificado expirado num emissor manifesta-se como silêncio, e
        // silêncio é indistinguível de "não houve nada a reportar". Por isso o
        // handshake recusado ganha ao descarte na escolha do código de erro:
        // é o que explica o silêncio.
        let (state, codigo) = if recusados > 0 {
            (DatasourceState::Degraded, Some("handshake_recusado"))
        } else if descartadas > 0 {
            (DatasourceState::Degraded, Some("buffer_cheio"))
        } else if recebidas == 0 {
            (DatasourceState::Starting, None)
        } else {
            (DatasourceState::Healthy, None)
        };

        SourceHealthSample {
            state,
            last_observed_at_micros: (ultimo > 0).then_some(ultimo),
            last_checkpoint: (self.confirmadas > 0).then(|| self.confirmadas.to_string()),
            counters: SourceCounters {
                observed: recebidas,
                acknowledged: self.confirmadas,
                backpressure_events: descartadas + recusados,
                dropped: descartadas,
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
            sensor_id: "syslog-tls-1".into(),
        }
    }

    struct Pki {
        ca_pem: String,
        servidor_cadeia: String,
        servidor_chave: String,
        cliente_cadeia: String,
        cliente_chave: String,
        /// Um cliente assinado por OUTRA CA.
        intruso_cadeia: String,
        intruso_chave: String,
    }

    /// Gera tudo em memoria. Uma chave privada em disco, mesmo de teste, acaba
    /// por ser copiada para onde nao devia.
    fn pki() -> Pki {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

        fn ca(nome: &str) -> (rcgen::Certificate, KeyPair) {
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, nome.to_string());
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::CrlSign,
            ];
            let chave = KeyPair::generate().unwrap();
            let cert = params.self_signed(&chave).unwrap();
            (cert, chave)
        }

        fn emitir(
            nomes: Vec<String>,
            emissor: &rcgen::Certificate,
            chave_emissor: &KeyPair,
        ) -> (String, String) {
            let params = CertificateParams::new(nomes).unwrap();
            let chave = KeyPair::generate().unwrap();
            let cert = params.signed_by(&chave, emissor, chave_emissor).unwrap();
            (cert.pem(), chave.serialize_pem())
        }

        let (ca_cert, ca_chave) = ca("CA do orgao");
        let (outra_ca, outra_chave) = ca("CA de outro sitio");
        let (srv_c, srv_k) = emitir(vec!["localhost".into()], &ca_cert, &ca_chave);
        let (cli_c, cli_k) = emitir(vec!["emissor".into()], &ca_cert, &ca_chave);
        let (int_c, int_k) = emitir(vec!["intruso".into()], &outra_ca, &outra_chave);

        Pki {
            ca_pem: ca_cert.pem(),
            servidor_cadeia: srv_c,
            servidor_chave: srv_k,
            cliente_cadeia: cli_c,
            cliente_chave: cli_k,
            intruso_cadeia: int_c,
            intruso_chave: int_k,
        }
    }

    fn materiais(p: &Pki, clientes: AutenticacaoDeCliente) -> MateriaisTls {
        MateriaisTls {
            cadeia_pem: p.servidor_cadeia.clone().into_bytes(),
            chave_pem: p.servidor_chave.clone().into_bytes(),
            clientes,
        }
    }

    /// Cliente TLS que confia na CA do orgao e opcionalmente apresenta o seu
    /// proprio certificado.
    fn cliente_config(p: &Pki, com_certificado: Option<(&str, &str)>) -> rustls::ClientConfig {
        let mut raizes = rustls::RootCertStore::empty();
        let mut leitor = std::io::Cursor::new(p.ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut leitor) {
            raizes.add(cert.unwrap()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let base = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(raizes);
        match com_certificado {
            None => base.with_no_client_auth(),
            Some((cadeia, chave)) => {
                let mut lc = std::io::Cursor::new(cadeia.as_bytes());
                let certs: Vec<CertificateDer<'static>> =
                    rustls_pemfile::certs(&mut lc).map(|c| c.unwrap()).collect();
                let mut lk = std::io::Cursor::new(chave.as_bytes());
                let k = rustls_pemfile::private_key(&mut lk).unwrap().unwrap();
                base.with_client_auth_cert(certs, k).unwrap()
            }
        }
    }

    /// Envia linhas e fecha a ligacao COM EDUCACAO.
    ///
    /// O fecho limpo nao e um detalhe do teste. Se o cliente largar o socket
    /// com bytes por ler no seu buffer de recepcao — os tickets de sessao que o
    /// TLS 1.3 manda a seguir ao handshake, por exemplo — o Windows responde
    /// com RST em vez de FIN, e o RST faz o SO deitar fora o que ainda estava
    /// no buffer de recepcao DO SERVIDOR. As linhas ja tinham chegado a maquina
    /// e desapareciam na mesma.
    ///
    /// Foi exactamente isso que fez estes testes falharem com
    /// `ConnectionAborted` (10053) e zero linhas recebidas.
    fn enviar(
        destino: SocketAddr,
        config: rustls::ClientConfig,
        linhas: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read;

        let servidor = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
        let mut conexao = rustls::ClientConnection::new(Arc::new(config), servidor)?;
        let mut tcp = std::net::TcpStream::connect(destino)?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        {
            let mut fluxo = rustls::Stream::new(&mut conexao, &mut tcp);
            fluxo.write_all(linhas.as_bytes())?;
            fluxo.flush()?;
        }

        // close_notify primeiro: diz ao servidor que o fim do fluxo e
        // deliberado e nao uma ligacao cortada a meio.
        conexao.send_close_notify();
        {
            let mut fluxo = rustls::Stream::new(&mut conexao, &mut tcp);
            let _ = fluxo.flush();
        }
        tcp.shutdown(std::net::Shutdown::Write)?;

        // Drenar ate ao fim antes de largar o socket.
        let mut resto = Vec::new();
        let mut fluxo = rustls::Stream::new(&mut conexao, &mut tcp);
        let _ = fluxo.read_to_end(&mut resto);
        Ok(())
    }

    /// Espera que o servidor registe uma recusa de handshake.
    fn esperar_recusa(a: &SyslogTlsAdapter) {
        let prazo = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while a.health().counters.backpressure_events == 0 {
            assert!(
                std::time::Instant::now() < prazo,
                "o handshake recusado nao foi contado"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn esperar_recebidas(a: &SyslogTlsAdapter, quantas: u64) {
        let prazo = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while a.health().counters.observed < quantas {
            assert!(
                std::time::Instant::now() < prazo,
                "so chegaram {} de {quantas}",
                a.health().counters.observed
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn recebe_linhas_sobre_tls_sem_mtls() {
        let p = pki();
        let mut a = SyslogTlsAdapter::ligar(
            identidade("ds-tls"),
            "127.0.0.1:0",
            1 << 20,
            materiais(&p, AutenticacaoDeCliente::Qualquer),
        )
        .expect("ligar");
        assert!(!a.exige_certificado_de_cliente());

        enviar(
            a.endereco_local(),
            cliente_config(&p, None),
            "<34>primeira\n<34>segunda\n",
        )
        .expect("enviar");
        esperar_recebidas(&a, 2);

        let obs = a.poll(10).unwrap().observations;
        assert_eq!(obs.len(), 2);
        assert_eq!(String::from_utf8_lossy(&obs[0].payload), "<34>primeira");
    }

    /// mTLS a funcionar: o emissor com certificado da CA do orgao passa.
    #[test]
    fn com_mtls_o_cliente_da_ca_do_orgao_e_aceite() {
        let p = pki();
        let mut a = SyslogTlsAdapter::ligar(
            identidade("ds-mtls"),
            "127.0.0.1:0",
            1 << 20,
            materiais(
                &p,
                AutenticacaoDeCliente::CaObrigatoria(p.ca_pem.clone().into_bytes()),
            ),
        )
        .expect("ligar");
        assert!(a.exige_certificado_de_cliente());

        enviar(
            a.endereco_local(),
            cliente_config(&p, Some((&p.cliente_cadeia, &p.cliente_chave))),
            "<34>autenticado\n",
        )
        .expect("o cliente da CA do orgao tem de passar");
        esperar_recebidas(&a, 1);

        let obs = a.poll(10).unwrap().observations;
        assert_eq!(String::from_utf8_lossy(&obs[0].payload), "<34>autenticado");
        assert_eq!(a.health().state, DatasourceState::Healthy);
    }

    /// O ponto do mTLS: telemetria forjada nao entra.
    #[test]
    fn com_mtls_um_cliente_sem_certificado_nao_entrega_nada() {
        let p = pki();
        let a = SyslogTlsAdapter::ligar(
            identidade("ds-mtls-2"),
            "127.0.0.1:0",
            1 << 20,
            materiais(
                &p,
                AutenticacaoDeCliente::CaObrigatoria(p.ca_pem.clone().into_bytes()),
            ),
        )
        .expect("ligar");

        // Sem certificado: o servidor recusa.
        let _ = enviar(
            a.endereco_local(),
            cliente_config(&p, None),
            "<34>forjado\n",
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            a.health().counters.observed,
            0,
            "nenhuma linha pode ter entrado"
        );
    }

    /// Um certificado de OUTRA CA tambem nao serve — senao qualquer CA publica
    /// autorizaria a enviar telemetria ao orgao.
    #[test]
    fn com_mtls_um_cliente_de_outra_ca_e_recusado() {
        let p = pki();
        let a = SyslogTlsAdapter::ligar(
            identidade("ds-mtls-3"),
            "127.0.0.1:0",
            1 << 20,
            materiais(
                &p,
                AutenticacaoDeCliente::CaObrigatoria(p.ca_pem.clone().into_bytes()),
            ),
        )
        .expect("ligar");

        let _ = enviar(
            a.endereco_local(),
            cliente_config(&p, Some((&p.intruso_cadeia, &p.intruso_chave))),
            "<34>intruso\n",
        );
        esperar_recusa(&a);
        assert_eq!(a.health().counters.observed, 0);
        assert_eq!(
            a.health().last_error_code.as_deref(),
            Some("handshake_recusado"),
            "o rustls recusa isto com `UnknownIssuer`, que e InvalidData"
        );
    }

    /// A classificacao em si: so uma recusa DE TLS conta como handshake
    /// recusado. Um socket abortado pela rede acontece a emissores legitimos
    /// que fecham mal a ligacao, e conta-lo faria um desajeitado parecer um
    /// intruso — com o alerta que interessa perdido no meio.
    #[test]
    fn um_socket_abortado_nao_e_uma_recusa_de_tls() {
        use std::io::ErrorKind::*;

        // O que o rustls devolve quando recusa um cliente. Verificado nos
        // testes de mTLS acima: "peer sent no certificates" e
        // "invalid peer certificate: UnknownIssuer" chegam ambos como
        // InvalidData.
        assert!(e_recusa_de_tls(&std::io::Error::new(
            InvalidData,
            "peer sent no certificates"
        )));
        assert!(e_recusa_de_tls(&std::io::Error::new(
            UnexpectedEof,
            "alerta fatal a meio do handshake"
        )));

        // O que a REDE devolve.
        assert!(!e_recusa_de_tls(&std::io::Error::new(
            ConnectionAborted,
            "10053"
        )));
        assert!(!e_recusa_de_tls(&std::io::Error::new(ConnectionReset, "")));
        assert!(!e_recusa_de_tls(&std::io::Error::new(TimedOut, "")));
        assert!(!e_recusa_de_tls(&std::io::Error::new(BrokenPipe, "")));
    }

    /// Um handshake recusado tem de ser VISIVEL: senao o sintoma de um
    /// certificado expirado e o datasource ficar calado, e calado e
    /// indistinguivel de "nao houve nada a reportar".
    #[test]
    fn um_handshake_recusado_e_contado_e_deixa_o_datasource_degraded() {
        let p = pki();
        let a = SyslogTlsAdapter::ligar(
            identidade("ds-mtls-4"),
            "127.0.0.1:0",
            1 << 20,
            materiais(
                &p,
                AutenticacaoDeCliente::CaObrigatoria(p.ca_pem.clone().into_bytes()),
            ),
        )
        .expect("ligar");

        let _ = enviar(a.endereco_local(), cliente_config(&p, None), "<34>x\n");

        let prazo = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while a.health().counters.backpressure_events == 0 {
            assert!(
                std::time::Instant::now() < prazo,
                "o handshake nao foi contado"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let saude = a.health();
        assert_eq!(saude.state, DatasourceState::Degraded);
        assert_eq!(saude.last_error_code.as_deref(), Some("handshake_recusado"));
        assert_eq!(saude.counters.dropped, 0, "nao foi um descarte");
    }

    /// Material mal formado tem de falhar a CONFIGURAR, e nao na primeira
    /// ligacao — que pode ser dali a horas, com ninguem a olhar.
    #[test]
    fn material_criptografico_invalido_falha_no_arranque() {
        let p = pki();

        let mut maus = materiais(&p, AutenticacaoDeCliente::Qualquer);
        maus.cadeia_pem = b"nao e um PEM".to_vec();
        assert!(
            SyslogTlsAdapter::ligar(identidade("ds"), "127.0.0.1:0", 1 << 20, maus).is_err(),
            "cadeia invalida"
        );

        let mut maus = materiais(&p, AutenticacaoDeCliente::Qualquer);
        maus.chave_pem = b"".to_vec();
        assert!(
            SyslogTlsAdapter::ligar(identidade("ds"), "127.0.0.1:0", 1 << 20, maus).is_err(),
            "chave vazia"
        );

        // Uma CA vazia aceitaria zero clientes, e o sintoma seria silencio.
        let maus = materiais(
            &p,
            AutenticacaoDeCliente::CaObrigatoria(b"# so um comentario\n".to_vec()),
        );
        assert!(
            SyslogTlsAdapter::ligar(identidade("ds"), "127.0.0.1:0", 1 << 20, maus).is_err(),
            "CA sem certificados"
        );
    }

    /// A chave privada nunca pode aparecer num log.
    #[test]
    fn a_chave_privada_nao_aparece_no_debug() {
        let p = pki();
        let m = materiais(&p, AutenticacaoDeCliente::Qualquer);
        let impresso = format!("{m:?}");
        assert!(!impresso.contains("PRIVATE KEY"), "vazou: {impresso}");
        assert!(impresso.contains("<oculta>"));
    }

    #[test]
    fn o_poll_nao_consome_so_o_checkpoint_consome() {
        let p = pki();
        let mut a = SyslogTlsAdapter::ligar(
            identidade("ds-tls-ck"),
            "127.0.0.1:0",
            1 << 20,
            materiais(&p, AutenticacaoDeCliente::Qualquer),
        )
        .expect("ligar");
        enviar(
            a.endereco_local(),
            cliente_config(&p, None),
            "<34>a\n<34>b\n<34>c\n",
        )
        .expect("enviar");
        esperar_recebidas(&a, 3);

        let primeiro = a.poll(10).unwrap();
        let segundo = a.poll(10).unwrap();
        assert_eq!(segundo.observations, primeiro.observations);
        a.checkpoint(segundo.ack.unwrap()).unwrap();
        assert!(a.poll(10).unwrap().observations.is_empty());
    }

    #[test]
    fn as_capacidades_nao_prometem_ordem_entre_ligacoes() {
        let p = pki();
        let a = SyslogTlsAdapter::ligar(
            identidade("ds-tls-caps"),
            "127.0.0.1:0",
            1 << 20,
            materiais(&p, AutenticacaoDeCliente::Qualquer),
        )
        .expect("ligar");
        let caps = a.capabilities();
        assert!(
            !caps.ordered,
            "o TLS garante ordem dentro de uma ligacao; nao entre ligacoes"
        );
        assert!(caps.reliable_transport);
        assert!(!caps.source_timestamp);
    }

    #[test]
    fn um_cursor_invalido_e_recusado() {
        let p = pki();
        let mut a = SyslogTlsAdapter::ligar(
            identidade("ds-tls-cursor"),
            "127.0.0.1:0",
            1 << 20,
            materiais(&p, AutenticacaoDeCliente::Qualquer),
        )
        .expect("ligar");
        assert!(a.checkpoint(SourceAck { cursor: "5".into() }).is_err());
        assert!(a
            .checkpoint(SourceAck {
                cursor: "abc".into()
            })
            .is_err());
    }
}
