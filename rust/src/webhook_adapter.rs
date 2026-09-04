//! SPEC-0071 §5.2 P0 #4 — o adapter `http-webhook`.
//!
//! A §5.2 manda "extrair do `gateway`". O `gateway` já tinha um `POST /ingest`,
//! mas fazia o caminho todo — recebia, parseava e escrevia no `.hdb` no mesmo
//! handler. Um adapter não pode fazer isso: a §5.1 diz que "parsing, persistência
//! HFB2 e emissão de telemetria ficam acima desta fronteira".
//!
//! ## O que este adapter pode prometer e o syslog não
//!
//! Num datagrama UDP não há forma de dizer "espera". Em HTTP há: é o
//! `429 Too Many Requests`. Por isso a §5.4 — "buffer cheio aplica backpressure
//! **ou** spill cifrado; nunca descarte invisível" — aqui cumpre-se pelo ramo
//! bom: **este adapter nunca descarta**. Quando o buffer enche, recusa com 429 e
//! o emissor reenviará. `dropped` fica em zero por construção; o que sobe é
//! `backpressure_events`.
//!
//! Descartar aqui seria inexcusável, porque havia maneira de não o fazer.
//!
//! ## Porquê `202 Accepted` e não `200 OK`
//!
//! Um 200 diria "está feito". Não está: o adapter só pôs a observação no
//! buffer, e a §5.4 é explícita em que o checkpoint só avança depois da
//! persistência. O 202 é a única resposta honesta — aceite, ainda não durável.
//!
//! ## Autenticação não é opcional por omissão
//!
//! Um webhook sem autenticação aceita telemetria de qualquer um, e telemetria
//! falsa é pior do que telemetria nenhuma: envenena as detecções e a auditoria.
//! Por isso não há `token: Option<String>` com `None` por omissão — há
//! [`WebhookAuth`], onde não ter autenticação é a variante
//! [`WebhookAuth::Aberto`], que quem configura tem de escrever com esse nome.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;

use crate::source::{
    AdapterError, DatasourceIdentity, DatasourceState, Observation, ObservationBatch, SourceAck,
    SourceAdapter, SourceCapabilities, SourceCounters, SourceHealthSample,
};

/// Tecto por pedido. Um corpo maior é recusado com `413`.
///
/// Sem tecto, um único POST poderia esgotar a memória do processo antes de o
/// tecto do buffer sequer ser consultado.
pub const MAX_CORPO_BYTES: usize = 8 * 1024 * 1024;

/// Como o webhook autentica quem envia.
#[derive(Clone)]
pub enum WebhookAuth {
    /// `Authorization: Bearer <token>`, comparado em tempo constante.
    Bearer(String),
    /// Sem autenticação. Existe para bancadas de teste e para o caso em que o
    /// órgão termina o TLS mútuo à frente. Tem de ser escrito com este nome:
    /// ninguém abre um webhook ao mundo por distração.
    Aberto,
}

impl std::fmt::Debug for WebhookAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(<oculto>)"),
            Self::Aberto => f.write_str("Aberto"),
        }
    }
}

/// Comparação sem saída antecipada.
///
/// Um `==` de `String` devolve mal na primeira diferença, e a diferença de
/// tempo entre "errou no primeiro byte" e "errou no último" chega para
/// adivinhar um token byte a byte.
fn comparar_constante(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diferenca = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diferenca |= x ^ y;
    }
    diferenca == 0
}

struct Fila {
    itens: VecDeque<Observation>,
    bytes: usize,
    limite_bytes: usize,
    recusadas: u64,
}

struct Partilhado {
    fila: Mutex<Fila>,
    recebidas: AtomicU64,
    ultimo_micros: AtomicU64,
    auth: WebhookAuth,
}

impl Partilhado {
    fn autorizado(&self, headers: &HeaderMap) -> bool {
        match &self.auth {
            WebhookAuth::Aberto => true,
            WebhookAuth::Bearer(esperado) => headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|dado| comparar_constante(dado.as_bytes(), esperado.as_bytes())),
        }
    }
}

fn agora_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// O handler. Não parseia o corpo: guarda-o como veio.
///
/// Interpretar aqui obrigaria o adapter a conhecer o formato de cada emissor, e
/// um adapter que parseia é um adapter que rejeita o que não percebe — telemetria
/// perdida na fronteira, sem ninguém ver.
async fn receber(
    State(partilhado): State<Arc<Partilhado>>,
    headers: HeaderMap,
    corpo: Bytes,
) -> (StatusCode, &'static str) {
    if !partilhado.autorizado(&headers) {
        return (StatusCode::UNAUTHORIZED, "credencial invalida");
    }
    if corpo.is_empty() {
        return (StatusCode::BAD_REQUEST, "corpo vazio");
    }
    if corpo.len() > MAX_CORPO_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "corpo acima do tecto");
    }

    // Cabeçalhos que o emissor PODE dar e que entram na chave de idempotência
    // (§5.4). Nenhum é obrigatório: exigi-los faria o adapter recusar emissores
    // legítimos que não os enviam.
    let event_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let sequencia_do_emissor = headers
        .get("x-sequence")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let mut fila = match partilhado.fila.lock() {
        Ok(f) => f,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "fila indisponivel"),
    };
    let tamanho = corpo.len() + 64;
    if fila.bytes + tamanho > fila.limite_bytes {
        // O ramo bom da §5.4: recusar em vez de descartar. O emissor reenvia.
        fila.recusadas += 1;
        return (StatusCode::TOO_MANY_REQUESTS, "buffer cheio; reenvie");
    }

    let seq = partilhado.recebidas.fetch_add(1, Ordering::SeqCst) + 1;
    partilhado
        .ultimo_micros
        .store(agora_micros(), Ordering::Relaxed);
    let obs = Observation {
        payload: corpo.to_vec(),
        // A sequência do emissor ganha à de recepção quando existe: é ela que
        // sobrevive a um reenvio depois de um 429, e é isso que a torna útil
        // como chave. A de recepção mudaria, e o mesmo evento entraria duas
        // vezes com chaves diferentes.
        source_sequence: Some(sequencia_do_emissor.unwrap_or_else(|| seq.to_string())),
        source_event_id: event_id,
        observed_at_micros: Some(agora_micros()),
    };
    fila.bytes += obs.wire_bytes();
    fila.itens.push_back(obs);

    // 202 e não 200: aceite no buffer, ainda não durável.
    (StatusCode::ACCEPTED, "aceite")
}

/// Recebe telemetria por HTTP e entrega-a por `poll`.
pub struct HttpWebhookAdapter {
    identity: DatasourceIdentity,
    endereco: std::net::SocketAddr,
    partilhado: Arc<Partilhado>,
    confirmadas: u64,
    parar: Arc<AtomicBool>,
    desligar: Option<tokio::sync::oneshot::Sender<()>>,
    servidor: Option<std::thread::JoinHandle<()>>,
}

impl HttpWebhookAdapter {
    /// Liga o webhook.
    ///
    /// O bind é síncrono, feito com um `TcpListener` da biblioteca padrão antes
    /// de a runtime arrancar: um porto ocupado tem de falhar aqui e não numa
    /// tarefa assíncrona que ninguém observa.
    pub fn ligar(
        identity: DatasourceIdentity,
        addr: &str,
        limite_bytes: usize,
        auth: WebhookAuth,
    ) -> Result<Self, AdapterError> {
        identity.validate()?;
        if limite_bytes == 0 {
            return Err(AdapterError::InvalidConfig(
                "buffer_limit_bytes tem de ser > 0".into(),
            ));
        }
        if let WebhookAuth::Bearer(token) = &auth {
            // Um token curto é pior do que nenhum: dá a sensação de estar
            // protegido enquanto se adivinha por força bruta.
            if token.len() < 32 {
                return Err(AdapterError::InvalidConfig(
                    "o token do webhook tem de ter pelo menos 32 caracteres".into(),
                ));
            }
        }

        let ouvinte = std::net::TcpListener::bind(addr)?;
        let endereco = ouvinte.local_addr()?;
        ouvinte.set_nonblocking(true)?;

        let partilhado = Arc::new(Partilhado {
            fila: Mutex::new(Fila {
                itens: VecDeque::new(),
                bytes: 0,
                limite_bytes,
                recusadas: 0,
            }),
            recebidas: AtomicU64::new(0),
            ultimo_micros: AtomicU64::new(0),
            auth,
        });

        let (desligar, receber_desligar) = tokio::sync::oneshot::channel::<()>();
        let estado = partilhado.clone();
        let servidor = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(erro) => {
                    tracing::error!(%erro, "webhook: runtime nao arrancou");
                    return;
                }
            };
            runtime.block_on(async move {
                let ouvinte = match tokio::net::TcpListener::from_std(ouvinte) {
                    Ok(l) => l,
                    Err(erro) => {
                        tracing::error!(%erro, "webhook: ouvinte nao converteu");
                        return;
                    }
                };
                let app = Router::new()
                    .route("/ingest", post(receber))
                    .with_state(estado);
                if let Err(erro) = axum::serve(ouvinte, app)
                    .with_graceful_shutdown(async {
                        let _ = receber_desligar.await;
                    })
                    .await
                {
                    tracing::error!(%erro, "webhook: servidor terminou com erro");
                }
            });
        });

        Ok(Self {
            identity,
            endereco,
            partilhado,
            confirmadas: 0,
            parar: Arc::new(AtomicBool::new(false)),
            desligar: Some(desligar),
            servidor: Some(servidor),
        })
    }

    pub fn endereco_local(&self) -> std::net::SocketAddr {
        self.endereco
    }

    /// A URL a dar ao emissor.
    pub fn url_de_ingestao(&self) -> String {
        format!("http://{}/ingest", self.endereco)
    }
}

impl Drop for HttpWebhookAdapter {
    fn drop(&mut self) {
        self.parar.store(true, Ordering::Relaxed);
        if let Some(desligar) = self.desligar.take() {
            let _ = desligar.send(());
        }
        if let Some(t) = self.servidor.take() {
            let _ = t.join();
        }
    }
}

impl SourceAdapter for HttpWebhookAdapter {
    fn identity(&self) -> &DatasourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            // Pedidos concorrentes chegam em qualquer ordem, e o emissor pode
            // repetir um depois de um 429. Prometer ordem seria falso.
            ordered: false,
            reliable_transport: true,
            source_sequence: true,
            // O corpo pode trazer um timestamp, mas lê-lo é parsing, e parsing
            // é da camada de cima.
            source_timestamp: false,
            backpressure: true,
        }
    }

    /// Entrega sem consumir. Só o `checkpoint` consome (§5.4).
    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
        let fila = self.partilhado.fila.lock().map_err(|_| {
            AdapterError::InvalidConfig("fila do webhook envenenada por um panico".into())
        })?;
        let observations: Vec<Observation> = fila.itens.iter().take(limit).cloned().collect();
        if observations.is_empty() {
            return Ok(ObservationBatch {
                observations,
                ack: None,
            });
        }
        // O cursor é a POSIÇÃO no buffer, não a sequência do emissor: a do
        // emissor é dele, pode repetir-se e pode nem ser numérica.
        Ok(ObservationBatch {
            observations: observations.clone(),
            ack: Some(SourceAck {
                cursor: (self.confirmadas + observations.len() as u64).to_string(),
            }),
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
        let mut fila = self.partilhado.fila.lock().map_err(|_| {
            AdapterError::InvalidConfig("fila do webhook envenenada por um panico".into())
        })?;
        let a_remover = (ate - self.confirmadas) as usize;
        if a_remover > fila.itens.len() {
            return Err(AdapterError::InvalidAck(format!(
                "cursor {ate} confirma {a_remover} observacoes; so ha {} por confirmar",
                fila.itens.len()
            )));
        }
        for _ in 0..a_remover {
            if let Some(obs) = fila.itens.pop_front() {
                fila.bytes -= obs.wire_bytes();
            }
        }
        self.confirmadas = ate;
        Ok(())
    }

    fn health(&self) -> SourceHealthSample {
        let recusadas = self
            .partilhado
            .fila
            .lock()
            .map(|f| f.recusadas)
            .unwrap_or(0);
        let recebidas = self.partilhado.recebidas.load(Ordering::SeqCst);
        let ultimo = self.partilhado.ultimo_micros.load(Ordering::Relaxed);

        // `Degraded` com recusas: o emissor está a levar 429 e alguém tem de
        // saber. Não é `Quarantined` — o datasource está bom, o caudal é que
        // não cabe.
        let state = if recusadas > 0 {
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
                backpressure_events: recusadas,
                // Zero por construção: este adapter recusa, não descarta.
                dropped: 0,
            },
            last_error_code: (recusadas > 0).then(|| "buffer_cheio_429".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn identidade(id: &str) -> DatasourceIdentity {
        DatasourceIdentity {
            tenant_id: "tenant-a".into(),
            datasource_id: id.into(),
            sensor_id: "webhook-1".into(),
        }
    }

    fn ligar(id: &str, limite: usize, auth: WebhookAuth) -> HttpWebhookAdapter {
        HttpWebhookAdapter::ligar(identidade(id), "127.0.0.1:0", limite, auth).expect("bind")
    }

    /// Cliente HTTP/1.1 minimo em TCP puro: nao vale a pena puxar uma
    /// dependencia de cliente so para testar tres pedidos.
    fn postar(
        url_host: std::net::SocketAddr,
        corpo: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
    ) -> u16 {
        use std::io::{Read, Write};
        let mut fluxo = std::net::TcpStream::connect(url_host).expect("connect");
        let mut cabecalhos = String::new();
        if let Some(t) = token {
            cabecalhos.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        for (k, v) in extra {
            cabecalhos.push_str(&format!("{k}: {v}\r\n"));
        }
        let pedido = format!(
            "POST /ingest HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n{cabecalhos}Connection: close\r\n\r\n{corpo}",
            corpo.len()
        );
        fluxo.write_all(pedido.as_bytes()).expect("write");
        fluxo.flush().ok();
        let mut resposta = String::new();
        let _ = fluxo.read_to_string(&mut resposta);
        resposta
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }

    fn esperar_recebidas(a: &HttpWebhookAdapter, quantas: u64) {
        let prazo = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while a.health().counters.observed < quantas {
            assert!(
                std::time::Instant::now() < prazo,
                "so chegaram {} de {quantas}",
                a.health().counters.observed
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn aceita_um_post_autenticado_com_202() {
        let mut adapter = ligar("ds-wh", 1 << 20, WebhookAuth::Bearer(TOKEN.into()));
        let destino = adapter.endereco_local();

        assert_eq!(postar(destino, "linha um", Some(TOKEN), &[]), 202);
        esperar_recebidas(&adapter, 1);

        let lote = adapter.poll(10).unwrap();
        assert_eq!(lote.observations.len(), 1);
        assert_eq!(
            String::from_utf8_lossy(&lote.observations[0].payload),
            "linha um"
        );
        assert!(adapter.url_de_ingestao().ends_with("/ingest"));
    }

    /// 202 e nao 200: aceite no buffer, ainda nao duravel. Um 200 mentiria.
    #[test]
    fn a_resposta_e_202_e_nao_200() {
        let adapter = ligar("ds-wh-202", 1 << 20, WebhookAuth::Aberto);
        assert_eq!(postar(adapter.endereco_local(), "x", None, &[]), 202);
    }

    /// Telemetria falsa e pior do que telemetria nenhuma.
    #[test]
    fn um_post_sem_credencial_e_recusado() {
        let adapter = ligar("ds-wh-auth", 1 << 20, WebhookAuth::Bearer(TOKEN.into()));
        let destino = adapter.endereco_local();
        assert_eq!(postar(destino, "intruso", None, &[]), 401);
        assert_eq!(postar(destino, "intruso", Some("errado"), &[]), 401);
        assert_eq!(
            postar(destino, "intruso", Some(&TOKEN[..31]), &[]),
            401,
            "um prefixo correcto nao vale"
        );
        assert_eq!(adapter.health().counters.observed, 0);
    }

    /// Um token curto da a sensacao de proteccao enquanto se adivinha.
    #[test]
    fn um_token_curto_e_recusado_na_configuracao() {
        let erro = HttpWebhookAdapter::ligar(
            identidade("ds"),
            "127.0.0.1:0",
            1 << 20,
            WebhookAuth::Bearer("curto".into()),
        );
        assert!(erro.is_err());
    }

    /// O ramo BOM da §5.4: com maneira de dizer "espera", nao se descarta.
    #[test]
    fn o_buffer_cheio_recusa_com_429_e_nao_descarta() {
        // Tecto pequeno: o primeiro corpo entra, o segundo ja nao cabe.
        let adapter = ligar("ds-wh-cheio", 200, WebhookAuth::Aberto);
        let destino = adapter.endereco_local();

        assert_eq!(postar(destino, &"a".repeat(100), None, &[]), 202);
        esperar_recebidas(&adapter, 1);
        assert_eq!(postar(destino, &"b".repeat(150), None, &[]), 429);

        let saude = adapter.health();
        assert_eq!(
            saude.counters.dropped, 0,
            "este adapter recusa; nunca descarta"
        );
        assert!(saude.counters.backpressure_events >= 1);
        assert_eq!(saude.state, DatasourceState::Degraded);
        assert_eq!(saude.last_error_code.as_deref(), Some("buffer_cheio_429"));
    }

    #[test]
    fn um_corpo_vazio_e_recusado() {
        let adapter = ligar("ds-wh-vazio", 1 << 20, WebhookAuth::Aberto);
        assert_eq!(postar(adapter.endereco_local(), "", None, &[]), 400);
        assert_eq!(adapter.health().counters.observed, 0);
    }

    /// A sequencia do emissor sobrevive a um reenvio; a de recepcao nao. E por
    /// isso que ela ganha quando existe.
    #[test]
    fn a_sequencia_do_emissor_ganha_a_de_recepcao() {
        let mut adapter = ligar("ds-wh-seq", 1 << 20, WebhookAuth::Aberto);
        let destino = adapter.endereco_local();
        assert_eq!(
            postar(
                destino,
                "evento",
                None,
                &[("X-Sequence", "abc-42"), ("X-Request-Id", "pedido-7")]
            ),
            202
        );
        esperar_recebidas(&adapter, 1);

        let obs = adapter.poll(10).unwrap().observations;
        assert_eq!(obs[0].source_sequence.as_deref(), Some("abc-42"));
        assert_eq!(obs[0].source_event_id.as_deref(), Some("pedido-7"));
    }

    /// Sem cabecalhos, cai-se na sequencia de recepcao — exigi-los faria o
    /// adapter recusar emissores legitimos.
    #[test]
    fn sem_cabecalhos_usa_se_a_sequencia_de_recepcao() {
        let mut adapter = ligar("ds-wh-sem", 1 << 20, WebhookAuth::Aberto);
        let destino = adapter.endereco_local();
        assert_eq!(postar(destino, "um", None, &[]), 202);
        esperar_recebidas(&adapter, 1);
        let obs = adapter.poll(10).unwrap().observations;
        assert_eq!(obs[0].source_sequence.as_deref(), Some("1"));
        assert!(obs[0].source_event_id.is_none());
    }

    #[test]
    fn o_poll_nao_consome_so_o_checkpoint_consome() {
        let mut adapter = ligar("ds-wh-ck", 1 << 20, WebhookAuth::Aberto);
        let destino = adapter.endereco_local();
        for i in 0..3 {
            assert_eq!(postar(destino, &format!("linha {i}"), None, &[]), 202);
        }
        esperar_recebidas(&adapter, 3);

        let primeiro = adapter.poll(10).unwrap();
        assert_eq!(primeiro.observations.len(), 3);
        let segundo = adapter.poll(10).unwrap();
        assert_eq!(segundo.observations, primeiro.observations);

        adapter.checkpoint(segundo.ack.unwrap()).unwrap();
        assert!(adapter.poll(10).unwrap().observations.is_empty());
        assert_eq!(adapter.health().counters.acknowledged, 3);
    }

    #[test]
    fn um_cursor_invalido_e_recusado() {
        let mut adapter = ligar("ds-wh-cursor", 1 << 20, WebhookAuth::Aberto);
        assert!(
            adapter
                .checkpoint(SourceAck { cursor: "5".into() })
                .is_err(),
            "confirmar 5 sem ter recebido nada"
        );
        assert!(adapter
            .checkpoint(SourceAck {
                cursor: "abc".into()
            })
            .is_err());
    }

    #[test]
    fn as_capacidades_nao_prometem_ordem() {
        let a = ligar("ds-wh-caps", 1 << 20, WebhookAuth::Aberto);
        let caps = a.capabilities();
        assert!(
            !caps.ordered,
            "pedidos concorrentes chegam em qualquer ordem"
        );
        assert!(caps.reliable_transport);
        assert!(caps.backpressure);
        assert!(!caps.source_timestamp);
    }

    #[test]
    fn o_token_nao_aparece_no_debug() {
        let auth = WebhookAuth::Bearer(TOKEN.into());
        let impresso = format!("{auth:?}");
        assert!(!impresso.contains(TOKEN), "vazou: {impresso}");
    }

    #[test]
    fn a_comparacao_de_token_nao_sai_mais_cedo() {
        assert!(comparar_constante(b"abc", b"abc"));
        assert!(!comparar_constante(b"abc", b"abd"));
        assert!(!comparar_constante(b"abc", b"ab"));
        assert!(comparar_constante(b"", b""));
    }

    #[test]
    fn um_endereco_ocupado_falha_no_arranque() {
        let primeiro = ligar("ds-wh-ocupado", 1 << 20, WebhookAuth::Aberto);
        let ocupado = primeiro.endereco_local().to_string();
        assert!(HttpWebhookAdapter::ligar(
            identidade("ds-wh-ocupado-2"),
            &ocupado,
            1 << 20,
            WebhookAuth::Aberto,
        )
        .is_err());
    }
}
