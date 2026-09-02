//! Emissao de Telemetry Health (`heraclitus-telemetry-health/1.0`).
//!
//! O consumidor vive no HeraclitusDB (crate `heraclitus-telemetry-health`), que
//! reconstroi a saude de cada sensor a partir do log imutavel. Este modulo e o
//! lado do PRODUTOR: constroi os envelopes que a borda consegue mesmo observar.
//!
//! Porque e que o contrato esta duplicado
//! -------------------------------------
//! O Forge nao pode depender do crate do HeraclitusDB — sao repositorios
//! separados e a CI de cada um so faz checkout do seu. A alternativa seria o
//! Forge inventar um formato proprio e alguem traduzir a meio, o que e pior:
//! duas semanticas em vez de duas copias da mesma. As `struct`s aqui espelham
//! as de la campo a campo e ha um golden do JSON emitido — se o contrato mudar
//! de um lado, o teste do outro cai.
//!
//! O que NAO se emite, e porque
//! ----------------------------
//! * `SensorClockSkewObserved` — o Fato `1.0` so carrega o instante de
//!   INGESTAO; `observed == ingested` por construcao, portanto o skew mediria
//!   sempre zero. Reportar zero seria afirmar "sem desvio" quando a verdade e
//!   "nao sei". Fica por emitir ate o Fabric emitir o carimbo da fonte.
//! * `ParserFailureObserved` — na borda, uma linha que nenhuma regex casa e
//!   exatamente o que o Forge ja chama Schema Drift. Emitir os dois eventos
//!   contaria o mesmo facto duas vezes.
//! * `TelemetryDropRecorded` — hoje nada e descartado: nao ha buffer limitado.
//!   O tipo existe para quando houver; emiti-lo agora seria ficcao.

use serde::Serialize;

use crate::hfb2::SecurityIdentity;

pub const SCHEMA: &str = "heraclitus-telemetry-health/1.0";

/// Identidade do sensor. Igual, campo a campo, a `SecurityIdentity` — e o mesmo
/// triplo que o registo HFB2 autentica.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct SensorIdentity<'a> {
    pub tenant_id: &'a str,
    pub datasource_id: &'a str,
    pub sensor_id: &'a str,
}

impl<'a> From<&'a SecurityIdentity> for SensorIdentity<'a> {
    fn from(identity: &'a SecurityIdentity) -> Self {
        SensorIdentity {
            tenant_id: &identity.tenant_id,
            datasource_id: &identity.datasource_id,
            sensor_id: &identity.sensor_id,
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    pub schema: &'static str,
    pub identity: SensorIdentity<'a>,
    pub emitted_at_micros: u64,
    pub event: Event,
}

impl<'a> Envelope<'a> {
    pub fn new(identity: &'a SecurityIdentity, emitted_at_micros: i64, event: Event) -> Self {
        Envelope {
            schema: SCHEMA,
            identity: identity.into(),
            // O contrato do consumidor usa `u64`. Um instante negativo seria um
            // relogio antes da epoca; satura em 0 em vez de dar a volta ao tipo.
            emitted_at_micros: emitted_at_micros.max(0) as u64,
            event,
        }
    }

    pub fn to_json(&self) -> Result<String, crate::error::HeraclitusError> {
        serde_json::to_string(self)
            .map_err(|error| crate::error::HeraclitusError::FactEncodingError(error.to_string()))
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", content = "data")]
pub enum Event {
    ExpectationConfigured(ExpectationConfigured),
    SensorHeartbeat(SensorHeartbeat),
    IngestionWindowClosed(Box<IngestionWindowClosed>),
    SchemaDriftObserved(SchemaDriftObserved),
    CheckpointAdvanced(CheckpointAdvanced),
    ConnectorActivated(ConnectorActivated),
    ConnectorRejected(ConnectorRejected),
    HealthEvaluationTick(HealthEvaluationTick),
}

impl Event {
    pub fn event_type(&self) -> &'static str {
        match self {
            Event::ExpectationConfigured(_) => "ExpectationConfigured",
            Event::SensorHeartbeat(_) => "SensorHeartbeat",
            Event::IngestionWindowClosed(_) => "IngestionWindowClosed",
            Event::SchemaDriftObserved(_) => "SchemaDriftObserved",
            Event::CheckpointAdvanced(_) => "CheckpointAdvanced",
            Event::ConnectorActivated(_) => "ConnectorActivated",
            Event::ConnectorRejected(_) => "ConnectorRejected",
            Event::HealthEvaluationTick(_) => "HealthEvaluationTick",
        }
    }
}

/// Estado DESEJADO do datasource (SPEC-0071 secao 5.3). E o que permite ao
/// consumidor distinguir "fonte calada porque morreu" de "fonte calada porque
/// e assim que ela e".
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ExpectationConfigured {
    pub heartbeat_cadence_micros: Option<u64>,
    pub max_lateness_micros: u64,
    pub minimum_events_per_window: Option<u64>,
    /// Fracao de duplicados a partir da qual e tempestade (0..=10000).
    pub duplicate_storm_basis_points: u16,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct SensorHeartbeat {
    pub observed_at_micros: u64,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct IngestionWindowClosed {
    pub window_start_micros: u64,
    pub window_end_micros: u64,
    pub received: u64,
    pub parsed: u64,
    pub normalized: u64,
    pub duplicated: u64,
    pub dropped: u64,
    pub quarantined: u64,
    pub parser_errors: u64,
    pub max_observed_lateness_millis: u64,
    pub connector_digest: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct SchemaDriftObserved {
    pub count: u64,
    pub field: Option<String>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointIntegrity {
    Unknown,
    Verified,
    Divergent,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CheckpointAdvanced {
    pub source_sequence: Option<u64>,
    pub source_watermark: Option<String>,
    pub integrity: CheckpointIntegrity,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ConnectorActivated {
    pub connector_digest: String,
    pub approved: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRejected {
    pub connector_digest: Option<String>,
    pub reason_code: String,
}

/// Avanco explicito do tempo de evento. O consumidor deriva silencio a partir
/// disto e nunca do relogio de parede — e o que torna a reconstrucao `AS OF
/// LSN` identica a avaliacao ao vivo.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct HealthEvaluationTick {
    pub evaluated_at_micros: u64,
}

// ---------------------------------------------------------------------------
// Contadores de janela
// ---------------------------------------------------------------------------

/// Acumula o que aconteceu numa janela de ingestao.
///
/// O consumidor exige `normalized <= parsed <= received`; a contagem tem de
/// respeitar isso por construcao, e nao por sorte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowCounters {
    pub received: u64,
    pub parsed: u64,
    pub normalized: u64,
    pub quarantined: u64,
}

impl WindowCounters {
    /// Uma linha lida da fonte.
    pub fn observed(&mut self) {
        self.received += 1;
    }

    /// A linha virou Fato. `canonical` diz se tambem virou evento canonico.
    pub fn accepted(&mut self, canonical: bool) {
        self.parsed += 1;
        if canonical {
            self.normalized += 1;
        }
    }

    /// A linha nao casou com nenhuma regra e foi para a quarentena cifrada.
    pub fn drifted(&mut self) {
        self.quarantined += 1;
    }

    pub fn is_empty(&self) -> bool {
        *self == WindowCounters::default()
    }

    /// Monta o evento de fecho de janela.
    ///
    /// `max_observed_lateness_millis` e 0 e assim vai ficar enquanto o Fato so
    /// carregar o instante de ingestao: sem carimbo da fonte nao ha atraso
    /// observavel, e inventar um numero seria pior do que reportar zero com
    /// esta nota escrita.
    pub fn close(
        &self,
        window_start_micros: i64,
        window_end_micros: i64,
        connector_digest: String,
    ) -> IngestionWindowClosed {
        IngestionWindowClosed {
            window_start_micros: window_start_micros.max(0) as u64,
            window_end_micros: window_end_micros.max(0) as u64,
            received: self.received,
            parsed: self.parsed,
            normalized: self.normalized,
            // Nada deduplica na borda e nada descarta: nao ha buffer limitado.
            duplicated: 0,
            dropped: 0,
            quarantined: self.quarantined,
            // Na borda, "parser falhou" e "schema mudou" sao a MESMA observacao:
            // a linha nao casou. Contar nos dois campos seria contar duas vezes.
            parser_errors: self.quarantined,
            max_observed_lateness_millis: 0,
            connector_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> SecurityIdentity {
        SecurityIdentity::new("gov.br/orgao-a", "teste://fonte", "forge-teste").unwrap()
    }

    /// Golden do formato de fio. Se o contrato do consumidor mudar, isto cai —
    /// que e exatamente o aviso que se quer, em vez de eventos silenciosamente
    /// rejeitados do outro lado.
    #[test]
    fn the_envelope_matches_the_published_wire_contract() {
        let identity = identity();
        let envelope = Envelope::new(
            &identity,
            1_782_782_405_000_000,
            Event::SensorHeartbeat(SensorHeartbeat {
                observed_at_micros: 1_782_782_405_000_000,
            }),
        );
        assert_eq!(
            envelope.to_json().unwrap(),
            r#"{"schema":"heraclitus-telemetry-health/1.0","identity":{"tenant_id":"gov.br/orgao-a","datasource_id":"teste://fonte","sensor_id":"forge-teste"},"emitted_at_micros":1782782405000000,"event":{"type":"SensorHeartbeat","data":{"observed_at_micros":1782782405000000}}}"#
        );
    }

    #[test]
    fn the_event_enum_is_externally_tagged_as_type_and_data() {
        let identity = identity();
        let envelope = Envelope::new(
            &identity,
            1,
            Event::CheckpointAdvanced(CheckpointAdvanced {
                source_sequence: Some(4096),
                source_watermark: None,
                integrity: CheckpointIntegrity::Verified,
            }),
        );
        let json: serde_json::Value = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();
        assert_eq!(json["event"]["type"], "CheckpointAdvanced");
        assert_eq!(json["event"]["data"]["source_sequence"], 4096);
        assert_eq!(json["event"]["data"]["integrity"], "Verified");
    }

    #[test]
    fn counters_never_break_the_consumer_invariant() {
        // `normalized <= parsed <= received` é validado do outro lado; aqui é
        // garantido por construção.
        let mut counters = WindowCounters::default();
        for index in 0..10 {
            counters.observed();
            if index % 3 == 0 {
                counters.drifted();
            } else {
                counters.accepted(index % 2 == 0);
            }
        }
        let window = counters.close(10, 20, "ab".repeat(32));
        assert!(window.normalized <= window.parsed);
        assert!(window.parsed <= window.received);
        assert_eq!(window.received, 10);
        assert_eq!(window.quarantined, window.parser_errors);
    }

    #[test]
    fn an_empty_window_is_recognisable() {
        assert!(WindowCounters::default().is_empty());
        let mut counters = WindowCounters::default();
        counters.observed();
        assert!(!counters.is_empty());
    }

    #[test]
    fn lateness_is_zero_and_stays_zero_until_the_source_timestamp_exists() {
        let window = WindowCounters::default().close(0, 1, "cd".repeat(32));
        assert_eq!(window.max_observed_lateness_millis, 0);
    }

    #[test]
    fn a_timestamp_before_the_epoch_saturates_instead_of_wrapping() {
        let identity = identity();
        let envelope = Envelope::new(
            &identity,
            -5,
            Event::HealthEvaluationTick(HealthEvaluationTick {
                evaluated_at_micros: 0,
            }),
        );
        assert_eq!(envelope.emitted_at_micros, 0);
    }
}
