//! Validacao do evento canonico.
//!
//! Corre SEMPRE antes de um evento sair do normalizador e esta disponivel a
//! quem construa um evento a mao. Recolhe todos os problemas em vez de parar
//! no primeiro: quem esta a escrever um mapping quer a lista completa.

use crate::error::SchemaError;
use crate::model::{CanonicalSecurityEvent, MAX_SEVERITY, SCHEMA_VERSION};

/// Campos de topo do evento canonico. E esta lista que o `.hcx` pode citar em
/// `required_fields` — um nome fora dela e erro de contrato, nao um pedido
/// silenciosamente ignorado.
pub const FIELDS: &[&str] = &[
    "schema_version",
    "category",
    "event_type",
    "outcome",
    "severity",
    "observed_at_micros",
    "ingested_at_micros",
    "normalized_at_micros",
    "tenant_id",
    "datasource_id",
    "sensor_id",
    "source_sequence",
    "actor",
    "target",
    "source",
    "destination",
    "extensions",
    "provenance",
];

pub fn is_known_field(name: &str) -> bool {
    FIELDS.contains(&name)
}

fn is_lower_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'))
}

/// Verifica que os campos que o `.hcx` declarou obrigatorios estao mesmo
/// preenchidos neste evento.
pub fn validate_required(
    event: &CanonicalSecurityEvent,
    required: &[String],
) -> Result<(), SchemaError> {
    let mut errors = Vec::new();
    for name in required {
        let present = match name.as_str() {
            "schema_version" => !event.schema_version.is_empty(),
            "category" | "severity" | "extensions" | "provenance" => true,
            "event_type" => !event.event_type.is_empty(),
            "outcome" => event.outcome.is_some(),
            "observed_at_micros" => event.observed_at_micros > 0,
            "ingested_at_micros" => event.ingested_at_micros > 0,
            "normalized_at_micros" => event.normalized_at_micros > 0,
            "tenant_id" => !event.tenant_id.is_empty(),
            "datasource_id" => !event.datasource_id.is_empty(),
            "sensor_id" => !event.sensor_id.is_empty(),
            "source_sequence" => event.source_sequence.is_some(),
            "actor" => event.actor.is_some(),
            "target" => event.target.is_some(),
            "source" => event.source.is_some(),
            "destination" => event.destination.is_some(),
            other => {
                errors.push(format!("required_fields cita campo inexistente: {other:?}"));
                continue;
            }
        };
        if !present {
            errors.push(format!("campo declarado obrigatorio esta vazio: {name}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(SchemaError::Invalid(errors))
    }
}

/// Invariantes do proprio modelo, independentes do conector.
pub fn validate(event: &CanonicalSecurityEvent) -> Result<(), SchemaError> {
    let mut errors = Vec::new();

    if event.schema_version != SCHEMA_VERSION {
        errors.push(format!(
            "schema_version {:?} nao e {SCHEMA_VERSION:?}",
            event.schema_version
        ));
    }
    if !is_lower_token(&event.event_type) {
        errors.push(format!(
            "event_type {:?} deve ser minusculo, pontuado e nao vazio",
            event.event_type
        ));
    }
    if event.severity > MAX_SEVERITY {
        errors.push(format!(
            "severity {} acima do maximo {MAX_SEVERITY}",
            event.severity
        ));
    }

    for (name, value) in [
        ("tenant_id", &event.tenant_id),
        ("datasource_id", &event.datasource_id),
        ("sensor_id", &event.sensor_id),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("{name} vazio"));
        }
    }
    if let Some(sequence) = &event.source_sequence {
        if sequence.trim().is_empty() {
            errors.push("source_sequence presente mas vazio".to_owned());
        }
    }

    for (name, value) in [
        ("observed_at_micros", event.observed_at_micros),
        ("ingested_at_micros", event.ingested_at_micros),
        ("normalized_at_micros", event.normalized_at_micros),
    ] {
        if value <= 0 {
            errors.push(format!("{name} tem de ser positivo, e {value}"));
        }
    }
    // Ingestao e normalizacao acontecem no mesmo processo, com o mesmo relogio.
    // Observacao vem do sensor e PODE estar adiantada — isso e clock skew, que
    // o Marco 3 tem de ver, nao um evento invalido.
    if event.normalized_at_micros < event.ingested_at_micros {
        errors.push("normalized_at_micros anterior a ingested_at_micros".to_owned());
    }

    if event.actor.as_ref().is_some_and(|e| e.is_anonymous()) {
        errors.push("actor presente sem id nem name".to_owned());
    }
    if event.target.as_ref().is_some_and(|e| e.is_anonymous()) {
        errors.push("target presente sem id nem name".to_owned());
    }
    if event.source.as_ref().is_some_and(|e| e.is_anonymous()) {
        errors.push("source presente sem address nem hostname".to_owned());
    }
    if event.destination.as_ref().is_some_and(|e| e.is_anonymous()) {
        errors.push("destination presente sem address nem hostname".to_owned());
    }

    for key in event.extensions.keys() {
        match key.split_once('.') {
            Some((namespace, rest))
                if is_lower_token(namespace) && !namespace.contains('.') && !rest.is_empty() => {}
            _ => errors.push(format!(
                "extension {key:?} tem de ser <namespace>.<campo> em minusculas"
            )),
        }
    }

    let provenance = &event.provenance;
    for (name, value) in [
        ("forge_source_id", &provenance.forge_source_id),
        ("connector_id", &provenance.connector_id),
        ("connector_version", &provenance.connector_version),
        ("parser_signature", &provenance.parser_signature),
        ("matched_rule", &provenance.matched_rule),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("provenance.{name} vazio"));
        }
    }
    if provenance.transformation_steps.is_empty() {
        errors.push("provenance.transformation_steps vazio".to_owned());
    }
    if provenance.raw_observation_hash == [0u8; 32] {
        errors.push("provenance.raw_observation_hash nulo".to_owned());
    }
    if provenance.connector_digest == [0u8; 32] {
        errors.push("provenance.connector_digest nulo".to_owned());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(SchemaError::Invalid(errors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CanonicalValue;
    use crate::test_support::sample_event;

    #[test]
    fn sample_event_is_valid() {
        validate(&sample_event()).expect("o exemplo do crate tem de validar");
    }

    #[test]
    fn extension_without_namespace_is_rejected() {
        let mut event = sample_event();
        event
            .extensions
            .insert("sem_namespace".to_owned(), CanonicalValue::Int(1));
        let error = validate(&event).expect_err("recusa");
        assert!(error.to_string().contains("namespace"));
    }

    #[test]
    fn severity_above_scale_is_rejected() {
        let mut event = sample_event();
        event.severity = MAX_SEVERITY + 1;
        assert!(validate(&event).is_err());
    }

    #[test]
    fn anonymous_actor_is_rejected() {
        let mut event = sample_event();
        if let Some(actor) = event.actor.as_mut() {
            actor.id = None;
            actor.name = None;
        }
        let error = validate(&event).expect_err("recusa");
        assert!(error.to_string().contains("actor"));
    }

    #[test]
    fn sensor_ahead_of_ingestion_is_accepted_as_skew() {
        // Nao e evento invalido: e o sinal que o Telemetry Health precisa de ver.
        let mut event = sample_event();
        event.observed_at_micros = event.ingested_at_micros + 5_000_000;
        validate(&event).expect("skew nao invalida o evento");
    }

    #[test]
    fn required_field_that_is_null_fails() {
        let mut event = sample_event();
        event.outcome = None;
        let error = validate_required(&event, &["outcome".to_owned()]).expect_err("recusa");
        assert!(error.to_string().contains("outcome"));
    }

    #[test]
    fn required_field_with_unknown_name_fails() {
        let event = sample_event();
        let error = validate_required(&event, &["campo_inventado".to_owned()]).expect_err("recusa");
        assert!(error.to_string().contains("inexistente"));
    }
}
