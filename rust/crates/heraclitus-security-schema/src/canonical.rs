//! Forma canonica: a representacao que se compara, se assina e se guarda.
//!
//! O gate CM0 exige que a mesma observacao, com o mesmo digest de conector,
//! produza os mesmos campos canonicos. Comparar `struct`s prova isso em Rust;
//! comparar BYTES prova isso tambem para quem esta do outro lado de um fio.
//! Por isso a forma canonica e estavel por construcao:
//!
//!   * a ordem dos campos e a ordem de declaracao do `struct` (o serde_json
//!     nao reordena);
//!   * `extensions` e um `BTreeMap`, logo sai ordenado por chave;
//!   * nao ha ponto flutuante no modelo (ver `CanonicalValue`);
//!   * ausencia e `null` explicito, nao omissao — um consumidor distingue
//!     "desconhecido" de "campo que este produtor nao escreve".

use sha2::{Digest, Sha256};

use crate::model::CanonicalSecurityEvent;

/// JSON canonico, compacto e sem espacos.
pub fn canonical_json(event: &CanonicalSecurityEvent) -> String {
    // O modelo so tem tipos serializaveis; falhar aqui seria um bug de tipos,
    // nao um dado invalido.
    serde_json::to_string(event).expect("evento canonico e serializavel")
}

pub fn canonical_bytes(event: &CanonicalSecurityEvent) -> Vec<u8> {
    canonical_json(event).into_bytes()
}

/// SHA-256 da forma canonica — identidade de conteudo do evento.
pub fn canonical_digest(event: &CanonicalSecurityEvent) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(canonical_bytes(event));
    hash.finalize().into()
}

pub fn canonical_digest_hex(event: &CanonicalSecurityEvent) -> String {
    crate::model::hash32::to_hex(&canonical_digest(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CanonicalValue;
    use crate::test_support::sample_event;

    #[test]
    fn canonical_form_is_stable_across_calls() {
        let event = sample_event();
        assert_eq!(canonical_bytes(&event), canonical_bytes(&event));
        assert_eq!(canonical_digest(&event), canonical_digest(&event));
    }

    #[test]
    fn extension_insertion_order_does_not_change_the_digest() {
        let mut first = sample_event();
        first.extensions.clear();
        first
            .extensions
            .insert("heraclitus.a".to_owned(), CanonicalValue::Int(1));
        first
            .extensions
            .insert("heraclitus.b".to_owned(), CanonicalValue::Int(2));

        let mut second = sample_event();
        second.extensions.clear();
        second
            .extensions
            .insert("heraclitus.b".to_owned(), CanonicalValue::Int(2));
        second
            .extensions
            .insert("heraclitus.a".to_owned(), CanonicalValue::Int(1));

        assert_eq!(canonical_digest(&first), canonical_digest(&second));
    }

    #[test]
    fn unknown_outcome_is_written_as_null_not_omitted() {
        let mut event = sample_event();
        event.outcome = None;
        assert!(canonical_json(&event).contains("\"outcome\":null"));
    }

    #[test]
    fn canonical_form_round_trips() {
        let event = sample_event();
        let decoded: CanonicalSecurityEvent =
            serde_json::from_str(&canonical_json(&event)).expect("desserializa");
        assert_eq!(decoded, event);
    }

    #[test]
    fn field_order_is_the_declared_order_and_is_pinned() {
        // A forma canonica e a ordem de declaracao do `struct`, nao a ordem
        // alfabetica: quem reimplementar isto noutra linguagem precisa da
        // sequencia exata, e um campo movido tem de aparecer como mudanca.
        let json = canonical_json(&sample_event());
        let keys: Vec<&str> = json
            .match_indices("\":")
            .filter_map(|(index, _)| json[..index].rsplit_once('"').map(|(_, key)| key))
            .collect();
        assert_eq!(
            &keys[..18],
            &[
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
                "kind",
                "id",
                "name",
                "domain",
                "target",
            ]
        );
    }

    #[test]
    fn a_single_changed_field_changes_the_digest() {
        let event = sample_event();
        let mut tampered = event.clone();
        tampered.severity += 1;
        assert_ne!(canonical_digest(&event), canonical_digest(&tampered));
    }
}
