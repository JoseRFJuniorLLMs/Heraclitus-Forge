//! O `.proto` e o modelo Rust tem de descrever o MESMO evento.
//!
//! Nao ha geracao de codigo entre os dois, portanto nada os mantem alinhados
//! sozinhos. Este teste le o `.proto` como texto e compara-o com o que o
//! modelo realmente serializa: acrescentar um campo so de um lado parte a
//! build, que e exatamente o que se quer de um contrato publicado.

use std::collections::{BTreeMap, BTreeSet};

use heraclitus_security_schema::model::{EntityKind, Outcome, SecurityCategory};
use heraclitus_security_schema::test_support::sample_event;

const PROTO: &str = include_str!("../schema/security_event.proto");

/// Campos de um bloco, pela ordem em que aparecem: `(nome, numero)`.
type Fields = Vec<(String, u32)>;

#[derive(Default)]
struct Proto {
    /// Caminho do bloco (`CanonicalValue.ValueList` para os aninhados) -> campos.
    messages: BTreeMap<String, Fields>,
    enums: BTreeMap<String, Fields>,
}

impl Proto {
    fn names(&self, message: &str) -> BTreeSet<String> {
        self.messages
            .get(message)
            .unwrap_or_else(|| panic!("mensagem {message} ausente do .proto"))
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Blocos de topo, que sao os unicos que descrevem tipos publicados.
    fn top_level_messages(&self) -> BTreeSet<&str> {
        self.messages
            .keys()
            .filter(|path| !path.contains('.'))
            .map(String::as_str)
            .collect()
    }
}

/// Leitor deliberadamente ingenuo: so lida com o subconjunto de protobuf que
/// este ficheiro usa. `oneof` e transparente — os seus campos partilham o
/// espaco de numeros da mensagem que o contem, tal como manda o protobuf.
fn parse(source: &str) -> Proto {
    let mut proto = Proto::default();
    let mut path: Vec<(String, bool)> = Vec::new();
    let mut pushed: Vec<bool> = Vec::new();

    for raw in source.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if line.ends_with('{') {
            let head = line.trim_end_matches('{').trim();
            let declared = match head.split_whitespace().collect::<Vec<_>>()[..] {
                ["message", name] => Some((name.to_owned(), true)),
                ["enum", name] => Some((name.to_owned(), false)),
                _ => None,
            };
            match declared {
                Some(block) => {
                    path.push(block);
                    pushed.push(true);
                    let (scope, is_message) = scope_of(&path);
                    let bucket = if is_message {
                        &mut proto.messages
                    } else {
                        &mut proto.enums
                    };
                    bucket.entry(scope).or_default();
                }
                None => pushed.push(false),
            }
            continue;
        }
        if line.starts_with('}') {
            if pushed.pop() == Some(true) {
                path.pop();
            }
            continue;
        }
        if !line.ends_with(';') || path.is_empty() {
            continue;
        }
        let Some((left, right)) = line.trim_end_matches(';').split_once('=') else {
            continue;
        };
        let (Some(field), Ok(number)) =
            (left.split_whitespace().last(), right.trim().parse::<u32>())
        else {
            continue;
        };
        let (scope, is_message) = scope_of(&path);
        let bucket = if is_message {
            &mut proto.messages
        } else {
            &mut proto.enums
        };
        bucket
            .entry(scope)
            .or_default()
            .push((field.to_owned(), number));
    }

    assert!(
        path.is_empty() && pushed.is_empty(),
        "chavetas desequilibradas"
    );
    proto
}

fn scope_of(path: &[(String, bool)]) -> (String, bool) {
    let names: Vec<&str> = path.iter().map(|(name, _)| name.as_str()).collect();
    let is_message = path.last().map(|(_, kind)| *kind).unwrap_or(true);
    (names.join("."), is_message)
}

fn json_keys(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("objeto JSON")
        .keys()
        .cloned()
        .collect()
}

/// Nomes de valor de enum em protobuf levam o nome do enum como prefixo.
fn enum_wire_names(values: &Fields, prefix: &str) -> BTreeSet<String> {
    values
        .iter()
        .map(|(value, _)| value.as_str())
        .filter(|value| !value.ends_with("_UNSPECIFIED"))
        .map(|value| {
            value
                .strip_prefix(prefix)
                .unwrap_or_else(|| panic!("{value} devia comecar por {prefix}"))
                .to_lowercase()
        })
        .collect()
}

#[test]
fn message_fields_match_the_serialized_model() {
    let proto = parse(PROTO);
    let json = serde_json::to_value(sample_event()).expect("serializa");

    for (message, actual) in [
        ("CanonicalSecurityEvent", json_keys(&json)),
        ("EntityRef", json_keys(&json["actor"])),
        ("EndpointRef", json_keys(&json["source"])),
        ("NormalizationProvenance", json_keys(&json["provenance"])),
    ] {
        assert_eq!(
            proto.names(message),
            actual,
            "campos de {message} divergem entre .proto e modelo Rust"
        );
    }
}

#[test]
fn every_message_in_the_proto_is_checked_or_deliberately_skipped() {
    // Impede que uma mensagem nova entre no `.proto` sem ninguem a comparar
    // com o modelo. `CanonicalValue` esta fora porque e um `oneof` e o JSON
    // canonico serializa-o sem etiqueta (`untagged`).
    let expected: BTreeSet<&str> = [
        "CanonicalSecurityEvent",
        "CanonicalValue",
        "EndpointRef",
        "EntityRef",
        "NormalizationProvenance",
    ]
    .into_iter()
    .collect();
    assert_eq!(parse(PROTO).top_level_messages(), expected);
}

#[test]
fn enum_values_match_the_closed_vocabularies() {
    let proto = parse(PROTO);

    let categories = enum_wire_names(
        proto.enums.get("SecurityCategory").expect("enum no .proto"),
        "SECURITY_CATEGORY_",
    );
    assert_eq!(
        categories,
        SecurityCategory::ALL
            .iter()
            .map(|category| category.as_str().to_owned())
            .collect::<BTreeSet<_>>()
    );

    let outcomes = enum_wire_names(proto.enums.get("Outcome").expect("enum"), "OUTCOME_");
    assert_eq!(
        outcomes,
        Outcome::ALL
            .iter()
            .map(|outcome| outcome.as_str().to_owned())
            .collect::<BTreeSet<_>>()
    );

    let kinds = enum_wire_names(proto.enums.get("EntityKind").expect("enum"), "ENTITY_KIND_");
    assert_eq!(
        kinds,
        EntityKind::ALL
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn field_numbers_are_unique_within_each_block() {
    // Reutilizar um numero faz um consumidor antigo ler o campo novo como se
    // fosse o velho — corrupcao silenciosa, nao erro.
    let proto = parse(PROTO);
    let blocks = proto.messages.iter().chain(proto.enums.iter());
    let mut checked = 0;
    for (scope, fields) in blocks {
        let mut seen = BTreeSet::new();
        for (name, number) in fields {
            assert!(
                seen.insert(*number),
                "numero de campo {number} repetido em {scope} ({name})"
            );
            checked += 1;
        }
    }
    assert!(checked > 40, "so foram lidos {checked} campos do .proto");
}
