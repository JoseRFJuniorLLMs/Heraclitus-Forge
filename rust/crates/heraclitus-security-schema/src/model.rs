//! Tipos do `heraclitus-security-event/1.0` (SPEC-0071 secoes 4.2 e 4.3).
//!
//! O modelo e deliberadamente pobre em tipos "livres": categoria, desfecho e
//! especie de entidade sao enumeracoes fechadas. Um vendor novo acrescenta
//! campos em `extensions`, com namespace, e nunca inventa uma categoria nova
//! em runtime.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Versao do contrato canonico. Viaja dentro do evento: um consumidor que leia
/// um evento de outra versao recusa-o em vez de adivinhar a semantica.
pub const SCHEMA_VERSION: &str = "heraclitus-security-event/1.0";

/// Namespace reservado ao proprio Heraclitus dentro de `extensions`.
/// Mappings de vendor NAO o podem usar (ver `validate`).
pub const RESERVED_EXTENSION_NAMESPACE: &str = "heraclitus";

/// Severidade maxima da escala canonica (0..=10).
pub const MAX_SEVERITY: u8 = 10;

macro_rules! closed_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $( $variant ),+
        }

        impl $name {
            /// Vocabulario completo, na ordem em que a SPEC o declara.
            pub const ALL: &[$name] = &[ $( $name::$variant ),+ ];

            /// Nome de fio. Tem de coincidir com o que o serde escreve — ha um
            /// teste que o prova, para que `.proto`, YAML e JSON nao divirjam.
            pub const fn as_str(&self) -> &str {
                match self { $( $name::$variant => $wire ),+ }
            }

            /// Converte um nome de fio. Desconhecido devolve `None`: uma
            /// categoria que nao existe e erro de mapping, nao um valor novo.
            pub fn parse(value: &str) -> Option<Self> {
                match value { $( $wire => Some($name::$variant), )+ _ => None }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

closed_enum! {
    /// Categorias v1 (SPEC-0071 secao 4.2).
    SecurityCategory {
        Authentication => "authentication",
        Network => "network",
        Dns => "dns",
        Http => "http",
        Process => "process",
        File => "file",
        Registry => "registry",
        Endpoint => "endpoint",
        Cloud => "cloud",
        Identity => "identity",
        ThreatIntel => "threat_intel",
        Vulnerability => "vulnerability",
        Email => "email",
        DataAccess => "data_access",
        Privilege => "privilege",
        Alert => "alert",
        Finding => "finding",
        Incident => "incident",
    }
}

closed_enum! {
    /// Desfecho observado. Nao ha variante `unknown` de proposito: quando a
    /// fonte nao diz o desfecho, o campo fica `null` (gate CM3 — nao inventar).
    Outcome {
        Success => "success",
        Failure => "failure",
    }
}

closed_enum! {
    /// Especie da entidade referida. Fechada pela mesma razao que a categoria.
    EntityKind {
        User => "user",
        Account => "account",
        Group => "group",
        Service => "service",
        Host => "host",
        Process => "process",
        Resource => "resource",
    }
}

/// Ator ou alvo. Tudo e opcional menos a especie: quando a borda so conhece o
/// nome, o `id` fica `null` em vez de ser preenchido com o nome.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EntityRef {
    pub kind: EntityKind,
    pub id: Option<String>,
    pub name: Option<String>,
    pub domain: Option<String>,
}

impl EntityRef {
    /// Uma referencia sem `id` e sem `name` nao identifica nada — emiti-la
    /// seria fabricar a existencia de uma entidade.
    pub fn is_anonymous(&self) -> bool {
        self.id.is_none() && self.name.is_none()
    }
}

/// Ponta de rede. `port` e `hostname` ficam `null` enquanto nenhum adapter os
/// observar; o modelo nao os deriva do endereco.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EndpointRef {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub hostname: Option<String>,
}

impl EndpointRef {
    pub fn is_anonymous(&self) -> bool {
        self.address.is_none() && self.hostname.is_none()
    }
}

/// Valor admissivel em `extensions`.
///
/// Nao ha ponto flutuante de proposito: o evento canonico e comparado byte a
/// byte (gate CM0) e a representacao textual de um `f64` varia entre
/// serializadores. Um campo fracionario entra como texto ou como inteiro na
/// unidade base (microssegundos, bytes, centesimos).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum CanonicalValue {
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<CanonicalValue>),
}

impl From<&str> for CanonicalValue {
    fn from(value: &str) -> Self {
        CanonicalValue::Text(value.to_owned())
    }
}

impl From<String> for CanonicalValue {
    fn from(value: String) -> Self {
        CanonicalValue::Text(value)
    }
}

impl From<i64> for CanonicalValue {
    fn from(value: i64) -> Self {
        CanonicalValue::Int(value)
    }
}

impl From<bool> for CanonicalValue {
    fn from(value: bool) -> Self {
        CanonicalValue::Bool(value)
    }
}

/// Proveniencia obrigatoria (SPEC-0071 secao 4.3).
///
/// O raw nao viaja para o centro. Estes campos sao o que permite voltar a ele:
/// `forge_source_id` + `forge_lsn` localizam o registo no `.hdb` da borda e
/// `raw_observation_hash` prova que a evidencia encontrada la e a mesma.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NormalizationProvenance {
    pub forge_source_id: String,
    pub forge_lsn: u64,
    pub source_event_id: Option<String>,
    #[serde(with = "hash32")]
    pub raw_observation_hash: [u8; 32],
    pub connector_id: String,
    pub connector_version: String,
    #[serde(with = "hash32")]
    pub connector_digest: [u8; 32],
    pub parser_signature: String,
    pub matched_rule: String,
    pub transformation_steps: Vec<String>,
}

/// Evento canonico de seguranca (SPEC-0071 secao 4.2).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CanonicalSecurityEvent {
    pub schema_version: String,
    pub category: SecurityCategory,
    pub event_type: String,
    pub outcome: Option<Outcome>,
    pub severity: u8,

    pub observed_at_micros: i64,
    pub ingested_at_micros: i64,
    pub normalized_at_micros: i64,

    pub tenant_id: String,
    pub datasource_id: String,
    pub sensor_id: String,
    pub source_sequence: Option<String>,

    pub actor: Option<EntityRef>,
    pub target: Option<EntityRef>,
    pub source: Option<EndpointRef>,
    pub destination: Option<EndpointRef>,

    pub extensions: BTreeMap<String, CanonicalValue>,
    pub provenance: NormalizationProvenance,
}

/// Hash de 32 bytes serializado em hexadecimal minusculo.
pub mod hash32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn to_hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Aceita `<64 hex>` ou `<algoritmo>:<64 hex>` — o Forge escreve o hash da
    /// observacao como `b3:<hex>`. Prefixo diferente do esperado e recusado:
    /// dois hashes de algoritmos diferentes nao sao comparaveis.
    pub fn from_hex(value: &str, expected_prefix: Option<&str>) -> Result<[u8; 32], String> {
        let hex = match value.split_once(':') {
            Some((prefix, rest)) => match expected_prefix {
                Some(expected) if prefix == expected => rest,
                Some(expected) => {
                    return Err(format!(
                        "algoritmo de hash inesperado: {prefix:?}; esperado {expected:?}"
                    ))
                }
                None => {
                    return Err(format!(
                        "hash nao devia ter prefixo de algoritmo: {value:?}"
                    ))
                }
            },
            None => value,
        };
        if hex.len() != 64 {
            return Err(format!(
                "hash deve ter 64 digitos hexadecimais, tem {}",
                hex.len()
            ));
        }
        let mut out = [0u8; 32];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| format!("hash com digito nao hexadecimal: {hex:?}"))?;
        }
        Ok(out)
    }

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&to_hex(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        from_hex(&text, None).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_match_serde_names() {
        for category in SecurityCategory::ALL {
            let json = serde_json::to_string(category).expect("serializa");
            assert_eq!(json, format!("\"{}\"", category.as_str()));
            assert_eq!(SecurityCategory::parse(category.as_str()), Some(*category));
        }
        for kind in EntityKind::ALL {
            assert_eq!(
                serde_json::to_string(kind).expect("serializa"),
                format!("\"{}\"", kind.as_str())
            );
        }
        for outcome in Outcome::ALL {
            assert_eq!(
                serde_json::to_string(outcome).expect("serializa"),
                format!("\"{}\"", outcome.as_str())
            );
        }
    }

    #[test]
    fn v1_declares_exactly_eighteen_categories() {
        // A lista e contrato publicado; cresce-la sem versionar o schema
        // partiria consumidores que ja fazem exaustividade sobre ela.
        assert_eq!(SecurityCategory::ALL.len(), 18);
    }

    #[test]
    fn unknown_category_is_rejected_not_invented() {
        assert_eq!(SecurityCategory::parse("ransomware"), None);
    }

    #[test]
    fn blake3_prefixed_hash_round_trips() {
        let hex = "a".repeat(64);
        let bytes = hash32::from_hex(&format!("b3:{hex}"), Some("b3")).expect("hash valido");
        assert_eq!(hash32::to_hex(&bytes), hex);
    }

    #[test]
    fn hash_with_wrong_algorithm_is_rejected() {
        let hex = "a".repeat(64);
        let error = hash32::from_hex(&format!("sha256:{hex}"), Some("b3")).expect_err("recusa");
        assert!(error.contains("algoritmo"));
    }
}
