//! Mappings versionados: a ponte declarativa entre a semantica que um `.hcx`
//! produz e o modelo canonico.
//!
//! Um mapping e conteudo, nao codigo: vive em YAML, tem versao propria e o
//! `.hcx` declara qual usa (`mapping_version`, SPEC-0071 secao 4.4). Ficam
//! embutidos no binario porque o normalizador nao pode depender do disco do
//! centro para saber o que a borda quis dizer.
//!
//! Fail-closed em dois pontos:
//!   * uma chave desconhecida no YAML e erro (`deny_unknown_fields`) — um
//!     mapping com um campo mal escrito seria silenciosamente ignorado;
//!   * uma acao que o mapping nao declara e erro na normalizacao, nao um
//!     evento com categoria adivinhada.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::error::SchemaError;
use crate::model::{EntityKind, Outcome, SecurityCategory, SCHEMA_VERSION};

/// Mappings publicados nesta versao do crate.
const BUILTIN: &[(&str, &str)] = &[
    (
        "postgresql/1.0.0",
        include_str!("../mappings/postgresql-1.0.0.yaml"),
    ),
    (
        "linux-sshd/1.0.0",
        include_str!("../mappings/linux-sshd-1.0.0.yaml"),
    ),
    (
        "nginx-access/1.0.0",
        include_str!("../mappings/nginx-access-1.0.0.yaml"),
    ),
    (
        "windows-security/1.0.0",
        include_str!("../mappings/windows-security-1.0.0.yaml"),
    ),
];

/// De onde sai `observed_at_micros`.
///
/// Hoje o Fato Operacional `1.0` so carrega o instante de INGESTAO
/// (`fact.time.system_timestamp`): o parser extrai o carimbo da linha mas nao
/// o emite. Ate isso mudar, os mappings declaram `ingest_fallback` e o evento
/// diz em `extensions` que o instante observado e uma aproximacao — mentir
/// sobre isso cegaria a deteccao de clock skew do Marco 3.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedAt {
    /// Usa o instante de ingestao e marca a origem como aproximada.
    IngestFallback,
    /// Le o carimbo da propria fonte no caminho indicado do Fato.
    FactField { path: Vec<String> },
}

impl ObservedAt {
    /// Valor de `heraclitus.observed_at_source` no evento emitido.
    pub fn marker(&self) -> &str {
        match self {
            ObservedAt::IngestFallback => "ingest_fallback",
            ObservedAt::FactField { .. } => "source_timestamp",
        }
    }
}

/// Especie das entidades que este conector produz. O formato do Fato e igual
/// para todos os conectores; o que muda e o que o ator e o alvo SAO.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySpec {
    pub actor_kind: EntityKind,
    pub target_kind: EntityKind,
    /// Valores com que o formato da fonte escreve "campo ausente" (o `-` do
    /// log combinado, por exemplo). Tratar um deles como identidade seria
    /// inventar um ator que a fonte nunca observou.
    #[serde(default)]
    pub absent_markers: Vec<String>,
}

impl IdentitySpec {
    pub fn is_absent(&self, value: &str) -> bool {
        self.absent_markers.iter().any(|marker| marker == value)
    }
}

/// Semantica canonica de uma acao do Reasoner.
///
/// O `event_type` e sempre o proprio nome da acao: a taxonomia do Reasoner ja
/// e a taxonomia canonica, e um segundo nome so criaria duas verdades.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionMapping {
    /// `false` diz que a acao nao e um evento de seguranca (ruido operacional
    /// do proprio servico). O Fato Operacional continua a existir; o que nao
    /// existe e um evento canonico — enfiar `log.info` numa categoria de
    /// seguranca seria inventar significado.
    #[serde(default = "security_relevant_by_default")]
    pub security_relevant: bool,
    /// Omissa usa `primary_category` do mapping.
    #[serde(default)]
    pub category: Option<SecurityCategory>,
    /// `null` (ou ausente) significa desfecho DESCONHECIDO, nao "sucesso".
    #[serde(default)]
    pub outcome: Option<Outcome>,
}

fn security_relevant_by_default() -> bool {
    true
}

/// Um mapping versionado completo.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MappingSpec {
    pub mapping_version: String,
    pub security_schema: String,
    /// Conector a que este mapping pertence. Confere com o `manifest.id` do
    /// `.hcx` que produziu o Fato — aplicar o mapping errado e um erro.
    pub connector: String,
    pub primary_category: SecurityCategory,
    pub required_fields: Vec<String>,
    pub observed_at: ObservedAt,
    pub identity: IdentitySpec,
    pub severity_by_risk: BTreeMap<String, u8>,
    pub actions: BTreeMap<String, ActionMapping>,
}

impl MappingSpec {
    /// Semantica declarada para uma acao. Ausente e erro, nunca um default.
    pub fn action(&self, action: &str) -> Result<&ActionMapping, SchemaError> {
        self.actions
            .get(action)
            .ok_or_else(|| SchemaError::UnmappedAction {
                mapping_version: self.mapping_version.clone(),
                action: action.to_owned(),
            })
    }

    pub fn severity_for(&self, risk: &str) -> Result<u8, SchemaError> {
        self.severity_by_risk
            .get(risk)
            .copied()
            .ok_or_else(|| SchemaError::UnknownRisk {
                mapping_version: self.mapping_version.clone(),
                risk: risk.to_owned(),
            })
    }

    /// O `manifest.id` do Forge e `<namespace>.<conector>-v<versao>`. Aceitar
    /// qualquer artefato com qualquer mapping deixaria o evento canonico
    /// dizer, com toda a confianca, a semantica de outro produto.
    pub fn accepts_manifest(&self, manifest_id: &str) -> bool {
        let stem = manifest_id
            .rsplit_once("-v")
            .map_or(manifest_id, |(a, _)| a);
        stem == self.connector || stem.ends_with(&format!(".{}", self.connector))
    }

    fn self_check(&self) -> Result<(), String> {
        if self.security_schema != SCHEMA_VERSION {
            return Err(format!(
                "{}: security_schema {:?} nao e {SCHEMA_VERSION:?}",
                self.mapping_version, self.security_schema
            ));
        }
        if self.severity_by_risk.is_empty() {
            return Err(format!("{}: severity_by_risk vazio", self.mapping_version));
        }
        for severity in self.severity_by_risk.values() {
            if *severity > crate::model::MAX_SEVERITY {
                return Err(format!(
                    "{}: severidade {severity} acima do maximo",
                    self.mapping_version
                ));
            }
        }
        if self.actions.is_empty() {
            return Err(format!("{}: nenhuma acao declarada", self.mapping_version));
        }
        for name in &self.required_fields {
            if !crate::validate::is_known_field(name) {
                return Err(format!(
                    "{}: required_fields refere campo inexistente {name:?}",
                    self.mapping_version
                ));
            }
        }
        Ok(())
    }
}

fn registry() -> &'static BTreeMap<String, MappingSpec> {
    static REGISTRY: OnceLock<BTreeMap<String, MappingSpec>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut out = BTreeMap::new();
        for (version, source) in BUILTIN {
            let spec: MappingSpec = serde_yaml::from_str(source)
                .unwrap_or_else(|error| panic!("mapping {version} invalido: {error}"));
            assert_eq!(
                &spec.mapping_version, version,
                "mapping {version} declara mapping_version {:?}",
                spec.mapping_version
            );
            if let Err(error) = spec.self_check() {
                panic!("mapping {version} inconsistente: {error}");
            }
            out.insert(spec.mapping_version.clone(), spec);
        }
        out
    })
}

/// Mapping publicado com esta versao. Desconhecido e erro.
pub fn mapping(version: &str) -> Result<&'static MappingSpec, SchemaError> {
    registry()
        .get(version)
        .ok_or_else(|| SchemaError::UnknownMapping(version.to_owned()))
}

/// Versoes disponiveis, por ordem.
pub fn versions() -> Vec<&'static str> {
    registry().keys().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_mapping_loads_and_self_checks() {
        let versions = versions();
        assert_eq!(versions.len(), BUILTIN.len());
        for version in versions {
            mapping(version).expect("mapping publicado tem de carregar");
        }
    }

    #[test]
    fn unknown_mapping_version_is_an_error() {
        let error = mapping("inexistente/9.9.9").expect_err("recusa");
        assert!(matches!(error, SchemaError::UnknownMapping(_)));
    }

    #[test]
    fn mapping_only_accepts_its_own_connector() {
        let spec = mapping("postgresql/1.0.0").expect("mapping");
        assert!(spec.accepts_manifest("br.gov.heraclitus.pipelines.postgresql-v1.2.0"));
        assert!(!spec.accepts_manifest("br.gov.heraclitus.pipelines.linux_sshd-v1.1.0"));
        // Sufixo nao basta: `pg_postgresql` nao e `postgresql`.
        assert!(!spec.accepts_manifest("br.gov.heraclitus.pipelines.pg_postgresql-v1.0.0"));
    }

    #[test]
    fn unknown_yaml_key_is_rejected() {
        let source = "mapping_version: x/1.0.0\ninesperado: 1\n";
        let parsed: Result<MappingSpec, _> = serde_yaml::from_str(source);
        assert!(parsed.is_err(), "chave desconhecida tem de falhar");
    }

    #[test]
    fn unmapped_action_is_an_error_not_a_default() {
        let spec = mapping("nginx-access/1.0.0").expect("mapping");
        let error = spec.action("crypto.mining").expect_err("recusa");
        assert!(matches!(error, SchemaError::UnmappedAction { .. }));
    }
}
