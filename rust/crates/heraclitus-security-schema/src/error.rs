//! Erros do modelo canonico. Todos fecham a porta: nenhum deles tem uma
//! variante "continua sem o campo".

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchemaError {
    #[error("campo obrigatorio ausente no Fato Operacional: {0}")]
    MissingField(String),

    #[error("campo invalido {field}: {reason}")]
    InvalidField { field: String, reason: String },

    #[error("mapping {mapping_version} nao declara a acao {action:?}")]
    UnmappedAction {
        mapping_version: String,
        action: String,
    },

    #[error("mapping {mapping_version} nao declara severidade para o risco {risk:?}")]
    UnknownRisk {
        mapping_version: String,
        risk: String,
    },

    #[error("mapping {mapping_version} e do conector {expected:?}, mas o Fato veio de {found:?}")]
    ConnectorMismatch {
        mapping_version: String,
        expected: String,
        found: String,
    },

    #[error("mapping desconhecido: {0}")]
    UnknownMapping(String),

    #[error("evento canonico invalido: {}", .0.join("; "))]
    Invalid(Vec<String>),
}
