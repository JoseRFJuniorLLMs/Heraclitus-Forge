//! `heraclitus-security-schema` — o modelo canonico de evento de seguranca
//! (SPEC-0071, delta 1 / Marco 1).
//!
//! O que este crate E
//! ------------------
//! Tipos, validacao, canonicalizacao e **mappings versionados** que traduzem o
//! que um conector `.hcx` produziu (`operational-fact/1.0`) para uma forma
//! comum a todas as fontes (`heraclitus-security-event/1.0`).
//!
//! O que este crate NAO E
//! ----------------------
//! Nao tem rede, nao tem armazenamento, nao tem IA e nao faz parsing de vendor
//! nenhum. Quem observa e o Forge; quem guarda e o HeraclitusDB. Aqui so se
//! decide o que os campos SIGNIFICAM — e por isso e a unica peca que pode ser
//! auditada isoladamente.
//!
//! Compatibilidade (gate CM2)
//! --------------------------
//! O Fato Operacional `1.0` continua intacto e continua a ser a evidencia. Um
//! `.hcx` que nao declare `security_schema` e um conector legado: produz Fatos
//! validos e nao produz eventos canonicos. Ausencia de declaracao nunca
//! autoriza inventar campos canonicos na leitura.
//!
//! Nao inventar (gate CM3)
//! -----------------------
//! Campo que a fonte nao observou fica `null`. Acao que o mapping nao declara
//! e erro, nao um default. Categoria fora do vocabulario e erro, nao um valor
//! novo. E `observed_at_micros`, enquanto o Fato so carregar o instante de
//! ingestao, vem marcado como aproximacao em
//! `extensions["heraclitus.observed_at_source"]`.
//!
//! ```no_run
//! use heraclitus_security_schema as schema;
//!
//! let mapping = schema::mapping::mapping("linux-sshd/1.0.0")?;
//! let fact = schema::test_support::sshd_fact();
//! let context = schema::test_support::sample_context();
//! let normalized = schema::normalize::from_operational_fact(&fact, mapping, &context)?;
//! if let Some(event) = normalized.event() {
//!     println!("{} {}", event.category, event.event_type);
//! }
//! # Ok::<(), schema::SchemaError>(())
//! ```

pub mod canonical;
pub mod error;
pub mod mapping;
pub mod model;
pub mod normalize;
pub mod test_support;
pub mod validate;

pub use error::SchemaError;
pub use mapping::MappingSpec;
pub use model::{
    CanonicalSecurityEvent, CanonicalValue, EndpointRef, EntityKind, EntityRef,
    NormalizationProvenance, Outcome, SecurityCategory, SCHEMA_VERSION,
};
pub use normalize::{from_operational_fact, NormalizationContext, Normalized};
