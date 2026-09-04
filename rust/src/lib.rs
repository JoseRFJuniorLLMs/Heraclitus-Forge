//! Heraclitus — runtime nativo (port Rust do Runner + FactStore).
//!
//! O Forge (compilacao de conhecimento, Design-Time) permanece em Python, como
//! manda a spec (esteira de IA isolada). Este crate porta APENAS o caminho quente
//! de producao — o Runner (line-rate) e o HeraclitusDB (append-only) — para Rust,
//! lendo os artefatos `.hcx` ja homologados.

pub mod auditd_adapter;
pub mod buffer_fonte;
pub mod crc32c;
pub mod datasource;
pub mod db;
pub mod error;
pub mod fact;
pub mod hcx;
pub mod hfb2;
pub mod hql;
pub mod journald_adapter;
pub mod quarantine;
pub mod raft;
pub mod runner;
pub mod source;
pub mod syslog_adapter;
pub mod syslog_tls_adapter;
pub mod telemetry;
pub mod webhook_adapter;
pub mod wineventlog_adapter;
pub mod wire;
