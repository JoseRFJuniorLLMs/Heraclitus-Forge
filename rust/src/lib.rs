//! Heraclitus — runtime nativo (port Rust do Runner + HeraclitusDB).
//!
//! O Forge (compilacao de conhecimento, Design-Time) permanece em Python, como
//! manda a spec (esteira de IA isolada). Este crate porta APENAS o caminho quente
//! de producao — o Runner (line-rate) e o HeraclitusDB (append-only) — para Rust,
//! lendo os artefatos `.hcx` ja homologados.

pub mod fact;
pub mod db;
pub mod runner;
