//! Forge coverage — valida um artefato `.hcx` contra o RUNNER REAL de produção.
//!
//! Chamado pelo `forge_compiler.py` (Design-Time) para calcular a taxa de Coverage
//! sem reimplementar o runner em Python: roda a `test_matrix.json` do artefato pelo
//! mesmo motor que executa em produção.
//!
//!   coverage <artifact_dir>        # lê <artifact_dir>/test_matrix.json
//!   -> imprime em stdout:  "<covered> <total>"

use std::fs;

use heraclitus::runner::ReconstitutiveRunner;
use serde_json::Value;

fn main() {
    let art = std::env::args().nth(1).unwrap_or_default();
    if art.is_empty() {
        eprintln!("uso: coverage <artifact_dir>");
        std::process::exit(2);
    }

    let mut runner = match ReconstitutiveRunner::load(&art) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("falha ao carregar artefato: {e}");
            std::process::exit(2);
        }
    };

    let tm: Value = fs::read_to_string(format!("{art}/test_matrix.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    let cases = tm.get("cases").and_then(|c| c.as_array()).cloned().unwrap_or_default();

    let mut covered = 0usize;
    for c in &cases {
        let input = c.get("input").and_then(|v| v.as_str()).unwrap_or("");
        let expect = c.get("expect_action").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(f) = runner.process_observation(input) {
            if f["fact.behavior"]["action"].as_str() == Some(expect) {
                covered += 1;
            }
        }
    }
    println!("{covered} {}", cases.len());
}
