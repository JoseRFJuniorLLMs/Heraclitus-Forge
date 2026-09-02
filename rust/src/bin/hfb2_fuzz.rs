//! `hfb2_fuzz` — harness de fuzzing do descodificador HFB2.
//!
//! O parser HFB2 le bytes que vieram de um disco que pode estar corrompido ou
//! de um par que pode ser hostil. A premissa e entrada adversarial: nenhum
//! comprimento forjado pode causar panico, alocacao descontrolada ou leitura
//! fora dos limites.
//!
//! Este binario compila em Rust **estavel** e nao precisa de `cargo-fuzz` nem
//! de nightly, o que significa que corre onde o projeto ja corre. Serve dois
//! usos:
//!
//! ```text
//! hfb2_fuzz --sweep 2000000        # varredura determinista e reprodutivel
//! hfb2_fuzz corpus/*.bin           # um ficheiro por caso (AFL, libFuzzer, manual)
//! ```
//!
//! Um panico aqui e uma falha: o processo morre com o caso que o causou no
//! stderr. Para ligar a um fuzzer com cobertura (libFuzzer/AFL), aponte-o a
//! `run_once` — a funcao e deliberadamente uma so, sem estado global.

use std::process::ExitCode;

use heraclitus::hfb2::{self, RecordView};

/// Um caso: tudo o que o parser expoe a bytes nao confiaveis.
fn run_once(bytes: &[u8]) {
    if let Ok(view) = RecordView::parse(bytes) {
        // Estrutura aceite: a folha tem de ser calculavel e os acessores
        // zero-copy tem de andar dentro dos limites do core.
        let _ = view.leaf();
        let _ = hfb2::core_action(view.core);
        let _ = hfb2::core_target_id(view.core);
        let _ = hfb2::OperationalFactCore::parse(view.core);
    }
    let _ = hfb2::decode_fact(bytes);
    let _ = hfb2::describe(bytes);
}

/// Gerador determinista. Um fuzz reprodutivel vale mais do que um aleatorio
/// que ninguem consegue repetir depois de falhar.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 33) as usize % n.max(1)
    }
}

/// Registo valido de partida — as mutacoes interessantes sao as que partem de
/// algo que quase passa, nao de ruido puro.
fn seed_record() -> Vec<u8> {
    let fact = serde_json::json!({
        "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
        "fact.datasource": {
            "tenant_id": "gov.br/orgao-a",
            "datasource_id": "fuzz://seed",
            "sensor_id": "forge-fuzz"
        },
        "fact.identity": {"actor.id":"a","actor.name":"a","target.id":"t","source.ip":"10.0.0.1"},
        "fact.time": {"system_timestamp": 1_782_467_794_979_937i64},
        "fact.behavior": {"class":"c","action":"authentication.failure","risk_level":"High"},
        "fact.evidence": {
            "raw_observation_hash": "b3:9611cd00aabbccddeeff00112233445566778899aabbccddeeff001122334455",
            "carimbo_tempo_legal": "icp"
        },
        "fact.lineage": {"transformation_steps":["parse","normalize"],"input_source":"pg","matched_rule":"r"},
        "fact.confidence": 0.9,
        "fact.knowledge_version":"k@1","fact.reasoning_version":"r","fact.ontology_version":"v9",
        "fact.extensions": [{"tag": "0xffff0001", "value_hex": "deadbeef"}]
    });
    hfb2::encode_fact(&fact, 7).expect("a semente tem de ser valida")
}

fn mutate(seed: &[u8], rng: &mut Lcg) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    match rng.below(6) {
        0 => {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << rng.below(8);
        }
        1 => bytes.truncate(rng.below(bytes.len())),
        2 => {
            // Comprimento forjado: o caso que mais interessa.
            let at = rng.below(bytes.len());
            if at + 4 <= bytes.len() {
                bytes[at..at + 4].copy_from_slice(&(rng.next() as u32).to_be_bytes());
            }
        }
        3 => {
            let extra = rng.below(256);
            let byte = rng.next() as u8;
            bytes.extend(std::iter::repeat_n(byte, extra));
        }
        4 => {
            // Troca dois blocos de bytes de sitio (quebra ordem canonica).
            let len = bytes.len();
            let (a, b) = (rng.below(len), rng.below(len));
            bytes.swap(a, b);
        }
        _ => {
            let at = rng.below(bytes.len());
            bytes[at] = rng.next() as u8;
        }
    }
    bytes
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        eprintln!(
            "uso: hfb2_fuzz --sweep [iteracoes]   varredura determinista\n\
             uso: hfb2_fuzz <ficheiro>...         um caso por ficheiro"
        );
        return ExitCode::from(2);
    }

    if args[0] == "--sweep" {
        let iterations: u64 = args
            .get(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000_000);
        let seed = seed_record();
        let mut rng = Lcg(0x5EED_1234_ABCD_0001);
        let mut accepted = 0u64;
        for _ in 0..iterations {
            let case = mutate(&seed, &mut rng);
            if RecordView::parse(&case).is_ok() {
                accepted += 1;
            }
            run_once(&case);
        }
        // Casos puramente aleatorios: garante que o parser tambem aguenta
        // entrada que nao se parece nada com um registo.
        for size in [0usize, 1, 71, 72, 84, 512, 4096] {
            for _ in 0..(iterations / 100).max(100) {
                let case: Vec<u8> = (0..size).map(|_| rng.next() as u8).collect();
                run_once(&case);
            }
        }
        println!(
            "{iterations} mutacoes sem panico; {accepted} continuaram estruturalmente validas"
        );
        return ExitCode::SUCCESS;
    }

    for path in &args {
        match std::fs::read(path) {
            Ok(bytes) => {
                run_once(&bytes);
                println!("{path}: {} bytes processados sem panico", bytes.len());
            }
            Err(error) => {
                eprintln!("{path}: {error}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}
