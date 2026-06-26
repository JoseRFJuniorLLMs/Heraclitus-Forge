//! Benchmark de vazao (EPS) do pipeline Rust — meta da spec: > 50.000 eventos/s.

use std::fs;
use std::io::{BufWriter, Write};
use std::time::Instant;

use heraclitus::db::HeraclitusDB;
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT: &str = "../registry/postgresql.hcx";
const DB_PATH: &str = "bench_rs.hdb";

const SAMPLES: &[&str] = &[
    "2026-06-26 01:20:00.001 UTC [14801] LOG:  database system is ready to accept connections",
    "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"bob\"",
    "2026-06-26 01:20:11.500 UTC [14808] admin@prod LOG:  connection authorized: user=admin database=prod",
    "2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
];

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);

    let mut runner = ReconstitutiveRunner::load(ARTIFACT).expect("carregar artefato");
    println!("Runner carregado. Plano: {}", runner.plan_str());
    println!("Eventos: {n}\n");

    // --- 1. Runner-only (transform line-rate, sem disco) ---
    let mut ok = 0usize;
    let t0 = Instant::now();
    for i in 0..n {
        if runner.process_observation(SAMPLES[i % SAMPLES.len()]).is_some() {
            ok += 1;
        }
    }
    let dt = t0.elapsed().as_secs_f64();
    let eps = n as f64 / dt;
    println!("[1] Runner-only (parse+reason+behavior)");
    println!("    {ok}/{n} fatos | {:.3}s | {:.0} EPS  ({:.2}x da meta de 50k)\n", dt, eps, eps / 50_000.0);

    // --- 2. Ponta a ponta (process + serialize + append bufferizado) ---
    let _ = fs::remove_file(DB_PATH);
    let _ = fs::remove_file(format!("{DB_PATH}.anchor"));
    let mut runner2 = ReconstitutiveRunner::load(ARTIFACT).expect("carregar artefato");
    let mut db = HeraclitusDB::new(DB_PATH).expect("abrir db");

    let m = n.min(200_000);
    let file = fs::OpenOptions::new().append(true).open(DB_PATH).unwrap();
    let mut w = BufWriter::new(file);
    let t1 = Instant::now();
    for i in 0..m {
        let mut f = runner2.process_observation(SAMPLES[i % SAMPLES.len()]).unwrap();
        let block = db.build_block(&mut f);
        w.write_all(&block).unwrap();
    }
    w.flush().unwrap();
    fs::write(format!("{DB_PATH}.anchor"), &db.trusted_root).unwrap();
    let dt1 = t1.elapsed().as_secs_f64();
    let eps1 = m as f64 / dt1;
    println!("[2] Ponta a ponta (Runner + HeraclitusDB append)");
    println!("    {m} fatos gravados | {:.3}s | {:.0} EPS", dt1, eps1);

    let r = db.verify();
    println!("    verify(): {} (Fatos: {})", r.status, r.facts);

    // --- 3. Zero-copy: ler 'action' do payload fbfact vs parsear JSON ---
    let sample = runner2.process_observation(SAMPLES[1]).unwrap();
    let fb = heraclitus::fbfact::encode(&sample);
    let js = serde_json::to_vec(&sample).unwrap();
    let reads = n;
    let t2 = Instant::now();
    let mut a1 = 0usize;
    for _ in 0..reads {
        a1 += heraclitus::fbfact::action(&fb).map(|s| s.len()).unwrap_or(0);
    }
    let dt_fb = t2.elapsed().as_secs_f64().max(1e-9);
    let t3 = Instant::now();
    let mut a2 = 0usize;
    for _ in 0..reads {
        let v: serde_json::Value = serde_json::from_slice(&js).unwrap();
        a2 += v["fact.behavior"]["action"].as_str().map(|s| s.len()).unwrap_or(0);
    }
    let dt_js = t3.elapsed().as_secs_f64().max(1e-9);
    println!("\n[3] Ler campo 'action' ({reads} leituras) — payload fbfact {}B vs JSON {}B", fb.len(), js.len());
    println!("    fbfact zero-copy: {:.3}s ({:.0}/s)", dt_fb, reads as f64 / dt_fb);
    println!("    JSON parse      : {:.3}s ({:.0}/s)", dt_js, reads as f64 / dt_js);
    println!("    speedup zero-copy: {:.0}x  (chk {a1}/{a2})", dt_js / dt_fb);

    let _ = fs::remove_file(DB_PATH);
    let _ = fs::remove_file(format!("{DB_PATH}.anchor"));
}
