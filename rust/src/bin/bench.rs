//! Benchmark de vazao (EPS) do pipeline Rust — meta da spec: > 50.000 eventos/s.

use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{info, warn};

use heraclitus::db::FactStore;
use heraclitus::runner::ReconstitutiveRunner;

const ARTIFACT_DIR: &str = "../registry/postgresql";

const SAMPLES: &[&str] = &[
    "2026-06-26 01:20:00.001 UTC [14801] LOG:  database system is ready to accept connections",
    "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user \"admin\"",
    "2026-06-26 01:20:06.230 UTC [14803] FATAL:  password authentication failed for user \"bob\"",
    "2026-06-26 01:20:11.500 UTC [14808] admin@prod LOG:  connection authorized: user=admin database=prod",
    "2026-06-26 01:20:12.000 UTC [14808] admin@prod LOG:  statement: SELECT * FROM salaries;",
    "2026-06-26 01:20:13.000 UTC [14809] guest@prod ERROR:  permission denied for table salaries",
];

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--demo") {
        anyhow::bail!("benchmark sintético: uso bench --demo [eventos]");
    }
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(100_000);
    if args.next().is_some() || n == 0 || n > 5_000_000 {
        anyhow::bail!("eventos deve estar entre 1 e 5.000.000");
    }

    let artifact = heraclitus::runner::resolve_latest_artifact(ARTIFACT_DIR)
        .context("nenhum artefato PostgreSQL assinado no registry")?;
    let mut runner = ReconstitutiveRunner::load(&artifact).context("carregar artefato")?;
    info!("Runner carregado. Plano: {}", runner.plan_str());
    info!("Eventos: {n}");

    // --- 1. Runner-only (transform line-rate, sem disco) ---
    let mut ok = 0usize;
    let t0 = Instant::now();
    for i in 0..n {
        if runner
            .process_observation(SAMPLES[i % SAMPLES.len()])
            .is_some()
        {
            ok += 1;
        }
    }
    let dt = t0.elapsed().as_secs_f64();
    let eps = n as f64 / dt;
    info!("[1] Runner-only (parse+reason+behavior)");
    info!(
        "    {ok}/{n} fatos | {:.3}s | {:.0} EPS  ({:.2}x da meta de 50k)",
        dt,
        eps,
        eps / 50_000.0
    );

    // --- 2. Ponta a ponta (process + append durável real) ---
    let temp = tempfile::tempdir().context("criar diretório temporário")?;
    let db_path = temp.path().join("bench.hdb").to_string_lossy().into_owned();
    let mut runner2 = ReconstitutiveRunner::load(&artifact).context("carregar artefato")?;
    let mut db = FactStore::new(&db_path).context("abrir db temporário")?;

    let m = n.min(10_000);
    let t1 = Instant::now();
    for i in 0..m {
        if let Some(mut f) = runner2.process_observation(SAMPLES[i % SAMPLES.len()]) {
            db.write_fact(&mut f).context("falha no append durável")?;
        }
    }
    let dt1 = t1.elapsed().as_secs_f64();
    let eps1 = m as f64 / dt1;
    info!("[2] Ponta a ponta (Runner + FactStore append)");
    info!("    {m} fatos gravados | {:.3}s | {:.0} EPS", dt1, eps1);

    let r = db.verify();
    info!("    verify(): {} (Fatos: {})", r.status, r.facts);

    // --- 3. Zero-copy: ler 'action' do payload fbfact vs parsear JSON ---
    if let Some(sample) = runner2.process_observation(SAMPLES[1]) {
        let fb = heraclitus::fbfact::encode(&sample);
        let js = serde_json::to_vec(&sample).context("to_vec")?;
        let reads = n;
        let t2 = Instant::now();
        let mut a1 = 0usize;
        for _ in 0..reads {
            a1 += heraclitus::fbfact::action(&fb)
                .map(|s| s.len())
                .unwrap_or(0);
        }
        let dt_fb = t2.elapsed().as_secs_f64().max(1e-9);
        let t3 = Instant::now();
        let mut a2 = 0usize;
        for _ in 0..reads {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&js) {
                a2 += v["fact.behavior"]["action"]
                    .as_str()
                    .map(|s| s.len())
                    .unwrap_or(0);
            }
        }
        let dt_js = t3.elapsed().as_secs_f64().max(1e-9);
        info!(
            "[3] Ler campo 'action' ({reads} leituras) — payload fbfact {}B vs JSON {}B",
            fb.len(),
            js.len()
        );
        info!(
            "    fbfact zero-copy: {:.3}s ({:.0}/s)",
            dt_fb,
            reads as f64 / dt_fb
        );
        info!(
            "    JSON parse      : {:.3}s ({:.0}/s)",
            dt_js,
            reads as f64 / dt_js
        );
        info!(
            "    speedup zero-copy: {:.0}x  (chk {a1}/{a2})",
            dt_js / dt_fb
        );
    } else {
        warn!("Falha ao gerar o sample 1 para a etapa de zero-copy.");
    }

    Ok(())
}
