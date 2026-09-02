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

    let identity = heraclitus::hfb2::SecurityIdentity::demo("bench");
    let m = n.min(10_000);
    let t1 = Instant::now();
    for i in 0..m {
        if let Some(mut f) = runner2.process_observation(SAMPLES[i % SAMPLES.len()]) {
            identity.apply(&mut f);
            db.write_fact(&mut f).context("falha no append durável")?;
        }
    }
    let dt1 = t1.elapsed().as_secs_f64();
    let eps1 = m as f64 / dt1;
    info!("[2] Ponta a ponta (Runner + FactStore append)");
    info!("    {m} fatos gravados | {:.3}s | {:.0} EPS", dt1, eps1);

    let r = db.verify();
    info!("    verify(): {} (Fatos: {})", r.status, r.facts);

    // --- 3. Codec HFB2: encode, decode, folha e leitura zero-copy ---------
    if let Some(mut sample) = runner2.process_observation(SAMPLES[1]) {
        identity.apply(&mut sample);
        let record = heraclitus::hfb2::encode_fact(&sample, 1).context("encode HFB2")?;
        let js = serde_json::to_vec(&sample).context("to_vec")?;
        let reads = n;

        let t2 = Instant::now();
        let mut acc = 0usize;
        for _ in 0..reads {
            let view = heraclitus::hfb2::RecordView::parse(&record).context("parse")?;
            acc += heraclitus::hfb2::core_action(view.core)
                .map(str::len)
                .unwrap_or(0);
        }
        let dt_fb = t2.elapsed().as_secs_f64().max(1e-9);

        let t3 = Instant::now();
        let mut acc_json = 0usize;
        for _ in 0..reads {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&js) {
                acc_json += v["fact.behavior"]["action"]
                    .as_str()
                    .map(str::len)
                    .unwrap_or(0);
            }
        }
        let dt_js = t3.elapsed().as_secs_f64().max(1e-9);

        info!(
            "[3] Ler 'action' ({reads} leituras) — registo HFB2 {}B vs JSON {}B",
            record.len(),
            js.len()
        );
        info!(
            "    HFB2 validar+ler: {:.3}s ({:.0}/s)",
            dt_fb,
            reads as f64 / dt_fb
        );
        info!(
            "    JSON parse      : {:.3}s ({:.0}/s)",
            dt_js,
            reads as f64 / dt_js
        );
        info!("    speedup: {:.0}x  (chk {acc}/{acc_json})", dt_js / dt_fb);

        // --- 4. Custo de cada etapa do formato -----------------------------
        let ops = n.min(200_000);
        let t_enc = Instant::now();
        for i in 0..ops {
            let bytes = heraclitus::hfb2::encode_fact(&sample, i as u64).context("encode")?;
            std::hint::black_box(bytes.len());
        }
        let dt_enc = t_enc.elapsed().as_secs_f64().max(1e-9);

        let t_dec = Instant::now();
        for _ in 0..ops {
            std::hint::black_box(heraclitus::hfb2::decode_fact(&record).context("decode")?);
        }
        let dt_dec = t_dec.elapsed().as_secs_f64().max(1e-9);

        let t_leaf = Instant::now();
        for _ in 0..ops {
            std::hint::black_box(heraclitus::hfb2::record_leaf(&record).context("leaf")?);
        }
        let dt_leaf = t_leaf.elapsed().as_secs_f64().max(1e-9);

        // Passagem de extensao DESCONHECIDA: o custo de preservar o que nao se
        // entende. Se isto fosse caro, alguem seria tentado a descartar.
        let mut opaque = sample.clone();
        opaque["fact.extensions"] = serde_json::json!([
            {"tag": "0xffff0001", "value_hex": "de".repeat(64)}
        ]);
        let opaque_record = heraclitus::hfb2::encode_fact(&opaque, 1).context("encode opaco")?;
        let t_opaque = Instant::now();
        for _ in 0..ops {
            let decoded = heraclitus::hfb2::decode_fact(&opaque_record).context("decode opaco")?;
            std::hint::black_box(heraclitus::hfb2::encode_fact(&decoded, 1).context("reencode")?);
        }
        let dt_opaque = t_opaque.elapsed().as_secs_f64().max(1e-9);

        info!("[4] Custo do formato ({ops} operacoes)");
        for (nome, dt) in [
            ("encode      ", dt_enc),
            ("decode      ", dt_dec),
            ("folha BLAKE3", dt_leaf),
            ("round-trip de extensao desconhecida", dt_opaque),
        ] {
            info!("    {nome}: {:.3}s ({:.0}/s)", dt, ops as f64 / dt);
        }

        // --- 5. verify() sobre o banco inteiro -----------------------------
        let t_verify = Instant::now();
        let verified = db.verify();
        let dt_verify = t_verify.elapsed().as_secs_f64().max(1e-9);
        info!(
            "[5] verify() {} Fatos: {:.3}s ({:.0} Fatos/s) — {}",
            verified.facts,
            dt_verify,
            verified.facts as f64 / dt_verify,
            verified.status
        );
    } else {
        warn!("Falha ao gerar o sample 1 para a etapa de zero-copy.");
    }

    Ok(())
}
