use anyhow::{Context, Result};
use heraclitus::quarantine::{decrypt_each, key_from_env};
use std::io::Write;
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let path = args.next().map(PathBuf::from);
    if command != "decrypt" || path.is_none() || args.next().is_some() {
        anyhow::bail!("uso: quarantine decrypt <ficheiro.hq>\nA chave vem de FORGE_QUARANTINE_KEY");
    }
    let key = key_from_env().context("carregar chave de quarentena")?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    decrypt_each(path.unwrap(), key, |record| {
        serde_json::to_writer(&mut out, &record)?;
        out.write_all(b"\n")
    })
    .context("decifrar quarentena")?;
    Ok(())
}
