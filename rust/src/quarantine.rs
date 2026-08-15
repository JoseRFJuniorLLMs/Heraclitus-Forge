//! Quarentena cifrada para observações que ainda não possuem conector/schema.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const KEY_ENV: &str = "FORGE_QUARANTINE_KEY";
const AAD: &[u8] = b"heraclitus-forge-quarantine-v1";

fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(H[(byte >> 4) as usize] as char);
        out.push(H[(byte & 15) as usize] as char);
    }
    out
}

fn unhex(value: &str) -> std::io::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(invalid("hex com comprimento ímpar"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| invalid("hex inválido"))?;
            u8::from_str_radix(text, 16).map_err(|_| invalid("hex inválido"))
        })
        .collect()
}

pub fn key_from_env() -> std::io::Result<[u8; 32]> {
    let value = std::env::var(KEY_ENV).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{KEY_ENV} obrigatório (64 caracteres hex / 32 bytes aleatórios)"),
        )
    })?;
    let raw = unhex(value.trim())?;
    raw.try_into()
        .map_err(|_| invalid(format!("{KEY_ENV} deve ter 32 bytes")))
}

pub struct QuarantineWriter {
    path: PathBuf,
    file: File,
    cipher: XChaCha20Poly1305,
}

impl QuarantineWriter {
    pub fn open(path: impl AsRef<Path>, key: [u8; 32]) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file,
            cipher: XChaCha20Poly1305::new((&key).into()),
        })
    }

    pub fn append(&mut self, source: &str, observation: &str) -> std::io::Result<()> {
        let ts_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "source": source,
            "observation": observation,
            "ts_unix_ms": ts_unix_ms,
        }))?;
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|e| invalid(format!("CSPRNG: {e}")))?;
        let ciphertext = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| invalid("falha cifrando quarentena"))?;
        let envelope = serde_json::json!({
            "v": 1,
            "nonce": hex(&nonce),
            "ciphertext": hex(&ciphertext),
        });
        serde_json::to_writer(&mut self.file, &envelope)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn decrypt_each(
    path: impl AsRef<Path>,
    key: [u8; 32],
    mut consume: impl FnMut(Value) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let cipher = XChaCha20Poly1305::new((&key).into());
    for (index, line) in BufReader::new(File::open(path)?).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Value = serde_json::from_str(&line)
            .map_err(|e| invalid(format!("linha {}: envelope JSON: {e}", index + 1)))?;
        if envelope["v"] != 1 {
            return Err(invalid(format!("linha {}: versão desconhecida", index + 1)));
        }
        let nonce = unhex(envelope["nonce"].as_str().unwrap_or(""))?;
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| invalid(format!("linha {}: nonce inválido", index + 1)))?;
        let ciphertext = unhex(envelope["ciphertext"].as_str().unwrap_or(""))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| invalid(format!("linha {}: autenticação falhou", index + 1)))?;
        let record = serde_json::from_slice(&plaintext)
            .map_err(|e| invalid(format!("linha {}: payload JSON: {e}", index + 1)))?;
        consume(record)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_hides_pii_and_tamper_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quarantine.hq");
        let key = [7u8; 32];
        let mut writer = QuarantineWriter::open(&path, key).unwrap();
        writer
            .append("cliente-1", "matricula=123 source.ip=10.20.30.40")
            .unwrap();
        drop(writer);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("matricula"));
        assert!(!raw.contains("10.20.30.40"));

        let mut records = Vec::new();
        decrypt_each(&path, key, |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(records[0]["source"], "cliente-1");

        let mut envelope: Value = serde_json::from_str(raw.trim()).unwrap();
        let ciphertext = envelope["ciphertext"].as_str().unwrap();
        let replacement = if ciphertext.starts_with('0') {
            "1"
        } else {
            "0"
        };
        envelope["ciphertext"] = format!("{replacement}{}", &ciphertext[1..]).into();
        std::fs::write(&path, format!("{}\n", envelope)).unwrap();
        assert!(decrypt_each(&path, key, |_| Ok(())).is_err());
    }
}
