//! Quarentena cifrada para observações que ainda não possuem conector/schema.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

pub const KEY_ENV: &str = "FORGE_QUARANTINE_KEY";
const AAD: &[u8] = b"heraclitus-forge-quarantine-v1";

/// Versão do envelope escrita hoje. A v1 (sem `kid`) continua a ser LIDA.
const ENVELOPE_VERSION: u64 = 2;

/// Tecto por linha ao ler. Um registo de quarentena é uma observação, não um
/// ficheiro: 8 MiB já é folgado. Sem isto, `lines()` carrega a linha inteira
/// para memória ANTES de qualquer validação — a mesma classe de problema que o
/// `fbfact.rs` fechou ao limitar a alocação pelos bytes restantes. Importa
/// porque o desenho do CKE prevê enviar a quarentena da borda para a cloud: aí
/// quem lê deixa de ser quem escreveu.
const MAX_LINE_BYTES: u64 = 8 * 1024 * 1024;

/// Impressão digital da chave — os 8 primeiros bytes do BLAKE3 da chave.
///
/// Sem isto, rodar a `FORGE_QUARANTINE_KEY` transforma todos os registos
/// antigos em lixo indistinguível de corrupção: o `decrypt` falha na
/// autenticação e não há forma de saber que a causa foi a chave errada. Com a
/// impressão digital, o erro diz exatamente qual a chave que o registo espera.
/// Não revela nada sobre a chave (é um hash de 64 bits de uma chave de 256).
pub fn key_id(key: &[u8; 32]) -> String {
    hex(&blake3::hash(key).as_bytes()[..8])
}

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
    kid: String,
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
            kid: key_id(&key),
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
            "v": ENVELOPE_VERSION,
            "kid": self.kid,
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
    let expected_kid = key_id(&key);
    let mut reader = BufReader::new(File::open(path)?);
    let mut index = 0usize;
    loop {
        index += 1;
        // Lê no máximo MAX_LINE_BYTES: uma linha gigante (corrompida ou
        // hostil) é rejeitada em vez de alocada.
        let mut line = String::new();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES + 1)
            .read_line(&mut line)?;
        if read == 0 {
            break; // EOF
        }
        if read as u64 > MAX_LINE_BYTES {
            return Err(invalid(format!(
                "linha {index}: excede {MAX_LINE_BYTES} bytes"
            )));
        }
        if line.trim().is_empty() {
            continue;
        }
        let envelope: Value = serde_json::from_str(&line)
            .map_err(|e| invalid(format!("linha {index}: envelope JSON: {e}")))?;
        let version = envelope["v"].as_u64().unwrap_or(0);
        if version == 0 || version > ENVELOPE_VERSION {
            return Err(invalid(format!("linha {index}: versão desconhecida")));
        }
        // v2 traz a impressão digital da chave. Se não bate, o erro diz QUAL a
        // chave em falta — em vez de um "autenticação falhou" que se confunde
        // com adulteração. Envelopes v1 (sem kid) continuam a ser aceites.
        if let Some(kid) = envelope["kid"].as_str() {
            if kid != expected_kid {
                return Err(invalid(format!(
                    "linha {index}: cifrada com a chave {kid}, mas {KEY_ENV} é {expected_kid} \
                     — a chave rodou; use a anterior para ler este registo"
                )));
            }
        }
        let nonce = unhex(envelope["nonce"].as_str().unwrap_or(""))?;
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| invalid(format!("linha {index}: nonce inválido")))?;
        let ciphertext = unhex(envelope["ciphertext"].as_str().unwrap_or(""))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| invalid(format!("linha {index}: autenticação falhou")))?;
        let record = serde_json::from_slice(&plaintext)
            .map_err(|e| invalid(format!("linha {index}: payload JSON: {e}")))?;
        consume(record)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uma chave rodada tem de dar um erro que DIZ que a chave rodou. Antes
    /// disto, o registo antigo falhava na autenticação e era indistinguível de
    /// adulteração — mandava investigar um ataque que não existiu.
    #[test]
    fn rotated_key_says_the_key_rotated_not_that_it_was_tampered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q.hq");
        let old = [1u8; 32];
        let new = [2u8; 32];

        let mut w = QuarantineWriter::open(&path, old).unwrap();
        w.append("cliente-1", "observacao").unwrap();
        drop(w);

        let err = decrypt_each(&path, new, |_| Ok(())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(&key_id(&old)), "o erro tem de nomear a chave do registo: {msg}");
        assert!(msg.contains("rodou"), "o erro tem de dizer que a chave rodou: {msg}");
        // E a chave certa continua a ler.
        let mut n = 0;
        decrypt_each(&path, old, |_| { n += 1; Ok(()) }).unwrap();
        assert_eq!(n, 1);
    }

    /// Envelopes v1 (escritos antes do `kid`) não podem ficar órfãos.
    #[test]
    fn legacy_v1_envelope_without_kid_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.hq");
        let key = [9u8; 32];

        // Escreve v2 e rebaixa o envelope para v1 removendo o kid.
        let mut w = QuarantineWriter::open(&path, key).unwrap();
        w.append("cliente", "obs").unwrap();
        drop(w);
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut env: Value = serde_json::from_str(raw.trim()).unwrap();
        env.as_object_mut().unwrap().remove("kid");
        env["v"] = 1.into();
        std::fs::write(&path, format!("{env}\n")).unwrap();

        let mut n = 0;
        decrypt_each(&path, key, |_| { n += 1; Ok(()) }).unwrap();
        assert_eq!(n, 1, "um envelope v1 legado tem de continuar legível");
    }

    /// Uma linha gigante é REJEITADA, não alocada. O leitor da quarentena
    /// processa entrada que pode vir de outra máquina (desenho do CKE).
    #[test]
    fn oversized_line_is_rejected_not_allocated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.hq");
        let mut line = String::with_capacity(MAX_LINE_BYTES as usize + 16);
        line.push_str("{\"v\":2,\"kid\":\"00\",\"nonce\":\"00\",\"ciphertext\":\"");
        line.push_str(&"a".repeat(MAX_LINE_BYTES as usize));
        line.push_str("\"}\n");
        std::fs::write(&path, line).unwrap();

        let err = decrypt_each(&path, [3u8; 32], |_| Ok(())).unwrap_err();
        assert!(err.to_string().contains("excede"), "erro: {err}");
    }

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
