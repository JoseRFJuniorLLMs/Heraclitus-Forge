//! Verificacao fail-closed dos artefatos de conhecimento `.hcx`.
//!
//! O formato e deliberadamente identico ao produzido por `forge_sign.py`:
//! SHA-256 canonico `hcx-v3`, seguido de assinatura Ed25519 contra uma chave
//! publica fixada pela organizacao. Nenhum YAML deve ser interpretado antes
//! desta verificacao terminar com sucesso.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::HeraclitusError;

const FORMAT: &str = "hcx-v3";
const SIGNATURE_FILE: &str = "signature.sig";
const TRUST_ROOT_ENV: &str = "HERACLITUS_PUBLISHER_PUB";

fn artifact_error(message: impl Into<String>) -> HeraclitusError {
    HeraclitusError::ArtifactError(message.into())
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, HeraclitusError> {
    if !value.len().is_multiple_of(2) {
        return Err(artifact_error(format!(
            "{field} hexadecimal tem tamanho impar"
        )));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| artifact_error(format!("{field} hexadecimal invalido")))
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), HeraclitusError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(artifact_error(format!(
                "links simbolicos nao sao permitidos em .hcx: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_files(root, &path, files)?;
        } else if file_type.is_file()
            && path.file_name().and_then(|name| name.to_str()) != Some(SIGNATURE_FILE)
        {
            path.strip_prefix(root)
                .map_err(|_| artifact_error("ficheiro fora da raiz do artefato"))?;
            files.push(path);
        }
    }
    Ok(())
}

fn canonical_file_bytes(path: &Path) -> Result<Vec<u8>, HeraclitusError> {
    let bytes = fs::read(path)?;
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text.replace("\r\n", "\n").replace('\r', "\n").into_bytes()),
        Err(error) => Ok(error.into_bytes()),
    }
}

/// Calcula o digest canonico coberto por `forge_sign.py`.
pub fn artifact_digest(root: &Path) -> Result<[u8; 32], HeraclitusError> {
    if !root.is_dir() {
        return Err(artifact_error(format!(
            "artefato nao e um diretorio: {}",
            root.display()
        )));
    }

    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by_key(|path| {
        path.strip_prefix(root)
            .expect("ficheiros foram validados por collect_files")
            .to_string_lossy()
            .replace('\\', "/")
    });
    if files.is_empty() {
        return Err(artifact_error("artefato vazio"));
    }

    let mut hash = Sha256::new();
    hash.update(FORMAT.as_bytes());
    hash.update(b"\n");
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| artifact_error("ficheiro fora da raiz do artefato"))?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = canonical_file_bytes(&path)?;
        hash.update(relative.as_bytes());
        hash.update(b"\0");
        hash.update(bytes.len().to_string().as_bytes());
        hash.update(b"\0");
        hash.update(&bytes);
    }
    Ok(hash.finalize().into())
}

fn parse_signature(path: &Path) -> Result<BTreeMap<String, String>, HeraclitusError> {
    let raw = fs::read_to_string(path)
        .map_err(|_| artifact_error(format!("assinatura ausente: {}", path.display())))?;
    if raw.trim().starts_with("ed25519:sig:") {
        return Err(artifact_error(
            "selo legado nao e uma assinatura criptografica valida",
        ));
    }

    let mut fields = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| artifact_error("linha invalida em signature.sig"))?;
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(artifact_error(format!(
                "campo duplicado em signature.sig: {key}"
            )));
        }
    }
    Ok(fields)
}

/// Resolve a trust root explicita ou o `publisher.pub` do registry ancestral.
pub fn resolve_trust_root(artifact: &Path) -> Result<PathBuf, HeraclitusError> {
    if let Some(configured) = std::env::var_os(TRUST_ROOT_ENV) {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Ok(path);
        }
        return Err(artifact_error(format!(
            "trust root configurada em {TRUST_ROOT_ENV} nao existe: {}",
            path.display()
        )));
    }

    for ancestor in artifact.ancestors().skip(1) {
        let candidate = ancestor.join("publisher.pub");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(artifact_error(format!(
        "trust root nao encontrada; configure {TRUST_ROOT_ENV} ou coloque publisher.pub no registry"
    )))
}

/// Verifica integralmente o pacote antes de o Runner interpretar conteudo.
/// Retorna o digest validado, apropriado para proveniencia/auditoria.
pub fn verify_artifact(root: &Path, trust_root: &Path) -> Result<String, HeraclitusError> {
    let fields = parse_signature(&root.join(SIGNATURE_FILE))?;
    if fields.get("format").map(String::as_str) != Some(FORMAT) {
        return Err(artifact_error("formato de assinatura .hcx nao suportado"));
    }
    if fields.get("alg").map(String::as_str) != Some("ed25519") {
        return Err(artifact_error("algoritmo de assinatura .hcx nao suportado"));
    }

    let public_text = fs::read_to_string(trust_root).map_err(|error| {
        artifact_error(format!(
            "nao foi possivel ler trust root {}: {error}",
            trust_root.display()
        ))
    })?;
    let public_hex = public_text
        .trim()
        .strip_prefix("ed25519:")
        .ok_or_else(|| artifact_error("trust root deve usar ed25519:<hex>"))?;
    if fields.get("key").map(String::as_str) != Some(public_hex) {
        return Err(artifact_error("artefato assinado por chave nao confiavel"));
    }

    let public_bytes: [u8; 32] = decode_hex(public_hex, "chave publica")?
        .try_into()
        .map_err(|_| artifact_error("chave publica Ed25519 deve ter 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| artifact_error("chave publica Ed25519 invalida"))?;

    let digest = artifact_digest(root)?;
    let digest_hex = encode_hex(&digest);
    if fields.get("digest").map(String::as_str) != Some(digest_hex.as_str()) {
        return Err(artifact_error(
            "digest .hcx divergente; conteudo adulterado",
        ));
    }

    let signature_bytes = decode_hex(
        fields
            .get("sig")
            .ok_or_else(|| artifact_error("assinatura Ed25519 ausente"))?,
        "assinatura",
    )?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| artifact_error("assinatura Ed25519 deve ter 64 bytes"))?;
    verifying_key
        .verify(&digest, &signature)
        .map_err(|_| artifact_error("assinatura Ed25519 invalida"))?;

    Ok(digest_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARTIFACT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../registry/postgresql/v1.1.0.hcx"
    );
    const TRUST_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../registry/publisher.pub");

    #[test]
    fn published_artifact_verifies() {
        let digest = verify_artifact(Path::new(ARTIFACT), Path::new(TRUST_ROOT))
            .expect("artefato publicado deve verificar");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn one_byte_tamper_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let copy = temp.path().join("v1.1.0.hcx");
        copy_dir(Path::new(ARTIFACT), &copy).expect("copiar artefato");
        let reasoning = copy.join("reasoning.yaml");
        let mut bytes = fs::read(&reasoning).expect("ler reasoning");
        bytes[0] ^= 1;
        fs::write(&reasoning, bytes).expect("adulterar reasoning");

        let error = verify_artifact(&copy, Path::new(TRUST_ROOT))
            .expect_err("um byte alterado deve impedir load");
        assert!(error.to_string().contains("adulterado"));
    }

    fn copy_dir(source: &Path, destination: &Path) -> std::io::Result<()> {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let target = destination.join(entry.file_name());
            if entry.path().is_dir() {
                copy_dir(&entry.path(), &target)?;
            } else {
                fs::copy(entry.path(), target)?;
            }
        }
        Ok(())
    }
}
