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
    // Sobre BYTES e não sobre a `&str` fatiada por índices.
    //
    // `&value[i..i + 2]` entra em PÂNICO quando o corte cai a meio de um
    // caractere multibyte. O conteúdo vem de um `signature.sig` que ainda não
    // foi verificado — é entrada não confiável por definição — e um pânico aqui
    // derruba o verificador em vez de produzir `Quarantined`. Um verificador
    // que morre não é fail-closed: é fail-nenhum.
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(artifact_error(format!(
            "{field} hexadecimal tem tamanho impar"
        )));
    }
    bytes
        .chunks_exact(2)
        .map(|par| {
            let texto = std::str::from_utf8(par)
                .map_err(|_| artifact_error(format!("{field} hexadecimal invalido")))?;
            u8::from_str_radix(texto, 16)
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
        } else if file_type.is_file() {
            let relativo = path
                .strip_prefix(root)
                .map_err(|_| artifact_error("ficheiro fora da raiz do artefato"))?;
            // Só o `signature.sig` da RAIZ fica de fora do digest — é ele que
            // contém o digest, e não se pode assinar a si próprio.
            //
            // A exclusão era por nome, a qualquer profundidade: um ficheiro
            // `subpasta/signature.sig` ficava fora do digest e podia ser
            // trocado sem a verificação dar por nada. Conteúdo não assinado
            // dentro de um artefacto que verifica é exactamente o que a §5.5
            // existe para impedir.
            if relativo == Path::new(SIGNATURE_FILE) {
                continue;
            }
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

    /// O `signature.sig` chega como texto NAO verificado. Um corte a meio de um
    /// caractere multibyte fazia o `decode_hex` entrar em panico, e um
    /// verificador que morre nao e fail-closed: e fail-nenhum.
    #[test]
    fn decode_hex_nao_entra_em_panico_com_multibyte() {
        // 'é' ocupa dois bytes: o corte de dois em dois cai a meio dele.
        assert!(decode_hex("éé", "teste").is_err());
        assert!(decode_hex("ab€cd", "teste").is_err());
        assert!(decode_hex("日本語", "teste").is_err());
        // E o caminho normal continua a funcionar.
        assert_eq!(
            decode_hex("00ff10", "teste").unwrap(),
            vec![0x00, 0xff, 0x10]
        );
        assert!(decode_hex("abc", "teste").is_err(), "tamanho impar");
    }

    /// Um ficheiro chamado `signature.sig` DENTRO de uma subpasta ficava fora do
    /// digest: conteudo nao assinado dentro de um artefacto que verifica.
    #[test]
    fn um_signature_sig_em_subpasta_e_coberto_pelo_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let copy = temp.path().join("v1.1.0.hcx");
        copy_dir(Path::new(ARTIFACT), &copy).expect("copiar artefato");

        let sub = copy.join("modelos");
        fs::create_dir_all(&sub).unwrap();
        let intruso = sub.join(SIGNATURE_FILE);
        fs::write(&intruso, b"conteudo qualquer").unwrap();

        let com = artifact_digest(&copy).expect("digest com o ficheiro");
        fs::write(&intruso, b"conteudo DIFERENTE").unwrap();
        let depois = artifact_digest(&copy).expect("digest depois de mexer");
        assert_ne!(
            com, depois,
            "mexer num `subpasta/signature.sig` TEM de mudar o digest"
        );

        // E o `signature.sig` da raiz continua de fora — nao se pode assinar a
        // si proprio.
        let so_raiz = artifact_digest(Path::new(ARTIFACT)).expect("digest do original");
        let mut ficheiros = Vec::new();
        collect_files(Path::new(ARTIFACT), Path::new(ARTIFACT), &mut ficheiros).unwrap();
        assert!(
            !ficheiros
                .iter()
                .any(|f| f.file_name().and_then(|n| n.to_str()) == Some(SIGNATURE_FILE)),
            "o signature.sig da raiz nao entra no digest"
        );
        assert_eq!(so_raiz.len(), 32);
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
