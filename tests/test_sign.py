"""
Testes da assinatura Ed25519 dos artefatos `.hcx` (Marco B).

O que interessa provar não é que assinar funciona — é que **falha** nos casos
certos: conteúdo alterado, ficheiro acrescentado, chave errada, selo antigo.
Uma assinatura que aceita tudo é pior do que assinatura nenhuma, porque dá
confiança sem a merecer — foi exatamente esse o defeito do selo que isto
substituiu.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import forge_sign

REAL_REGISTRY = Path(__file__).resolve().parent.parent / "registry"


@pytest.fixture
def pkg(tmp_path) -> Path:
    """Um artefato mínimo mas realista, isolado do registry verdadeiro."""
    p = tmp_path / "conector" / "v1.0.0.hcx"
    p.mkdir(parents=True)
    (p / "manifest.yaml").write_text("id: teste\nversion: 1.0.0\n", encoding="utf-8")
    (p / "ontology.yaml").write_text("map:\n  a: b\n", encoding="utf-8")
    (p / "reasoning.yaml").write_text("rules: []\n", encoding="utf-8")
    return p


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def pinned(tmp_path, key, monkeypatch) -> Path:
    """Fixa `key` como a chave em que o registry confia."""
    pub = tmp_path / "publisher.pub"
    pub.write_text(f"ed25519:{key.public_key().public_bytes_raw().hex()}\n", encoding="utf-8")
    monkeypatch.setattr(forge_sign, "PUBKEY_PATH", pub)
    return pub


# ---------------------------------------------------------------------------
# O caminho feliz
# ---------------------------------------------------------------------------


def test_artefato_assinado_verifica(pkg, key, pinned):
    forge_sign.sign_artifact(pkg, key)
    estado, detalhe = forge_sign.verify_artifact(pkg)
    assert estado == "OK", detalhe


def test_a_assinatura_tem_64_bytes(pkg, key, pinned):
    sig = forge_sign.sign_artifact(pkg, key)
    assert len(bytes.fromhex(sig)) == 64, (
        "ed25519 produz 64 bytes; menos que isso é um hash disfarçado"
    )


def test_signature_sig_e_autodescritivo(pkg, key, pinned):
    forge_sign.sign_artifact(pkg, key)
    campos = dict(
        line.split("=", 1) for line in (pkg / "signature.sig").read_text().strip().splitlines()
    )
    assert campos["format"] == "hcx-v2"
    assert campos["alg"] == "ed25519"
    # A chave viaja no ficheiro: dá para saber QUEM assinou sem adivinhar.
    assert campos["key"] == key.public_key().public_bytes_raw().hex()


# ---------------------------------------------------------------------------
# O que tem de FALHAR
# ---------------------------------------------------------------------------


def test_alterar_um_byte_invalida(pkg, key, pinned):
    forge_sign.sign_artifact(pkg, key)
    (pkg / "reasoning.yaml").write_text("rules: [{id: injetada}]\n", encoding="utf-8")
    estado, _ = forge_sign.verify_artifact(pkg)
    assert estado == "TAMPERED"


def test_acrescentar_um_ficheiro_invalida(pkg, key, pinned):
    """
    O selo antigo cobria uma LISTA FIXA de ficheiros: acrescentar um ficheiro
    novo ao artefato não mexia no hash. Aqui o digest cobre tudo.
    """
    forge_sign.sign_artifact(pkg, key)
    (pkg / "backdoor.yaml").write_text("evil: true\n", encoding="utf-8")
    estado, _ = forge_sign.verify_artifact(pkg)
    assert estado == "TAMPERED"


def test_apagar_um_ficheiro_invalida(pkg, key, pinned):
    forge_sign.sign_artifact(pkg, key)
    (pkg / "ontology.yaml").unlink()
    estado, _ = forge_sign.verify_artifact(pkg)
    assert estado == "TAMPERED"


def test_renomear_um_ficheiro_invalida(pkg, key, pinned):
    """O nome entra no digest — mover conteúdo entre ficheiros não passa."""
    forge_sign.sign_artifact(pkg, key)
    (pkg / "ontology.yaml").rename(pkg / "ontologia.yaml")
    estado, _ = forge_sign.verify_artifact(pkg)
    assert estado == "TAMPERED"


def test_assinatura_de_chave_estranha_e_rejeitada(pkg, pinned):
    """Um atacante assina com a SUA chave — o registry confia noutra."""
    forge_sign.sign_artifact(pkg, Ed25519PrivateKey.generate())
    estado, detalhe = forge_sign.verify_artifact(pkg)
    assert estado == "WRONG_KEY", detalhe


def test_assinatura_corrompida_e_rejeitada(pkg, key, pinned):
    forge_sign.sign_artifact(pkg, key)
    sig_file = pkg / "signature.sig"
    txt = sig_file.read_text()
    linha = next(line for line in txt.splitlines() if line.startswith("sig="))
    trocado = linha[:5] + ("0" if linha[5] != "0" else "1") + linha[6:]
    sig_file.write_text(txt.replace(linha, trocado), encoding="utf-8")
    estado, _ = forge_sign.verify_artifact(pkg)
    assert estado == "BAD_SIGNATURE"


def test_selo_antigo_e_identificado_como_mock_nao_como_valido(pkg, pinned):
    """
    Regressão do defeito original: o selo `ed25519:sig:<hash>` NÃO pode ser
    reportado como assinatura válida. Distinguir isto de um artefato corrompido
    também importa — não é ataque, é dívida técnica.
    """
    (pkg / "signature.sig").write_text("ed25519:sig:" + "ab" * 24, encoding="utf-8")
    estado, detalhe = forge_sign.verify_artifact(pkg)
    assert estado == "LEGACY_MOCK"
    assert estado != "OK"
    assert "não prova origem" in detalhe


def test_sem_assinatura_nao_e_o_mesmo_que_assinatura_invalida(pkg, pinned):
    estado, _ = forge_sign.verify_artifact(pkg)
    assert estado == "NO_SIGNATURE"


# ---------------------------------------------------------------------------
# Digest canónico
# ---------------------------------------------------------------------------


def test_digest_e_deterministico(pkg):
    assert forge_sign.artifact_digest(pkg) == forge_sign.artifact_digest(pkg)


def test_digest_ignora_o_proprio_signature_sig(pkg, key, pinned):
    antes = forge_sign.artifact_digest(pkg)
    forge_sign.sign_artifact(pkg, key)
    assert forge_sign.artifact_digest(pkg) == antes, (
        "escrever a assinatura não pode mudar o que ela assina"
    )


def test_copia_do_artefato_tem_o_mesmo_digest(pkg, tmp_path):
    copia = tmp_path / "copia.hcx"
    shutil.copytree(pkg, copia)
    assert forge_sign.artifact_digest(copia) == forge_sign.artifact_digest(pkg)


# ---------------------------------------------------------------------------
# O registry a sério
# ---------------------------------------------------------------------------


def test_todos_os_artefatos_publicados_estao_assinados():
    """
    Guarda de publicação: nenhum `.hcx` entra no repositório sem assinatura
    válida. Se este teste falhar, alguém publicou conhecimento sem prova de
    origem — corre `python forge_sign.py sign-all`.
    """
    artefatos = list(forge_sign.iter_artifacts(REAL_REGISTRY))
    if not artefatos:
        pytest.skip("registry vazio")
    maus = [
        (p.parent.name + "/" + p.name, *forge_sign.verify_artifact(p))
        for p in artefatos
        if forge_sign.verify_artifact(p)[0] != "OK"
    ]
    assert not maus, f"artefatos sem assinatura válida: {maus}"
