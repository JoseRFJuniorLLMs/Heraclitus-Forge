"""
forge_sign — assinatura Ed25519 REAL dos artefatos `.hcx` (fecha o Marco B).

Até 2026-08-14 o `signature.sig` dizia `ed25519:sig:<48 hex>` mas era um hash
SHA-256 truncado: **não havia chave nenhuma**. Qualquer pessoa que alterasse um
`.hcx` recalculava o selo em duas linhas. Agora a assinatura é ed25519 a sério,
sobre um digest canónico de todo o artefato, verificável contra a chave pública
fixada no registry.

Modelo de confiança
-------------------
A chave de PUBLICAÇÃO é distinta da chave da âncora do `.hdb` (Marco B, Rust).
São domínios diferentes: a âncora prova que *os dados* não foram adulterados na
máquina que os serve; esta prova que *o conhecimento* foi publicado por quem diz
tê-lo publicado. Comprometer uma não compromete a outra.

    privada : ~/.heraclitus/publisher.key   (0600, FORA do repositório)
    pública : registry/publisher.pub        (versionada — é a âncora de confiança)

A privada vive fora do repositório de propósito: um `git add -A` distraído nunca
a pode apanhar. Sobrepõe-se com `HERACLITUS_PUBLISHER_KEY`.

Digest canónico
---------------
O selo antigo concatenava o conteúdo de uma lista fixa de ficheiros, sem
enquadramento — dois artefatos diferentes podiam produzir o mesmo hash movendo
bytes de um ficheiro para o seguinte. Aqui o digest cobre **todos** os ficheiros
do artefato (exceto o próprio `signature.sig`), por ordem, com o nome e o
comprimento a enquadrar cada um:

    SHA256( "hcx-v3\\n" || for each file: name || "\\0" || len || "\\0" || bytes )

Acrescentar um ficheiro novo ao artefato passa a invalidar a assinatura — o que
com a lista fixa não acontecia. Para que o mesmo checkout seja verificável em
Windows e Linux, texto UTF-8 é canonizado para finais de linha LF antes do hash;
ficheiros binários continuam cobertos byte a byte.

CLI
---
    python forge_sign.py keygen                       # cria o par (uma vez)
    python forge_sign.py sign   registry/x/v1.0.0.hcx
    python forge_sign.py verify registry/x/v1.0.0.hcx
    python forge_sign.py verify-all                   # varre o registry inteiro
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from contextlib import suppress
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import _console  # noqa: F401  (consola UTF-8 no Windows)

HERE = Path(__file__).resolve().parent
REGISTRY = HERE / "registry"
PUBKEY_PATH = REGISTRY / "publisher.pub"
SIG_NAME = "signature.sig"
FORMAT = "hcx-v3"

#: Ficheiro cujo conteúdo NÃO entra no digest (é onde o digest vai parar).
EXCLUDED = {SIG_NAME}


def privkey_path() -> Path:
    env = os.environ.get("HERACLITUS_PUBLISHER_KEY")
    if env:
        return Path(env)
    return Path.home() / ".heraclitus" / "publisher.key"


# ---------------------------------------------------------------------------
# Chaves
# ---------------------------------------------------------------------------


def keygen(*, force: bool = False) -> tuple[Path, Path]:
    """Gera o par de publicação. Recusa-se a sobrepor uma chave existente."""
    priv_p = privkey_path()
    if priv_p.exists() and not force:
        raise SystemExit(
            f"[ERRO] já existe uma chave em {priv_p}.\n"
            f"       Sobrepô-la invalida TODAS as assinaturas já publicadas.\n"
            f"       Se é mesmo o que queres: --force"
        )
    priv_p.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes_raw()
    priv_p.write_bytes(raw)
    with suppress(OSError):
        priv_p.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 (no-op no Windows)

    REGISTRY.mkdir(parents=True, exist_ok=True)
    pub_hex = key.public_key().public_bytes_raw().hex()
    PUBKEY_PATH.write_text(f"ed25519:{pub_hex}\n", encoding="utf-8")
    return priv_p, PUBKEY_PATH


def load_private() -> Ed25519PrivateKey:
    p = privkey_path()
    if not p.exists():
        raise SystemExit(
            f"[ERRO] chave de publicação não encontrada: {p}\n"
            f"       Cria-a uma vez com:  python forge_sign.py keygen"
        )
    return Ed25519PrivateKey.from_private_bytes(p.read_bytes())


def load_public() -> Ed25519PublicKey | None:
    if not PUBKEY_PATH.exists():
        return None
    txt = PUBKEY_PATH.read_text(encoding="utf-8").strip()
    if not txt.startswith("ed25519:"):
        raise SystemExit(f"[ERRO] {PUBKEY_PATH} não tem o formato ed25519:<hex>")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(txt.split(":", 1)[1]))


# ---------------------------------------------------------------------------
# Digest canónico
# ---------------------------------------------------------------------------


def _canonical_file_bytes(path: Path) -> bytes:
    """Lê o ficheiro com representação estável entre checkouts Windows/Linux.

    O Git pode materializar o mesmo blob textual como CRLF no Windows e LF no
    Linux. Se os bytes crus fossem assinados, uma assinatura criada num sistema
    seria reportada como adulterada no outro. Conteúdo UTF-8 usa LF canónico;
    conteúdo que não seja UTF-8 é tratado como binário e permanece byte a byte.
    """
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def artifact_digest(pkg: Path) -> bytes:
    """
    Digest canónico do artefato. Determinístico: a mesma pasta dá sempre o mesmo
    digest, em qualquer sistema de ficheiros (ordem forçada, nomes com `/`).
    """
    h = hashlib.sha256()
    h.update(FORMAT.encode() + b"\n")
    files = sorted(
        (p for p in pkg.rglob("*") if p.is_file() and p.name not in EXCLUDED),
        key=lambda p: p.relative_to(pkg).as_posix(),
    )
    if not files:
        raise SystemExit(f"[ERRO] artefato vazio: {pkg}")
    for p in files:
        data = _canonical_file_bytes(p)
        h.update(p.relative_to(pkg).as_posix().encode())
        h.update(b"\0")
        h.update(str(len(data)).encode())
        h.update(b"\0")
        h.update(data)
    return h.digest()


# ---------------------------------------------------------------------------
# Assinar / verificar
# ---------------------------------------------------------------------------


def sign_artifact(
    pkg: Path,
    signer: Ed25519PrivateKey | None = None,
) -> str:
    signer = signer or load_private()
    digest = artifact_digest(pkg)
    sig = signer.sign(digest)
    pub = signer.public_key().public_bytes_raw().hex()
    body = f"format={FORMAT}\nalg=ed25519\nkey={pub}\ndigest={digest.hex()}\nsig={sig.hex()}\n"
    (pkg / SIG_NAME).write_text(body, encoding="utf-8")
    return sig.hex()


def verify_artifact(pkg: Path) -> tuple[str, str]:
    """
    Devolve `(estado, detalhe)`. Estados:

      OK            assinatura ed25519 válida contra a chave pública do registry
      LEGACY_MOCK   o selo antigo `ed25519:sig:` — NÃO é prova de origem
      TAMPERED      o conteúdo mudou desde que foi assinado
      BAD_SIGNATURE a assinatura não bate com esta chave pública
      WRONG_KEY     assinado por uma chave que não é a do registry
      NO_SIGNATURE  não tem signature.sig
      NO_PUBKEY     o registry não tem publisher.pub para verificar contra
    """
    sig_file = pkg / SIG_NAME
    if not sig_file.exists():
        return "NO_SIGNATURE", "sem signature.sig"

    raw = sig_file.read_text(encoding="utf-8").strip()
    if raw.startswith("ed25519:sig:"):
        return ("LEGACY_MOCK", "selo antigo sem chave — não prova origem (ver registry/README.md)")

    fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if fields.get("format") != FORMAT or "sig" not in fields:
        return "BAD_SIGNATURE", f"formato irreconhecível: {raw[:40]!r}"

    pub = load_public()
    if pub is None:
        return "NO_PUBKEY", f"{PUBKEY_PATH} não existe"

    if fields.get("key") != pub.public_bytes_raw().hex():
        return (
            "WRONG_KEY",
            f"assinado por {fields.get('key', '?')[:16]}…, "
            f"o registry confia em {pub.public_bytes_raw().hex()[:16]}…",
        )

    actual = artifact_digest(pkg)
    if actual.hex() != fields.get("digest"):
        return (
            "TAMPERED",
            f"digest agora {actual.hex()[:16]}…, assinado {fields.get('digest', '?')[:16]}…",
        )

    try:
        pub.verify(bytes.fromhex(fields["sig"]), actual)
    except (InvalidSignature, ValueError) as e:
        return "BAD_SIGNATURE", f"{type(e).__name__}"
    return "OK", f"ed25519 válida · digest {actual.hex()[:16]}…"


def iter_artifacts(root: Path = REGISTRY):
    yield from sorted(p for p in root.glob("*/*.hcx") if p.is_dir())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_MARK = {"OK": "✓", "LEGACY_MOCK": "!", "NO_PUBKEY": "!"}


def main() -> None:
    args = sys.argv[1:]
    cmd = args[0] if args else "verify-all"

    if cmd == "keygen":
        priv, pub = keygen(force="--force" in args)
        print(f"[+] chave privada : {priv}  (0600, FORA do repositório)")
        print(f"[+] chave pública : {pub}   (versionar — é a âncora de confiança)")
        print("\nAssina os artefatos existentes com:  python forge_sign.py sign-all")

    elif cmd in ("sign", "sign-all"):
        key = load_private()
        alvos = (
            [Path(a) for a in args[1:] if not a.startswith("-")]
            if cmd == "sign"
            else list(iter_artifacts())
        )
        if not alvos:
            raise SystemExit("[ERRO] nada para assinar")
        for pkg in alvos:
            sig = sign_artifact(pkg, key)
            print(f"[+] assinado {pkg}  sig={sig[:16]}…")

    elif cmd in ("verify", "verify-all"):
        alvos = (
            [Path(a) for a in args[1:] if not a.startswith("-")]
            if cmd == "verify" and len(args) > 1
            else list(iter_artifacts())
        )
        if not alvos:
            raise SystemExit(f"[ERRO] nenhum artefato em {REGISTRY}")
        mau = 0
        for pkg in alvos:
            estado, detalhe = verify_artifact(pkg)
            if estado != "OK":
                mau += 1
            print(
                f"  {_MARK.get(estado, '✗')} {estado:14s} {pkg.parent.name}/{pkg.name}  — {detalhe}"
            )
        print(f"\n{len(alvos) - mau}/{len(alvos)} artefato(s) com assinatura válida.")
        sys.exit(1 if mau else 0)

    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
