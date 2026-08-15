"""
bridge.py — a ponte Forge → HeraclitusDB.

Lê os Fatos Operacionais do `.hdb` do Forge (via o binário Rust `export_facts`)
e escreve-os no HeraclitusDB (o banco event-sourced em `D:\\DEV\\HeraclitusDB`,
gRPC em 127.0.0.1:7474) através do SDK Python.

Porque é que a ponte existe
---------------------------
Os dois sistemas partilham o nome "HeraclitusDB" mas não partilham formato: o
Forge escreve blocos `HERA`/`FACT` com âncora ed25519 externa; o HeraclitusDB
escreve segmentos `HRKL`/`HFTR`. Nenhum lê o ficheiro do outro. Esta ponte é a
tradução — não uma migração: o `.hdb` continua a ser o buffer tamper-evidente de
borda, o HeraclitusDB passa a ser o sistema de registo durável e consultável.

Divisão de trabalho
-------------------
    export_facts (Rust)   decodifica o .hdb    — é o único que sabe o formato
            │ JSON Lines
            ▼
    bridge.py (Python)    fala gRPC            — é onde o SDK vive

Uso
---
    python bridge.py                          # dry-run: mostra o mapeamento
    python bridge.py --apply                  # escreve mesmo no HeraclitusDB
    python bridge.py --hdb rust/gateway.hdb --apply
    python bridge.py --apply --reset          # reexporta do início (LSN 0)

Retoma e exactly-once
---------------------
O último LSN confirmado fica em `.bridge_state.json`, gravado por replace
atómico e protegido por lock de processo. Além disso, cada Fato leva uma chave
idempotente estável ao HeraclitusDB: crash depois do Append, perda deliberada do
estado ou `--reset` devolvem o LSN original em vez de duplicar evidência.

Antes de emitir uma única linha, o exportador cria um snapshot privado do `.hdb`
e exige CRC-32C + cadeia BLAKE3 + âncora Ed25519 válidos. Falha de integridade é
fatal e nenhum Fato é enviado ao destino.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager, nullcontext, suppress
from datetime import datetime, timezone
from pathlib import Path

# A consola do Windows arranca em cp1252 e rebenta com "→"/"…". Passar a UTF-8
# com `errors="replace"` evita que um caractere no relatório mate a exportação.
for _s in (sys.stdout, sys.stderr):
    with suppress(AttributeError, ValueError):
        _s.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
DEFAULT_HDB = HERE / "rust" / "storage_rs.hdb"
DEFAULT_STATE = HERE / ".bridge_state.json"
DEFAULT_ADDR = "127.0.0.1:7474"
DEFAULT_QUARANTINE = HERE / ".bridge_quarantine.hq"
SUBJECT_HMAC_ENV = "FORGE_SUBJECT_HMAC_KEY"
QUARANTINE_KEY_ENV = "FORGE_QUARANTINE_KEY"
QUARANTINE_AAD = b"heraclitus-forge-quarantine-v1"
SCHEMA_VERSION = "operational-fact/1.0"
BRIDGE_CONTRACT_VERSION = "forge-heraclitusdb/1"
DESTINATION_API_VERSION = "heraclitus.v1"
REQUIRED_HDB_SDK_VERSION = "1.0.5"

#: O `kind` sob o qual os Fatos do Forge vivem no HeraclitusDB. Mantido igual ao
#: nome canónico da spec (md/Operational-Fact.md §1) para que uma query
#: `MATCH (n:OperationalFact)` encontre exatamente o que o Forge produziu.
KIND = "OperationalFact"

#: Quem PRODUZIU os Fatos. Vai em `attrs.producer` (não em `agent_id` — ver abaixo).
PRODUCER = "heraclitus-forge"

#: Prefixo do `agent_id`. O `agent_id` do HeraclitusDB **não** é um rótulo de
#: proveniência: é a unidade de APAGAMENTO. A cifra em repouso guarda uma chave
#: ChaCha20-Poly1305 por `agent_id` e o `shred(agent_id)` destrói essa chave,
#: tornando o conteúdo permanentemente ilegível sem nunca mutar o log — é assim
#: que um log append-only cumpre o direito à eliminação (LGPD art. 18, GDPR 17).
#:
#: Logo o `agent_id` tem de ser o TITULAR DOS DADOS, não o sistema produtor. Com
#: `agent_id="heraclitus-forge"` para tudo, apagar os dados de um servidor
#: obrigaria a destruir a chave de TODOS os Fatos do Forge — o pedido de
#: eliminação de uma pessoa apagaria o histórico de toda a gente, e recusá-lo
#: seria incumprimento. Com um `agent_id` por titular, `shred("titular:carlos")`
#: apaga exatamente o que tem de apagar.
SUBJECT_PREFIX = "titular:hmac-sha256:"
SESSION_PREFIX = "forge-session:hmac-sha256:"

#: Usado quando o Fato não identifica um actor (log de sistema, ruído).
#: Fica num balde próprio para nunca se misturar com dados de uma pessoa.
NO_SUBJECT = "sistema:sem-titular"


# ---------------------------------------------------------------------------
# O MAPA CANÓNICO — Fato Operacional → (kind, content, attrs)
# ---------------------------------------------------------------------------


def _flat(fact: dict, *path, default=None):
    """Lê `fact["a"]["b"]` tolerando níveis em falta."""
    cur = fact
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return default if cur is None else cur


def render_content(fact: dict) -> str:
    """
    O texto indexado para busca (`recall`) e mostrado a um humano.

    O Fato não guarda a observação bruta — só o seu hash BLAKE3 (é essa a
    propriedade de privacidade do Forge). Portanto o `content` é uma
    reconstituição determinística a partir dos campos semânticos: dois Fatos
    iguais geram o mesmo texto, e o texto diz o que aconteceu sem revelar o log
    original.
    """
    actor = _flat(fact, "fact.identity", "actor.name", default="unknown")
    target = _flat(fact, "fact.identity", "target.id", default="unknown")
    action = _flat(fact, "fact.behavior", "action", default="unknown")
    src = _flat(fact, "fact.identity", "source.ip")
    tail = f" from {src}" if src else ""
    return f"{actor} executed {action} on {target}{tail}"


def subject_of(fact: dict, secret: str | bytes | None = None) -> str:
    """
    O titular dos dados deste Fato — vira o `agent_id`, que é a unidade de
    apagamento do HeraclitusDB (ver SUBJECT_PREFIX).

    Usa exclusivamente `actor.id`, nunca o nome. O identificador é
    pseudonimizado por HMAC-SHA-256 antes de sair da borda; assim o seletor de
    chave do HeraclitusDB não revela matrícula/login por inspeção do WAL.
    """
    actor = _flat(fact, "fact.identity", "actor.id")
    if not actor or actor == "unknown":
        return NO_SUBJECT
    if secret is None:
        secret = os.environ.get(SUBJECT_HMAC_ENV)
    # O fallback continua pseudonimizado para dry-run/testes, mas `run(apply)`
    # recusa operar sem segredo explícito de produção.
    key = (
        (secret or "forge-insecure-dry-run-only").encode()
        if isinstance(secret, str) or secret is None
        else secret
    )
    digest = hmac.new(key, str(actor).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{SUBJECT_PREFIX}{digest}"


def session_of(fact: dict, secret: str | bytes | None = None) -> str:
    """Agrupa pelo artefato de conhecimento sem expô-lo no WAL.

    `session_id` é parte pública do envelope físico do HeraclitusDB. Algumas
    versões de conhecimento incluem origem e alvo, portanto o valor bruto não
    pode ser usado. O prefixo de domínio impede correlação com o HMAC do titular
    mesmo quando a mesma chave operacional é utilizada.
    """
    version = str(fact.get("fact.knowledge_version") or "")
    if secret is None:
        secret = os.environ.get(SUBJECT_HMAC_ENV)
    key = (
        (secret or "forge-insecure-dry-run-only").encode()
        if isinstance(secret, str) or secret is None
        else secret
    )
    digest = hmac.new(key, b"session\0" + version.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{SESSION_PREFIX}{digest}"


def map_fact(lsn: int, fact: dict, *, subject_secret=None) -> dict:
    """
    Traduz um Fato Operacional do Forge no episódio do HeraclitusDB.

    Devolve o dicionário de argumentos de `Client.append`. É a **única**
    definição do contrato entre os dois sistemas — os testes importam esta
    função, não uma cópia.

    Os nomes dos `attrs` mantêm os que o `inserir.py` já usava (`source_ip`,
    `actor_name`, `target_id`, `risk_level`, `action_class`) para não partir
    nada que já consulte por eles, e acrescentam a cadeia de custódia que o
    `inserir.py` deitava fora: o hash da evidência, o carimbo de tempo legal, a
    confiança, as versões de conhecimento/ontologia e a regra que casou.
    """
    attestation = fact.get("_forge_export_attestation") or {}
    attrs = {
        # --- identidade e comportamento (compatível com inserir.py) ---
        "actor_id": _flat(fact, "fact.identity", "actor.id"),
        "actor_name": _flat(fact, "fact.identity", "actor.name"),
        "target_id": _flat(fact, "fact.identity", "target.id"),
        "source_ip": _flat(fact, "fact.identity", "source.ip"),
        "action": _flat(fact, "fact.behavior", "action"),
        "action_class": _flat(fact, "fact.behavior", "class"),
        "risk_level": _flat(fact, "fact.behavior", "risk_level"),
        "system_timestamp": _flat(fact, "fact.time", "system_timestamp"),
        # --- cadeia de custódia (o que o inserir.py perdia) ---
        # Sem estes campos o Fato chega ao HeraclitusDB como um registo qualquer:
        # deixa de ser possível provar, a partir do HeraclitusDB, que ele saiu
        # íntegro do `.hdb`. `merkle_root_anchor` + `leaf_hash` são o que liga o
        # episódio de volta à cadeia BLAKE3 assinada do Forge.
        "fact_id": fact.get("fact_id"),
        "evidence_hash": _flat(fact, "fact.evidence", "raw_observation_hash"),
        "carimbo_tempo_legal": _flat(fact, "fact.evidence", "carimbo_tempo_legal"),
        "merkle_root_anchor": _flat(fact, "fact.integrity", "merkle_root_anchor"),
        "leaf_hash": _flat(fact, "fact.integrity", "leaf_hash"),
        "integrity_signature": _flat(fact, "fact.integrity", "signature"),
        "parser_signature": _flat(fact, "fact.integrity", "parser_signature"),
        "confidence": fact.get("fact.confidence"),
        "knowledge_version": fact.get("fact.knowledge_version"),
        "ontology_version": fact.get("fact.ontology_version"),
        "reasoning_version": fact.get("fact.reasoning_version"),
        "matched_rule": _flat(fact, "fact.lineage", "matched_rule"),
        "input_source": _flat(fact, "fact.lineage", "input_source"),
        # --- proveniência da própria ponte ---
        # `producer` substitui o antigo uso do `agent_id` como marca de origem.
        # Filtrar tudo o que veio do Forge:  WHERE n.producer = "heraclitus-forge"
        "producer": PRODUCER,
        "forge_lsn": lsn,
        "generated_by": "heraclitus_forge_bridge",
        "schema_version": SCHEMA_VERSION,
        "forge_integrity_verified": attestation.get("status") == "INTEG_OK",
        "forge_verified_root": attestation.get("verified_root"),
        "forge_source_id": attestation.get("source_id"),
        "forge_public_key": attestation.get("public_key"),
        "forge_anchor_signature": attestation.get("anchor_signature"),
        "forge_integrity_algorithm": attestation.get("algorithm"),
    }
    # Um attr ausente é ruído: o HeraclitusDB indexa chaves, e uma chave com
    # "None" é pior do que chave nenhuma numa query por atributo.
    attrs = {k: v for k, v in attrs.items() if v is not None and v != ""}

    return {
        "kind": KIND,
        "content": render_content(fact),
        "agent_id": subject_of(fact, subject_secret),
        # Agrupa pelo artefato .hcx, mas com HMAC: `session_id` é público no
        # envelope físico e a versão bruta pode carregar origem/alvo.
        "session_id": session_of(fact, subject_secret),
        "attrs": attrs,
        "parents": [],
    }


def validate_fact(lsn: int, fact: dict) -> list[str]:
    """Validação fail-closed do contrato que todo conector `.hcx` deve emitir."""
    required = {
        "fact_id": fact.get("fact_id"),
        "fact.time.system_timestamp": _flat(fact, "fact.time", "system_timestamp"),
        "fact.behavior.action": _flat(fact, "fact.behavior", "action"),
        "fact.behavior.class": _flat(fact, "fact.behavior", "class"),
        "fact.evidence.raw_observation_hash": _flat(fact, "fact.evidence", "raw_observation_hash"),
        "fact.integrity.leaf_hash": _flat(fact, "fact.integrity", "leaf_hash"),
        "fact.integrity.merkle_root_anchor": _flat(fact, "fact.integrity", "merkle_root_anchor"),
        "fact.knowledge_version": fact.get("fact.knowledge_version"),
    }
    errors = [f"{name} ausente" for name, value in required.items() if value in (None, "")]
    att = fact.get("_forge_export_attestation") or {}
    if att.get("status") != "INTEG_OK":
        errors.append("snapshot Forge não possui atestação INTEG_OK")
    if len(str(att.get("public_key") or "")) != 64:
        errors.append("chave pública Ed25519 inválida")
    if len(str(att.get("anchor_signature") or "")) != 128:
        errors.append("assinatura Ed25519 da âncora inválida")
    if not att.get("source_id") or not att.get("verified_root"):
        errors.append("identidade/raiz verificadas da origem ausentes")
    if att.get("bridge_contract") != BRIDGE_CONTRACT_VERSION:
        errors.append(
            f"contrato da ponte incompatível: {att.get('bridge_contract')!r}; "
            f"esperado {BRIDGE_CONTRACT_VERSION!r}"
        )
    if att.get("fact_schema") != SCHEMA_VERSION:
        errors.append(
            f"schema do Fato incompatível: {att.get('fact_schema')!r}; esperado {SCHEMA_VERSION!r}"
        )
    if att.get("destination_api") != DESTINATION_API_VERSION:
        errors.append(
            f"API de destino incompatível: {att.get('destination_api')!r}; "
            f"esperado {DESTINATION_API_VERSION!r}"
        )
    return [f"LSN {lsn}: {e}" for e in errors]


def source_event_identity(lsn: int, fact: dict) -> tuple[str, str]:
    """Devolve `(identidade legível, chave <=80 chars)` para exactly-once."""
    att = fact.get("_forge_export_attestation") or {}
    source = str(att.get("source_id") or "")
    fact_id = str(fact.get("fact_id") or "")
    identity = f"forge:{source}:{lsn}:{fact_id}"
    return identity, hashlib.sha256(identity.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Exportador Rust
# ---------------------------------------------------------------------------


def exporter_bin() -> str:
    """
    Localiza o binário `export_facts`. Ao contrário do Coverage do
    `forge_compiler.py`, aqui a ausência é **erro fatal** e não um fallback
    silencioso: uma ponte que não encontra o exportador não tem nada a fazer, e
    fingir sucesso seria pior do que parar.
    """
    name = "export_facts.exe" if os.name == "nt" else "export_facts"
    # Não herdar CARGO_TARGET_DIR: esta máquina compila vários workspaces Rust
    # num alvo comum e um binário homónimo antigo pode ser executado por engano.
    # Quem precisa de override deve apontar para o executável exato.
    override = os.environ.get("FORGE_EXPORTER_BIN")
    exe = Path(override) if override else HERE / "rust" / "target" / "release" / name
    if not exe.exists():
        raise SystemExit(
            f"[ERRO] binário do exportador não encontrado: {exe}\n"
            f"       compile-o primeiro:  cd rust && cargo build --release --bin export_facts"
        )
    return str(exe)


def _is_loopback_addr(addr: str) -> bool:
    host = addr.rsplit(":", 1)[0].strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def connect_destination(heraclitusdb, addr: str, rpc_timeout: float):
    """Liga com mTLS quando configurado e recusa plaintext fora do loopback."""
    ca_path = os.environ.get("HERACLITUS_TLS_CA")
    cert_path = os.environ.get("HERACLITUS_TLS_CERT")
    key_path = os.environ.get("HERACLITUS_TLS_KEY")
    if bool(cert_path) != bool(key_path):
        raise RuntimeError("HERACLITUS_TLS_CERT e HERACLITUS_TLS_KEY devem vir juntos")
    if not _is_loopback_addr(addr) and not ca_path:
        raise RuntimeError(
            f"destino não-loopback {addr} exige HERACLITUS_TLS_CA (plaintext recusado)"
        )
    tls = bool(ca_path)
    return heraclitusdb.connect(
        addr,
        timeout=rpc_timeout,
        tls=tls,
        root_certificates=Path(ca_path).read_bytes() if ca_path else None,
        certificate_chain=Path(cert_path).read_bytes() if cert_path else None,
        private_key=Path(key_path).read_bytes() if key_path else None,
        server_name=os.environ.get("HERACLITUS_TLS_SERVER_NAME") or None,
    )


def export_jsonl(hdb: Path, from_lsn: int, limit: int | None = None):
    """Produz `(lsn, fact)` em streaming, apenas de snapshot integralmente verificado."""
    cmd = [exporter_bin(), str(hdb), "--from-lsn", str(from_lsn)]
    if limit:
        cmd += ["--limit", str(limit)]
    # O executável é resolvido localmente por `exporter_bin`; `shell=False` e
    # todos os argumentos são posições distintas, sem interpretação do shell.
    proc = subprocess.Popen(  # noqa: S603
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        if proc.stdout is None:
            raise RuntimeError("exportador iniciou sem stdout canalizado")
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            contract = rec.get("contract_version")
            if contract != BRIDGE_CONTRACT_VERSION:
                raise BridgeStateError(
                    f"exportador usa contrato {contract!r}; "
                    f"a ponte exige {BRIDGE_CONTRACT_VERSION!r}"
                )
            fact = rec["fact"]
            fact["_forge_export_attestation"] = rec.get("attestation") or {}
            yield rec["lsn"], fact
        stderr = proc.stderr.read() if proc.stderr is not None else ""
        code = proc.wait()
        if code != 0:
            raise RuntimeError(
                f"integridade/exportação Forge recusada (código {code}): {stderr.strip()}"
            )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


# ---------------------------------------------------------------------------
# Estado de retoma
# ---------------------------------------------------------------------------


class BridgeStateError(RuntimeError):
    pass


def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise BridgeStateError(
            f"estado de retoma ilegível em {path}; recusa fail-closed: {exc}"
        ) from exc


def save_state(
    path: Path,
    hdb: Path,
    last_lsn: int,
    appended: int,
    *,
    last_event_id: str = "",
    source_id: str = "",
) -> None:
    st = load_state(path)
    key = str(hdb.resolve())
    prev = st.get(key, {})
    st[key] = {
        "last_lsn": last_lsn,
        "total_appended": prev.get("total_appended", 0) + appended,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "last_event_id": last_event_id or prev.get("last_event_id", ""),
        "source_id": source_id or prev.get("source_id", ""),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    raw = json.dumps(st, indent=2, sort_keys=True).encode("utf-8")
    try:
        with open(tmp, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        with suppress(OSError):
            tmp.unlink(missing_ok=True)


@contextmanager
def state_lock(path: Path, timeout: float = 30.0):
    """Lock exclusivo cross-platform para impedir duas pontes sobre o mesmo estado."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # O handle precisa permanecer aberto durante o `yield`; é o próprio lock.
    fh = open(lock_path, "a+b")  # noqa: SIM115
    fh.seek(0, os.SEEK_END)
    if fh.tell() == 0:
        fh.write(b"0")
        fh.flush()
    deadline = time.monotonic() + timeout
    locked = False
    try:
        while not locked:
            try:
                fh.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise BridgeStateError(
                        f"outra ponte mantém o lock {lock_path} há mais de {timeout:.0f}s"
                    ) from exc
                time.sleep(0.1)
        yield
    finally:
        if locked:
            try:
                fh.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------


def _quarantine_key(value: str | None = None) -> bytes:
    """Carrega a chave XChaCha20-Poly1305 compartilhada com o utilitário Rust."""
    encoded = value if value is not None else os.environ.get(QUARANTINE_KEY_ENV, "")
    try:
        key = bytes.fromhex(encoded)
    except ValueError as exc:
        raise BridgeStateError(
            f"{QUARANTINE_KEY_ENV} deve conter exatamente 64 caracteres hex"
        ) from exc
    if len(key) != 32 or len(encoded) != 64:
        raise BridgeStateError(f"{QUARANTINE_KEY_ENV} deve conter exatamente 64 caracteres hex")
    return key


def _quarantine(
    path: Path, lsn: int, fact: dict, errors: list[str], *, key: bytes | None = None
) -> None:
    """Persiste um Fato inválido cifrado e autenticado; nunca grava PII em claro."""
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    except ImportError as exc:
        raise BridgeStateError(
            "PyNaCl é obrigatório para a quarentena cifrada; instale requirements.txt"
        ) from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "quarantined_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lsn": lsn,
        "errors": errors,
        "fact": {k: v for k, v in fact.items() if not k.startswith("_forge_")},
    }
    nonce = os.urandom(24)
    plaintext = json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, QUARANTINE_AAD, nonce, key or _quarantine_key()
    )
    envelope = {
        "v": 1,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }
    with open(path, "a", encoding="ascii") as fh:
        fh.write(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def decrypt_quarantine(path: Path, *, key: bytes | None = None):
    """Itera registros autenticados; qualquer linha adulterada encerra a leitura."""
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
        from nacl.exceptions import CryptoError
    except ImportError as exc:
        raise BridgeStateError("PyNaCl é obrigatório para decifrar a quarentena") from exc

    cipher_key = key or _quarantine_key()
    with open(path, encoding="ascii") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                envelope = json.loads(line)
                if envelope.get("v") != 1:
                    raise ValueError("versão desconhecida")
                nonce = bytes.fromhex(envelope["nonce"])
                ciphertext = bytes.fromhex(envelope["ciphertext"])
                if len(nonce) != 24:
                    raise ValueError("nonce inválido")
                plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
                    ciphertext, QUARANTINE_AAD, nonce, cipher_key
                )
                yield json.loads(plaintext)
            except (CryptoError, KeyError, TypeError, ValueError) as exc:
                raise BridgeStateError(
                    f"quarentena adulterada ou inválida na linha {number}"
                ) from exc


def run(
    hdb: Path,
    *,
    apply: bool,
    addr: str,
    state_path: Path,
    reset: bool,
    limit: int | None,
    batch: int,
    quarantine_path: Path = DEFAULT_QUARANTINE,
    rpc_timeout: float = 30.0,
    max_retries: int = 3,
) -> dict:
    if not hdb.exists():
        raise SystemExit(f"[ERRO] .hdb não encontrado: {hdb}")

    subject_secret = os.environ.get(SUBJECT_HMAC_ENV)
    if apply and (not subject_secret or len(subject_secret.encode("utf-8")) < 32):
        raise SystemExit(
            f"[ERRO] {SUBJECT_HMAC_ENV} é obrigatório em --apply e deve ter ao menos 32 bytes"
        )
    try:
        quarantine_key = _quarantine_key() if apply else None
    except BridgeStateError as exc:
        raise SystemExit(f"[ERRO] {exc}") from exc

    lock = state_lock(state_path) if apply else nullcontext()
    with lock:
        state = load_state(state_path)
        previous = state.get(str(hdb.resolve()), {})
        from_lsn = 0 if reset else int(previous.get("last_lsn", 0))
        last_event_id = "" if reset else str(previous.get("last_event_id", ""))

        print("=== ponte Forge → HeraclitusDB ===")
        print(f"  origem : {hdb}")
        print(f"  destino: {addr if apply else 'DRY-RUN (nada será escrito)'}")
        print(f"  retoma : LSN > {from_lsn}\n")

        db = None
        if apply:
            try:
                import heraclitusdb  # só é preciso quando se escreve mesmo
            except ImportError as exc:
                raise BridgeStateError(
                    "SDK heraclitusdb 1.0.5 ausente; instale o wheel privado ou "
                    "`uv pip install -e ..\\HeraclitusDB\\sdk\\python`"
                ) from exc
            sdk_version = getattr(heraclitusdb, "__version__", None)
            if sdk_version != REQUIRED_HDB_SDK_VERSION:
                raise BridgeStateError(
                    f"SDK heraclitusdb incompatível: {sdk_version!r}; "
                    f"homologado={REQUIRED_HDB_SDK_VERSION!r}"
                )

            db = connect_destination(heraclitusdb, addr, rpc_timeout)

        read = appended = deduplicated = 0
        errors: list[str] = []
        last_lsn = from_lsn
        try:
            for lsn, fact in export_jsonl(hdb, from_lsn, limit):
                read += 1
                validation = validate_fact(lsn, fact)
                if validation:
                    _quarantine(quarantine_path, lsn, fact, validation, key=quarantine_key)
                    errors.extend(validation)
                    break

                ep = map_fact(lsn, fact, subject_secret=subject_secret)
                source_identity, idempotency_key = source_event_identity(lsn, fact)
                ep["attrs"]["source_event_id"] = source_identity
                ep["parents"] = [last_event_id] if last_event_id else []

                if not apply:
                    if read <= 3:
                        print(f"  LSN {lsn} → kind={ep['kind']}  content={ep['content']!r}")
                        print(f"          attrs={json.dumps(ep['attrs'], ensure_ascii=False)}\n")
                    continue

                if db is None:
                    raise BridgeStateError("destino não inicializado em modo --apply")
                response = None
                for attempt in range(max(1, max_retries)):
                    try:
                        response = db.append(
                            ep["kind"],
                            ep["content"],
                            agent_id=ep["agent_id"],
                            session_id=ep["session_id"],
                            attrs=ep["attrs"],
                            parents=ep["parents"],
                            idempotency_key=idempotency_key,
                            timeout=rpc_timeout,
                            return_metadata=True,
                        )
                        break
                    except (OSError, RuntimeError) as exc:
                        if attempt + 1 >= max(1, max_retries):
                            errors.append(f"LSN {lsn}: {type(exc).__name__}: {exc}")
                            break
                        time.sleep(min(2**attempt, 5))
                if response is None:
                    break

                was_dedup = bool(response["deduplicated"])
                appended += 0 if was_dedup else 1
                deduplicated += 1 if was_dedup else 0
                last_lsn = lsn
                last_event_id = str(response["event_id"])
                source_id = str(
                    (fact.get("_forge_export_attestation") or {}).get("source_id") or ""
                )
                # Checkpoint por confirmação: fecha a janela crash após Append.
                # Se o crash ocorrer antes deste replace, o retry é absorvido
                # pela idempotência persistente do servidor.
                save_state(
                    state_path,
                    hdb,
                    last_lsn,
                    0 if was_dedup else 1,
                    last_event_id=last_event_id,
                    source_id=source_id,
                )
                if read % max(1, batch) == 0:
                    print(f"  … {read} confirmados", flush=True)
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
            errors.append(f"exportação: {type(exc).__name__}: {exc}")
        finally:
            if db is not None:
                db.close()

    if read == 0 and not errors:
        print("Nada de novo para exportar.")
    elif not apply:
        if read > 3:
            print(f"  … e mais {read - 3}.\n")
        print("Dry-run. Use --apply para escrever no HeraclitusDB.")
    else:
        print(
            f"\n{appended} Fato(s) novo(s), {deduplicated} retry(s) deduplicado(s). "
            f"Último LSN do Forge: {last_lsn}."
        )
    if errors:
        print(f"{len(errors)} erro(s):")
        for e in errors:
            print(f"  • {e}")
    print(f'Consultar:   MATCH (n:{KIND}) WHERE n.producer = "{PRODUCER}" RETURN n')
    print(
        f'Apagar (LGPD): admin("shred:{SUBJECT_PREFIX}<HMAC do titular>")'
        f"  — exige encryption_at_rest ligado"
    )
    return {
        "read": read,
        "appended": appended,
        "deduplicated": deduplicated,
        "last_lsn": last_lsn,
        "errors": errors,
    }


def main() -> None:
    p = argparse.ArgumentParser(
        description="Exporta os Fatos Operacionais do .hdb do Forge para o HeraclitusDB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Sem --apply, não escreve nada: mostra o mapeamento e sai.",
    )
    p.add_argument(
        "--hdb", type=Path, default=DEFAULT_HDB, help=f"ficheiro .hdb (padrão: {DEFAULT_HDB})"
    )
    p.add_argument("--apply", action="store_true", help="escreve mesmo (por omissão é dry-run)")
    p.add_argument("--addr", default=DEFAULT_ADDR, help=f"endereço gRPC (padrão: {DEFAULT_ADDR})")
    p.add_argument("--state", type=Path, default=DEFAULT_STATE, help="ficheiro de retoma")
    p.add_argument("--reset", action="store_true", help="ignora a retoma e exporta desde o LSN 0")
    p.add_argument("--limit", type=int, default=None, help="exporta no máximo N Fatos")
    p.add_argument("--batch", type=int, default=500, help="frequência do relatório de progresso")
    p.add_argument(
        "--quarantine",
        type=Path,
        default=DEFAULT_QUARANTINE,
        help="envelopes XChaCha20-Poly1305 para Fatos que falham o schema",
    )
    p.add_argument(
        "--rpc-timeout", type=float, default=30.0, help="deadline de cada Append gRPC em segundos"
    )
    p.add_argument(
        "--max-retries", type=int, default=3, help="tentativas seguras por Fato (idempotentes)"
    )
    a = p.parse_args()

    r = run(
        a.hdb,
        apply=a.apply,
        addr=a.addr,
        state_path=a.state,
        reset=a.reset,
        limit=a.limit,
        batch=a.batch,
        quarantine_path=a.quarantine,
        rpc_timeout=a.rpc_timeout,
        max_retries=a.max_retries,
    )
    sys.exit(1 if r["errors"] else 0)


if __name__ == "__main__":
    main()
