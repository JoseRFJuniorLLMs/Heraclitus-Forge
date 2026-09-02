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

#: Versão do envelope de quarentena escrita hoje. A v1 (sem `kid`) continua a
#: ser LIDA — envelopes antigos não ficam órfãos por causa desta mudança.
QUARANTINE_ENVELOPE_VERSION = 2

#: Tecto por linha ao decifrar (ver `rust/src/quarantine.rs`). Um registo é uma
#: observação, não um ficheiro.
QUARANTINE_MAX_LINE_BYTES = 8 * 1024 * 1024


def quarantine_key_id(key: bytes) -> str:
    """
    Impressão digital da chave — 8 primeiros bytes do BLAKE3, em hex.

    Sem isto, rodar a `FORGE_QUARANTINE_KEY` transforma todos os registos
    antigos em lixo indistinguível de corrupção: a autenticação falha e não há
    forma de saber que a causa foi a chave errada. Tem de bater bit a bit com
    `quarantine::key_id` do lado Rust — há um teste de interoperabilidade.
    """
    import blake3

    return blake3.blake3(key).digest()[:8].hex()


SCHEMA_VERSION = "operational-fact/1.0"

#: Modelo canónico de evento de segurança (SPEC-0071 §4). É uma **extensão
#: compatível**: viaja em `fact.security`, ao lado do Fato Operacional, e nunca
#: no lugar dele. Um `.hcx` sem `security:` no manifesto é um conector legado —
#: produz Fatos `operational-fact/1.0` perfeitamente válidos e não produz evento
#: canónico. Ausência do bloco NÃO autoriza inventar campos canónicos na leitura
#: (§4.1); por isso a ponte só valida o que está lá, e passa adiante.
#:
#: A definição normativa é o crate `rust/crates/heraclitus-security-schema`.
#: Aqui está apenas a verificação de fronteira: o que entra no HeraclitusDB tem
#: de estar consistente com o Fato que o transporta.
SECURITY_SCHEMA_VERSION = "heraclitus-security-event/1.0"

#: Schema dos eventos de saúde do sensor. O contrato normativo é o crate
#: `heraclitus-telemetry-health` do HeraclitusDB; aqui está a verificação de
#: fronteira do que a ponte aceita escrever.
TELEMETRY_SCHEMA_VERSION = "heraclitus-telemetry-health/1.0"

#: Vocabulário fechado das categorias v1 (SPEC-0071 §4.2). Categoria fora desta
#: lista é erro de contrato, não uma categoria nova.
SECURITY_CATEGORIES = frozenset(
    {
        "authentication",
        "network",
        "dns",
        "http",
        "process",
        "file",
        "registry",
        "endpoint",
        "cloud",
        "identity",
        "threat_intel",
        "vulnerability",
        "email",
        "data_access",
        "privilege",
        "alert",
        "finding",
        "incident",
    }
)

#: Desfecho observado. `None` significa DESCONHECIDO — nunca sucesso.
SECURITY_OUTCOMES = frozenset({"success", "failure"})
MAX_SECURITY_SEVERITY = 10

#: Versão 2: uma linha do JSONL deixou de ser sempre um Fato. O `.hdb` passou a
#: carregar também eventos de Telemetry Health, e cada linha diz o que é em
#: `record_type`. Mudar a forma do envelope sem mudar o número seria exatamente
#: o que o número existe para impedir.
BRIDGE_CONTRACT_VERSION = "forge-heraclitusdb/2"

#: `kind` sob o qual os eventos de saúde vivem no HeraclitusDB. Tem de bater com
#: `TELEMETRY_HEALTH_KIND` do crate consumidor: a view filtra por ele.
TELEMETRY_KIND = "TelemetryHealth"
#: O `agent_id` de um evento de saúde é o PRODUTOR, não um titular de dados —
#: um heartbeat não é dado pessoal de ninguém e não entra no crypto-shredding.
TELEMETRY_AGENT_ID = "heraclitus-forge"
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
        # --- identidade de segurança do datasource (autenticada no HFB2) ---
        # Vem do cabeçalho autenticado do registo: alterá-la muda a folha
        # BLAKE3 e a raiz Merkle. Sobe como attrs porque é por aqui que se
        # isola tenant, se correlaciona por fonte e se responde "de que sensor
        # veio isto".
        "tenant_id": _flat(fact, "fact.datasource", "tenant_id"),
        "datasource_id": _flat(fact, "fact.datasource", "datasource_id"),
        "sensor_id": _flat(fact, "fact.datasource", "sensor_id"),
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
    # --- modelo canónico, quando o conector o declara (SPEC-0071 §4) ---
    # Sobe como attrs planos porque é assim que se consulta o HeraclitusDB:
    #   MATCH (n:OperationalFact) WHERE n.security_category = "authentication"
    # O evento canónico completo continua a ser reconstituível a partir do
    # Forge — aqui vai o que serve para filtrar e correlacionar.
    security = fact.get("fact.security")
    if isinstance(security, dict):
        provenance = security.get("provenance") or {}
        attrs.update(
            {
                "security_schema": security.get("schema_version"),
                "security_category": security.get("category"),
                "security_event_type": security.get("event_type"),
                # Ausente = desconhecido. O filtro abaixo remove-o em vez de o
                # gravar como "None" — uma chave a mentir é pior que chave
                # nenhuma numa query.
                "security_outcome": security.get("outcome"),
                "security_severity": security.get("severity"),
                "security_tenant_id": security.get("tenant_id"),
                "security_datasource_id": security.get("datasource_id"),
                "security_sensor_id": security.get("sensor_id"),
                "security_observed_at": security.get("observed_at_micros"),
                "security_source_sequence": security.get("source_sequence"),
                # Liga o evento ao artefato exato que o produziu (gate CM1).
                "security_connector_digest": provenance.get("connector_digest"),
            }
        )

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


def validate_security(fact: dict) -> list[str]:
    """
    Valida o evento canónico **quando ele existe** (SPEC-0071 §4).

    Ausência não é erro: é um conector legado (§4.1, gate CM2). O que não pode
    passar é um bloco presente e meio preenchido — isso chegaria ao
    HeraclitusDB com aparência de evento canónico sem o ser.

    Além da forma, verifica-se a **coerência com o Fato que o transporta**: o
    evento tem de descrever a MESMA observação. Sem isto, um bug a montante
    podia colar a semântica de uma linha à evidência de outra, e a cadeia de
    custódia deixava de provar o que diz provar.
    """
    security = fact.get("fact.security")
    if security is None:
        return []
    if not isinstance(security, dict):
        return ["fact.security presente mas não é um objeto"]

    errors = []
    if security.get("schema_version") != SECURITY_SCHEMA_VERSION:
        errors.append(
            f"schema canónico incompatível: {security.get('schema_version')!r}; "
            f"esperado {SECURITY_SCHEMA_VERSION!r}"
        )
    if security.get("category") not in SECURITY_CATEGORIES:
        errors.append(f"categoria fora do vocabulário v1: {security.get('category')!r}")
    if not str(security.get("event_type") or "").strip():
        errors.append("fact.security.event_type ausente")
    outcome = security.get("outcome")
    if outcome is not None and outcome not in SECURITY_OUTCOMES:
        errors.append(f"desfecho inválido: {outcome!r} (desconhecido escreve-se null)")
    severity = security.get("severity")
    if not isinstance(severity, int) or isinstance(severity, bool):
        errors.append(f"severidade não é inteira: {severity!r}")
    elif not 0 <= severity <= MAX_SECURITY_SEVERITY:
        errors.append(f"severidade fora da escala 0..{MAX_SECURITY_SEVERITY}: {severity}")
    for name in ("tenant_id", "datasource_id", "sensor_id"):
        if not str(security.get(name) or "").strip():
            errors.append(f"fact.security.{name} ausente")
    for name in ("observed_at_micros", "ingested_at_micros", "normalized_at_micros"):
        value = security.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(f"fact.security.{name} não é um instante válido: {value!r}")

    provenance = security.get("provenance")
    if not isinstance(provenance, dict):
        return [*errors, "fact.security.provenance ausente"]
    for name in (
        "forge_source_id",
        "connector_id",
        "connector_version",
        "connector_digest",
        "raw_observation_hash",
        "matched_rule",
    ):
        if not str(provenance.get(name) or "").strip():
            errors.append(f"fact.security.provenance.{name} ausente")

    # Coerência com o Fato: mesma evidência, mesma regra, mesmo artefato.
    evidence = str(_flat(fact, "fact.evidence", "raw_observation_hash") or "")
    if evidence.startswith("b3:") and provenance.get("raw_observation_hash") != evidence[3:]:
        errors.append("evento canónico aponta para outra observação que não a do Fato")
    matched = _flat(fact, "fact.lineage", "matched_rule")
    if matched and provenance.get("matched_rule") != matched:
        errors.append(
            f"regra divergente: Fato casou {matched!r}, evento diz "
            f"{provenance.get('matched_rule')!r}"
        )
    knowledge = str(fact.get("fact.knowledge_version") or "")
    if knowledge and "@" in knowledge:
        connector_id, connector_version = knowledge.split("@", 1)
        if provenance.get("connector_id") != connector_id:
            errors.append("evento canónico atribuído a outro conector")
        if provenance.get("connector_version") != connector_version:
            errors.append("evento canónico atribuído a outra versão do conector")
    return errors


def validate_fact(lsn: int, fact: dict) -> list[str]:
    """Validação fail-closed do contrato que todo conector `.hcx` deve emitir."""
    required = {
        "fact_id": fact.get("fact_id"),
        # HDB2: sem identidade não há registo. Se isto falta, o Fato não veio
        # de um `.hdb` desta geração — e aceitar seria escrever no banco
        # central um evento que não se sabe a quem pertence.
        "fact.datasource.tenant_id": _flat(fact, "fact.datasource", "tenant_id"),
        "fact.datasource.datasource_id": _flat(fact, "fact.datasource", "datasource_id"),
        "fact.datasource.sensor_id": _flat(fact, "fact.datasource", "sensor_id"),
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
    # Extensão canónica: só valida se estiver lá (ver `validate_security`).
    errors.extend(validate_security(fact))
    return [f"LSN {lsn}: {e}" for e in errors]


def telemetry_episode(lsn: int, record: dict) -> dict:
    """
    Traduz uma linha de Telemetry Health no episódio do HeraclitusDB.

    O envelope viaja como **texto**, exatamente como foi gravado e coberto pela
    folha BLAKE3 do registo HFB2: reserializá-lo aqui daria outros bytes e a
    ponte deixaria de poder afirmar que entregou o que estava no disco.
    """
    telemetry = record["telemetry"]
    envelope = telemetry["envelope"]
    identity = telemetry["identity"]
    # O tipo do evento é atributo indexado: a view filtra por ele sem abrir o
    # conteúdo. Parsear aqui é leitura, não reescrita — o texto segue intacto.
    event_type = (json.loads(envelope).get("event") or {}).get("type")
    attrs = {
        "telemetry.schema": TELEMETRY_SCHEMA_VERSION,
        "telemetry.event_type": event_type,
        "tenant_id": identity["tenant_id"],
        "datasource_id": identity["datasource_id"],
        "sensor_id": identity["sensor_id"],
        "producer": PRODUCER,
        "forge_lsn": lsn,
        "generated_by": "heraclitus_forge_bridge",
    }
    return {
        "kind": TELEMETRY_KIND,
        "content": envelope,
        "agent_id": TELEMETRY_AGENT_ID,
        "session_id": identity["datasource_id"],
        "attrs": {k: v for k, v in attrs.items() if v is not None and v != ""},
        "parents": [],
    }


def validate_telemetry(lsn: int, record: dict) -> list[str]:
    """Validação fail-closed do que se escreve como evento de saúde."""
    telemetry = record.get("telemetry")
    if not isinstance(telemetry, dict):
        return [f"LSN {lsn}: linha de telemetria sem bloco `telemetry`"]
    errors = []
    identity = telemetry.get("identity")
    if not isinstance(identity, dict):
        errors.append("identidade do sensor ausente")
    else:
        for name in ("tenant_id", "datasource_id", "sensor_id"):
            if not str(identity.get(name) or "").strip():
                errors.append(f"{name} ausente")
    try:
        envelope = json.loads(telemetry.get("envelope") or "")
    except (TypeError, ValueError) as exc:
        return [f"LSN {lsn}: envelope de telemetria ilegível: {exc}"]
    if envelope.get("schema") != TELEMETRY_SCHEMA_VERSION:
        errors.append(
            f"schema de telemetria incompatível: {envelope.get('schema')!r}; "
            f"esperado {TELEMETRY_SCHEMA_VERSION!r}"
        )
    if not (envelope.get("event") or {}).get("type"):
        errors.append("envelope sem tipo de evento")
    # A identidade do envelope e a do registo autenticado têm de ser a mesma:
    # divergirem significa que alguém montou o envelope noutro sítio.
    if isinstance(identity, dict) and envelope.get("identity") != identity:
        errors.append("identidade do envelope diverge da identidade autenticada")
    return [f"LSN {lsn}: {e}" for e in errors]


def source_event_identity(lsn: int, fact: dict) -> tuple[str, str]:
    """Devolve `(identidade legível, chave <=80 chars)` para exactly-once."""
    att = fact.get("_forge_export_attestation") or {}
    source = str(att.get("source_id") or "")
    fact_id = str(fact.get("fact_id") or "")
    identity = f"forge:{source}:{lsn}:{fact_id}"
    return identity, hashlib.sha256(identity.encode("utf-8")).hexdigest()


def telemetry_event_identity(lsn: int, record: dict) -> tuple[str, str]:
    """
    Identidade exactly-once de um evento de saúde.

    Um evento de saúde não tem `fact_id`, mas tem algo tão bom: o LSN é único no
    log e o `source_id` identifica a origem. Reprocessar o mesmo LSN devolve a
    mesma chave e o destino desduplica.
    """
    att = record.get("attestation") or {}
    source = str(att.get("source_id") or "")
    identity = f"forge-telemetry:{source}:{lsn}"
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


def _export_lines(hdb: Path, from_lsn: int, limit: int | None = None):
    """Linhas cruas do exportador, já verificadas quanto ao contrato."""
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
            yield rec
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


def export_jsonl(hdb: Path, from_lsn: int, limit: int | None = None):
    """Produz `(lsn, fact)` — apenas Fatos Operacionais."""
    for rec in _export_lines(hdb, from_lsn, limit):
        if rec.get("record_type", "OperationalFact") != "OperationalFact":
            continue
        fact = rec["fact"]
        fact["_forge_export_attestation"] = rec.get("attestation") or {}
        yield rec["lsn"], fact


def export_all(hdb: Path, from_lsn: int, limit: int | None = None):
    """
    Produz `(lsn, record_type, payload)` — **tudo** o que está no log.

    Um registo íntegro que a ponte não soubesse encaminhar seria perda
    silenciosa: o log tem-no, o destino não, e ninguém repara. Por isso um tipo
    desconhecido não é ignorado — é erro (ver `run`).
    """
    for rec in _export_lines(hdb, from_lsn, limit):
        kind = rec.get("record_type", "OperationalFact")
        if kind == "OperationalFact":
            fact = rec["fact"]
            fact["_forge_export_attestation"] = rec.get("attestation") or {}
            yield rec["lsn"], kind, fact
        else:
            yield rec["lsn"], kind, rec


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
        "v": QUARANTINE_ENVELOPE_VERSION,
        "kid": quarantine_key_id(key or _quarantine_key()),
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
    expected_kid = quarantine_key_id(cipher_key)
    with open(path, encoding="ascii") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            if len(line) > QUARANTINE_MAX_LINE_BYTES:
                raise BridgeStateError(
                    f"quarentena: linha {number} excede {QUARANTINE_MAX_LINE_BYTES} bytes"
                )
            try:
                envelope = json.loads(line)
                version = envelope.get("v")
                if not isinstance(version, int) or not (
                    1 <= version <= QUARANTINE_ENVELOPE_VERSION
                ):
                    raise ValueError("versão desconhecida")
                # v2 traz a impressão digital da chave. Erro explícito de chave
                # rodada em vez de um "adulterada" que manda investigar o ataque
                # errado. Envelopes v1 (sem kid) continuam a ser aceites.
                kid = envelope.get("kid")
                if kid is not None and kid != expected_kid:
                    raise BridgeStateError(
                        f"quarentena: linha {number} foi cifrada com a chave {kid}, "
                        f"mas {QUARANTINE_KEY_ENV} é {expected_kid} — a chave rodou; "
                        f"use a anterior para ler este registo"
                    )
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
            for lsn, record_type, payload in export_all(hdb, from_lsn, limit):
                read += 1
                if record_type == "OperationalFact":
                    fact = payload
                    validation = validate_fact(lsn, fact)
                    if validation:
                        _quarantine(quarantine_path, lsn, fact, validation, key=quarantine_key)
                        errors.extend(validation)
                        break
                    ep = map_fact(lsn, fact, subject_secret=subject_secret)
                    source_identity, idempotency_key = source_event_identity(lsn, fact)
                elif record_type == TELEMETRY_KIND:
                    validation = validate_telemetry(lsn, payload)
                    if validation:
                        _quarantine(quarantine_path, lsn, payload, validation, key=quarantine_key)
                        errors.extend(validation)
                        break
                    ep = telemetry_episode(lsn, payload)
                    source_identity, idempotency_key = telemetry_event_identity(lsn, payload)
                else:
                    # Um tipo de registo que a ponte não sabe encaminhar não
                    # pode ser saltado em silêncio: o log tem-no e o destino
                    # não teria, sem ninguém reparar.
                    errors.append(f"LSN {lsn}: tipo de registo não encaminhável: {record_type!r}")
                    break
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
