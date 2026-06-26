"""
HQL Engine — Heraclitus Query Language (Studio / consulta pericial).

Implementa a gramatica EBNF de `Operational-Fact.md` (secao 10):

    FROM FACTS
    MATCH (actor.id [, actor.name]) EXECUTES "action" AGAINST "object"
    [ WITHIN LAST <n> (MINUTES|HOURS|DAYS) ]
    SELECT field [, field ...]

A consulta varre o arquivo binario `.hdb` append-only e projeta apenas os Fatos que
casam com o comportamento canonico — sem se importar com a string do log original.
"""

import os
import json
import time
import struct
import re
from typing import List, Dict, Any

from heraclitus_db import HEADER_FORMAT, HEADER_SIZE

_UNIT_US = {"MINUTES": 60, "HOURS": 3600, "DAYS": 86400}

_QUERY_RE = re.compile(
    r"FROM\s+FACTS\s+"
    r"MATCH\s+\((?P<actor_vars>[^)]+)\)\s+"
    r'EXECUTES\s+"(?P<action>[^"]+)"\s+AGAINST\s+"(?P<target>[^"]+)"'
    r"(?:\s+WITHIN\s+LAST\s+(?P<amount>\d+)\s+(?P<unit>MINUTES|HOURS|DAYS))?"
    r"\s+SELECT\s+(?P<fields>.+)",
    re.IGNORECASE | re.DOTALL,
)


class HQLEngine:
    def __init__(self, db_path: str = "storage.hdb"):
        self.db_path = db_path

    def _parse_query(self, query_str: str) -> Dict[str, Any]:
        match = _QUERY_RE.match(query_str.strip())
        if not match:
            raise ValueError("Erro de Sintaxe HQL: a consulta nao obedece a gramatica EBNF v6.0.")
        plan = match.groupdict()
        plan["fields"] = [f.strip() for f in plan["fields"].split(",") if f.strip()]
        return plan

    @staticmethod
    def _resolve_field(fact: Dict[str, Any], field: str):
        """Mapeia um alias plano da HQL para a navegacao no Fato aninhado."""
        aliases = {
            "fact.id": ("fact_id",),
            "actor.id": ("fact.identity", "actor.id"),
            "actor.name": ("fact.identity", "actor.name"),
            "target.id": ("fact.identity", "target.id"),
            "source.ip": ("fact.identity", "source.ip"),
            "fact.behavior.class": ("fact.behavior", "class"),
            "fact.behavior.action": ("fact.behavior", "action"),
            "fact.behavior.risk_level": ("fact.behavior", "risk_level"),
            "fact.confidence": ("fact.confidence",),
            "fact.knowledge_version": ("fact.knowledge_version",),
            "lsn": ("fact.time", "log_sequence_number"),
            "timestamp": ("fact.time", "system_timestamp"),
            "integrity.merkle_root_anchor": ("fact.integrity", "merkle_root_anchor"),
            "integrity.signature": ("fact.integrity", "signature"),
        }
        path = aliases.get(field)
        if path is None:
            return fact.get(field)
        node = fact
        for key in path:
            if not isinstance(node, dict):
                return None
            node = node.get(key)
        return node

    def execute_query(self, query_str: str) -> List[Dict[str, Any]]:
        plan = self._parse_query(query_str)
        results: List[Dict[str, Any]] = []

        if not os.path.exists(self.db_path):
            return results

        cutoff_ts = None
        if plan["amount"] and plan["unit"]:
            span_us = int(plan["amount"]) * _UNIT_US[plan["unit"].upper()] * 1_000_000
            cutoff_ts = int(time.time() * 1_000_000) - span_us

        with open(self.db_path, "rb") as f:
            f.seek(8)  # pula o file header ('HERA' + versao)
            while True:
                header_bytes = f.read(HEADER_SIZE)
                if not header_bytes or len(header_bytes) < HEADER_SIZE:
                    break
                _magic, _lsn, _ts, _conf, _ev, payload_len = struct.unpack(HEADER_FORMAT, header_bytes)
                fact = json.loads(f.read(payload_len).decode("utf-8"))

                # Filtro comportamental/ontologico (MATCH ... EXECUTES ... AGAINST)
                fact_action = fact["fact.behavior"]["action"]
                fact_target = fact["fact.identity"]["target.id"]
                if plan["action"] not in ("*", fact_action):
                    continue
                if plan["target"] not in ("*", fact_target):
                    continue

                # Filtro temporal (WITHIN LAST ...)
                if cutoff_ts is not None and fact["fact.time"]["system_timestamp"] < cutoff_ts:
                    continue

                # Projecao (SELECT)
                results.append({field: self._resolve_field(fact, field) for field in plan["fields"]})

        return results


if __name__ == "__main__":
    from heraclitus_db import HeraclitusDB
    from runner_engine import ReconstitutiveRunner

    for path in ("storage.hdb", "storage.hdb.anchor"):
        if os.path.exists(path):
            os.remove(path)

    db = HeraclitusDB(db_path="storage.hdb")
    runner = ReconstitutiveRunner(artifact_path="./registry/postgresql.hcx")
    runner.compile_and_optimize()

    log_sample = '2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user "admin"'
    for _ in range(6):
        fact = runner.process_observation(log_sample)
        db.write_fact(fact)

    hql = HQLEngine(db_path="storage.hdb")
    query = (
        'FROM FACTS '
        'MATCH (actor.id, actor.name) EXECUTES "authentication.failure" AGAINST "postgresql" '
        'WITHIN LAST 2 HOURS '
        'SELECT fact.id, actor.name, fact.behavior.class, fact.confidence, integrity.merkle_root_anchor'
    )
    print(f"\n[HQL EXECUTOR] Submetendo consulta pericial:\n>>> {query}\n")

    rows = hql.execute_query(query)
    print(f"[OK] Consulta concluida. Fatos operacionais extraidos: {len(rows)}")
    print("-" * 60)
    print(json.dumps(rows, indent=2, ensure_ascii=False))
