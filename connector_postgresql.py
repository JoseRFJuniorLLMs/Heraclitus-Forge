"""
CASO DE USO 1 — Conector de log do PostgreSQL (ponta a ponta).

Demonstra a esteira completa da Heraclitus Suite descrita em `plataforma.md`:

    Forge (compila .hcx) -> Runner (executa) -> HeraclitusDB (grava)
                         -> HQLEngine (consulta) -> db.verify() (audita)

O PostgreSQL e o primeiro conector da biblioteca "Community" citada na monetizacao
(Linux, Windows, Nginx, Apache, PostgreSQL...). Detecta brute force de credenciais,
acesso a dados e violacoes de permissao a partir do log textual padrao do Postgres.
"""

import os
import json

from forge_compiler import HeraclitusForgeCompiler
from runner_engine import ReconstitutiveRunner
from heraclitus_db import HeraclitusDB
from hql_engine import HQLEngine

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY_DIR = os.path.join(HERE, "registry")
DB_PATH = os.path.join(HERE, "storage.hdb")
SAMPLE_LOG = os.path.join(HERE, "samples", "postgresql.log")


def _reset():
    for path in (DB_PATH, DB_PATH + ".anchor"):
        if os.path.exists(path):
            os.remove(path)


def main():
    _reset()
    print("#" * 72)
    print("#  HERACLITUS FORGE — CONECTOR POSTGRESQL (caso de uso 1)")
    print("#" * 72)

    # === 1. FORGE: compila o conhecimento do PostgreSQL em um artefato .hcx ===
    print("\n>>> [1/5] FORGE — compilando o conector PostgreSQL...\n")
    forge = HeraclitusForgeCompiler(output_dir=REGISTRY_DIR)
    artifact_path = forge.compile_knowledge(
        artifact_id="postgresql",
        vendor="PostgreSQL Global Development Group",
        sample_log='2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for user "admin"',
    )

    # === 2. RUNNER: carrega o artefato declarativo e otimiza ===
    print(">>> [2/5] RUNNER — instanciando kernel determinístico...\n")
    runner = ReconstitutiveRunner(artifact_path=artifact_path)
    runner.compile_and_optimize()

    # === 3. INGESTAO: log real do PostgreSQL -> Fatos Operacionais -> DB ===
    print("\n>>> [3/5] INGESTAO — processando samples/postgresql.log...\n")
    db = HeraclitusDB(db_path=DB_PATH)
    with open(SAMPLE_LOG, "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]

    for raw in lines:
        fact = runner.process_observation(raw)
        if fact is None:
            print(f"  [DRIFT] linha rejeitada (quarentena CKE): {raw[:60]}")
            continue
        lsn = db.write_fact(fact)
        b = fact["fact.behavior"]
        actor = fact["fact.identity"]["actor.name"]
        print(f"  LSN {lsn} | {b['action']:<24} | class={b['class']:<18} "
              f"| risk={b['risk_level']:<8} | actor={actor}")

    # === 4. HQL: consulta pericial pelo comportamento canonico ===
    print("\n>>> [4/5] HQL — consulta pericial (brute force de credenciais)\n")
    hql = HQLEngine(db_path=DB_PATH)
    query = (
        'FROM FACTS '
        'MATCH (actor.id, actor.name) EXECUTES "authentication.failure" AGAINST "postgresql" '
        'WITHIN LAST 6 HOURS '
        'SELECT fact.id, actor.name, fact.behavior.class, fact.behavior.risk_level, '
        'fact.confidence, integrity.merkle_root_anchor'
    )
    print(f">>> {query}\n")
    rows = hql.execute_query(query)
    print(f"[OK] Fatos extraidos: {len(rows)}")
    print(json.dumps(rows, indent=2, ensure_ascii=False))

    # === 5. AUDITORIA: integridade criptografica + simulacao de adulteracao ===
    print("\n>>> [5/5] AUDITORIA — db.verify() (cadeia Merkle)\n")
    r1 = db.verify()
    print(f"Auditoria inicial: {r1['status']} (Fatos: {r1.get('facts_verified')})")

    print("\n--- Simulando atacante adulterando o .hdb para apagar rastros ---")
    db.inject_malicious_tamper(target_lsn=db.current_lsn)
    r2 = db.verify()
    print(f"Auditoria pos-ataque: {r2['status']}")
    if r2["status"] != "INTEG_OK":
        print("[ALERTA FORENSE] Adulteracao detectada — valor probatorio preservado.")

    print("\n" + "#" * 72)
    print("#  PIPELINE POSTGRESQL CONCLUIDO")
    print("#" * 72)


if __name__ == "__main__":
    main()
