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

Retoma
------
O último LSN exportado por `.hdb` fica em `.bridge_state.json`. Correr duas
vezes seguidas não duplica nada — a segunda corrida não tem trabalho.

LIMITE CONHECIDO: a idempotência vem do ficheiro de estado, **não** do banco.
Se o `.bridge_state.json` se perder, ou se correr com `--reset`, os mesmos Fatos
são acrescentados outra vez — e o log do HeraclitusDB é append-only, esses
episódios não se apagam. Distinguem-se pelo `attrs.fact_id`, que é estável para
o mesmo Fato (o mesmo `fact_id` a aparecer duas vezes = reexportação, não dois
acontecimentos). Uma versão futura pode deduplicar consultando os `fact_id` já
presentes antes de escrever; hoje não o faz para não pagar uma query por Fato.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# A consola do Windows arranca em cp1252 e rebenta com "→"/"…". Passar a UTF-8
# com `errors="replace"` evita que um caractere no relatório mate a exportação.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # stream redirecionado/substituído
        pass

HERE = Path(__file__).resolve().parent
DEFAULT_HDB = HERE / "rust" / "storage_rs.hdb"
DEFAULT_STATE = HERE / ".bridge_state.json"
DEFAULT_ADDR = "127.0.0.1:7474"

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
SUBJECT_PREFIX = "titular:"

#: Usado quando o Fato não identifica um actor (log de sistema, ruído).
#: Fica num balde próprio para nunca se misturar com dados de uma pessoa.
NO_SUBJECT = "titular:_sem_titular"


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


def subject_of(fact: dict) -> str:
    """
    O titular dos dados deste Fato — vira o `agent_id`, que é a unidade de
    apagamento do HeraclitusDB (ver SUBJECT_PREFIX).

    Usa `actor.id` e não `actor.name`: o id é a chave estável da pessoa; o nome
    muda (casamento, correção de registo) e um apagamento que dependa do nome
    falha silenciosamente contra os Fatos gravados com o nome antigo.
    """
    actor = _flat(fact, "fact.identity", "actor.id") \
        or _flat(fact, "fact.identity", "actor.name")
    if not actor or actor == "unknown":
        return NO_SUBJECT
    return f"{SUBJECT_PREFIX}{actor}"


def map_fact(lsn: int, fact: dict) -> dict:
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
    attrs = {
        # --- identidade e comportamento (compatível com inserir.py) ---
        "actor_id":            _flat(fact, "fact.identity", "actor.id"),
        "actor_name":          _flat(fact, "fact.identity", "actor.name"),
        "target_id":           _flat(fact, "fact.identity", "target.id"),
        "source_ip":           _flat(fact, "fact.identity", "source.ip"),
        "action":              _flat(fact, "fact.behavior", "action"),
        "action_class":        _flat(fact, "fact.behavior", "class"),
        "risk_level":          _flat(fact, "fact.behavior", "risk_level"),
        "system_timestamp":    _flat(fact, "fact.time", "system_timestamp"),

        # --- cadeia de custódia (o que o inserir.py perdia) ---
        # Sem estes campos o Fato chega ao HeraclitusDB como um registo qualquer:
        # deixa de ser possível provar, a partir do HeraclitusDB, que ele saiu
        # íntegro do `.hdb`. `merkle_root_anchor` + `leaf_hash` são o que liga o
        # episódio de volta à cadeia BLAKE3 assinada do Forge.
        "fact_id":             fact.get("fact_id"),
        "evidence_hash":       _flat(fact, "fact.evidence", "raw_observation_hash"),
        "carimbo_tempo_legal": _flat(fact, "fact.evidence", "carimbo_tempo_legal"),
        "merkle_root_anchor":  _flat(fact, "fact.integrity", "merkle_root_anchor"),
        "leaf_hash":           _flat(fact, "fact.integrity", "leaf_hash"),
        "integrity_signature": _flat(fact, "fact.integrity", "signature"),
        "parser_signature":    _flat(fact, "fact.integrity", "parser_signature"),
        "confidence":          fact.get("fact.confidence"),
        "knowledge_version":   fact.get("fact.knowledge_version"),
        "ontology_version":    fact.get("fact.ontology_version"),
        "reasoning_version":   fact.get("fact.reasoning_version"),
        "matched_rule":        _flat(fact, "fact.lineage", "matched_rule"),
        "input_source":        _flat(fact, "fact.lineage", "input_source"),

        # --- proveniência da própria ponte ---
        # `producer` substitui o antigo uso do `agent_id` como marca de origem.
        # Filtrar tudo o que veio do Forge:  WHERE n.producer = "heraclitus-forge"
        "producer":            PRODUCER,
        "forge_lsn":           lsn,
        "generated_by":        "heraclitus_forge_bridge",
    }
    # Um attr ausente é ruído: o HeraclitusDB indexa chaves, e uma chave com
    # "None" é pior do que chave nenhuma numa query por atributo.
    attrs = {k: v for k, v in attrs.items() if v is not None and v != ""}

    return {
        "kind": KIND,
        "content": render_content(fact),
        "agent_id": subject_of(fact),
        # Agrupa os Fatos pelo artefato .hcx que os produziu — todas as leituras
        # de um mesmo conector versionado partilham a "sessão".
        "session_id": str(fact.get("fact.knowledge_version") or ""),
        "attrs": attrs,
    }


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
    target = os.environ.get("CARGO_TARGET_DIR") or str(HERE / "rust" / "target")
    name = "export_facts.exe" if os.name == "nt" else "export_facts"
    exe = Path(target) / "release" / name
    if not exe.exists():
        raise SystemExit(
            f"[ERRO] binário do exportador não encontrado: {exe}\n"
            f"       compile-o primeiro:  cd rust && cargo build --release --bin export_facts"
        )
    return str(exe)


def export_jsonl(hdb: Path, from_lsn: int, limit: int | None = None):
    """Corre o exportador Rust e produz `(lsn, fact)` linha a linha."""
    cmd = [exporter_bin(), str(hdb), "--from-lsn", str(from_lsn)]
    if limit:
        cmd += ["--limit", str(limit)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # Código 3 = houve blocos com CRC partido. Não é motivo para deitar fora os
    # Fatos íntegros — mas tem de aparecer no ecrã.
    if proc.returncode not in (0, 3):
        raise SystemExit(f"[ERRO] export_facts saiu com {proc.returncode}:\n{proc.stderr.strip()}")
    if proc.returncode == 3:
        print(f"[!] AVISO integridade: {proc.stderr.strip()}", file=sys.stderr)

    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            rec = json.loads(line)
            yield rec["lsn"], rec["fact"]


# ---------------------------------------------------------------------------
# Estado de retoma
# ---------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        print(f"[!] estado ilegível em {path}; a recomeçar do LSN 0", file=sys.stderr)
        return {}


def save_state(path: Path, hdb: Path, last_lsn: int, appended: int) -> None:
    st = load_state(path)
    key = str(hdb.resolve())
    prev = st.get(key, {})
    st[key] = {
        "last_lsn": last_lsn,
        "total_appended": prev.get("total_appended", 0) + appended,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path.write_text(json.dumps(st, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------

def run(hdb: Path, *, apply: bool, addr: str, state_path: Path,
        reset: bool, limit: int | None, batch: int) -> dict:
    if not hdb.exists():
        raise SystemExit(f"[ERRO] .hdb não encontrado: {hdb}")

    state = load_state(state_path)
    from_lsn = 0 if reset else int(state.get(str(hdb.resolve()), {}).get("last_lsn", 0))

    print("=== ponte Forge → HeraclitusDB ===")
    print(f"  origem : {hdb}")
    print(f"  destino: {addr if apply else 'DRY-RUN (nada será escrito)'}")
    print(f"  retoma : LSN > {from_lsn}\n")

    facts = list(export_jsonl(hdb, from_lsn, limit))
    if not facts:
        print("Nada de novo para exportar.")
        return {"read": 0, "appended": 0, "last_lsn": from_lsn, "errors": []}

    print(f"{len(facts)} Fato(s) novo(s) a exportar.\n")

    if not apply:
        for lsn, fact in facts[:3]:
            ep = map_fact(lsn, fact)
            print(f"  LSN {lsn} → kind={ep['kind']}  content={ep['content']!r}")
            print(f"          attrs={json.dumps(ep['attrs'], ensure_ascii=False)}\n")
        if len(facts) > 3:
            print(f"  … e mais {len(facts) - 3}.\n")
        print("Dry-run. Use --apply para escrever no HeraclitusDB.")
        return {"read": len(facts), "appended": 0, "last_lsn": from_lsn, "errors": []}

    import heraclitusdb  # só é preciso quando se escreve mesmo

    db = heraclitusdb.connect(addr)
    appended, errors, last_lsn = 0, [], from_lsn
    try:
        for i, (lsn, fact) in enumerate(facts, start=1):
            ep = map_fact(lsn, fact)
            try:
                db.append(ep["kind"], ep["content"], agent_id=ep["agent_id"],
                          session_id=ep["session_id"], attrs=ep["attrs"])
                appended += 1
                last_lsn = lsn
            except Exception as exc:
                # Parar no primeiro erro: o estado de retoma só avança até ao
                # último Fato mesmo escrito, por isso uma nova corrida continua
                # exatamente onde esta falhou — sem duplicar nem saltar.
                errors.append(f"LSN {lsn}: {type(exc).__name__}: {exc}")
                break
            if i % batch == 0:
                print(f"  … {i}/{len(facts)}", flush=True)
    finally:
        db.close()

    save_state(state_path, hdb, last_lsn, appended)

    print(f"\n{appended} Fato(s) escrito(s) no HeraclitusDB. Último LSN do Forge: {last_lsn}.")
    if errors:
        print(f"{len(errors)} erro(s):")
        for e in errors:
            print(f"  • {e}")
    print(f"Consultar:   MATCH (n:{KIND}) WHERE n.producer = \"{PRODUCER}\" RETURN n")
    print(f"Apagar (LGPD): admin(\"shred:{SUBJECT_PREFIX}<id do titular>\")"
          f"  — exige encryption_at_rest ligado")
    return {"read": len(facts), "appended": appended, "last_lsn": last_lsn, "errors": errors}


def main() -> None:
    p = argparse.ArgumentParser(
        description="Exporta os Fatos Operacionais do .hdb do Forge para o HeraclitusDB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Sem --apply, não escreve nada: mostra o mapeamento e sai.",
    )
    p.add_argument("--hdb", type=Path, default=DEFAULT_HDB, help=f"ficheiro .hdb (padrão: {DEFAULT_HDB})")
    p.add_argument("--apply", action="store_true", help="escreve mesmo (por omissão é dry-run)")
    p.add_argument("--addr", default=DEFAULT_ADDR, help=f"endereço gRPC (padrão: {DEFAULT_ADDR})")
    p.add_argument("--state", type=Path, default=DEFAULT_STATE, help="ficheiro de retoma")
    p.add_argument("--reset", action="store_true", help="ignora a retoma e exporta desde o LSN 0")
    p.add_argument("--limit", type=int, default=None, help="exporta no máximo N Fatos")
    p.add_argument("--batch", type=int, default=500, help="frequência do relatório de progresso")
    a = p.parse_args()

    r = run(a.hdb, apply=a.apply, addr=a.addr, state_path=a.state,
            reset=a.reset, limit=a.limit, batch=a.batch)
    sys.exit(1 if r["errors"] else 0)


if __name__ == "__main__":
    main()
