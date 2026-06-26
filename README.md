# Heraclitus-Forge

Implementação da **Heraclitus Suite v6.0** — transforma observações heterogêneas
(logs) em **Fatos Operacionais** determinísticos e criptograficamente verificáveis.

A divisão de linguagem segue a spec: o **runtime (caminho quente)** é todo **Rust**;
o que é **Design-Time / Knowledge-Cloud** (não line-rate) fica em **Python**.

```
Python (Design-Time / Cloud)            Rust (Runtime / Line-Rate)
  Forge  ── compila .hcx ──────────────►  Runner ─► HeraclitusDB ─► HQL
  Forge AI (Claude)                       Fabric (edge) ─► Gateway ─► Raft
  CKE (clusteriza quarentena) ◄── quarantine.log ◄── Fabric
```

## Python — Design-Time / Cloud (o que **deve** ser Python)

| Arquivo | Papel |
| --- | --- |
| `forge_compiler.py` | **Forge** — compila o conhecimento num artefato `.hcx` v6 declarativo. O Coverage é validado pelo **runner Rust real** (bin `coverage`), não por um runner Python. |
| `forge_ai.py` | **Forge AI** (opcional) — deriva conector de formatos desconhecidos via **Claude** (`messages.parse` + Pydantic, `claude-opus-4-8`). |
| `cke.py` | **CKE** (Knowledge Cloud) — clusteriza a quarentena (`quarantine.log` do Fabric) e gera sementes de novos conectores. |

> Latência de IA/compilação não afeta produção; orquestrar agentes e validar schema
> é muito mais ágil em Python — por isso o Forge **permanece** em Python (spec).

## Rust — Runtime / Line-Rate (todo o caminho quente)

Vive em [`rust/`](rust/README.md): **Runner** (Planner+Reasoner+Behavior), **HeraclitusDB**
(append-only + cadeia Merkle BLAKE3 + payload **zero-copy** `fbfact`), **HQL** nativo,
**Fabric** de borda (descoberta + Schema Drift), **Gateway** (axum/tokio) e **replicação
Raft**. Runner ~**87k EPS**; ponta-a-ponta ~**72k EPS**. Veja [`rust/README.md`](rust/README.md).

## Anatomia do `.hcx` (gerada pelo Forge, spec §5)

```
postgresql.hcx/
├── manifest.yaml      ├── reasoning.yaml     ├── benchmarks.json
├── architecture.yaml  ├── behavior.model     └── signature.sig
├── ontology.yaml      └── test_matrix.json
```

## Como rodar

Requisitos: Python 3 + PyYAML + BLAKE3 (`pip install -r requirements.txt`); Rust (MSVC
no Windows — ver [`rust/README.md`](rust/README.md)).

```bash
# 1. Design-Time (Python): compila os conectores em registry/*.hcx
python forge_compiler.py            # PostgreSQL (Coverage via runner Rust)

# 2. Runtime (Rust): compila e roda o caminho quente
cd rust && cargo build --release
cargo run --release --bin connector_postgresql   # ingestão -> Fatos -> verify -> tamper
cargo run --release --bin fabric                 # ciclo de borda -> quarantine.log
cargo run --release --bin hql                    # consulta pericial HQL
cargo run --release --bin cluster_demo           # replicação Raft (3 nós)
cargo run --release --bin gateway                # backend REST do dashboard (:7480)
cargo run --release --bin bench -- 1000000       # benchmark de EPS

# 3. Cloud (Python): o CKE evolui o conhecimento a partir da quarentena
python cke.py rust/quarantine.log   # clusteriza -> sementes de conector p/ o Forge
```

## Conectores

`postgresql` (headline), `linux_sshd`, `keyvalue_generic` (fallback). Formatos
**desconhecidos** vão para a quarentena → o CKE propõe a semente → o Forge compila o
novo `.hcx` (com `forge_ai.py` + `ANTHROPIC_API_KEY`, a derivação é feita pelo Claude).
