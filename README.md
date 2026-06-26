# Heraclitus-Forge

Implementação de referência (simulação em Python) da **Heraclitus Suite v6.0** — a
pipeline que transforma observações heterogêneas (logs) em **Fatos Operacionais**
determinísticos, criptograficamente verificáveis.

```
Fabric (conecta) -> Forge (compila .hcx) -> Runner (executa) -> HeraclitusDB (grava)
                                                              -> HQLEngine (consulta)
```

## Módulos

| Arquivo | Papel (produto da suite) |
| --- | --- |
| `heraclitus_fabric.py` | **Fabric** — descobre ativos, baixa/compila o `.hcx`, sobe Runners, detecta Schema Drift. |
| `forge_compiler.py` | **Forge** — compila conhecimento em um artefato `.hcx` v6 declarativo (Design-Time). |
| `runner_engine.py` | **Runner** — Planner (Kahn) + Reasoner (regras) + Behavior Engine (janela deslizante). |
| `heraclitus_db.py` | **HeraclitusDB** — armazenamento append-only `.hdb` + `verify()` (cadeia Merkle). |
| `hql_engine.py` | **HQL** — consulta pericial sobre os Fatos (gramática EBNF da spec §10). |
| `connector_postgresql.py` | **Caso de uso 1** — conector de log do PostgreSQL, ponta a ponta. |

O comportamento de cada conector vive **inteiramente** no artefato `.hcx` (DSL
declarativa), nunca em código Python — exatamente o guardrail de segurança da spec.
Anatomia gerada pelo Forge (spec §5):

```
postgresql.hcx/
├── manifest.yaml       # metadados / governança
├── architecture.yaml   # DAG declarativa (depends_on) p/ o Planner
├── ontology.yaml       # core binding + confiança
├── reasoning.yaml      # regras de inferência do Reasoner
├── behavior.model      # assinaturas do Behavior Engine
├── test_matrix.json    # testes de regressão sintática (Coverage)
├── benchmarks.json     # selo metrológico (EPS, latência, coverage)
└── signature.sig       # assinatura Ed25519 (mock)
```

## Como rodar

Requisitos: Python 3 + PyYAML + BLAKE3 (`pip install -r requirements.txt`).

> A integridade forense (hash de evidência, folha e árvore Merkle) usa **BLAKE3**,
> conforme a spec (§8 wire checksum, §9 Merkle, "aplica o hash blake3").

```bash
# Caso de uso 1 — conector PostgreSQL ponta a ponta (recomendado)
python connector_postgresql.py

# Ciclo de vida "Segunda-Feira" do Fabric (descobre + compila + ingere 3 fontes)
python heraclitus_fabric.py

# Módulos isolados (cada um tem demo no __main__)
python forge_compiler.py     # compila o postgresql.hcx
python runner_engine.py      # executa o linux_sshd.hcx
python heraclitus_db.py      # grava + verify() + detecção de adulteração
python hql_engine.py         # consulta HQL
```

## Caso de uso 1 — Conector PostgreSQL

Lê o log textual padrão do PostgreSQL (`log_line_prefix = '%m [%p] %q%u@%d '`) e
detecta, sem regex manual em produção:

- `authentication.failure` — `FATAL: password authentication failed for user "..."`
  → escala para `brute_force_attack` (Critical) após 5 falhas em 60s (Behavior Engine).
- `authentication.success` — `connection authorized: user=... database=...`
- `query.execute` — `statement: ...`
- `authorization.failure` — `permission denied ...`

Amostra de entrada em [`samples/postgresql.log`](samples/postgresql.log).

## Conectores disponíveis

`postgresql` (headline), `linux_sshd` (SSH/syslog) e `keyvalue_generic` (fallback
para formatos proprietários `KEY=VALUE`, ex.: SIGRH). Novos conectores = novo
profile em `CONNECTOR_PROFILES` (`forge_compiler.py`), sem tocar no Runner.

## Runtime nativo em Rust (`rust/`)

O caminho quente de produção — **Runner** + **HeraclitusDB** — foi portado para
Rust em [`rust/`](rust/README.md), atingindo **~87.000 EPS** single-thread no Runner
(meta da spec: > 50.000). O Forge (IA/design-time) permanece em Python; o runtime
Rust apenas lê os artefatos `.hcx` homologados. Inclui **replicação Raft** orientada a
LSN (eleição, `AppendEntries` com `Previous_Merkle_Root`, fast-sync) — `cluster_demo`
mostra 3 nós convergindo após partição de rede. Veja [`rust/README.md`](rust/README.md).
