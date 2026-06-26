# heraclitus-forge (Rust) — runtime nativo line-rate

Porte para Rust do **caminho quente de produção**: o **Runner** (transformação
line-rate) e o **HeraclitusDB** (append-only). O **Forge** (compilação de
conhecimento, com IA) permanece em Python — como manda a spec, a esteira de IA é
isolada do runtime determinístico. O runtime Rust apenas **lê os artefatos `.hcx`**
já compilados e homologados.

```
Forge (Python, design-time)  ──>  .hcx  ──>  Runner + HeraclitusDB (Rust, runtime)
```

## Componentes

| Arquivo | Papel |
| --- | --- |
| `src/runner.rs` | Planner (Kahn) + Parser (regex/keyvalue) + Reasoner (regras `.hcx`) + Behavior Engine (janela deslizante). |
| `src/db.rs` | Append-only `.hdb`, cadeia Merkle rolante BLAKE3 (O(1)/append), `verify()`, detecção de adulteração. |
| `src/fact.rs` | Primitivas: UUIDv7, evidence hash BLAKE3, timestamp µs. |
| `src/raft.rs` | Replicação Raft orientada a LSN: eleição, `AppendEntries` com `Previous_Merkle_Root`, validação do follower, fast-sync. |
| `src/main.rs` | Conector PostgreSQL ponta a ponta (bin `connector_postgresql`). |
| `src/bin/bench.rs` | Benchmark de EPS (bin `bench`). |
| `src/bin/cluster_demo.rs` | Demo de cluster Raft de 3 nós (bin `cluster_demo`). |
| `src/bin/gateway.rs` | Gateway de ingestão axum/tokio — backend REST do dashboard (bin `gateway`). |

## Pré-requisito de toolchain (Windows)

Este projeto usa a ABI **MSVC** (o host GNU exige MinGW/`dlltool`, normalmente
ausente). Com o Visual Studio / Build Tools instalado:

```powershell
rustup override set stable-x86_64-pc-windows-msvc   # nesta pasta
# ou: rustup default stable-msvc
```

## Build & execução

> O Runner lê `../registry/postgresql.hcx`, gerado pelo Forge Python.
> Rode antes, na raiz do repo: `python forge_compiler.py`

```powershell
cargo build --release

# Conector PostgreSQL (ingestão -> Fatos -> verify -> tamper)
cargo run --release --bin connector_postgresql

# Benchmark (N eventos, default 1.000.000)
cargo run --release --bin bench -- 1000000

# Cluster Raft de 3 nós (eleição -> replicação -> partição -> fast-sync)
cargo run --release --bin cluster_demo

# Gateway de ingestão (backend do dashboard) em http://127.0.0.1:7480
cargo run --release --bin gateway
```

## Gateway de ingestão (backend do dashboard)

`gateway` (axum + tokio) é o backend REST que liga o dashboard ao runtime. Roda um
stream de ingestão contínuo (Runner → HeraclitusDB) e expõe, com CORS aberto:

| Rota | Resposta |
| --- | --- |
| `GET /facts?limit=N` | `{ "facts": [ <OperationalFact>, … ] }` (mais recentes 1º) |
| `GET /stats` | `{ "head", "events", "lsn" }` (KPIs / badge "ao vivo") |
| `GET /healthz` | `ok` |

Escuta em `127.0.0.1:7480` (a `7475` é do HeraclitusDB de produção, que responde
`panta rhei`). No dashboard, clique no badge e aponte para `http://127.0.0.1:7480`.

## Replicação Raft (spec §11)

Raft modificado para logs **imutáveis append-only**: a ordem global é o **LSN** e cada
`AppendEntries` carrega o `Previous_Merkle_Root`. Um follower só aplica um bloco se
`Last_LSN == Current_LSN − 1` **e** se a raiz da cadeia Merkle local, após recalcular,
bater com a âncora embutida pelo líder (`db.append_replicated_block`). Inconsistência
→ rejeição → o líder retrocede o `next_index` e faz **fast-sync** (re-stream dos blocos
a partir do último ponto de integridade comum — o backtracking de log do Raft).

`cluster_demo` exercita: eleição de líder → replicação de Fatos → **partição de rede**
isolando um nó enquanto novos Fatos são commitados → **cura** com fast-sync. Ao final os
3 nós convergem para o mesmo LSN e a **mesma raiz Merkle**, com `verify() == INTEG_OK`
em todos — a garantia de alta disponibilidade da spec.

> Simulação determinística dirigida por ticks (sem rede real, reproduzível). Em produção
> os mesmos `Msg` viajam pelo Wire Protocol TCP (§8). Como o log é imutável, o follower
> persiste no aceite (otimização da spec); eleição usa timeouts distintos — PreVote e
> persistência de `term`/`votedFor` ficam como evolução.

## Desempenho (single-thread, release)

Meta da spec: **> 50.000 EPS** em velocidade de linha.

| Caminho | EPS | Observação |
| --- | --- | --- |
| Runner-only (parse + reason + behavior) | **~87.000** | 1.74× a meta; este é o "processamento de eventos". |
| Ponta a ponta (Runner + append durável + integridade) | **~43.000** | inclui dupla serialização JSON + BLAKE3 + I/O. |

O Runner é stateless exceto pelas janelas do Behavior Engine (indexadas por ator),
então escala quase linearmente no worker-pool lock-free previsto na spec (§2). A
cadeia Merkle rolante (`root = BLAKE3(root_anterior ‖ folha)`) custa O(1) por evento
e fornece o `Previous_Merkle_Root` exigido pela replicação Raft (§11).

## Paridade com o Python

Mesma classificação, mesma escalada para `brute_force_attack` na 5ª falha em 60s, e
mesma detecção `INTEG_OK → VIOLATED` sob adulteração. O formato `.hdb` é próprio do
runtime Rust (serialização independente); a interoperabilidade binária com o
`.hdb` Python pode ser um passo futuro se necessário.
