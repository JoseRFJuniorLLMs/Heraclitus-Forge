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
| `src/db.rs` | Geração **HDB2**: append-only `.hdb`, cadeia Merkle rolante BLAKE3 (O(1)/append), `verify()` sobre os bytes gravados, âncora Ed25519 atómica. |
| `src/fact.rs` | Primitivas: UUIDv7, evidence hash BLAKE3, timestamp µs. |
| `src/hfb2.rs` | Registo canónico **HFB2**: identidade de segurança autenticada, extensões TLV, folha com separação de domínio. Ver [`md/HDB2-HFB2.md`](../md/HDB2-HFB2.md). |
| `src/crc32c.rs` | CRC-32C Castagnoli — camada física, deliberadamente separada da criptográfica. |
| `src/raft.rs` | Replicação Raft orientada a LSN: eleição, `AppendEntries` com `Previous_Merkle_Root`, validação do follower, fast-sync. |
| `src/main.rs` | Conector PostgreSQL ponta a ponta (bin `connector_postgresql`). |
| `src/bin/bench.rs` | Benchmark de EPS (bin `bench`). |
| `src/bin/cluster_demo.rs` | Demo de cluster Raft de 3 nós (bin `cluster_demo`). |
| `src/bin/gateway.rs` | Gateway de ingestão axum/tokio — backend REST do dashboard (bin `gateway`). |
| `src/hql.rs` + `src/bin/hql.rs` | HQL nativo (parser EBNF + projeção) varrendo o `.hdb` (bin `hql`). |
| `src/bin/probe.rs` | Probe de ingestão de ponta — socket **UDP syslog** real + Schema Drift (bin `probe`). |
| `src/bin/fabric.rs` | **Fabric** de borda nativo — discover → deploy runners → drift → `quarantine.log` (bin `fabric`). |
| `src/bin/coverage.rs` | Valida o `.hcx` contra o runner real; usado pelo Forge Python p/ calcular Coverage (bin `coverage`). |

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
| Runner-only (parse + reason + behavior) | **~87k–150k** | ≥1.74× a meta; este é o "processamento de eventos". |
| Ponta a ponta (Runner + append durável + integridade) | medir com `bench --demo` | um `fsync` e uma assinatura Ed25519 por Fato; `write_batch` amortiza ambos. |

### Custo do formato

O payload do `.hdb` é um registo binário canónico (HFB2), não JSON. O `bench`
mede as quatro etapas que interessam — `encode`, `decode`, folha BLAKE3 e
round-trip de uma extensão desconhecida — além da leitura zero-copy do campo
`action` (que valida a estrutura e lê `&str` direto do buffer, sem alocar) e do
`verify()` sobre o banco inteiro:

```powershell
cargo run --release --bin bench -- --demo 100000
```

Os números dependem da máquina; corra-o em vez de citar uma tabela. O que o
formato garante por construção é que verificar **não** exige desserializar: a
folha é calculada sobre os bytes persistidos.

O Runner é stateless exceto pelas janelas do Behavior Engine (indexadas por ator),
então escala quase linearmente no worker-pool lock-free previsto na spec (§2). A
cadeia Merkle rolante (`root = BLAKE3(root_anterior ‖ folha)`) custa O(1) por evento
e fornece o `Previous_Merkle_Root` exigido pela replicação Raft (§11).

## Paridade com o Python

Mesma classificação, mesma escalada para `brute_force_attack` na 5ª falha em 60s, e
mesma detecção `INTEG_OK → VIOLATED` sob adulteração. O formato `.hdb` é próprio do
runtime Rust (serialização independente); a interoperabilidade binária com o
`.hdb` Python pode ser um passo futuro se necessário.
