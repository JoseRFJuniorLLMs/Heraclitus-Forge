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
| `src/main.rs` | Conector PostgreSQL ponta a ponta (bin `connector_postgresql`). |
| `src/bin/bench.rs` | Benchmark de EPS (bin `bench`). |

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
```

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
