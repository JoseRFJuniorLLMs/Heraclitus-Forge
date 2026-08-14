# Heraclitus-Forge

Implementação da **Heraclitus Suite v6.0** — transforma observações heterogêneas
(logs) em **Fatos Operacionais** determinísticos e **tamper-evidentes**: cada Fato
é uma folha de uma cadeia Merkle rolante BLAKE3 ancorada em disco, com uma camada
física CRC-32C (CPM-200) por baixo. Qualquer adulteração ou bit-rot é **detectado**
no `verify()`.

A âncora (a raiz da cadeia) é **assinada com ed25519 real** (Marco B): a chave
privada vive fora do `.hdb` (`<db>.key`, 0600) e o `verify()` confere a
assinatura (`<db>.anchor.sig`) contra a pública fixada (`<db>.pub`). Um atacante
que reescreva `.hdb` + `.anchor` de forma consistente **não** consegue forjar a
assinatura sem a chave — o `verify()` deteta.

> **Nota de honestidade (ver [`AUDIT.md`](AUDIT.md)):** a segurança da assinatura
> depende de **proteger a chave privada** (`<db>.key`) — mantê-la 0600 e, em
> produção, fora da máquina que serve os dados. O campo por-Fato
> `fact.integrity.signature` é apenas uma **tag BLAKE3** (`b3tag:`), não uma
> assinatura — a assinatura autoritativa é a da âncora. O **consenso Raft** tem
> estado **durável** (term/voto/log em `<db>.raftmeta`/`.raftlog`), a regra de
> **Figura-8** e um **transporte TCP real** (`wire.rs`, spec §8), com teste de
> integração de 3 nós em localhost. Resta o **Marco D** (ingestão real + mais
> conectores) para "produção completa".

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
| `bridge.py` | **Ponte Forge → HeraclitusDB** — traduz os Fatos do `.hdb` para o [HeraclitusDB](https://github.com/JoseRFJuniorLLMs/HeraclitusDB) event-sourced (gRPC :7474). Ver [§ A ponte](#a-ponte-para-o-heraclitusdb). |

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

## A ponte para o HeraclitusDB

> **Dois sistemas, um nome.** O `HeraclitusDB` deste repositório (`rust/src/db.rs`)
> é o store append-only **embebido** do runtime — blocos `HERA`/`FACT`, âncora
> ed25519 externa, feito para line-rate na borda. O
> [HeraclitusDB](https://github.com/JoseRFJuniorLLMs/HeraclitusDB) é um projeto
> **separado**: um banco event-sourced em rede (gRPC :7474, segmentos `HRKL`/`HFTR`,
> grafo + vetor + texto). Os formatos são **incompatíveis** e nenhum lê o ficheiro
> do outro — por isso existe uma ponte, e não uma migração.

O `.hdb` continua a ser o buffer tamper-evidente de borda; o HeraclitusDB passa a
ser o sistema de registo durável e consultável.

```
.hdb ──► export_facts (Rust) ──JSONL──► bridge.py (Python) ──gRPC──► HeraclitusDB
         decodifica o formato            fala o SDK
```

```bash
cd rust && cargo build --release --bin export_facts && cd ..

python bridge.py                 # dry-run: mostra o mapeamento, não escreve
python bridge.py --apply         # escreve mesmo (retoma de onde ficou)
python bridge.py --apply --reset # reexporta desde o LSN 0
```

A ponte é **idempotente**: o último LSN exportado fica em `.bridge_state.json`, por
isso correr duas vezes não duplica. A **cadeia de custódia** atravessa a tradução —
`merkle_root_anchor`, `leaf_hash`, `integrity_signature` e `evidence_hash` viajam
nos `attrs`, para que um Fato no HeraclitusDB continue a poder ser ligado de volta
à cadeia BLAKE3 assinada do Forge. O mapa canónico é a função `bridge.map_fact()` —
é a **única** definição do contrato, e os testes importam-na em vez de a copiar.

Consultar do lado do HeraclitusDB:

```
MATCH (n:OperationalFact) WHERE n.agent_id = "heraclitus-forge" RETURN n
```

## Testes

```bash
cd rust && cargo test          # 28 testes do runtime
cd .. && pytest                # 19 testes da ponte (não escrevem em lado nenhum)
pytest -m live                 # + 2 ponta-a-ponta contra o HeraclitusDB real
```

Os testes `live` estão **de fora** por omissão: o HeraclitusDB local costuma ser um
banco a sério, não um sandbox — um `pytest` distraído não lhe deve acrescentar lixo.

## Conectores

`postgresql` (headline), `linux_sshd`, `keyvalue_generic` (fallback). Formatos
**desconhecidos** vão para a quarentena → o CKE propõe a semente → o Forge compila o
novo `.hcx` (com `forge_ai.py` + `ANTHROPIC_API_KEY`, a derivação é feita pelo Claude).
