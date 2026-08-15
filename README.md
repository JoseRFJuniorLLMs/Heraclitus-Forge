# Heraclitus-Forge

O Heraclitus-Forge 1.0 transforma logs em **Fatos Operacionais** determinísticos,
assina a cadeia de custódia na borda e envia os fatos ao HeraclitusDB sem
duplicação. O runtime de ingestão é Rust; compilação de conectores, CKE e a ponte
gRPC são ferramentas Python fora do caminho crítico.

## Limite do produto

- O Forge recebe observações por arquivo/conector ou pelo `gateway /ingest`.
  Um coletor do órgão ainda é necessário para acompanhar journald, Event Log,
  PostgreSQL ou outra fonte em tempo real.
- O `.hdb` da borda usa blocos `HERA`/`FACT`, CRC-32C, cadeia BLAKE3 e âncora
  Ed25519. O HeraclitusDB em rede usa segmentos `HRKL`/`HFTR`. Os formatos não
  são intercambiáveis; `export_facts` + `bridge.py` é a fronteira oficial.
- O log bruto não é copiado para o banco central. Fatos fora do schema vão para
  quarentena XChaCha20-Poly1305 autenticada.

## Arquitetura

```text
fonte/collector -> Runner Rust -> .hdb assinado -> export_facts
                       |                              |
                       +-> quarentena .hq             +-> JSONL versionado
                                                           |
                                      bridge.py -> gRPC -> HeraclitusDB
```

O contrato está em [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md):

- Forge `1.0.x`;
- HeraclitusDB/SDK `1.0.5`;
- envelope `forge-heraclitusdb/1`;
- Fato `operational-fact/1.0`;
- API protobuf `heraclitus.v1`.

Versões desconhecidas falham antes do primeiro `Append`. Cada fato usa uma
chave idempotente derivada de `source_id + LSN + fact_id`; retry após perda do
ACK ou do checkpoint devolve o evento original.

## Registry assinado

`registry/` contém conectores versionados e assinados. A chave privada de
publicação nunca entra no repositório; `registry/publisher.pub` é a âncora de
confiança versionada.

```powershell
python forge_sign.py verify-all
python forge_sign.py verify registry\postgresql\v1.2.0.hcx
```

Conectores atualmente homologados no registry: PostgreSQL `1.0.0`–`1.2.0` e
Linux SSHD `1.0.0`–`1.1.0`.

## Instalação reproduzível

Python de CI: 3.12. O lock contém versões e hashes.

```powershell
uv pip sync --python 3.12 --require-hashes requirements.lock
uv pip install -e ..\HeraclitusDB\sdk\python
cd rust
cargo build --release --bins --locked
```

Dependências opcionais ficam separadas em `requirements-ai.txt` e
`requirements-dashboard.txt`. O Forge AI só inicia com `ANTHROPIC_API_KEY` e
`FORGE_AI_MODEL` explícitos; nenhum modelo fica silenciosamente hardcoded.

## Uso seguro

Os binários demonstrativos não criam dados por padrão. Para laboratório:

```powershell
cargo run --release --bin connector_postgresql -- --demo
cargo run --release --bin fabric -- --demo
cargo run --release --bin gateway -- --demo
cargo run --release --bin hql -- --demo
cargo run --release --bin cluster_demo -- --demo
cargo run --release --bin bench -- --demo 10000
```

Para uma fonte real, configure caminhos explícitos, segredo HMAC do titular e
chave da quarentena; faça primeiro o dry-run da ponte:

```powershell
$env:HERACLITUS_ARTIFACT = 'D:\seguro\registry\postgresql'
$env:HERACLITUS_SAMPLE = 'D:\entrada\cliente.log'
$env:HERACLITUS_DB_PATH = 'D:\dados\cliente\edge.hdb'
$env:FORGE_QUARANTINE_PATH = 'D:\dados\cliente\quarantine.hq'
$env:FORGE_QUARANTINE_KEY = '<64 hex em cofre>'
$env:FORGE_SUBJECT_HMAC_KEY = '<segredo >= 32 bytes em cofre>'
$env:HERACLITUS_TOKEN_FILE = 'D:\seguro\heraclitus\writer.token'

python bridge.py --hdb $env:HERACLITUS_DB_PATH
python bridge.py --hdb $env:HERACLITUS_DB_PATH --apply
```

Fora de loopback, a ponte recusa plaintext e exige
`HERACLITUS_TLS_CA`; para mTLS, configure também `HERACLITUS_TLS_CERT` e
`HERACLITUS_TLS_KEY`.

Consulta central:

```text
MATCH (n:OperationalFact)
WHERE n.producer = "heraclitus-forge"
RETURN n LIMIT 200
```

`agent_id` não identifica o produtor: ele é um HMAC do titular e define a
unidade de crypto-shredding LGPD. `session_id` também é HMAC porque a versão de
conhecimento pode carregar origem/alvo. A origem fica em `attrs.producer`.

## Testes e gates

```powershell
cd rust
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo audit --deny warnings

cd ..
ruff check .
ruff format --check .
pytest -m "not live"
python forge_sign.py verify-all
```

Os dois testes `live` são opt-in para não poluir um banco append-only real. A
CI executa os testes herméticos e a auditoria de dependências. O resultado e as
condicionantes de produção estão em [AUDIT.md](AUDIT.md).
