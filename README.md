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

## Implantação: o ingestor como serviço

Um ingestor que só corre quando alguém se lembra não é um ingestor. O `ingest`
sabe falar com o SCM do Windows — regista-se, arranca no boot e é reiniciado
automaticamente se morrer:

```powershell
cd windows
.orge-ingest-service.ps1 install `
    -Source   C:\logs
ginxccess.log `
    -Artifact D:\DEV\Heraclitus-Forgeegistry
ginx_access

.orge-ingest-service.ps1 status    # estado, conta, fonte, destino
.orge-ingest-service.ps1 logs      # segue o log rotativo diário
.orge-ingest-service.ps1 uninstall # remove o serviço; os dados ficam
```

Corre sob a **conta virtual** `NT SERVICE\HeraclitusForgeIngest`, com privilégio
mínimo: lê a fonte e o registry, escreve no data dir e nos logs. Nada mais.

O install **gera a `FORGE_QUARANTINE_KEY`** se ainda não existir e mostra-a uma
única vez — guarde-a em custódia. Sem ela a quarentena fica ilegível para sempre,
e é lá que ficam as observações que ainda não têm conector.

A configuração vai por ambiente de máquina (`FORGE_INGEST_SOURCE`,
`FORGE_INGEST_ARTIFACT`, `FORGE_INGEST_DB`), porque o SCM lança o binário sem
argumentos. Faltar uma delas é erro de instalação: o serviço regista o motivo no
log e **para**, em vez de o SCM ficar a reiniciar em ciclo algo que nunca vai
arrancar.

## Ingestão real

Os binários acima são **demonstrações** — o `connector_postgresql` apaga o
`.hdb` ao arrancar e adultera o último LSN ao sair, de propósito, para mostrar
que o `verify()` deteta. Para ler uma fonte a sério use o `ingest`:

```powershell
$env:FORGE_QUARANTINE_KEY = "<64 caracteres hex>"

# segue o ficheiro ao vivo, como um tail -f
cargo run --release --bin ingest -- C:\logs\postgresql.log `
    --artifact ..\registry\postgresql --db producao.hdb --follow

# ou processa o que houver e sai (bom para agendar)
cargo run --release --bin ingest -- amostra.log `
    --artifact ..\registry\linux_sshd --db producao.hdb --from-start --once
```

O `ingest` **abre** o `.hdb` existente (recupera LSN e cadeia Merkle), nunca
apaga e nunca adultera. Retoma de onde ficou por um sidecar `<db>.ingest-state`,
deteta rotação e truncagem do ficheiro, e só processa linhas completas — uma
linha ainda a ser escrita espera pela passagem seguinte.

Linhas que nenhuma regra do artefato casa (Schema Drift) vão para a **quarentena
cifrada**, nunca para o ecrã: podem conter dados pessoais. Daí a
`FORGE_QUARANTINE_KEY` ser obrigatória.

Num ficheiro que ainda não conhece, começa no **fim**. Arrancar a ler um log de
meses inundaria o banco com histórico que ninguém pediu; `--from-start` é
explícito para quem quer o histórico.

> **Entrega pelo menos uma vez.** O deslocamento é gravado depois de os Fatos
> irem para o disco, por isso uma paragem abrupta pode reprocessar as últimas
> linhas. É o compromisso certo aqui: num sistema de auditoria, repetir é
> recuperável, perder não é.

Para a ponte, configure caminhos explícitos, segredo HMAC do titular e
chave da quarentena; faça primeiro o dry-run:

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
