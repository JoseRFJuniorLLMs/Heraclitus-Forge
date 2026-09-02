# Heraclitus-Forge

O Heraclitus-Forge 2.0 transforma logs em **Fatos Operacionais** determinísticos,
assina a cadeia de custódia na borda e envia os fatos ao HeraclitusDB sem
duplicação. O runtime de ingestão é Rust; compilação de conectores, CKE e a ponte
gRPC são ferramentas Python fora do caminho crítico.

## Limite do produto

- O Forge recebe observações por arquivo/conector ou pelo `gateway /ingest`.
  Um coletor do órgão ainda é necessário para acompanhar journald, Event Log,
  PostgreSQL ou outra fonte em tempo real.
- O `.hdb` da borda está na geração **HDB2**: blocos `FCT2` com registos
  canónicos `HFB2`, CRC-32C na camada física e folha BLAKE3 com separação de
  domínio + âncora Ed25519 na camada criptográfica. Ficheiros da geração
  anterior (HDB1) são **recusados por nome**, sem migração automática — ver
  [md/HDB2-HFB2.md](md/HDB2-HFB2.md). O HeraclitusDB em rede usa segmentos
  `HRKL`/`HFTR`; os formatos não são intercambiáveis e `export_facts` +
  `bridge.py` é a fronteira oficial.
- `tenant_id`, `datasource_id` e `sensor_id` são campos autenticados de todo o
  registo, não metadados opcionais: alterá-los muda a folha e a raiz Merkle. Não
  existe valor por omissão para eles, e o ingestor recusa arrancar sem os três.
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

- Forge `2.0.x`;
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

O Runner Rust repete essa verificação antes de interpretar YAML ou compilar
regex. Por padrão ele encontra `publisher.pub` no registry ancestral; pacotes
instalados noutro layout devem fixar a trust root explicitamente:

```powershell
$env:HERACLITUS_PUBLISHER_PUB = "C:\ProgramData\Heraclitus\trust\publisher.pub"
```

Assinatura ausente, chave diferente, digest divergente, selo legado ou link
simbólico dentro do pacote impedem o datasource de iniciar.

Conectores atualmente homologados no registry: PostgreSQL `1.0.0`–`1.2.0`,
Linux SSHD `1.0.0`–`1.1.0`, nginx/Apache `1.0.0` e Windows Security `1.0.0`.

O inventário executável do baseline lista todos os binários, adapters e `.hcx`,
vinculados aos commits do Forge e do HeraclitusDB:

```powershell
python tools\forge_inventory.py --check
```

## Modelo canónico de segurança

Um Fato Operacional diz o que aconteceu naquela fonte. Correlacionar quatro
fontes exige que "falha de autenticação" signifique a mesma coisa nas quatro —
é isso o `heraclitus-security-event/1.0` (SPEC-0071 §4), definido em
[rust/crates/heraclitus-security-schema](rust/crates/heraclitus-security-schema).

O crate tem tipos, validação, canonicalização e os **mappings versionados**.
Não tem rede, armazenamento, IA nem parsing de vendor: pode ser auditado
isolado. O contrato para quem não é Rust é o
[`security_event.proto`](rust/crates/heraclitus-security-schema/schema/security_event.proto),
mantido alinhado com o modelo por um teste de paridade.

O `.hcx` declara a que modelo pertence e qual mapping o traduz:

```yaml
security:
  security_schema: heraclitus-security-event/1.0
  category: identity            # categoria PRIMÁRIA; as ações sobrepõem-na
  mapping_version: windows-security/1.0.0
  required_fields:
  - observed_at_micros
  - datasource_id
  - sensor_id
```

**Compatibilidade.** `operational-fact/1.0` não mudou. Um `.hcx` sem bloco
`security:` é um conector legado: produz Fatos válidos e não produz eventos
canónicos — e a ausência nunca autoriza inventar campos canónicos na leitura.
`postgresql/v1.1.0` continua publicado exatamente assim, de propósito.

**Não inventar.** Campo que a fonte não observou sai `null`. O `-` do log
combinado e o `IpAddress=-` do Windows são ausência, não identidade. Ação que o
mapping não declara é erro, não um valor por omissão. `log.info` e `log.unknown`
são ruído operacional: continuam a ser Fatos e não viram evento de segurança.

**Limite conhecido.** O Fato `1.0` ainda só carrega o instante de *ingestão*: o
parser extrai o carimbo da linha e não o emite. Por isso `observed_at_micros` é
hoje uma aproximação, e diz-o em `extensions["heraclitus.observed_at_source"] =
"ingest_fallback"`. Emitir o carimbo da fonte é trabalho do Fabric (Marco 2) —
até lá, a deteção de clock skew não tem base para funcionar, e o evento não
finge que tem.

Os golden fixtures em [rust/tests/golden](rust/tests/golden) gravam o evento
canónico de cada caso da `test_matrix.json` dos quatro conectores, produzido
pelo Runner real sobre o artefato assinado. Republicar um conector muda o
`connector_digest` e, portanto, o golden:

```powershell
cd rust
$env:UPDATE_GOLDEN = "1"; cargo test --test canonical_golden   # e REVER o diff
```

**Ligado ao caminho quente.** O Runner resolve o mapping no load do `.hcx` — um
artefato que declare um mapping inexistente, de outro conector, ou com categoria
ou `required_fields` divergentes, **impede o datasource de iniciar** — e emite
`fact.security` junto com o Fato. O registo HFB2 autentica-o: alterar o evento
muda a folha BLAKE3. `ingest`, `probe` e `gateway` são os emissores.

A identidade (`tenant_id`, `datasource_id`, `sensor_id`) vem do supervisor, não
do conteúdo do log, e o `forge_lsn` do evento é confirmado contra o LSN que a
escrita devolveu: se divergirem, o ingestor pára em vez de gravar uma cadeia de
custódia que não se sustenta.

A ponte valida o evento e recusa um que descreva outra observação, outra regra
ou outro conector.

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
    -Artifact D:\DEV\Heraclitus-Forge
egistry
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
    --tenant gov.br/orgao-a --datasource "postgresql://db-01/postgresql.log" `
    --sensor forge-edge-01 `
    --artifact ..\registry\postgresql --db producao.hdb --follow

# ou processa o que houver e sai (bom para agendar)
cargo run --release --bin ingest -- amostra.log `
    --tenant gov.br/orgao-a --datasource "sshd://bastion-01/auth.log" `
    --sensor forge-edge-01 `
    --artifact ..\registry\linux_sshd --db producao.hdb --from-start --once
```

`--tenant`, `--datasource` e `--sensor` são **obrigatórios** e não têm valor por
omissão: viajam autenticados em cada registo, e um deles adivinhado seria uma
falha de isolamento gravada de forma indelével na cadeia de custódia. O
`--datasource` identifica a fonte — não é o caminho do ficheiro.

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
