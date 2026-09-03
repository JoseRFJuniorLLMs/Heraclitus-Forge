# HDB2 / HFB2 — geração física e registo canónico

Este documento descreve o formato **implementado**. Onde algo não está feito,
está dito que não está.

Implementação: [`rust/src/hfb2.rs`](../rust/src/hfb2.rs) (registo),
[`rust/src/db.rs`](../rust/src/db.rs) (geração física e cadeia),
[`rust/src/crc32c.rs`](../rust/src/crc32c.rs).

## 1. Porque houve uma rutura

No HDB1 a folha criptográfica era calculada **reserializando** o Fato:

```text
bytes no disco -> decode -> Value -> encode_core -> BLAKE3 -> comparar
```

Três consequências, todas estruturais:

1. **A integridade era função do código, não dos bytes.** Qualquer campo
   acrescentado ao codec mudava a folha de ficheiros que ninguém tocou. Era
   impossível evoluir o formato sem invalidar história.
2. **O que o codec não entendia desaparecia.** O encoder tinha uma lista fixa de
   campos; um campo desconhecido era descartado na escrita — e o teste de
   round-trip passava na mesma, porque ambos os lados o descartavam.
3. **`tenant_id`, `datasource_id` e `sensor_id` não existiam.** Não havia onde
   os pôr sem cair em (1) ou em (2).

O HDB2 inverte a direção:

```text
bytes canónicos persistidos -> folha BLAKE3 -> cadeia Merkle -> âncora Ed25519
```

**Não há compatibilidade com HDB1/HFB1 e não há migração.** Abrir um ficheiro da
geração anterior produz:

```text
Unsupported database generation: HDB1
Expected: HDB2
```

## 2. Geração física

```text
master:  "HDB2" (4) | generation u32 = 2 (4)

bloco:   "FCT2" (4) | lsn u64 (8) | leaf [32] | chain_root [32]
         | record_len u32 (4) | header_crc32c u32 (4)         = 84 bytes
         | registo HFB2 (record_len bytes)
```

`leaf` e `chain_root` são valores **derivados** e por isso vivem no bloco, nunca
dentro do registo: gravar dentro do registo um hash do próprio registo é
circular. Foi assim que se eliminou a necessidade de um `encode_core` separado.

O `verify()` recalcula ambos a partir dos bytes e compara. O `lsn` aparece no
bloco *e* no registo; divergirem é violação (permite varrer sem interpretar o
registo, sem confiar no que se varreu).

## 3. Registo HFB2

```text
off  tam  campo                        autenticado
  0    4  magic "HFB2"                     sim
  4    2  format_version (=2)              sim
  6    2  flags (reservado, = 0)           sim
  8    2  record_type                      sim
 10    2  reservado (= 0)                  sim
 12    4  schema_id                        sim
 16    2  schema_major                     sim
 18    2  schema_minor                     sim
 20   16  event_id (UUID em bytes)         sim
 36    8  system_timestamp_micros (i64)    sim
 44    8  lsn (u64; 0 = não atribuído)     sim
 52    4  tenant_id_len                    sim
 56    4  datasource_id_len                sim
 60    4  sensor_id_len                    sim
 64    4  core_len                         sim
 68    4  extensions_len                   sim
 72    -  tenant_id | datasource_id | sensor_id | core | extensions   sim
  -    4  crc32c                           não (ver §7)
```

`tenant_id`, `datasource_id` e `sensor_id` são **campos estruturais do cabeçalho
autenticado**, não extensões opcionais. São eles que decidem isolamento
multi-tenant, autorização, correlação, Telemetry Health e cadeia de custódia:
protegê-los apenas com CRC deixaria a atribuição de um evento a outro órgão ao
alcance de quem consiga escrever no ficheiro. Alterar qualquer um muda a folha —
e logo a raiz Merkle.

Não há `Default` para a identidade e não há valor por omissão: um `tenant_id`
implícito é uma falha de isolamento à espera de acontecer. O caminho operacional
(`ingest`) recusa arrancar sem `--tenant/--datasource/--sensor`; os binários de
demonstração declaram-se explicitamente como demo.

### Tipos de registo

| `record_type` | Schema | Core |
|---|---|---|
| `1` | `operational-fact/1.0` (id 1) | campos do Fato, abaixo |
| `2` | `heraclitus-telemetry-health/1.0` (id 2) | uma string: o envelope, opaco |

O evento de saúde do sensor vive no **mesmo log** dos Fatos, com a mesma
identidade autenticada e a mesma folha. É deliberado: um sensor não consegue
esconder que esteve cego sem partir a cadeia Merkle que assina a evidência. O
core é opaco porque a semântica pertence ao consumidor
(`heraclitus-telemetry-health`, no HeraclitusDB) e não ao formato de
armazenamento.

### Core do `operational-fact/1.0` (`record_type = 1`, `schema 1/1.0`)

```text
opt_str actor.id | actor.name | target.id | source.ip
str     behavior.class | behavior.action | behavior.risk_level
u8      evidence_algorithm (1 = BLAKE3)
[32]    evidence_hash
u32     lineage_count  +  str * n
str     lineage.input_source | lineage.matched_rule
u32     confidence_ppm (0..=1 000 000)
str     knowledge_version | reasoning_version | ontology_version
```

## 4. Canonicalização

A propriedade obrigatória é:

```text
mesma informação lógica  =  mesmos bytes  =  mesma folha
```

| Elemento | Regra |
|---|---|
| Ordem de bytes | big-endian, sempre |
| Inteiros | largura fixa (u8/u16/u32/u64/i64); **sem varints** — um varint tem várias codificações para o mesmo valor |
| Booleanos | não existem no core; presença é `0x00`/`0x01` e qualquer outro valor é recusado |
| Strings | `u32` comprimento + UTF-8 validado; sem terminador, sem padding |
| Opcionais | byte de presença + (se presente) string. Ausente ≠ vazio, e nenhum comprimento mágico serve de sentinela |
| Ponto flutuante | **não é admitido**; a confiança viaja como inteiro em partes por milhão |
| Timestamps | `i64` microssegundos desde a época UNIX |
| UUID | 16 bytes crus; a forma textual é derivada na leitura |
| Campos reservados | têm de ser zero; diferente de zero é recusado |
| Extensões | ordenadas por `(tag, valor)` ascendente |
| Extensões repetidas | duplicado byte a byte é recusado; tags *singleton* não podem repetir |

A ordem canónica das extensões é imposta na **leitura**, não apenas na escrita.
Sem isso o mesmo conteúdo lógico teria várias codificações válidas e a folha
deixaria de identificar conteúdo.

## 5. Extensões

`tag: u32` = `namespace(16 bits) << 16 | índice(16 bits)`.

| Namespace | Valor |
|---|---|
| `security` | `0x0001` |
| `telemetry` | `0x0002` |
| `identity` | `0x0003` |
| `network` | `0x0004` |
| `cloud` | `0x0005` |
| `provenance` | `0x0006` |
| `case` | `0x0007` |
| `evidence` | `0x0008` |
| `vendor` | `0xFFFF` |

Definidas hoje:

| Tag | Nome | Conteúdo |
|---|---|---|
| `0x00010001` | `security.canonical_event` | evento `heraclitus-security-event/1.0` em JSON compacto |
| `0x00080001` | `evidence.legal_receipt` | recibo de carimbo de tempo legal |

**As extensões fazem parte integral da integridade criptográfica.** Não existe
"core protegido por Merkle, extensões protegidas por CRC": a folha cobre o corpo
inteiro.

### Campos desconhecidos

Um leitor que não conheça uma tag consegue: ler os limites do campo, preservar
`tag + bytes`, verificar a integridade do registo e reemiti-lo sem perder nada.
No JSON do Fato, as tags desconhecidas viajam em `fact.extensions` como
`{tag, namespace, value_hex}`; as conhecidas são projetadas no seu lugar
semântico (`fact.security`, `fact.evidence.carimbo_tempo_legal`).

Uma tag com projeção semântica **não pode** aparecer também em
`fact.extensions`: duas representações do mesmo dado destroem a canonicalização,
e isso é recusado.

## 6. Verificação sem descodificador semântico

`RecordView::parse` valida magic, versão, campos reservados, fronteiras,
comprimentos, UTF-8 das identidades, ordem canónica das extensões e CRC — **sem
interpretar o core nem o conteúdo das extensões**. `RecordView::leaf()` calcula
a folha a partir daí.

Consequência: uma versão anterior do binário, perante um registo com uma
extensão nova ou um `record_type` novo, consegue afirmar

```text
registo estruturalmente válido
integridade criptográfica válida
semântica da extensão X desconhecida
```

que é o requisito de arquitetura. `decode_fact` (a camada semântica) recusa um
`record_type` desconhecido em vez de o adivinhar.

## 7. Separação de domínio

Um hash sem domínio é ambíguo: os mesmos 32 bytes podiam ser lidos como folha,
como nó de Merkle ou como mensagem assinada, e uma prova de um contexto passaria
a valer noutro. Cada uso protocolar tem o seu prefixo, seguido de `0x00`:

| Domínio | Uso |
|---|---|
| `HERACLITUS/HFB2/RECORD-LEAF/v1` | folha do registo |
| `HERACLITUS/HDB2/MERKLE-NODE/v1` | nó da cadeia rolante |
| `HERACLITUS/HDB2/ANCHOR/v1` | mensagem que a âncora assina |
| `HERACLITUS/SCHEMA/v1` | identidade compacta de um schema |

```text
leaf   = BLAKE3(RECORD-LEAF || 0x00 || format_version || schema_id || major || minor || corpo)
root_n = BLAKE3(MERKLE-NODE || 0x00 || root_(n-1) || leaf_n)      root_0 = 32 zeros
âncora = Ed25519(ANCHOR || 0x00 || root || last_lsn)
```

`corpo` = o registo tal como está no disco, **menos** os 4 bytes finais de CRC.
O CRC fica de fora do material criptográfico por duas razões: não acrescenta
entropia (é função dos mesmos bytes) e misturá-lo baralharia as
responsabilidades das duas camadas. A assinatura inclui o `last_lsn` para que
uma âncora antiga não possa ser reapresentada como válida para um log mais
curto.

## 8. Identidade de schema

O cabeçalho carrega `schema_id`, `schema_major`, `schema_minor` — e esses bytes
entram também, em separado, na folha. A associação registo ↔ schema é
inequívoca **sem tabela externa**: `SchemaIdentity::hash()` é calculável por
quem não saiba o que o schema significa. A tabela de nomes legíveis
(`operational-fact/1.0`) existe só para diagnóstico; a verificação nunca depende
dela.

Isto prepara — e não implementa — a ligação futura a `.hcx`, Content Hub e ao
modelo canónico de segurança, incluindo schemas com publisher, assinatura e
política de confiança.

## 9. Duas camadas, duas responsabilidades

| Camada | Mecanismo | Deteta | Não deteta |
|---|---|---|---|
| Física | CRC-32C Castagnoli | bit-rot, disco a falhar, escrita truncada | adversário (recalcula o CRC) |
| Criptográfica | BLAKE3 com domínio + Ed25519 | adulteração intencional, reordenação, extensão do log | corrupção que o CRC apanha primeiro (por desenho) |

O CRC **não** foi removido por existir BLAKE3: responde depressa e localmente,
e é ele que distingue "disco com um bit trocado" de "alguém mexeu aqui".

## 10. Escrita e recuperação

```text
write  -> montar bytes canónicos -> escrever -> fsync -> SÓ ENTÃO avançar estado -> âncora atómica
verify -> ler bytes -> validar estrutura -> recalcular folha -> comparar -> dobrar cadeia -> âncora
```

No HDB1 o LSN e a raiz avançavam **antes** de qualquer I/O e não havia rollback:
um único `ENOSPC` transitório deixava o `FactStore` a descrever um bloco que
nunca chegou ao disco, e o banco ficava irrecuperável para sempre. No HDB2 o
estado só avança depois do `fsync` — há um teste que o prova.

A âncora (raiz + LSN + assinatura) é **um** ficheiro, escrito por
`tmp -> fsync -> rename`. Com dois ficheiros existia um estado intermédio em que
a raiz era nova e a assinatura velha, e o banco reabria a acusar adulteração
onde só tinha havido falta de luz.

### Estados do `verify()`

| Estado | Significado |
|---|---|
| `INTEG_OK` | cadeia recalculada bate com a âncora assinada |
| `VIOLATED` | folha, cadeia, CRC, LSN ou assinatura divergem |
| `ANCHOR_BEHIND` | log íntegro, com blocos **além** do último ponto assinado |
| `UNSUPPORTED` | geração HDB1 |
| `CORRUPTED` | cabeçalho mestre inválido |
| `ERROR` | ficheiro ausente ou ilegível |

`ANCHOR_BEHIND` é o corte de energia entre o `fsync` do bloco e a gravação da
âncora — e é **também** o que se veria se alguém tivesse acrescentado blocos sem
a chave. A partir do ficheiro as duas hipóteses são indistinguíveis, portanto o
banco **não** se auto-repara: reassinar automaticamente destruiria exatamente a
propriedade que a âncora existe para garantir. O estado é nomeado com o número
de blocos por assinar para que quem opera decida. **Não há hoje uma operação de
reparação implementada**: o procedimento, os critérios de aceitação e as peças
que faltam construir estão em [ANCHOR-BEHIND.md](ANCHOR-BEHIND.md).

## 11. Limites (entrada hostil)

| Limite | Valor |
|---|---|
| Registo | 16 MiB |
| String do core | 1 MiB |
| Identificador | 512 bytes, sem caracteres de controlo |
| Extensões | 256 por registo |
| Valor de extensão | 8 MiB |
| Passos de lineage | 64 |

Nenhum comprimento lido do disco é usado para alocar antes de ser confrontado
com os bytes disponíveis; as somas são feitas em `u64` para que nenhum
transbordo faça um registo gigante parecer pequeno. Não há `unsafe` no codec.

Fuzzing: `hfb2_fuzz --sweep N` (compila em Rust estável) e os testes
deterministas `random_mutations_never_panic_and_never_keep_the_leaf` e
`arbitrary_bytes_never_panic`, que correm na CI.

## 12. O que este documento não promete

- **Não há migração de HDB1** e não está planeada nesta entrega.
- **Não há reparação automática** de `ANCHOR_BEHIND` nem truncagem de cauda.
- **`record_type` tem dois valores** (`1 = OperationalFact`,
  `2 = TelemetryHealth`); os restantes são espaço reservado, não
  funcionalidade.
- **Os namespaces de extensão estão declarados, não povoados**: só
  `security.canonical_event` e `evidence.legal_receipt` existem.
- **A identidade de schema não tem publisher nem assinatura** — o formato não o
  impede, mas também não o implementa.
