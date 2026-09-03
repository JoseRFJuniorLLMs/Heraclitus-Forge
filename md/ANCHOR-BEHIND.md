# Política operacional para `ANCHOR_BEHIND`

Este documento define o que fazer quando um `.hdb` abre com o estado
`ANCHOR_BEHIND`. **Não descreve código implementado**: a decisão que ele
formaliza é de política, e a operação que a executa ainda não existe. Onde algo
não está feito, está dito que não está.

Implementação relacionada: [`rust/src/db.rs`](../rust/src/db.rs) (`FactStore::verify`),
[`md/HDB2-HFB2.md`](HDB2-HFB2.md) §10.

## 1. O que o estado significa

```text
ANCHOR_BEHIND  log íntegro até ao LSN N, âncora assinada no LSN M, com M < N
```

Concretamente, e só isto:

- todos os blocos até `N` passam a validação estrutural, o CRC-32C e a folha
  BLAKE3 recalculada sobre os bytes gravados;
- a cadeia Merkle reconstruída bate com a âncora **no ponto `M`**;
- existem `N − M` blocos depois desse ponto que **nenhuma assinatura cobre**.

O `verify()` devolve este estado com o número de blocos por assinar. O
`FactStore::new` **recusa abrir**. Nenhuma reparação automática acontece.

## 2. O que o estado NÃO distingue

Duas histórias produzem exatamente o mesmo ficheiro:

| Hipótese | Como acontece |
|---|---|
| **Corte de energia** | o processo morreu entre o `fsync` do bloco e a gravação da âncora. A janela é pequena mas real e existe por construção: a raiz depende dos dados, portanto a âncora só pode ser escrita depois deles. |
| **Extensão não autorizada** | alguém com escrita no ficheiro acrescentou blocos. Não conseguiu assinar — a chave privada está noutro lado — mas os blocos que escreveu são estruturalmente válidos e encadeiam-se corretamente. |

**A partir do ficheiro, as duas são indistinguíveis.** É por isso que a âncora
existe: ela é a única prova de que o log não foi estendido. Reassinar
automaticamente destrói exatamente a propriedade que se está a tentar verificar.

Qualquer política que comece por "o sistema recupera sozinho" é uma política que
transforma a âncora em decoração.

## 3. Regras

1. **Nunca reassinar automaticamente.** Nem no arranque, nem por um `--repair`
   silencioso, nem por retentativa.
2. **Nunca apagar os blocos por assinar** para "voltar ao estado bom". Isso é
   destruição de evidência, e o `N − M` que se descartaria é precisamente o
   material que interessa a quem investiga.
3. **A decisão é de uma pessoa identificada**, não do processo.
4. **A decisão fica registada** com a mesma força do que ela cobre: quem, quando,
   com que fundamento, e sobre que raiz exata.
5. **Enquanto não houver decisão, o datasource não arranca.** Um sensor parado é
   visível; um sensor a ingerir sobre um log cuja integridade ninguém confirmou
   não é.

## 4. Procedimento

### 4.1 Recolha, antes de decidir

Reunir, sem alterar o ficheiro:

- saída completa de `verify()`: estado, número de Fatos, raiz recalculada,
  mensagem com `N` e `M`;
- os `N − M` registos por assinar, exportados e legíveis — `tenant_id`,
  `datasource_id`, `sensor_id`, `record_type` e `matched_rule` de cada um;
- evidência independente do corte: log do sistema, evento de encerramento do
  serviço, registo do SCM, UPS, hipervisor;
- estado do sidecar de retoma (`<db>.ingest-state`) e o offset que ele declara,
  comparado com o que os blocos por assinar dizem ter consumido;
- quem teve acesso de escrita ao ficheiro no intervalo.

### 4.2 Critério de aceitação

Aceitar os blocos por assinar **apenas se todas** se verificarem:

- há evidência independente de paragem abrupta no intervalo;
- o número de blocos por assinar é compatível com o que a fonte teria produzido
  nesse intervalo;
- a identidade de segurança dos blocos por assinar é a mesma dos blocos já
  ancorados (`tenant_id`, `datasource_id`, `sensor_id`) — uma mudança aqui é
  motivo de recusa imediata;
- o `connector_digest` dos registos por assinar corresponde a um conector
  ativado e conhecido.

Faltando qualquer uma: **tratar como incidente de integridade**, não como
recuperação.

### 4.3 Se aceite

Selar o log a partir da raiz recalculada, e registar a decisão. O registo é
parte do dossier de custódia, não uma entrada de log operacional.

### 4.4 Se recusado

Preservar o ficheiro tal como está — cópia bit a bit para custódia — e abrir um
`.hdb` **novo** para retomar a ingestão. Nunca continuar a escrever sobre um log
cuja cauda está em disputa.

## 5. O que falta construir

Nada disto está implementado. Para a política ser executável faltam:

| Peça | O que faz |
|---|---|
| `heraclitus-forge seal` | operação explícita e autenticada que reassina a raiz recalculada, exigindo a decisão como argumento |
| Registo da decisão | evento com quem decidiu, quando, o fundamento, `M`, `N` e as duas raízes — coberto pela mesma cadeia |
| Exportação dos blocos em disputa | listar e exportar os `N − M` registos sem os aceitar |
| Sinal para o Telemetry Health | `ANCHOR_BEHIND` como entrada de `integrity`/`trust`, para que apareça no `TelemetryHealthGraph` em vez de só num terminal |

O último é o mais barato e o mais útil: hoje este estado **não tem consumidor
nenhum** — só aparece a quem correr `verify()` à mão.

## 6. O que esta política deliberadamente não decide

- **Quem** é a pessoa autorizada num órgão concreto. Isso é do órgão, e depende
  de segregação de funções que este projeto não conhece.
- **Quanto tempo** o ficheiro em disputa se guarda. É retenção legal, não
  engenharia.
- Se a aceitação exige **duas** pessoas. Defensável, e é decisão de política de
  quem opera.
