# AUDIT.md — Auditoria & Roadmap de Conclusão do Heraclitus-Forge

**Data:** 2026-07-22 · **Escopo:** runtime Rust (`rust/src/**`) + Design-Time Python
(`forge_compiler.py`, `forge_ai.py`, `cke.py`, `web_forge.py`, `dashboard.py`).
**Contexto:** o Forge é o runtime line-rate que é **parte do HeraclitusDB** — esta
auditoria aplica o mesmo padrão de rigor usado no HeraclitusDB de produção
(ver `docs/md/falta_fazer.md §6.4` naquele repo).

**Veredicto:** o Forge é um **protótipo ponta-a-ponta coerente e funcional** da
Heraclitus Suite v6.0, com um **núcleo sólido** (store append-only + codec +
runner dirigido por artefato). **Não está completo** para produção: vários
pilares distribuídos/cripto/ingestão são **simulação assumida no código**, e a
cobertura de testes é fina. Este documento lista o que foi corrigido, o que é
lacuna de design (decisão de dono) e o roadmap para "completo".

---

## 1. Bugs CORRIGIDOS (commit `7cde0cb`)

Todos confirmados contra o código real; cada um do mesmo tipo dos achados no
HeraclitusDB de produção. Verificado verde (`cargo test`, 8 testes + 1 regressão).

| Sev | Ficheiro | Bug | Correção |
|---|---|---|---|
| **HIGH** | `db.rs` | **Reabrir não recuperava estado.** `HeraclitusDB::new` de um `.hdb` existente repunha `current_lsn = BASE_LSN` e `trusted_root = ""`. O próximo `write_fact` atribuía um LSN já usado e dobrava a cadeia Merkle a partir do vazio ⇒ o `merkle_root_anchor` embutido divergia do que `verify()` recalcula sobre todo o ficheiro ⇒ **um append legítimo pós-restart marcava o banco como VIOLATED**. | Novo `recover()` reconstrói `current_lsn` + `trusted_root` do disco (filosofia replay-from-log do HeraclitusDB). Teste `reopen_preserves_chain_and_verifies`. |
| **HIGH** | `db.rs` | **Sem `fsync`.** `write_fact` / `write_stream` / `commit_local` / `append_replicated_block` faziam `write_all` sem sincronizar — durabilidade dada como garantida sem o ser (incl. o líder Raft que acka aos followers). | `sync_all()` antes de cada ack e antes de ancorar. |
| **MED** | `fbfact.rs` | **Alocação ilimitada.** `Vec::with_capacity(nsteps)` a partir de um `u32` não confiável do buffer. O CRC-32C do CPM não é *keyed* ⇒ quem tenha acesso de escrita ao ficheiro forja `nsteps = 0xFFFFFFFF` ⇒ OOM. | Limitado pelos bytes restantes do buffer. |
| **MED** | `gateway.rs` | **Panic em UTF-8.** `POST /ingest` fatiava o corpo HTTP por **byte** (`&line[..80]`); um corpo multibyte que caísse a meio de um caractere panicava o handler. | Truncagem por caractere (`chars().take(n)`). |
| **MED** | `raft.rs` | **Split-brain.** `become_follower` incondicional em `AppendEntries` apagava `voted_for` a cada heartbeat do MESMO termo ⇒ um nó que já votou em A no termo T podia votar em B no mesmo T. | Só reinicia o voto quando o termo **avança**. |
| **LOW** | `hql.rs` | **Overflow/underflow.** `WITHIN LAST N` transbordava `a*unit*1e6` e o `now-window` fazia underflow (panic em debug) com N gigante. | Aritmética saturante. |

---

## 2. Lacunas de DESIGN (não são bugs pontuais — decisão de dono)

Estas são **escolhas assumidas no código** (rotuladas como simulação/mock). Não
foram "corrigidas" porque mudá-las é trabalho de produto, não de patch. Listadas
por impacto para promover a produção.

### 2.1 — [ALTO] Consenso Raft — ✅ RESOLVIDO (Marco C completo)
- **Estado durável (✅):** `term` / `voted_for` persistem em `<db>.raftmeta` e o
  log Raft (com termos) em `<db>.raftlog`, reconstruídos no arranque. Um nó já
  não vota duas vezes no mesmo termo através de um restart (fecha o split-brain
  por reinício). Testes `vote_survives_restart`, `raft_log_survives_restart`.
- **Regra de Figura-8 (✅):** `advance_commit` só compromete DIRETAMENTE um
  índice cuja entrada é do termo corrente (§5.4.2 do Raft) — entradas de termos
  anteriores comprometem-se indiretamente. Teste
  `figure8_does_not_commit_previous_term_by_count_alone`.
- **Transporte TCP (✅ C.2):** módulo `wire.rs` — Wire Protocol TCP real (spec
  §8). Mensagens `Msg` serializadas (`bincode`), enquadradas (`u32` LE + payload)
  sobre `TcpStream`; o relógio lógico é um `tokio::time::interval`. O MESMO state
  machine `RaftNode` da simulação corre sobre a rede. Teste de integração
  `tcp_cluster_elects_and_replicates`: 3 nós reais em `127.0.0.1` elegem líder,
  replicam Fatos e cada um verifica INTEG_OK. (Liga por mensagem, best-effort —
  pool de ligações fica como otimização, como no `net.rs` do HeraclitusDB.)

### 2.2 — [ALTO] Assinatura era MOCK — ✅ RESOLVIDO (Marco B)
- **Antes:** `db.rs sign()` era BLAKE3 de um prefixo fixo (sem chave privada) e o
  `verify()` nem conferia — tamper-EVIDENTE mas não tamper-PROOF contra um
  atacante que reescrevesse `.hdb` + `.anchor` consistentes.
- **Agora:** a âncora é assinada com **ed25519 real**. Chave privada fora do
  `.hdb` (`<db>.key`, 0600), pública fixada em `<db>.pub`, assinatura em
  `<db>.anchor.sig`. O `verify()` confere a assinatura (camada 3): sig
  ausente/inválida ⇒ VIOLATED. Testes `tampered_anchor_signature_is_rejected`
  e `foreign_key_signature_is_rejected` (atacante assina com chave própria ⇒
  rejeitado pela `.pub` da vítima).
- **Ressalva residual:** a segurança reduz-se a **proteger a chave** — se o
  atacante ler `<db>.key`, re-assina. `.key` fica 0600 (no-op no Windows) e a
  recomendação é mantê-la fora da máquina de dados. A tag por-Fato
  `fact.integrity.signature` passou a ser honesta (`b3tag:`, não `ed25519:`).
- **Ainda mock:** a assinatura do **artefato `.hcx`** (`forge_compiler.py:341`)
  — é outro objeto (o pacote de conhecimento, não o store de Fatos). Follow-up
  separado (assinar o `.hcx` com a mesma chave / uma chave de publicação).

### 2.3 — [MÉDIO] Ingestão e conectores são de demonstração
- Gateway: `gateway.rs:238` alimenta o `.hdb` com um array `SAMPLES` fixo num
  timer de 1.2s — **não** é um tail real de PostgreSQL.
- Registry tem **um único conector** (`registry/postgresql/` v1.0.0 + v1.1.0).
  A proposta ("observações heterogêneas") pede vários; o CKE/forge_ai existem
  para os gerar, mas ainda não foram.

### 2.4 — [MÉDIO] Cobertura de testes fina
- 8 testes Rust, todos em `cpm.rs` / `db.rs` / `fbfact.rs`.
- **Sem teste nenhum** para `raft.rs`, `runner.rs`, `hql.rs`, `fabric`,
  `gateway`. O caminho de consenso e o de raciocínio não têm rede de segurança.

### 2.5 — [MÉDIO] Leitura carrega o ficheiro inteiro para a RAM
- `db.rs verify()` e `hql.rs execute_query` fazem `read_to_end` do `.hdb`
  completo. Ok à escala de demo; não passa disso num `.hdb` grande. O
  HeraclitusDB de produção usa scan janelado (`scan_capped`).

### 2.6 — [BAIXO] FlatBuffers hand-rolled
- `fbfact.rs` é um stand-in manual do schema (`flatc` não instalado). Funciona e
  é determinístico, mas não é o código gerado do `.fbs`. Trocar quando o `flatc`
  entrar não muda o `db.rs` (documentado).

### 2.7 — [BAIXO] Dashboard com dados mock
- `dashboard.py:320 eventos_mock` — a visão do dashboard mistura dados
  fabricados. Distinguir claramente do que vem do `/facts` real.

---

## 3. Roadmap de conclusão (ordem sugerida)

**Marco A — Honestidade & robustez (barato, alto valor) — ✅ FEITO (commit desta ronda)**
- [x] README alinhado: "tamper-EVIDENTE via Merkle+âncora", com nota explícita
  de que a assinatura é mock e o Raft é simulação (§2.1/§2.2).
- [x] Testes `raft.rs` (convergência 3 nós + `verify()` por nó; regressão de
  split-brain "no double vote"; termo-maior reabre voto), `hql.rs` (parser,
  wildcards, SELECT/LIMIT, saturação da janela de tempo, execução com filtros),
  `runner.rs` (linha PostgreSQL real casa; ruído vira drift). **18 testes** (era 8).
- [x] Leitura paginada: novo `db::scan_blocks` em **streaming** (um bloco em RAM
  de cada vez); `verify()`, `recover()` e `hql::execute_query` deixaram de fazer
  `read_to_end` do ficheiro inteiro. O `payload_len` do disco é limitado pelos
  bytes restantes antes de alocar.

**Marco B — Cripto real (§2.2) — ✅ FEITO**
- [x] Chave ed25519 de verdade a assinar a âncora/raiz (`ed25519-dalek`);
  chave privada em `<db>.key` (0600, `.gitignore`), pública em `<db>.pub`,
  assinatura em `<db>.anchor.sig`; `verify()` confere (camada 3). Cada nó Raft
  assina a sua própria âncora local. Tag por-Fato honesta (`b3tag:`).
- [x] **(residual) — ✅ FEITO (2026-08-14)** Assinar também o artefato `.hcx`.
  Novo `forge_sign.py`: chave de **publicação** ed25519 distinta da chave da
  âncora (domínios de confiança diferentes), privada em
  `~/.heraclitus/publisher.key` **fora do repositório**, pública fixada em
  `registry/publisher.pub` (versionada). O digest canónico cobre **todos** os
  ficheiros do artefato com nome+comprimento a enquadrar — o selo antigo cobria
  uma lista fixa, por isso acrescentar um ficheiro ao pacote não o invalidava.
  Sem chave, o compilador emite o artefato **sem** assinatura e diz que o fez.
  14 testes, incluindo alterar/acrescentar/apagar/renomear ficheiro, chave
  estranha, assinatura corrompida, e o selo antigo a ser reportado como
  `LEGACY_MOCK` e nunca como válido.

**Marco C — Consenso de produção (§2.1) — ✅ FEITO**
- [x] Persistir `term`/`voted_for` (`<db>.raftmeta`) + log Raft (`<db>.raftlog`),
  reconstruídos no arranque (à la `meta.bin`/WAL do HeraclitusDB).
- [x] Regra de commit por termo (Figura-8) em `advance_commit`.
- [x] **(C.2)** Transporte TCP real (`wire.rs`, spec §8): `Msg` via `bincode`
  enquadrado sobre `TcpStream`, relógio por `tokio::interval`. Teste de
  integração com 3 nós reais em localhost (elege + replica + verify por nó).

**Marco D — Ingestão & conectores (§2.3)**
- [ ] Tail real de PostgreSQL no gateway/fabric.
- [ ] ≥2 conectores novos via CKE/forge_ai (validar o Coverage pelo bin Rust).

---

## 4. O que já está SÓLIDO (não re-litigar)

- **`cpm.rs`** — decode com bounds em todos os campos (`record_size` range,
  `var_len+payload_len == record_size`, CRC, `parse_tlvs` com `checked_add`),
  CRC-32C correto (vetor de teste bate), bons testes de tamper físico/cripto.
- **`db.rs`** (pós-correções) — store append-only com dupla camada (CRC físico +
  Merkle cripto), recovery no reabrir, fsync antes do ack.
- **`fbfact.rs`** — codec determinístico zero-copy com bounds em `get_str`/
  `skip_str`; alocação agora limitada.
- **`runner.rs`** — motor **genérico dirigido por artefato** (`.hcx`), não
  hardcoded a um conector.
- **`forge_compiler.py`** — gera a anatomia `.hcx` completa e valida o Coverage
  pelo **runner Rust real** (bin `coverage`), não por um fake em Python.
