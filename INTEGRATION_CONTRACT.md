# Contrato Heraclitus-Forge ↔ HeraclitusDB

## Matriz homologada

| Componente | Versão |
| --- | --- |
| Heraclitus-Forge | `1.0.x` |
| HeraclitusDB e SDK Python | `1.0.5` |
| Envelope JSONL | `forge-heraclitusdb/1` |
| Fato canônico | `operational-fact/1.0` |
| API gRPC | `heraclitus.v1` |

O exportador inclui as quatro identidades no envelope/atestado. A ponte exige
igualdade exata; valor ausente ou versão desconhecida interrompe o lote antes
do primeiro `Append`.

## Fluxo e garantias

1. `export_facts` copia uma fotografia privada do `.hdb` e sidecars.
2. Verifica CRC-32C, cadeia BLAKE3, chave pública fixada e assinatura Ed25519.
3. Emite JSONL estrito em ordem crescente de LSN com atestado repetido por fato.
4. `bridge.py` valida contrato, campos obrigatórios e atestado.
5. Identifica o titular por HMAC-SHA-256 de `actor.id`; o valor bruto não entra
   no seletor de chave do HeraclitusDB.
6. Pseudonimiza `session_id` por HMAC com domínio `session`; a versão de
   conhecimento pode conter origem/alvo e nunca entra em claro no WAL.
7. Envia `Append` autenticado com chave idempotente
   `SHA-256("forge:" + source_id + ":" + lsn + ":" + fact_id)`.
8. Só avança o checkpoint local após o ACK. Se cair entre ACK e checkpoint, o
   retry retorna o mesmo `event_id`/LSN com `deduplicated=true`.

## Campos de custódia preservados

`fact_id`, `forge_lsn`, `source_event_id`, `evidence_hash`,
`carimbo_tempo_legal`, `leaf_hash`, `merkle_root_anchor`,
`integrity_signature`, `forge_verified_root`, `forge_source_id`,
`forge_public_key`, `forge_anchor_signature` e algoritmo de integridade.

`parents` encadeia cada evento ao ACK anterior do mesmo fluxo. A origem lógica é
`attrs.producer=heraclitus-forge`; `agent_id` é reservado à unidade de
crypto-shredding por titular.

## Evolução compatível

- Campos opcionais novos e attrs novos podem entrar em release minor.
- Remover/renomear campo obrigatório, mudar semântica de identidade,
  idempotência ou cadeia de custódia exige novo major do contrato.
- Campos protobuf novos devem usar novos números. Números removidos devem ficar
  `reserved`; nunca podem ser reutilizados.
- O registry só publica conector que passe matriz de testes e assinatura.

## Transporte

- Loopback pode usar gRPC plaintext apenas em desenvolvimento controlado.
- Fora de loopback, a ponte exige CA TLS; o perfil do órgão deve usar mTLS.
- `HERACLITUS_TOKEN_FILE` deve apontar para a credencial do principal `writer`,
  nunca a de `admin`. Segredos não podem aparecer em argumentos, logs ou Git.

## Entrada de um cliente/fonte nova

1. Copiar uma amostra minimizada para área restrita; não enviar PII a serviços
   externos sem base legal.
2. Criar versão nova do conector pelo CKE/Forge e revisar a ontologia/regras.
3. Rodar coverage pelo runner Rust, casos negativos e teste de drift.
4. Assinar o `.hcx` com a chave de publicação do órgão e executar
   `python forge_sign.py verify-all`.
5. Criar `.hdb`, quarentena e segredos separados por cliente/tenant.
6. Rodar `bridge.py` sem `--apply`; revisar o mapeamento e a classificação.
7. Rodar E2E numa instância descartável do HeraclitusDB e testar retry/crash.
8. Autorizar `--apply`, monitorar quarentena e guardar o aceite do conector.
