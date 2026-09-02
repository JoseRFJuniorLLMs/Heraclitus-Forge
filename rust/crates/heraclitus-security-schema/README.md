# heraclitus-security-schema

Modelo canónico de evento de segurança — `heraclitus-security-event/1.0`
(SPEC-0071, Δ1 / Marco 1).

## O que é

Um Fato Operacional descreve o que aconteceu *naquela* fonte, no vocabulário
*daquela* fonte. Correlacionar PostgreSQL, OpenSSH, nginx e Windows Security
exige que "falha de autenticação" signifique a mesma coisa nos quatro. Este
crate é essa definição: tipos, validação, canonicalização e os mappings
versionados que traduzem cada conector.

## O que não é

Não tem rede, não tem armazenamento, não tem IA e não faz parsing de vendor
nenhum. Quem observa é o Forge; quem guarda é o HeraclitusDB. Aqui só se decide
o que os campos **significam** — e é por isso que pode ser auditado sozinho.

## Peças

| Ficheiro | Papel |
|---|---|
| `src/model.rs` | os tipos e os vocabulários fechados (categoria, desfecho, espécie de entidade) |
| `src/mapping.rs` | leitura dos mappings versionados, embutidos no binário |
| `src/normalize.rs` | `operational-fact/1.0` → evento canónico, função pura |
| `src/validate.rs` | invariantes do modelo e os `required_fields` que o `.hcx` declara |
| `src/canonical.rs` | forma canónica em bytes e o seu digest SHA-256 |
| `schema/security_event.proto` | contrato de fio para quem não é Rust |
| `mappings/*.yaml` | um mapping por conector, com versão própria |

## Gates (SPEC-0071 §15)

- **CM0 Determinism** — a mesma observação com o mesmo digest de conector dá
  os mesmos bytes. A forma canónica é estável por construção: ordem de campos
  fixa, `extensions` ordenado, sem ponto flutuante, ausência escrita como
  `null` em vez de omitida.
- **CM1 Provenance** — todo evento volta ao Forge: LSN, `forge_source_id`,
  hash BLAKE3 da observação e digest do `.hcx` verificado. O raw não viaja
  para o centro; a referência viaja.
- **CM2 Compatibility** — `operational-fact/1.0` não mudou. `.hcx` sem
  `security:` é conector legado e continua a funcionar.
- **CM3 No Invention** — campo não observado é `null`; ação não declarada é
  erro; categoria fora do vocabulário é erro; marcador de ausência da fonte
  (`-`) não vira identidade.

## Escrever um mapping

```yaml
mapping_version: exemplo/1.0.0
security_schema: heraclitus-security-event/1.0
connector: exemplo                 # confere com o manifest.id do .hcx
primary_category: http             # categoria por omissão das ações
required_fields: [observed_at_micros, datasource_id, sensor_id]
observed_at:
  source: ingest_fallback          # ou: {source: fact_field, path: [...]}
identity:
  actor_kind: user
  target_kind: resource
  absent_markers: ["-"]            # o que a fonte escreve como "campo ausente"
severity_by_risk: {Low: 2, Medium: 4, High: 7, Critical: 9}
actions:
  authentication.failure: {category: authentication, outcome: failure}
  data.access: {outcome: success}
  log.unknown: {security_relevant: false}
```

Uma chave desconhecida no YAML é erro (`deny_unknown_fields`): um campo mal
escrito seria silenciosamente ignorado, e um mapping ignorado em silêncio é
pior do que nenhum. O `event_type` é sempre o nome da ação — a taxonomia do
Reasoner já é a taxonomia canónica, e um segundo nome só criaria duas verdades.

O mapping tem de declarar **exatamente** as ações que o `reasoning.yaml` do
conector emite, mais o `log.unknown` do Runner. Há um teste que compara as
duas listas: uma ação a mais é cobertura fingida, uma a menos falha fechado em
produção.
