//! Golden fixtures do modelo canonico (SPEC-0071 Marco 1).
//!
//! O que este teste prova, e que nenhum teste unitario do crate do schema
//! podia provar sozinho: que os artefatos REAIS do registry, verificados
//! criptograficamente, passados pelo Runner REAL, produzem exatamente os
//! eventos canonicos gravados em `tests/golden/`.
//!
//! Cada caso vem da `test_matrix.json` do proprio `.hcx` — a bateria que o
//! conector declara como o seu comportamento. O golden e portanto a traducao
//! canonica do que o conector diz que faz.
//!
//! Gates cobertos:
//!   CM0  o digest canonico esta gravado; muda se qualquer campo mudar;
//!   CM1  cada evento carrega LSN, hash da evidencia e digest do conector;
//!   CM2  `postgresql/v1.1.0` (sem `security:`) continua a produzir Fatos e
//!        nao produz eventos canonicos;
//!   CM3  campo nao observado sai `null` no golden, nunca preenchido.
//!
//! Regenerar (e REVER o diff, que e o ponto):
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test --test canonical_golden
//! ```
//!
//! Republicar um conector muda o `connector_digest` e, por isso, o golden:
//! e assim que se ve que o conteudo assinado mudou.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heraclitus::hcx;
use heraclitus::runner::{resolve_latest_artifact, ReconstitutiveRunner};
use heraclitus_security_schema as schema;
use schema::{CanonicalSecurityEvent, NormalizationContext, Normalized};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Instante de ingestao fixado. O Runner carimba `now()`; um golden com o
/// relogio real seria irreprodutivel — e o modelo canonico e uma funcao pura
/// das entradas, nao do momento em que o teste correu.
const PINNED_INGESTED_AT_MICROS: i64 = 1_782_782_405_000_000;
const PINNED_FORGE_SOURCE_ID: &str =
    "5f3c9d2b7a1e48606f9d0c3b2a1e4860e5f3c9d2b7a1e48606f9d0c3b2a1e4860";
const TENANT: &str = "tenant-demo";

const REGISTRY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../registry");

/// Conectores P0 da SPEC-0071 (secao 5.2).
const CONNECTORS: &[&str] = &[
    "postgresql",
    "linux_sshd",
    "nginx_access",
    "windows_security",
];

// ---------------------------------------------------------------------------
// Leitura dos artefatos
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SecurityDeclaration {
    security_schema: String,
    category: String,
    mapping_version: String,
    required_fields: Vec<String>,
}

#[derive(Deserialize)]
struct Manifest {
    id: String,
    #[serde(default)]
    security: Option<SecurityDeclaration>,
}

#[derive(Deserialize)]
struct TestMatrix {
    cases: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    input: String,
    expect_action: String,
}

#[derive(Deserialize)]
struct Reasoning {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
struct Rule {
    set: RuleSet,
}

#[derive(Deserialize)]
struct RuleSet {
    #[serde(default)]
    action: Option<String>,
}

fn artifact_dir(connector: &str) -> PathBuf {
    let base = format!("{REGISTRY}/{connector}");
    PathBuf::from(
        resolve_latest_artifact(&base).unwrap_or_else(|| panic!("nenhum artefato .hcx em {base}")),
    )
}

fn read<T: serde::de::DeserializeOwned>(dir: &Path, name: &str, yaml: bool) -> T {
    let text = std::fs::read_to_string(dir.join(name))
        .unwrap_or_else(|error| panic!("ler {}/{name}: {error}", dir.display()));
    if yaml {
        serde_yaml::from_str(&text).unwrap_or_else(|error| panic!("{name} invalido: {error}"))
    } else {
        serde_json::from_str(&text).unwrap_or_else(|error| panic!("{name} invalido: {error}"))
    }
}

fn verified_digest(dir: &Path) -> String {
    let trust_root = hcx::resolve_trust_root(dir).expect("trust root do registry");
    hcx::verify_artifact(dir, &trust_root).expect("artefato do registry tem de verificar")
}

// ---------------------------------------------------------------------------
// Golden
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Golden {
    connector: String,
    artifact: String,
    /// SHA-256 do `.hcx` verificado. Republicar o conector muda este valor.
    connector_digest: String,
    mapping_version: String,
    cases: Vec<GoldenCase>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct GoldenCase {
    input: String,
    expect_action: String,
    /// Presente quando o mapping declara a acao como nao relevante para
    /// seguranca: ha Fato Operacional e NAO ha evento canonico.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_security_relevant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canonical_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<CanonicalSecurityEvent>,
}

fn golden_path(connector: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{connector}.json"))
}

fn build_golden(connector: &str) -> Golden {
    let dir = artifact_dir(connector);
    let digest_hex = verified_digest(&dir);
    let connector_digest = schema::model::hash32::from_hex(&digest_hex, None).expect("digest hex");
    let manifest: Manifest = read(&dir, "manifest.yaml", true);
    let declaration = manifest
        .security
        .unwrap_or_else(|| panic!("{connector}: manifesto sem bloco `security`"));
    let mapping = schema::mapping::mapping(&declaration.mapping_version)
        .unwrap_or_else(|error| panic!("{connector}: {error}"));
    let matrix: TestMatrix = read(&dir, "test_matrix.json", false);

    let mut runner = ReconstitutiveRunner::load(&dir.to_string_lossy()).expect("runner carrega");
    let mut cases = Vec::new();
    for (index, case) in matrix.cases.iter().enumerate() {
        let mut fact: Json = runner
            .process_observation(&case.input)
            .unwrap_or_else(|| panic!("{connector}: linha da test_matrix caiu em drift"));
        assert_eq!(
            fact["fact.behavior"]["action"], case.expect_action,
            "{connector}: o Runner nao produziu a acao que a test_matrix declara"
        );
        fact["fact.time"]["system_timestamp"] = Json::from(PINNED_INGESTED_AT_MICROS);

        let datasource = format!("fixture://{connector}");
        let sequence = index.to_string();
        let event_id = format!("{connector}:{index}");
        let context = NormalizationContext {
            tenant_id: TENANT,
            datasource_id: &datasource,
            sensor_id: "forge-golden-fixture",
            source_sequence: Some(&sequence),
            normalized_at_micros: PINNED_INGESTED_AT_MICROS + 1_000,
            forge_source_id: PINNED_FORGE_SOURCE_ID,
            forge_lsn: index as u64 + 1,
            source_event_id: Some(&event_id),
            connector_digest,
        };

        let normalized = schema::from_operational_fact(&fact, mapping, &context)
            .unwrap_or_else(|error| panic!("{connector} caso {index}: {error}"));
        cases.push(match normalized {
            Normalized::NotSecurityRelevant { action } => GoldenCase {
                input: case.input.clone(),
                expect_action: case.expect_action.clone(),
                not_security_relevant: Some(action),
                canonical_digest: None,
                event: None,
            },
            Normalized::Event(event) => GoldenCase {
                input: case.input.clone(),
                expect_action: case.expect_action.clone(),
                not_security_relevant: None,
                canonical_digest: Some(schema::canonical::canonical_digest_hex(&event)),
                event: Some(*event),
            },
        });
    }

    Golden {
        connector: connector.to_owned(),
        artifact: dir
            .file_name()
            .expect("nome do artefato")
            .to_string_lossy()
            .to_string(),
        connector_digest: digest_hex,
        mapping_version: declaration.mapping_version,
        cases,
    }
}

#[test]
fn published_connectors_match_their_golden_canonical_events() {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    for connector in CONNECTORS {
        let produced = build_golden(connector);
        let path = golden_path(connector);
        if update {
            let mut text = serde_json::to_string_pretty(&produced).expect("serializa");
            text.push('\n');
            std::fs::write(&path, text).expect("gravar golden");
            continue;
        }
        let recorded: Golden = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("golden ausente para {connector}: {error}")),
        )
        .unwrap_or_else(|error| panic!("golden de {connector} ilegivel: {error}"));

        assert_eq!(
            produced.connector_digest, recorded.connector_digest,
            "{connector}: o artefato publicado mudou; regenera o golden com \
             UPDATE_GOLDEN=1 e RE o diff"
        );
        assert_eq!(
            produced, recorded,
            "{connector}: evento canonico divergiu do golden. Regenera com \
             UPDATE_GOLDEN=1 e revê o diff antes de aceitar"
        );
    }
    assert!(
        !update,
        "UPDATE_GOLDEN ativo: goldens regravados, nada verificado"
    );
}

#[test]
fn canonical_events_are_deterministic_for_the_same_input() {
    // Gate CM0: mesma observacao + mesmo digest de conector -> mesmos bytes.
    for connector in CONNECTORS {
        assert_eq!(
            build_golden(connector),
            build_golden(connector),
            "{connector}: duas normalizacoes da mesma entrada divergiram"
        );
    }
}

#[test]
fn manifest_declaration_agrees_with_the_published_mapping() {
    for connector in CONNECTORS {
        let dir = artifact_dir(connector);
        let manifest: Manifest = read(&dir, "manifest.yaml", true);
        let declaration = manifest
            .security
            .unwrap_or_else(|| panic!("{connector}: manifesto sem bloco `security`"));
        assert_eq!(
            declaration.security_schema,
            schema::SCHEMA_VERSION,
            "{connector}: declara outro schema canonico"
        );

        let mapping = schema::mapping::mapping(&declaration.mapping_version)
            .unwrap_or_else(|error| panic!("{connector}: {error}"));
        assert!(
            mapping.accepts_manifest(&manifest.id),
            "{connector}: o mapping {} nao e deste artefato",
            declaration.mapping_version
        );
        assert_eq!(
            mapping.primary_category.as_str(),
            declaration.category,
            "{connector}: categoria primaria diverge entre .hcx e mapping"
        );
        assert_eq!(
            mapping.required_fields, declaration.required_fields,
            "{connector}: required_fields divergem entre .hcx e mapping"
        );
    }
}

#[test]
fn mapping_covers_exactly_the_actions_the_connector_can_emit() {
    // Uma acao a mais no mapping e codigo morto que finge cobertura; uma a
    // menos e um evento que falha fechado em producao.
    for connector in CONNECTORS {
        let dir = artifact_dir(connector);
        let manifest: Manifest = read(&dir, "manifest.yaml", true);
        let declaration = manifest.security.expect("bloco security");
        let mapping = schema::mapping::mapping(&declaration.mapping_version).expect("mapping");
        let reasoning: Reasoning = read(&dir, "reasoning.yaml", true);

        let mut emitted: BTreeSet<String> = reasoning
            .rules
            .iter()
            .filter_map(|rule| rule.set.action.clone())
            .collect();
        // O Runner emite isto quando o parse funciona e nenhuma regra casa.
        emitted.insert("log.unknown".to_owned());

        let declared: BTreeSet<String> = mapping.actions.keys().cloned().collect();
        assert_eq!(
            declared, emitted,
            "{connector}: mapping e reasoning.yaml declaram acoes diferentes"
        );
    }
}

#[test]
fn a_connector_without_the_security_block_stays_legacy() {
    // Gate CM2: `postgresql/v1.1.0` continua publicado, valido e sem modelo
    // canonico. Compatibilidade nao e uma promessa no README — e este teste.
    let dir = PathBuf::from(format!("{REGISTRY}/postgresql/v1.1.0.hcx"));
    verified_digest(&dir);
    let manifest: Manifest = read(&dir, "manifest.yaml", true);
    assert!(
        manifest.security.is_none(),
        "a versao legada nao devia declarar modelo canonico"
    );

    let mut runner = ReconstitutiveRunner::load(&dir.to_string_lossy()).expect("runner carrega");
    let line = "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for \
                user \"admin\"";
    let fact = runner
        .process_observation(line)
        .expect("o conector legado continua a produzir Fatos");
    assert_eq!(fact["fact.behavior"]["action"], "authentication.failure");
}

// ---------------------------------------------------------------------------
// Caminho quente: quem EMITE o evento canonico
// ---------------------------------------------------------------------------

#[test]
fn the_hot_path_emits_the_same_event_an_independent_normalization_produces() {
    // O golden acima prova que o mapping traduz bem. Este prova que o Runner
    // usa MESMO esse mapping, com o digest do artefato verificado e com a
    // identidade que o supervisor lhe deu — e nao uma segunda normalizacao
    // paralela que ninguem ve.
    let identity = heraclitus::hfb2::SecurityIdentity::new(
        "gov.br/orgao-a",
        "teste://hot-path",
        "forge-teste",
    )
    .expect("identidade valida");

    for connector in CONNECTORS {
        let dir = artifact_dir(connector);
        let matrix: TestMatrix = read(&dir, "test_matrix.json", false);
        let mut runner = ReconstitutiveRunner::load(&dir.to_string_lossy()).expect("runner");
        assert!(
            !runner.is_legacy_connector(),
            "{connector}: devia declarar bloco security:"
        );
        let digest = schema::model::hash32::from_hex(&verified_digest(&dir), None).unwrap();
        assert_eq!(
            runner.connector_digest(),
            digest,
            "{connector}: o Runner tem de guardar o digest VERIFICADO"
        );
        let mapping = schema::mapping::mapping(runner.mapping_version().expect("mapping"))
            .expect("mapping publicado");

        for (index, case) in matrix.cases.iter().enumerate() {
            let sequence = index.to_string();
            let context = heraclitus::runner::EmissionContext {
                identity: &identity,
                forge_source_id: PINNED_FORGE_SOURCE_ID,
                forge_lsn: index as u64 + 1,
                source_sequence: Some(&sequence),
                source_event_id: None,
            };
            let fact = runner
                .process_observation_with_context(&case.input, &context)
                .unwrap_or_else(|error| panic!("{connector} caso {index}: {error}"))
                .unwrap_or_else(|| panic!("{connector} caso {index}: caiu em drift"));

            // A identidade que o supervisor deu viaja no Fato.
            assert_eq!(fact["fact.datasource"], identity.to_json());

            let declared = mapping.action(&case.expect_action).expect("acao mapeada");
            if !declared.security_relevant {
                assert!(
                    fact.get("fact.security").is_none(),
                    "{connector} caso {index}: ruido operacional nao vira evento"
                );
                continue;
            }

            let emitted = fact
                .get("fact.security")
                .unwrap_or_else(|| panic!("{connector} caso {index}: sem evento canonico"));
            assert_eq!(emitted["provenance"]["forge_lsn"], index as u64 + 1);
            assert_eq!(emitted["tenant_id"], "gov.br/orgao-a");
            assert_eq!(emitted["datasource_id"], "teste://hot-path");
            assert_eq!(emitted["sensor_id"], "forge-teste");
            assert_eq!(
                emitted["provenance"]["connector_digest"],
                schema::model::hash32::to_hex(&digest)
            );

            // Normalizacao independente do MESMO Fato, com o instante que o
            // proprio evento declara: se o caminho quente tivesse usado outro
            // mapping, outro digest ou outra identidade, isto divergia.
            let normalized_at = emitted["normalized_at_micros"].as_i64().expect("instante");
            let independent = schema::from_operational_fact(
                &fact,
                mapping,
                &NormalizationContext {
                    tenant_id: &identity.tenant_id,
                    datasource_id: &identity.datasource_id,
                    sensor_id: &identity.sensor_id,
                    source_sequence: Some(&sequence),
                    normalized_at_micros: normalized_at,
                    forge_source_id: PINNED_FORGE_SOURCE_ID,
                    forge_lsn: index as u64 + 1,
                    source_event_id: None,
                    connector_digest: digest,
                },
            )
            .expect("normaliza")
            .into_event()
            .expect("evento");
            assert_eq!(
                emitted,
                &serde_json::to_value(&independent).unwrap(),
                "{connector} caso {index}: o caminho quente divergiu da normalizacao"
            );
        }
    }
}

#[test]
fn a_legacy_connector_emits_no_canonical_event_in_the_hot_path() {
    // Gate CM2 no caminho quente, nao apenas no papel.
    let dir = PathBuf::from(format!("{REGISTRY}/postgresql/v1.1.0.hcx"));
    let mut runner = ReconstitutiveRunner::load(&dir.to_string_lossy()).expect("runner");
    assert!(runner.is_legacy_connector());
    assert_eq!(runner.mapping_version(), None);

    let identity =
        heraclitus::hfb2::SecurityIdentity::new("gov.br/orgao-a", "teste://legado", "forge-teste")
            .unwrap();
    let context = heraclitus::runner::EmissionContext {
        identity: &identity,
        forge_source_id: PINNED_FORGE_SOURCE_ID,
        forge_lsn: 1,
        source_sequence: None,
        source_event_id: None,
    };
    let line = "2026-06-26 01:20:05.123 UTC [14802] FATAL:  password authentication failed for \
                user \"admin\"";
    let fact = runner
        .process_observation_with_context(line, &context)
        .expect("sem erro")
        .expect("Fato valido");
    assert_eq!(fact["fact.behavior"]["action"], "authentication.failure");
    assert!(fact.get("fact.security").is_none());
    // Mas a identidade do datasource viaja na mesma: e requisito do formato.
    assert_eq!(fact["fact.datasource"], identity.to_json());
}

#[test]
fn an_artifact_declaring_an_unknown_mapping_refuses_to_load() {
    // O contrato e verificado no LOAD. Falhar aqui e barato; falhar na milesima
    // linha, em producao, nao e.
    let temp = std::env::temp_dir().join(format!("forge_mapping_{}.hcx", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    let source = artifact_dir("postgresql");
    std::fs::create_dir_all(&temp).unwrap();
    for entry in std::fs::read_dir(&source).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), temp.join(entry.file_name())).unwrap();
    }
    let manifest = std::fs::read_to_string(temp.join("manifest.yaml")).unwrap();
    std::fs::write(
        temp.join("manifest.yaml"),
        manifest.replace("postgresql/1.0.0", "inexistente/9.9.9"),
    )
    .unwrap();

    // O mapping citado nao existe neste binario...
    assert!(schema::mapping::mapping("inexistente/9.9.9").is_err());

    // ...mas o artefato nem chega a ser lido: trocar a declaracao muda o
    // digest, e sem a chave de publicacao ninguem reassina. E este o ponto —
    // apontar um conector publicado para outro mapping exige republica-lo.
    let trust_root = PathBuf::from(format!("{REGISTRY}/publisher.pub"));
    let error = ReconstitutiveRunner::load_with_trust_root(&temp, &trust_root)
        .err()
        .expect("artefato adulterado nao pode carregar");
    assert!(
        error.to_string().contains("adulterado"),
        "esperava recusa por digest: {error}"
    );
    let _ = std::fs::remove_dir_all(&temp);
}
