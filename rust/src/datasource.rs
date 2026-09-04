//! SPEC-0071 §5.3 e §5.5 — estado desejado, estado observado, e o portão de
//! admissão que decide se um datasource pode sequer arrancar.
//!
//! ## O que a §5.5 exige, e o que já existia
//!
//! O [`crate::hcx`] já faz o trabalho criptográfico: recomputa o digest
//! canónico de todos os ficheiros e verifica a assinatura Ed25519 contra a
//! trust root da organização. O que faltava era **ligar isso ao ciclo de vida
//! do datasource**:
//!
//! > Falha em qualquer etapa impede o datasource de iniciar e produz estado
//! > `Quarantined`.
//!
//! Verificar e depois arrancar à mesma não é fail-closed. É por isso que
//! [`admitir`] não devolve um `Result` que o chamador possa ignorar com um
//! `unwrap_or_default`: devolve um [`AdmissionOutcome`] cujo ramo de falha É um
//! estado de datasource, e [`DatasourceStatus::deve_arrancar`] é `false` nesse
//! ramo.
//!
//! ## Porque é que a quarentena nomeia a etapa
//!
//! Um `Quarantined` sem mais nada é intriável: quem opera não sabe se o pacote
//! foi adulterado, se a chave é outra, ou se o runtime é velho de mais para o
//! schema. [`AdmissionStep`] regista qual das seis etapas falhou, e o motivo
//! vai em texto ao lado.
//!
//! ## A ligação que ninguém faria à mão
//!
//! O [`DatasourceSpec::connector_ref`] declara QUAL conteúdo o datasource deve
//! usar. A verificação do `.hcx` diz que o conteúdo em disco está íntegro. São
//! coisas diferentes: sem comparar as duas, verifica-se um artefacto e carrega-
//! se outro — ambos legitimamente assinados. A etapa
//! [`AdmissionStep::DigestDeclarado`] existe só para isso.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::source::{DatasourceIdentity, DatasourceState, SourceCounters};

/// Versões de schema que este runtime sabe interpretar (§5.5 etapa 5).
///
/// É uma lista e não um mínimo: um runtime que aceita "tudo a partir de v9"
/// aceita um v12 que ainda não existe e cujo significado ninguém garantiu.
pub const SCHEMAS_SUPORTADOS: &[&str] = &["v9"];

/// §5.5 etapa 5, isolada do resto para poder ser testada sem reassinar um
/// pacote inteiro.
///
/// Um artefacto com um schema que este runtime não conhece está íntegro e bem
/// assinado — e continua a ser inutilizável, porque o significado dos campos
/// não é o que o código assume. Integridade não é compatibilidade.
pub fn schema_compativel(schema_version: &str) -> bool {
    SCHEMAS_SUPORTADOS.contains(&schema_version)
}

/// Referência a um conteúdo publicado, pelo seu digest.
///
/// Espelha o `ContentRef` do HeraclitusDB de propósito: os dois repositórios
/// têm de concordar na forma para o Δ1 fechar. A duplicação é uma costura
/// conhecida — enquanto o modelo canónico não for um crate partilhado, é aqui
/// que ela vive, declarada em vez de escondida.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContentRef {
    digest: String,
}

impl ContentRef {
    /// Aceita apenas 64 hexadecimais minúsculos.
    ///
    /// Um digest com maiúsculas comparava desigual a um igual em minúsculas, e
    /// a comparação de digests é a única coisa que separa "o conteúdo que a
    /// organização aprovou" de "um conteúdo qualquer bem assinado".
    pub fn novo(digest: impl Into<String>) -> Result<Self, String> {
        let digest = digest.into();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("digest deve ter 64 hexadecimais; veio {digest:?}"));
        }
        if digest.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err("digest deve ser hexadecimal minusculo".into());
        }
        Ok(Self { digest })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl fmt::Display for ContentRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.digest)
    }
}

/// Referência a um segredo, NUNCA o segredo.
///
/// O tipo guarda um identificador de cofre. Se guardasse o valor, ele acabaria
/// num `Debug`, num log ou num `.hdb` — e um segredo que passou por um log
/// deixou de ser segredo.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    vault_id: String,
}

impl SecretRef {
    pub fn novo(vault_id: impl Into<String>) -> Result<Self, String> {
        let vault_id = vault_id.into();
        if vault_id.trim().is_empty() {
            return Err("vault_id nao pode ser vazio".into());
        }
        Ok(Self { vault_id })
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
}

// `Debug` à mão: o derive imprimiria o campo. Aqui nem o identificador do cofre
// sai, porque um identificador de cofre em log é meio caminho para o segredo.
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretRef(<oculto>)")
    }
}

/// Estado DESEJADO de um datasource (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasourceSpec {
    pub datasource_id: String,
    pub tenant_id: String,
    pub adapter_kind: String,
    pub connector_ref: ContentRef,
    pub credential_ref: Option<SecretRef>,
    pub expected_cadence_secs: Option<u64>,
    pub max_lateness_secs: u64,
    pub buffer_limit_bytes: u64,
    pub enabled: bool,
}

impl DatasourceSpec {
    pub fn validar(&self) -> Result<(), String> {
        for (campo, valor) in [
            ("datasource_id", &self.datasource_id),
            ("tenant_id", &self.tenant_id),
            ("adapter_kind", &self.adapter_kind),
        ] {
            if valor.trim().is_empty() {
                return Err(format!("{campo} nao pode ser vazio"));
            }
        }
        if self.buffer_limit_bytes == 0 {
            return Err("buffer_limit_bytes tem de ser > 0".into());
        }
        // Uma cadência de 0 significaria "espero um evento a cada 0 segundos",
        // e todo o datasource ficaria `Delayed` para sempre.
        if self.expected_cadence_secs == Some(0) {
            return Err("expected_cadence_secs tem de ser > 0 quando presente".into());
        }
        Ok(())
    }
}

/// Estado OBSERVADO de um datasource (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasourceStatus {
    pub generation: u64,
    pub state: DatasourceState,
    pub last_observed_at: Option<i64>,
    pub last_ingested_at: Option<i64>,
    pub last_checkpoint: Option<String>,
    pub active_connector_digest: [u8; 32],
    pub counters: SourceCounters,
    pub last_error_code: Option<String>,
}

impl DatasourceStatus {
    /// O datasource passou a admissão e pode arrancar.
    pub fn admitido(generation: u64, digest: [u8; 32]) -> Self {
        Self {
            generation,
            state: DatasourceState::Starting,
            last_observed_at: None,
            last_ingested_at: None,
            last_checkpoint: None,
            active_connector_digest: digest,
            counters: SourceCounters::default(),
            last_error_code: None,
        }
    }

    /// O datasource NÃO passou a admissão.
    ///
    /// `active_connector_digest` fica a zeros de propósito: não há conteúdo
    /// activo nenhum, e pôr aqui o digest que falhou a verificação faria um
    /// artefacto rejeitado parecer, num painel, o conteúdo em uso.
    pub fn em_quarentena(generation: u64, codigo: impl Into<String>) -> Self {
        Self {
            generation,
            state: DatasourceState::Quarantined,
            last_observed_at: None,
            last_ingested_at: None,
            last_checkpoint: None,
            active_connector_digest: [0u8; 32],
            counters: SourceCounters::default(),
            last_error_code: Some(codigo.into()),
        }
    }

    /// Fail-closed: só arranca quem foi admitido.
    pub fn deve_arrancar(&self) -> bool {
        !matches!(
            self.state,
            DatasourceState::Quarantined | DatasourceState::Stopped
        )
    }
}

/// As seis etapas da §5.5, pela ordem em que correm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionStep {
    /// 1 — resolver a trust root configurada pelo órgão.
    TrustRoot,
    /// 2 — validar o manifesto canónico.
    Manifesto,
    /// 3+4 — recomputar o digest de todos os ficheiros e verificar Ed25519.
    /// São uma etapa só porque o `verify_artifact` faz as duas ou nenhuma.
    DigestEAssinatura,
    /// A ligação entre o que a spec declara e o que está em disco.
    DigestDeclarado,
    /// 5 — compatibilidade de schema/runtime.
    Compatibilidade,
    /// A spec em si estava malformada; nem se chega a olhar para o artefacto.
    SpecInvalida,
}

impl AdmissionStep {
    /// Código curto e estável para `last_error_code` e para alertas.
    pub fn codigo(&self) -> &'static str {
        match self {
            Self::TrustRoot => "hcx_trust_root",
            Self::Manifesto => "hcx_manifesto",
            Self::DigestEAssinatura => "hcx_assinatura",
            Self::DigestDeclarado => "hcx_digest_declarado",
            Self::Compatibilidade => "hcx_schema_incompativel",
            Self::SpecInvalida => "spec_invalida",
        }
    }
}

/// §5.5 etapa 6 — o registo do que foi activado, com o digest exacto.
///
/// É devolvido e não escrito: a persistência fica acima desta fronteira, tal
/// como nos adapters. Um módulo que verificasse E escrevesse tornaria a
/// verificação impossível de testar sem um `.hdb`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentActivated {
    pub tenant_id: String,
    pub datasource_id: String,
    pub adapter_kind: String,
    pub content: ContentRef,
    pub schema_version: String,
    pub manifest_id: String,
}

/// O resultado da admissão. Não há terceiro ramo: ou activa, ou fica em
/// quarentena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Activated {
        status: DatasourceStatus,
        evento: ContentActivated,
    },
    Quarantined {
        status: DatasourceStatus,
        etapa: AdmissionStep,
        motivo: String,
    },
}

impl AdmissionOutcome {
    pub fn status(&self) -> &DatasourceStatus {
        match self {
            Self::Activated { status, .. } | Self::Quarantined { status, .. } => status,
        }
    }

    pub fn activou(&self) -> bool {
        matches!(self, Self::Activated { .. })
    }
}

#[derive(Deserialize)]
struct ManifestoMinimo {
    id: String,
    #[serde(default = "schema_por_omissao")]
    schema_version: String,
}

fn schema_por_omissao() -> String {
    "v9".into()
}

fn quarentena(
    generation: u64,
    etapa: AdmissionStep,
    motivo: impl Into<String>,
) -> AdmissionOutcome {
    AdmissionOutcome::Quarantined {
        status: DatasourceStatus::em_quarentena(generation, etapa.codigo()),
        etapa,
        motivo: motivo.into(),
    }
}

/// Corre as seis etapas da §5.5 antes de o datasource poder arrancar.
///
/// `artefacto` é a raiz do `.hcx` em disco. Nenhum YAML, regex, modelo ou DAG
/// deve ser interpretado antes desta função devolver [`AdmissionOutcome::Activated`].
pub fn admitir(spec: &DatasourceSpec, artefacto: &Path, generation: u64) -> AdmissionOutcome {
    if let Err(erro) = spec.validar() {
        return quarentena(generation, AdmissionStep::SpecInvalida, erro);
    }
    if !spec.enabled {
        // Desligado por decisão do órgão não é quarentena: é `Stopped`. Confundir
        // os dois faria um datasource desligado à mão parecer um pacote rejeitado.
        let mut status = DatasourceStatus::admitido(generation, [0u8; 32]);
        status.state = DatasourceState::Stopped;
        return AdmissionOutcome::Quarantined {
            status,
            etapa: AdmissionStep::SpecInvalida,
            motivo: "datasource desactivado no spec".into(),
        };
    }

    // 1 — trust root.
    let trust_root = match crate::hcx::resolve_trust_root(artefacto) {
        Ok(caminho) => caminho,
        Err(erro) => return quarentena(generation, AdmissionStep::TrustRoot, erro.to_string()),
    };

    // 2 — manifesto canónico. Lê-se ANTES da assinatura só para saber se
    // existe e se é YAML; nada dele é usado antes da etapa 4 passar.
    let manifesto_bruto = match std::fs::read_to_string(artefacto.join("manifest.yaml")) {
        Ok(texto) => texto,
        Err(erro) => {
            return quarentena(
                generation,
                AdmissionStep::Manifesto,
                format!("manifest.yaml ilegivel: {erro}"),
            )
        }
    };
    let manifesto: ManifestoMinimo = match serde_yaml::from_str(&manifesto_bruto) {
        Ok(m) => m,
        Err(erro) => {
            return quarentena(
                generation,
                AdmissionStep::Manifesto,
                format!("manifest.yaml invalido: {erro}"),
            )
        }
    };

    // 3+4 — digest recomputado de todos os ficheiros e Ed25519.
    let digest_hex = match crate::hcx::verify_artifact(artefacto, &trust_root) {
        Ok(hex) => hex,
        Err(erro) => {
            return quarentena(
                generation,
                AdmissionStep::DigestEAssinatura,
                erro.to_string(),
            )
        }
    };

    // O que a spec declarou tem de ser o que está em disco. Sem isto,
    // verifica-se um artefacto e carrega-se outro — ambos bem assinados.
    if digest_hex != spec.connector_ref.digest() {
        return quarentena(
            generation,
            AdmissionStep::DigestDeclarado,
            format!(
                "spec declara {} mas o artefacto verificado e {digest_hex}",
                spec.connector_ref.digest()
            ),
        );
    }

    // 5 — compatibilidade de schema/runtime.
    if !schema_compativel(&manifesto.schema_version) {
        return quarentena(
            generation,
            AdmissionStep::Compatibilidade,
            format!(
                "schema {} nao suportado; este runtime aceita {SCHEMAS_SUPORTADOS:?}",
                manifesto.schema_version
            ),
        );
    }

    // 6 — o registo, com o digest exacto.
    let content = match ContentRef::novo(&digest_hex) {
        Ok(c) => c,
        Err(erro) => return quarentena(generation, AdmissionStep::DigestEAssinatura, erro),
    };
    let mut bytes = [0u8; 32];
    for (i, par) in digest_hex.as_bytes().chunks_exact(2).enumerate().take(32) {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(par).unwrap_or("00"), 16).unwrap_or(0);
    }

    AdmissionOutcome::Activated {
        status: DatasourceStatus::admitido(generation, bytes),
        evento: ContentActivated {
            tenant_id: spec.tenant_id.clone(),
            datasource_id: spec.datasource_id.clone(),
            adapter_kind: spec.adapter_kind.clone(),
            content,
            schema_version: manifesto.schema_version,
            manifest_id: manifesto.id,
        },
    }
}

/// A identidade que o adapter vai usar, derivada da spec.
impl DatasourceSpec {
    pub fn identidade(&self, sensor_id: impl Into<String>) -> DatasourceIdentity {
        DatasourceIdentity {
            tenant_id: self.tenant_id.clone(),
            datasource_id: self.datasource_id.clone(),
            sensor_id: sensor_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const ARTEFACTO: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../registry/postgresql/v1.1.0.hcx"
    );

    fn artefacto() -> PathBuf {
        PathBuf::from(ARTEFACTO)
    }

    /// O digest real do artefacto do registry, para a spec poder declara-lo.
    fn digest_real() -> String {
        let raiz = artefacto();
        let trust = crate::hcx::resolve_trust_root(&raiz).expect("trust root");
        crate::hcx::verify_artifact(&raiz, &trust).expect("artefacto do registry verifica")
    }

    fn spec_valida(digest: &str) -> DatasourceSpec {
        DatasourceSpec {
            datasource_id: "ds-pg-1".into(),
            tenant_id: "tenant-a".into(),
            adapter_kind: "file-tail".into(),
            connector_ref: ContentRef::novo(digest).expect("digest"),
            credential_ref: None,
            expected_cadence_secs: Some(60),
            max_lateness_secs: 300,
            buffer_limit_bytes: 1 << 20,
            enabled: true,
        }
    }

    #[test]
    fn um_artefacto_integro_e_declarado_e_admitido() {
        let digest = digest_real();
        let resultado = admitir(&spec_valida(&digest), &artefacto(), 1);
        let AdmissionOutcome::Activated { status, evento } = resultado else {
            panic!("o artefacto do registry tinha de ser admitido: {resultado:?}");
        };
        assert!(status.deve_arrancar());
        assert_eq!(status.state, DatasourceState::Starting);
        assert!(status.last_error_code.is_none());
        assert_eq!(evento.content.digest(), digest);
        assert_eq!(evento.schema_version, "v9");
        assert!(evento.manifest_id.contains("postgresql"));

        // O digest do status tem de ser os MESMOS bytes do hex verificado.
        let hex: String = status
            .active_connector_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, digest);
    }

    /// A ligacao que ninguem faria a mao: verificar um artefacto e carregar
    /// outro, ambos bem assinados.
    #[test]
    fn um_digest_declarado_diferente_manda_para_quarentena() {
        let mut spec = spec_valida(&digest_real());
        spec.connector_ref = ContentRef::novo("aa".repeat(32)).unwrap();
        let resultado = admitir(&spec, &artefacto(), 7);
        let AdmissionOutcome::Quarantined { status, etapa, .. } = resultado else {
            panic!("um digest declarado diferente nao pode ser admitido");
        };
        assert_eq!(etapa, AdmissionStep::DigestDeclarado);
        assert!(!status.deve_arrancar(), "fail-closed: nao arranca");
        assert_eq!(status.state, DatasourceState::Quarantined);
        assert_eq!(
            status.last_error_code.as_deref(),
            Some("hcx_digest_declarado")
        );
        assert_eq!(
            status.active_connector_digest, [0u8; 32],
            "um artefacto rejeitado nao pode aparecer como conteudo activo"
        );
    }

    /// Copia o artefacto do registry para um registry temporario, com a
    /// `publisher.pub` no sitio onde o `resolve_trust_root` a encontra ao subir
    /// os ancestrais.
    ///
    /// Deliberadamente SEM variaveis de ambiente: `set_var` e global ao
    /// processo, e os testes correm em paralelo — um teste que mexe no ambiente
    /// faz falhar outro que nao tem nada a ver com ele.
    fn registry_temporario(tmp: &Path) -> PathBuf {
        let registry = tmp.join("registry");
        let copia = registry.join("postgresql").join("v1.1.0.hcx");
        std::fs::create_dir_all(&copia).unwrap();
        for entrada in std::fs::read_dir(artefacto()).unwrap() {
            let entrada = entrada.unwrap();
            if entrada.file_type().unwrap().is_file() {
                std::fs::copy(entrada.path(), copia.join(entrada.file_name())).unwrap();
            }
        }
        let origem = artefacto()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("publisher.pub");
        std::fs::copy(origem, registry.join("publisher.pub")).unwrap();
        copia
    }

    /// Adulterar um byte de um ficheiro qualquer do pacote tem de ser apanhado.
    #[test]
    fn um_artefacto_adulterado_vai_para_quarentena() {
        let digest = digest_real();
        let temporario = tempfile::tempdir().expect("tempdir");
        let copia = registry_temporario(temporario.path());

        // A copia intacta admite — se nao admitisse, o resto do teste nao
        // provava nada sobre a adulteracao.
        assert!(admitir(&spec_valida(&digest), &copia, 1).activou());

        let ontologia = copia.join("ontology.yaml");
        let mut texto = std::fs::read_to_string(&ontologia).unwrap();
        texto.push_str("\n# um comentario a mais\n");
        std::fs::write(&ontologia, texto).unwrap();

        let resultado = admitir(&spec_valida(&digest), &copia, 1);
        let AdmissionOutcome::Quarantined { etapa, status, .. } = resultado else {
            panic!("conteudo adulterado nao pode ser admitido");
        };
        assert_eq!(etapa, AdmissionStep::DigestEAssinatura);
        assert!(!status.deve_arrancar());
    }

    /// Etapa 2 isolada: com a trust root a resolver, o que falha e o manifesto.
    #[test]
    fn um_manifesto_ausente_vai_para_quarentena() {
        let temporario = tempfile::tempdir().expect("tempdir");
        let copia = registry_temporario(temporario.path());
        std::fs::remove_file(copia.join("manifest.yaml")).unwrap();

        let resultado = admitir(&spec_valida(&digest_real()), &copia, 1);
        let AdmissionOutcome::Quarantined { etapa, status, .. } = resultado else {
            panic!("sem manifesto nao ha admissao");
        };
        assert_eq!(etapa, AdmissionStep::Manifesto);
        assert_eq!(status.last_error_code.as_deref(), Some("hcx_manifesto"));
    }

    /// Etapa 5 directamente. Nao se pode encenar no pacote sem a chave privada
    /// (mexer no manifesto muda o digest e a etapa 4 apanha-o primeiro), e um
    /// teste que fingisse ser da etapa 5 estando a exercitar a 4 seria pior do
    /// que nao existir.
    #[test]
    fn a_compatibilidade_de_schema_e_uma_lista_e_nao_um_minimo() {
        assert!(
            schema_compativel("v9"),
            "o schema em producao tem de continuar suportado"
        );
        assert!(!schema_compativel("v99"), "um schema futuro nao e aceite");
        assert!(!schema_compativel("v10"));
        assert!(!schema_compativel(""));
        // Integridade nao e compatibilidade: um pacote perfeito com um schema
        // que este runtime nao le continua inutilizavel.
        assert!(!schema_compativel("V9"), "a comparacao e exacta");
    }

    /// Alterar o manifesto muda o digest: a etapa 4 apanha-o antes da 5.
    /// A ordem das etapas e ela propria uma garantia.
    #[test]
    fn mexer_no_manifesto_e_apanhado_pela_assinatura() {
        let temporario = tempfile::tempdir().expect("tempdir");
        let copia = registry_temporario(temporario.path());
        let manifesto = copia.join("manifest.yaml");
        let texto = std::fs::read_to_string(&manifesto)
            .unwrap()
            .replace("schema_version: v9", "schema_version: v99");
        std::fs::write(&manifesto, texto).unwrap();

        let resultado = admitir(&spec_valida(&digest_real()), &copia, 1);
        let AdmissionOutcome::Quarantined { etapa, .. } = resultado else {
            panic!("manifesto alterado nao pode ser admitido");
        };
        assert_eq!(
            etapa,
            AdmissionStep::DigestEAssinatura,
            "a assinatura tem de falhar ANTES da compatibilidade"
        );
    }

    /// Desligado a mao NAO e o mesmo que rejeitado: um painel que os confunda
    /// manda alguem investigar um incidente que nao existe.
    #[test]
    fn desactivado_fica_stopped_e_nao_quarantined() {
        let mut spec = spec_valida(&digest_real());
        spec.enabled = false;
        let resultado = admitir(&spec, &artefacto(), 3);
        assert_eq!(resultado.status().state, DatasourceState::Stopped);
        assert!(!resultado.status().deve_arrancar());
    }

    #[test]
    fn uma_spec_malformada_nem_chega_a_olhar_para_o_artefacto() {
        let mut spec = spec_valida(&digest_real());
        spec.buffer_limit_bytes = 0;
        let r = admitir(&spec, Path::new("/nao/existe"), 1);
        assert!(matches!(
            r,
            AdmissionOutcome::Quarantined {
                etapa: AdmissionStep::SpecInvalida,
                ..
            }
        ));

        let mut spec = spec_valida(&digest_real());
        spec.expected_cadence_secs = Some(0);
        assert!(!admitir(&spec, Path::new("/nao/existe"), 1).activou());
    }

    #[test]
    fn o_content_ref_recusa_digests_que_nao_comparam() {
        assert!(ContentRef::novo("aa".repeat(32)).is_ok());
        assert!(ContentRef::novo("AA".repeat(32)).is_err(), "maiusculas");
        assert!(ContentRef::novo("aa".repeat(31)).is_err(), "curto");
        assert!(
            ContentRef::novo("zz".repeat(32)).is_err(),
            "nao hexadecimal"
        );
    }

    /// Um segredo que passou por um log deixou de ser segredo.
    #[test]
    fn o_secret_ref_nao_imprime_o_que_guarda() {
        let s = SecretRef::novo("cofre/pg/senha").unwrap();
        let impresso = format!("{s:?}");
        assert!(!impresso.contains("cofre"), "vazou: {impresso}");
        assert_eq!(s.vault_id(), "cofre/pg/senha");
        assert!(SecretRef::novo("  ").is_err());
    }

    #[test]
    fn a_identidade_do_adapter_sai_da_spec() {
        let spec = spec_valida(&digest_real());
        let id = spec.identidade("sensor-1");
        assert_eq!(id.tenant_id, "tenant-a");
        assert_eq!(id.datasource_id, "ds-pg-1");
        assert_eq!(id.sensor_id, "sensor-1");
        assert!(id.validate().is_ok());
    }
}
