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
//! ## A ordem das etapas é parte da garantia
//!
//! A §5.5 lista "validar o manifesto canónico" como etapa 2, antes do digest e
//! da assinatura. Aqui a etapa 2 verifica que o manifesto **existe e não está
//! vazio**, e o parser de YAML só corre depois da etapa 4.
//!
//! A secção abre com "antes de carregar qualquer YAML, regex, modelo ou DAG, o
//! runner MUST [as seis etapas]", e correr `serde_yaml` na etapa 2 seria
//! carregar YAML antes de alguém ter dito que aqueles bytes são os que a
//! organização assinou. O parser é código a correr sobre entrada controlada por
//! quem escreveu o ficheiro; que o valor não fosse usado não muda nada, porque
//! o risco é a execução.
//!
//! ## A ligação que ninguém faria à mão
//!
//! O [`DatasourceSpec::connector_ref`] declara QUAL conteúdo o datasource deve
//! usar. A verificação do `.hcx` diz que o conteúdo em disco está íntegro. São
//! coisas diferentes: sem comparar as duas, verifica-se um artefacto e carrega-
//! se outro — ambos legitimamente assinados. A etapa
//! [`AdmissionStep::DigestDeclarado`] existe só para isso.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::source::{
    AdapterError, DatasourceIdentity, DatasourceState, ObservationBatch, SourceAck, SourceAdapter,
    SourceCounters, SourceSupervisor,
};

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
///
/// ## Porque é que o `Debug` esconde e o `Serialize` não
///
/// Parece incoerente e não é. São duas saídas com destinos diferentes:
///
/// - o `Debug` aparece em mensagens de erro, em `tracing` e em despejos de
///   estado, sítios onde ninguém decidiu que aquele identificador devia ir. Um
///   caminho de cofre num log expõe a estrutura interna do cofre a quem lê o
///   log, e isso é meio caminho para o segredo;
/// - o `Serialize` é a persistência DELIBERADA do estado desejado. Uma
///   `DatasourceSpec` sem `credential_ref` é inútil: ninguém saberia que
///   credencial usar. Escondê-lo aqui não protegeria nada e partiria a spec.
///
/// O que nunca acontece, em nenhuma das duas, é o VALOR do segredo sair — ele
/// não está aqui dentro.
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
    /// O órgão desligou este datasource. Não é uma falha de nada.
    Desactivado,
    /// O artefacto passou e o adapter é que não subiu: porto ocupado, ficheiro
    /// inexistente, id duplicado.
    ///
    /// Tem etapa própria porque conflacioná-la com [`Self::SpecInvalida`]
    /// mandaria quem opera procurar um erro de configuração que não existe — a
    /// spec estava correcta e o conteúdo estava íntegro.
    ArranqueDoAdapter,
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
            Self::Desactivado => "desactivado",
            Self::ArranqueDoAdapter => "adapter_nao_arrancou",
        }
    }

    /// Se esta etapa representa um problema com o CONTEÚDO.
    ///
    /// Serve para separar o que exige investigação de segurança — pacote
    /// adulterado, chave errada — do que é operacional ou deliberado. Um alerta
    /// que trate as duas coisas por igual acaba silenciado.
    pub fn e_falha_de_conteudo(&self) -> bool {
        matches!(
            self,
            Self::TrustRoot
                | Self::Manifesto
                | Self::DigestEAssinatura
                | Self::DigestDeclarado
                | Self::Compatibilidade
        )
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
    /// SEM valor por omissao.
    ///
    /// Tinha `#[serde(default)]` a devolver "v9", e isso fazia a etapa 5 da
    /// §5.5 falhar ABERTA: um manifesto que nao declarasse schema nenhum era
    /// admitido como se declarasse o schema que este runtime sabe ler. A
    /// verificacao de compatibilidade passava sem nada ter sido verificado.
    ///
    /// Um artefacto que nao diz que schema usa nao pode ser interpretado — nao
    /// se adivinha o significado dos campos de outra pessoa.
    schema_version: String,
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
        status.last_error_code = Some(AdmissionStep::Desactivado.codigo().into());
        return AdmissionOutcome::Quarantined {
            status,
            etapa: AdmissionStep::Desactivado,
            motivo: "datasource desactivado no spec".into(),
        };
    }

    // 1 — trust root.
    let trust_root = match crate::hcx::resolve_trust_root(artefacto) {
        Ok(caminho) => caminho,
        Err(erro) => return quarentena(generation, AdmissionStep::TrustRoot, erro.to_string()),
    };

    // 2 — o manifesto canónico EXISTE e não está vazio.
    //
    // Só isso. Não se parseia aqui, e a diferença não é de estilo.
    //
    // A §5.5 abre com "antes de carregar qualquer YAML, regex, modelo ou DAG, o
    // runner MUST [as seis etapas]". Correr o parser de YAML na etapa 2 é
    // carregar YAML antes de a etapa 4 ter dito que os bytes são os que a
    // organização assinou — e o parser é código a correr sobre entrada
    // controlada por quem escreveu o ficheiro. Um `serde_yaml` com um bug de
    // profundidade ou de alias já foi executado quando a assinatura ainda nem
    // foi olhada. Não interessa que o VALOR não fosse usado: o problema é a
    // execução, não o uso.
    //
    // Foi o meu comentário anterior que estava errado, e contradizia a
    // invariante escrita no cabeçalho deste módulo e na linha 5 do `hcx.rs`.
    let manifesto_caminho = artefacto.join("manifest.yaml");
    match std::fs::metadata(&manifesto_caminho) {
        Ok(m) if m.is_file() && m.len() > 0 => {}
        Ok(_) => {
            return quarentena(
                generation,
                AdmissionStep::Manifesto,
                "manifest.yaml vazio ou nao e um ficheiro".to_string(),
            )
        }
        Err(erro) => {
            return quarentena(
                generation,
                AdmissionStep::Manifesto,
                format!("manifest.yaml ausente: {erro}"),
            )
        }
    }

    // 3+4 — digest recomputado de TODOS os ficheiros (o manifesto incluído) e
    // Ed25519 contra a trust root.
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

    // Só agora — com a assinatura verificada — é que o YAML é interpretado.
    //
    // Fica uma janela conhecida: o `verify_artifact` leu os bytes para os
    // somar e esta leitura é outra, e entre as duas o ficheiro pode mudar.
    // Fechá-la a sério é verificar a partir de uma cópia em memória, o que
    // muda o `hcx.rs` e afecta também o `runner.rs`, que tem exactamente a
    // mesma janela. Meia correcção só aqui daria dois comportamentos
    // diferentes para o mesmo problema — por isso fica declarada em vez de
    // remendada.
    let manifesto_bruto = match std::fs::read_to_string(&manifesto_caminho) {
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

/// O supervisor com o portão da §5.5 à frente.
///
/// O [`SourceSupervisor`] cru aceita qualquer adapter que lhe deem. Isso é
/// correcto para ele — não é trabalho dele saber de artefactos assinados — mas
/// deixa a §5.5 por cumprir enquanto ninguém a chamar. Este tipo é quem a
/// chama.
///
/// A diferença que interessa está em [`FabricSupervisor::admitir_e_registar`]:
/// o adapter só é **construído** depois de a admissão passar. Construir
/// primeiro e decidir depois faria um artefacto rejeitado abrir na mesma um
/// porto de escuta, ou começar a seguir um ficheiro — e um datasource em
/// quarentena que está a ouvir na rede é uma contradição em termos.
/// O que a spec diz sobre o ritmo esperado de um datasource (§5.3).
struct Cadencia {
    expected_cadence_secs: Option<u64>,
    max_lateness_secs: u64,
}

/// Traduz "há quanto tempo não chega nada" nos estados `Delayed` e `Silent`.
///
/// Sem isto, dois dos oito estados da §5.3 eram inalcançáveis: nenhum adapter
/// os pode produzir sozinho, porque nenhum adapter sabe qual é o ritmo esperado
/// da SUA fonte — isso está na spec, não no transporte.
///
/// E é a diferença que interessa numa plataforma de telemetria: uma fonte que
/// emudeceu parece exactamente igual a uma fonte sem nada a reportar. É por
/// isso que os campos `expected_cadence_secs` e `max_lateness_secs` existem na
/// §5.3, e enquanto ninguém os lesse eram decoração.
///
/// Só se aplica a quem estaria `Healthy`: um `Degraded` ou um `Drifted` dizem
/// algo mais específico, e trocá-los por `Delayed` perderia a razão concreta.
fn aplicar_silencio(estado: &mut DatasourceStatus, cadencia: &Cadencia, agora_micros: u64) {
    if estado.state != DatasourceState::Healthy {
        return;
    }
    let Some(ultimo) = estado.last_observed_at else {
        return;
    };
    let decorridos_secs = agora_micros.saturating_sub(ultimo.max(0) as u64) / 1_000_000;

    if decorridos_secs > cadencia.max_lateness_secs {
        estado.state = DatasourceState::Silent;
        estado.last_error_code = Some("sem_observacoes".into());
        return;
    }
    if let Some(esperada) = cadencia.expected_cadence_secs {
        if decorridos_secs > esperada {
            estado.state = DatasourceState::Delayed;
            estado.last_error_code = Some("atrasado".into());
        }
    }
}

pub struct FabricSupervisor {
    interno: SourceSupervisor,
    /// O ritmo esperado de cada datasource, guardado no registo.
    cadencias: BTreeMap<String, Cadencia>,
    /// Estado observado (§5.3) de TODOS os datasources, incluindo os que não
    /// arrancaram. Um datasource em quarentena não tem adapter, e sem isto
    /// desaparecia dos painéis — que é a pior forma de esconder uma rejeição.
    estados: BTreeMap<String, DatasourceStatus>,
    /// Os `ContentActivated` da etapa 6, à espera de quem os persista.
    activados: Vec<ContentActivated>,
}

impl Default for FabricSupervisor {
    fn default() -> Self {
        Self::novo()
    }
}

impl FabricSupervisor {
    pub fn novo() -> Self {
        Self {
            interno: SourceSupervisor::default(),
            cadencias: BTreeMap::new(),
            estados: BTreeMap::new(),
            activados: Vec::new(),
        }
    }

    /// Corre a admissão da §5.5 e, só se ela passar, constrói e regista o
    /// adapter.
    ///
    /// `construir` é uma closure e não um adapter já feito precisamente para
    /// que nada aconteça no caso rejeitado.
    pub fn admitir_e_registar(
        &mut self,
        spec: &DatasourceSpec,
        artefacto: &Path,
        generation: u64,
        construir: impl FnOnce() -> Result<Box<dyn SourceAdapter>, AdapterError>,
    ) -> AdmissionOutcome {
        let resultado = admitir(spec, artefacto, generation);
        let id = spec.datasource_id.clone();

        match &resultado {
            AdmissionOutcome::Quarantined { status, .. } => {
                self.estados.insert(id, status.clone());
            }
            AdmissionOutcome::Activated { status, evento } => {
                match construir() {
                    Ok(adapter) => {
                        if let Err(erro) = self.interno.register(adapter) {
                            // O artefacto era bom e o adapter não arrancou:
                            // porto ocupado, ficheiro que não existe, id
                            // duplicado. Não é quarentena — o conteúdo está
                            // íntegro — mas também não é `Starting`, e dizer
                            // `Starting` a um datasource que nunca vai receber
                            // nada é a mentira mais cara que este código podia
                            // contar.
                            let mut falhou = status.clone();
                            falhou.state = DatasourceState::Stopped;
                            falhou.last_error_code =
                                Some(AdmissionStep::ArranqueDoAdapter.codigo().into());
                            self.estados.insert(id, falhou.clone());
                            return AdmissionOutcome::Quarantined {
                                status: falhou,
                                etapa: AdmissionStep::ArranqueDoAdapter,
                                motivo: erro.to_string(),
                            };
                        }
                        self.cadencias.insert(
                            id.clone(),
                            Cadencia {
                                expected_cadence_secs: spec.expected_cadence_secs,
                                max_lateness_secs: spec.max_lateness_secs,
                            },
                        );
                        self.estados.insert(id, status.clone());
                        self.activados.push(evento.clone());
                    }
                    Err(erro) => {
                        let mut falhou = status.clone();
                        falhou.state = DatasourceState::Stopped;
                        falhou.last_error_code =
                            Some(AdmissionStep::ArranqueDoAdapter.codigo().into());
                        self.estados.insert(id, falhou.clone());
                        return AdmissionOutcome::Quarantined {
                            status: falhou,
                            etapa: AdmissionStep::ArranqueDoAdapter,
                            motivo: erro.to_string(),
                        };
                    }
                }
            }
        }
        resultado
    }

    /// Passa o que os adapters observaram para o estado observado da §5.3.
    ///
    /// Os datasources sem adapter — em quarentena ou parados — não são tocados:
    /// não há saúde a ler, e sobrescrevê-los com um estado por omissão
    /// apagaria a razão pela qual não arrancaram.
    ///
    /// `agora_micros` entra por argumento e não é lido do relógio aqui: um
    /// silêncio que só se manifesta ao fim de horas seria impossível de testar
    /// de outra forma, e um teste que espera horas não é um teste.
    pub fn sincronizar_saude(&mut self, agora_micros: u64) {
        for (identidade, saude) in self.interno.health() {
            let Some(estado) = self.estados.get_mut(&identidade.datasource_id) else {
                continue;
            };
            estado.state = saude.state;
            estado.last_observed_at = saude.last_observed_at_micros.map(|m| m as i64);
            estado.last_checkpoint = saude.last_checkpoint;
            estado.counters = saude.counters;
            estado.last_error_code = saude.last_error_code;

            if let Some(cadencia) = self.cadencias.get(&identidade.datasource_id) {
                aplicar_silencio(estado, cadencia, agora_micros);
            }
        }
    }

    pub fn estado(&self, datasource_id: &str) -> Option<&DatasourceStatus> {
        self.estados.get(datasource_id)
    }

    pub fn estados(&self) -> impl Iterator<Item = (&str, &DatasourceStatus)> {
        self.estados.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Entrega os `ContentActivated` acumulados e esvazia a lista.
    ///
    /// Esvaziar aqui e não no registo é o que impede o mesmo evento de ser
    /// persistido duas vezes se alguém chamar isto em ciclo.
    pub fn drenar_activados(&mut self) -> Vec<ContentActivated> {
        std::mem::take(&mut self.activados)
    }

    pub fn poll_cycle(
        &mut self,
        limite_por_fonte: usize,
    ) -> Vec<(DatasourceIdentity, Result<ObservationBatch, AdapterError>)> {
        self.interno.poll_cycle(limite_por_fonte)
    }

    pub fn checkpoint(&mut self, datasource_id: &str, ack: SourceAck) -> Result<(), AdapterError> {
        self.interno.checkpoint(datasource_id, ack)
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

    /// O parser de YAML NAO pode correr sobre bytes por verificar.
    ///
    /// A §5.5 abre com "antes de carregar qualquer YAML [...] o runner MUST [as
    /// seis etapas]". Se a etapa 2 parseasse, um `serde_yaml` com um bug de
    /// profundidade ou de alias ja tinha sido executado quando a assinatura
    /// ainda nem foi olhada — e nao interessa que o valor nao fosse usado,
    /// porque o problema e a EXECUCAO.
    ///
    /// Este teste poe no manifesto uma coisa que o parser recusaria, e exige
    /// que a rejeicao venha da ASSINATURA. Se a ordem se inverter outra vez,
    /// a etapa passa a `Manifesto` e o teste cai.
    #[test]
    fn o_yaml_nao_e_parseado_antes_da_assinatura() {
        let temporario = tempfile::tempdir().expect("tempdir");
        let copia = registry_temporario(temporario.path());
        // YAML sintacticamente invalido: aspas por fechar e indentacao absurda.
        std::fs::write(
            copia.join("manifest.yaml"),
            "id: \"sem fecho\n  : : :\n\t\tlixo\n",
        )
        .unwrap();

        let resultado = admitir(&spec_valida(&digest_real()), &copia, 1);
        let AdmissionOutcome::Quarantined { etapa, .. } = resultado else {
            panic!("nao pode ser admitido");
        };
        assert_eq!(
            etapa,
            AdmissionStep::DigestEAssinatura,
            "a rejeicao tem de vir da assinatura; se vier de `Manifesto`, o \
             parser correu sobre bytes por verificar"
        );
    }

    /// A etapa 2 continua a existir: um manifesto AUSENTE e apanhado antes de
    /// se gastar uma verificacao criptografica.
    #[test]
    fn um_manifesto_vazio_e_apanhado_na_etapa_2() {
        let temporario = tempfile::tempdir().expect("tempdir");
        let copia = registry_temporario(temporario.path());
        std::fs::write(copia.join("manifest.yaml"), "").unwrap();

        let resultado = admitir(&spec_valida(&digest_real()), &copia, 1);
        let AdmissionOutcome::Quarantined { etapa, motivo, .. } = resultado else {
            panic!("nao pode ser admitido");
        };
        assert_eq!(etapa, AdmissionStep::Manifesto);
        assert!(motivo.contains("vazio"), "motivo: {motivo}");
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
        let AdmissionOutcome::Quarantined { etapa, status, .. } = &resultado else {
            panic!("desactivado nao arranca");
        };
        assert_eq!(*etapa, AdmissionStep::Desactivado);
        assert_eq!(status.last_error_code.as_deref(), Some("desactivado"));
        assert!(
            !etapa.e_falha_de_conteudo(),
            "nao ha nada de errado com o pacote"
        );
    }

    /// As etapas separam o que exige investigacao de seguranca do que e
    /// operacional ou deliberado. Um alerta que trate as duas coisas por igual
    /// acaba silenciado, e depois o que se perde e o caso a serio.
    #[test]
    fn as_etapas_separam_falha_de_conteudo_de_problema_operacional() {
        use AdmissionStep::*;

        for e in [
            TrustRoot,
            Manifesto,
            DigestEAssinatura,
            DigestDeclarado,
            Compatibilidade,
        ] {
            assert!(e.e_falha_de_conteudo(), "{e:?} e um problema do pacote");
        }
        for e in [SpecInvalida, Desactivado, ArranqueDoAdapter] {
            assert!(
                !e.e_falha_de_conteudo(),
                "{e:?} nao diz nada sobre o pacote"
            );
        }

        // Os codigos tem de ser todos diferentes: dois estados com o mesmo
        // codigo sao indistinguiveis num alerta.
        let codigos = [
            TrustRoot,
            Manifesto,
            DigestEAssinatura,
            DigestDeclarado,
            Compatibilidade,
            SpecInvalida,
            Desactivado,
            ArranqueDoAdapter,
        ]
        .map(|e| e.codigo());
        let unicos: std::collections::BTreeSet<_> = codigos.iter().collect();
        assert_eq!(
            unicos.len(),
            codigos.len(),
            "codigos repetidos: {codigos:?}"
        );
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

        // O `Serialize` EMITE o identificador, e e para emitir: uma spec sem
        // `credential_ref` nao diz que credencial usar. O que nunca sai, nem
        // aqui nem no Debug, e o VALOR do segredo — ele nao esta neste tipo.
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains("cofre/pg/senha"),
            "a spec persistida precisa do identificador: {json}"
        );
    }

    /// A etapa 5 da §5.5 falhava ABERTA: um manifesto que nao declarasse schema
    /// nenhum era lido como se declarasse "v9", e a verificacao de
    /// compatibilidade passava sem nada ter sido verificado.
    #[test]
    fn um_manifesto_sem_schema_version_nao_e_lido_como_v9() {
        let sem: Result<ManifestoMinimo, _> = serde_yaml::from_str("id: qualquer\n");
        assert!(
            sem.is_err(),
            "nao se adivinha o schema de outra pessoa; tem de ser recusado"
        );

        let com: ManifestoMinimo =
            serde_yaml::from_str("id: x\nschema_version: v9\n").expect("com schema le-se");
        assert_eq!(com.schema_version, "v9");
        assert_eq!(com.id, "x");
    }

    /// Adapter minimo, so para o supervisor ter o que registar.
    struct AdapterFalso {
        identity: DatasourceIdentity,
        estado: DatasourceState,
        observadas: u64,
    }

    impl SourceAdapter for AdapterFalso {
        fn identity(&self) -> &DatasourceIdentity {
            &self.identity
        }
        fn capabilities(&self) -> crate::source::SourceCapabilities {
            crate::source::SourceCapabilities {
                ordered: true,
                reliable_transport: true,
                source_sequence: true,
                source_timestamp: false,
                backpressure: true,
            }
        }
        fn poll(&mut self, _limit: usize) -> Result<ObservationBatch, AdapterError> {
            Ok(ObservationBatch {
                observations: Vec::new(),
                ack: None,
            })
        }
        fn checkpoint(&mut self, _ack: SourceAck) -> Result<(), AdapterError> {
            Ok(())
        }
        fn health(&self) -> crate::source::SourceHealthSample {
            crate::source::SourceHealthSample {
                state: self.estado,
                last_observed_at_micros: Some(1234),
                last_checkpoint: Some("7".into()),
                counters: SourceCounters {
                    observed: self.observadas,
                    acknowledged: 0,
                    backpressure_events: 0,
                    dropped: 0,
                },
                last_error_code: None,
            }
        }
    }

    /// O ponto todo do `FabricSupervisor`: um artefacto rejeitado nao chega a
    /// CONSTRUIR o adapter. Construir primeiro e decidir depois faria um
    /// datasource em quarentena abrir na mesma um porto de escuta.
    #[test]
    fn um_datasource_rejeitado_nao_constroi_o_adapter() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut spec = spec_valida(&digest_real());
        spec.connector_ref = ContentRef::novo("bb".repeat(32)).unwrap();

        let construiu = AtomicBool::new(false);
        let mut sup = FabricSupervisor::novo();
        let resultado = sup.admitir_e_registar(&spec, &artefacto(), 1, || {
            construiu.store(true, Ordering::SeqCst);
            Ok(Box::new(AdapterFalso {
                identity: spec.identidade("s"),
                estado: DatasourceState::Healthy,
                observadas: 0,
            }))
        });

        assert!(!resultado.activou());
        assert!(
            !construiu.load(Ordering::SeqCst),
            "a closure de construcao NAO pode ter corrido"
        );
        // E continua visivel: um datasource em quarentena que desaparece do
        // painel e a pior forma de esconder uma rejeicao.
        let estado = sup.estado("ds-pg-1").expect("tem de aparecer nos estados");
        assert_eq!(estado.state, DatasourceState::Quarantined);
        assert_eq!(sup.estados().count(), 1);
    }

    #[test]
    fn um_datasource_admitido_e_registado_e_o_evento_fica_por_drenar() {
        let spec = spec_valida(&digest_real());
        let mut sup = FabricSupervisor::novo();
        let resultado = sup.admitir_e_registar(&spec, &artefacto(), 1, || {
            Ok(Box::new(AdapterFalso {
                identity: spec.identidade("s"),
                estado: DatasourceState::Healthy,
                observadas: 42,
            }))
        });
        assert!(resultado.activou());
        assert_eq!(
            sup.estado("ds-pg-1").unwrap().state,
            DatasourceState::Starting
        );

        let eventos = sup.drenar_activados();
        assert_eq!(eventos.len(), 1);
        assert_eq!(eventos[0].datasource_id, "ds-pg-1");
        // Drenar esvazia: chamar em ciclo nao pode persistir o mesmo evento
        // duas vezes.
        assert!(sup.drenar_activados().is_empty());
    }

    /// O `Starting` do registo passa a ser o que o adapter REALMENTE observou.
    #[test]
    fn sincronizar_saude_traz_o_observado_para_o_estado() {
        let spec = spec_valida(&digest_real());
        let mut sup = FabricSupervisor::novo();
        sup.admitir_e_registar(&spec, &artefacto(), 1, || {
            Ok(Box::new(AdapterFalso {
                identity: spec.identidade("s"),
                estado: DatasourceState::Healthy,
                observadas: 42,
            }))
        });
        assert_eq!(sup.estado("ds-pg-1").unwrap().counters.observed, 0);

        sup.sincronizar_saude(0);
        let estado = sup.estado("ds-pg-1").unwrap();
        assert_eq!(estado.state, DatasourceState::Healthy);
        assert_eq!(estado.counters.observed, 42);
        assert_eq!(estado.last_observed_at, Some(1234));
        assert_eq!(estado.last_checkpoint.as_deref(), Some("7"));
    }

    /// Sincronizar nao pode apagar a razao pela qual um datasource nao arrancou.
    #[test]
    fn sincronizar_saude_nao_toca_em_quem_nao_tem_adapter() {
        let mut mau = spec_valida(&digest_real());
        mau.datasource_id = "ds-rejeitado".into();
        mau.connector_ref = ContentRef::novo("cc".repeat(32)).unwrap();

        let bom = spec_valida(&digest_real());
        let mut sup = FabricSupervisor::novo();
        sup.admitir_e_registar(&mau, &artefacto(), 1, || panic!("nao devia construir"));
        sup.admitir_e_registar(&bom, &artefacto(), 1, || {
            Ok(Box::new(AdapterFalso {
                identity: bom.identidade("s"),
                estado: DatasourceState::Healthy,
                observadas: 9,
            }))
        });

        sup.sincronizar_saude(0);
        let rejeitado = sup.estado("ds-rejeitado").unwrap();
        assert_eq!(rejeitado.state, DatasourceState::Quarantined);
        assert_eq!(
            rejeitado.last_error_code.as_deref(),
            Some("hcx_digest_declarado"),
            "a razao da rejeicao tem de sobreviver ao sync"
        );
        assert_eq!(sup.estado("ds-pg-1").unwrap().counters.observed, 9);
    }

    /// Dois dos oito estados da §5.3 eram inalcancaveis: nenhum adapter os pode
    /// produzir sozinho, porque nenhum adapter sabe qual e o ritmo esperado da
    /// SUA fonte — isso esta na spec.
    ///
    /// E e a distincao que interessa numa plataforma de telemetria: uma fonte
    /// que emudeceu parece exactamente igual a uma fonte sem nada a reportar.
    #[test]
    fn uma_fonte_que_emudece_deixa_de_parecer_saudavel() {
        let mut spec = spec_valida(&digest_real());
        spec.expected_cadence_secs = Some(60);
        spec.max_lateness_secs = 300;

        let mut sup = FabricSupervisor::novo();
        sup.admitir_e_registar(&spec, &artefacto(), 1, || {
            Ok(Box::new(AdapterFalso {
                identity: spec.identidade("s"),
                estado: DatasourceState::Healthy,
                observadas: 5,
            }))
        });

        // O adapter falso diz que a ultima observacao foi aos 1234 micros.
        const ULTIMA: u64 = 1234;

        // Dentro da cadencia: saudavel.
        sup.sincronizar_saude(ULTIMA + 30 * 1_000_000);
        assert_eq!(
            sup.estado("ds-pg-1").unwrap().state,
            DatasourceState::Healthy
        );

        // Passada a cadencia esperada: atrasado.
        sup.sincronizar_saude(ULTIMA + 90 * 1_000_000);
        let atrasado = sup.estado("ds-pg-1").unwrap();
        assert_eq!(atrasado.state, DatasourceState::Delayed);
        assert_eq!(atrasado.last_error_code.as_deref(), Some("atrasado"));

        // Passada a tolerancia maxima: calado.
        sup.sincronizar_saude(ULTIMA + 400 * 1_000_000);
        let calado = sup.estado("ds-pg-1").unwrap();
        assert_eq!(calado.state, DatasourceState::Silent);
        assert_eq!(calado.last_error_code.as_deref(), Some("sem_observacoes"));
    }

    /// O silencio NAO pode tapar um problema mais especifico: um `Degraded` diz
    /// porque, e troca-lo por `Delayed` perderia a razao.
    #[test]
    fn o_silencio_nao_tapa_um_estado_mais_especifico() {
        let mut spec = spec_valida(&digest_real());
        spec.expected_cadence_secs = Some(1);
        spec.max_lateness_secs = 2;

        let mut sup = FabricSupervisor::novo();
        sup.admitir_e_registar(&spec, &artefacto(), 1, || {
            Ok(Box::new(AdapterFalso {
                identity: spec.identidade("s"),
                estado: DatasourceState::Degraded,
                observadas: 5,
            }))
        });

        sup.sincronizar_saude(1234 + 999 * 1_000_000);
        assert_eq!(
            sup.estado("ds-pg-1").unwrap().state,
            DatasourceState::Degraded,
            "o `Degraded` do adapter e mais especifico e fica"
        );
    }

    /// Conteudo bom e adapter que nao arranca (porto ocupado, ficheiro que nao
    /// existe) NAO e quarentena — mas tambem nao e `Starting`. Dizer `Starting`
    /// a um datasource que nunca vai receber nada e a mentira mais cara que este
    /// codigo podia contar.
    #[test]
    fn um_adapter_que_nao_arranca_fica_stopped_e_nao_starting() {
        let spec = spec_valida(&digest_real());
        let mut sup = FabricSupervisor::novo();
        let resultado = sup.admitir_e_registar(&spec, &artefacto(), 1, || {
            Err(AdapterError::InvalidConfig("porto ocupado".into()))
        });
        assert!(!resultado.activou());
        let AdmissionOutcome::Quarantined { etapa, .. } = &resultado else {
            panic!("um adapter que nao arranca nao pode contar como activado");
        };
        assert_eq!(
            *etapa,
            AdmissionStep::ArranqueDoAdapter,
            "nao e `SpecInvalida`: a spec estava correcta e o conteudo integro"
        );
        assert!(
            !etapa.e_falha_de_conteudo(),
            "isto nao manda ninguem investigar o pacote"
        );
        let estado = sup.estado("ds-pg-1").unwrap();
        assert_eq!(estado.state, DatasourceState::Stopped);
        assert_eq!(
            estado.last_error_code.as_deref(),
            Some("adapter_nao_arrancou")
        );
        assert!(!estado.deve_arrancar());
        // O conteudo era bom, por isso nao ha `ContentActivated` por drenar:
        // nada foi activado.
        assert!(sup.drenar_activados().is_empty());
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
