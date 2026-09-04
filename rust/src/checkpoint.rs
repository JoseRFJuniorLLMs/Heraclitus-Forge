//! Leitura e escrita dos checkpoints dos adapters (SPEC-0071 §5.4).
//!
//! Estava copiado em três ficheiros com a mesma forma e o mesmo defeito, e é
//! por isso que passou a viver aqui.
//!
//! ## Um checkpoint ilegível NÃO é a mesma coisa que um checkpoint ausente
//!
//! O padrão que estava nos três adapters era este:
//!
//! ```ignore
//! let guardado = fs::read_to_string(caminho).ok()
//!     .and_then(|t| serde_json::from_str(&t).ok());
//! ```
//!
//! Os dois `.ok()` transformam "o ficheiro existe e está corrompido" em "não há
//! ficheiro". O adapter recomeça do princípio — ou do fim, conforme a política —
//! sem que nada o diga. Numa fonte com retenção isso reprocessa; numa sem
//! retenção, salta. Nos dois casos é uma decisão grande tomada em silêncio a
//! partir de um erro.
//!
//! [`carregar`] distingue os três casos e deixa quem chama decidir o que dizer.
//!
//! ## A escrita é atómica E durável
//!
//! Escrever por cima do checkpoint antigo deixa-o a meio se a máquina cair
//! durante a escrita, e um checkpoint truncado é lido como um offset errado no
//! arranque seguinte. Por isso escreve-se num temporário e renomeia-se.
//!
//! Mas o `rename` sozinho não chega: sem `sync_all`, o conteúdo do temporário
//! pode ainda estar em cache quando o rename já está no disco, e o resultado é
//! um checkpoint com o nome certo e o conteúdo de ninguém.

use std::io::Write;
use std::path::Path;

use serde::de::DeserializeOwned;

/// O que se encontrou no caminho do checkpoint.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EstadoDoCheckpoint<T> {
    /// Não há ficheiro. É o arranque normal de um datasource novo.
    Ausente,
    Carregado(T),
    /// O ficheiro existe e não se consegue usar.
    ///
    /// Quem chama tem de o DIZER: recomeçar em silêncio a partir de um ficheiro
    /// corrompido é tomar uma decisão grande sem ninguém saber.
    Ilegivel(String),
}

pub(crate) fn carregar<T: DeserializeOwned>(caminho: &Path) -> EstadoDoCheckpoint<T> {
    let texto = match std::fs::read_to_string(caminho) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return EstadoDoCheckpoint::Ausente,
        Err(e) => return EstadoDoCheckpoint::Ilegivel(format!("nao foi possivel ler: {e}")),
    };
    match serde_json::from_str::<T>(&texto) {
        Ok(v) => EstadoDoCheckpoint::Carregado(v),
        Err(e) => EstadoDoCheckpoint::Ilegivel(format!("JSON invalido: {e}")),
    }
}

/// Escreve por temporário, sincroniza, e renomeia.
pub(crate) fn escrever_atomico(destino: &Path, dados: &[u8]) -> Result<(), std::io::Error> {
    let temporario = destino.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&temporario)?;
        f.write_all(dados)?;
        // Sem isto, o `rename` pode chegar ao disco antes do conteúdo, e fica um
        // checkpoint com o nome certo e o conteúdo de ninguém.
        f.sync_all()?;
    }
    std::fs::rename(&temporario, destino)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Exemplo {
        offset: u64,
    }

    #[test]
    fn ausente_carregado_e_ilegivel_sao_tres_coisas_diferentes() {
        let dir = tempfile::tempdir().unwrap();
        let caminho = dir.path().join("estado.json");

        assert!(matches!(
            carregar::<Exemplo>(&caminho),
            EstadoDoCheckpoint::Ausente
        ));

        escrever_atomico(&caminho, br#"{"offset":42}"#).unwrap();
        assert_eq!(
            carregar::<Exemplo>(&caminho),
            EstadoDoCheckpoint::Carregado(Exemplo { offset: 42 })
        );

        // Um ficheiro corrompido NAO pode passar por "nao ha ficheiro": o
        // adapter recomecaria do principio sem nada a dizer porque.
        std::fs::write(&caminho, b"{isto nao e json").unwrap();
        let ilegivel = carregar::<Exemplo>(&caminho);
        assert!(
            matches!(ilegivel, EstadoDoCheckpoint::Ilegivel(_)),
            "veio {ilegivel:?}"
        );
    }

    #[test]
    fn a_escrita_nao_deixa_o_temporario_para_tras() {
        let dir = tempfile::tempdir().unwrap();
        let caminho = dir.path().join("estado.json");
        escrever_atomico(&caminho, b"{}").unwrap();
        assert!(caminho.exists());
        assert!(
            !caminho.with_extension("tmp").exists(),
            "o temporario tem de ter sido renomeado"
        );
    }

    /// Escrever por cima e o que deixa um checkpoint truncado depois de uma
    /// queda. A segunda escrita tem de substituir a primeira por inteiro.
    #[test]
    fn escrever_por_cima_substitui_e_nao_mistura() {
        let dir = tempfile::tempdir().unwrap();
        let caminho = dir.path().join("estado.json");
        escrever_atomico(&caminho, br#"{"offset":123456789}"#).unwrap();
        escrever_atomico(&caminho, br#"{"offset":1}"#).unwrap();
        assert_eq!(
            carregar::<Exemplo>(&caminho),
            EstadoDoCheckpoint::Carregado(Exemplo { offset: 1 }),
            "sobrou conteudo da escrita anterior"
        );
    }
}
