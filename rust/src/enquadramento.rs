//! Leitura de linhas sobre um socket que pode ficar calado (SPEC-0071 §5.2).
//!
//! ## Porque é que o `BufRead::lines()` não serve
//!
//! Uma ligação de syslog sobre TCP é **longa e maioritariamente inactiva**: o
//! emissor abre-a uma vez e manda uma linha de vez em quando. Para poder ver a
//! bandeira de paragem, o socket tem um `read_timeout` — e aí o `lines()` faz
//! duas coisas erradas:
//!
//! 1. devolve `Err(TimedOut)`, que se lê como "a ligação morreu" quando na
//!    verdade é "ainda não chegou nada". Fechar aqui derruba todos os emissores
//!    reais, porque todos ficam calados mais de 200 ms;
//! 2. se o timeout apanhar meia linha, os bytes já lidos ficam no `String`
//!    temporário que o `lines()` deita fora. A linha desaparece sem erro.
//!
//! Este módulo lê para um acumulador próprio: um timeout é um não-evento, e o
//! que estiver a meio fica guardado para o resto chegar.
//!
//! ## O tecto por linha
//!
//! Sem tecto, um cliente que abra uma ligação e envie bytes sem nunca mandar um
//! `\n` faz o acumulador crescer até a memória acabar — e faz isso a partir da
//! rede, sem autenticação nenhuma. Com tecto, a linha gigante é descartada,
//! **contada**, e a leitura ressincroniza no `\n` seguinte.
//!
//! Descartar é aqui a única saída: não há a quem dizer "espera" num fluxo que
//! já está a chegar, e guardar não é opção. O que a §5.4 exige é que não seja
//! invisível, e por isso há um contador.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

/// Tecto por linha de syslog.
///
/// A RFC 5425 (syslog sobre TLS) obriga um receptor a aceitar pelo menos 2048
/// bytes e recomenda 8192. 64 KiB dá folga larga a emissores que mandam eventos
/// grandes sem deixar a memória à mercê de quem se ligar.
pub const MAX_LINHA: usize = 65_536;

/// O que aconteceu numa leitura.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FimDeSessao {
    /// O emissor fechou em ordem.
    Fim,
    /// A ligação morreu (reset, aborto, erro de I/O).
    Erro(std::io::ErrorKind),
    /// A bandeira de paragem foi levantada.
    Paragem,
}

/// Lê linhas até a ligação acabar, entregando cada uma a `ao_receber`.
///
/// `ao_exceder` é chamado uma vez por cada linha descartada por passar o tecto.
pub(crate) fn consumir_linhas<R: Read>(
    mut fonte: R,
    max_linha: usize,
    parar: &AtomicBool,
    mut ao_receber: impl FnMut(Vec<u8>),
    mut ao_exceder: impl FnMut(),
) -> FimDeSessao {
    let mut acumulador: Vec<u8> = Vec::with_capacity(4096);
    let mut bloco = [0u8; 8192];
    // Quando uma linha passa o tecto, deita-se fora tudo até ao `\n` seguinte.
    // Sem isto, a cauda da linha gigante seria lida como se fosse uma mensagem.
    let mut a_ressincronizar = false;

    loop {
        if parar.load(Ordering::Relaxed) {
            return FimDeSessao::Paragem;
        }
        match fonte.read(&mut bloco) {
            Ok(0) => {
                // EOF. Uma última linha sem `\n` é entregue: o emissor fechou
                // depois de a escrever, e descartá-la seria perder uma
                // mensagem completa por causa de um byte de pontuação.
                if !a_ressincronizar && !acumulador.is_empty() {
                    ao_receber(std::mem::take(&mut acumulador));
                }
                return FimDeSessao::Fim;
            }
            Ok(n) => {
                for &byte in &bloco[..n] {
                    if byte == b'\n' {
                        if a_ressincronizar {
                            a_ressincronizar = false;
                            acumulador.clear();
                            continue;
                        }
                        let mut linha = std::mem::take(&mut acumulador);
                        // `\r\n` é comum em emissores de Windows.
                        if linha.last() == Some(&b'\r') {
                            linha.pop();
                        }
                        if !linha.is_empty() {
                            ao_receber(linha);
                        }
                        continue;
                    }
                    if a_ressincronizar {
                        continue;
                    }
                    if acumulador.len() >= max_linha {
                        ao_exceder();
                        a_ressincronizar = true;
                        acumulador.clear();
                        continue;
                    }
                    acumulador.push(byte);
                }
            }
            // Um timeout NÃO é o fim da ligação: é o silêncio normal de um
            // emissor de syslog entre mensagens. Voltar ao topo do laço é o
            // que permite ver a bandeira de paragem sem fechar a ligação.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return FimDeSessao::Erro(e.kind()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn recolher(entrada: &[u8], max: usize) -> (Vec<String>, usize, FimDeSessao) {
        let parar = AtomicBool::new(false);
        let mut linhas = Vec::new();
        let mut excedidas = 0usize;
        let fim = consumir_linhas(
            Cursor::new(entrada.to_vec()),
            max,
            &parar,
            |l| linhas.push(String::from_utf8_lossy(&l).to_string()),
            || excedidas += 1,
        );
        (linhas, excedidas, fim)
    }

    #[test]
    fn separa_linhas_e_aceita_crlf() {
        let (linhas, _, fim) = recolher(b"uma\r\ndois\ntres\n", MAX_LINHA);
        assert_eq!(linhas, vec!["uma", "dois", "tres"]);
        assert_eq!(fim, FimDeSessao::Fim);
    }

    /// O emissor fechou depois de escrever: a mensagem esta completa e so lhe
    /// falta a pontuacao. Descarta-la perderia um evento inteiro.
    #[test]
    fn a_ultima_linha_sem_newline_e_entregue_no_fim() {
        let (linhas, _, _) = recolher(b"uma\nsem fim", MAX_LINHA);
        assert_eq!(linhas, vec!["uma", "sem fim"]);
    }

    #[test]
    fn linhas_vazias_sao_ignoradas() {
        let (linhas, _, _) = recolher(b"\n\numa\n\n\ndois\n", MAX_LINHA);
        assert_eq!(linhas, vec!["uma", "dois"]);
    }

    /// Sem tecto, quem se ligar esgota a memoria a partir da rede.
    #[test]
    fn uma_linha_acima_do_tecto_e_descartada_e_contada() {
        let mut entrada = vec![b'x'; 100];
        entrada.push(b'\n');
        entrada.extend_from_slice(b"boa\n");
        let (linhas, excedidas, _) = recolher(&entrada, 10);
        assert_eq!(excedidas, 1, "o descarte tem de ser contado");
        assert_eq!(
            linhas,
            vec!["boa"],
            "a cauda da linha gigante NAO pode entrar como mensagem"
        );
    }

    /// A ressincronizacao tem de aguentar varias linhas gigantes seguidas.
    #[test]
    fn ressincroniza_depois_de_varias_linhas_gigantes() {
        let mut entrada = Vec::new();
        for _ in 0..3 {
            entrada.extend(std::iter::repeat_n(b'y', 50));
            entrada.push(b'\n');
        }
        entrada.extend_from_slice(b"ok\n");
        let (linhas, excedidas, _) = recolher(&entrada, 5);
        assert_eq!(excedidas, 3);
        assert_eq!(linhas, vec!["ok"]);
    }

    /// Um timeout e o silencio normal de um emissor de syslog, nao o fim da
    /// ligacao. Fechar aqui derrubaria todos os emissores reais.
    #[test]
    fn um_timeout_nao_fecha_a_sessao() {
        struct FonteComTimeouts {
            blocos: Vec<Result<Vec<u8>, std::io::ErrorKind>>,
            i: usize,
        }
        impl Read for FonteComTimeouts {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.i >= self.blocos.len() {
                    return Ok(0);
                }
                let bloco = self.blocos[self.i].clone();
                self.i += 1;
                match bloco {
                    Ok(dados) => {
                        buf[..dados.len()].copy_from_slice(&dados);
                        Ok(dados.len())
                    }
                    Err(kind) => Err(std::io::Error::new(kind, "teste")),
                }
            }
        }

        let parar = AtomicBool::new(false);
        let mut linhas = Vec::new();
        // Meia linha, tres timeouts, o resto da MESMA linha, e outra.
        let fonte = FonteComTimeouts {
            blocos: vec![
                Ok(b"primeira met".to_vec()),
                Err(std::io::ErrorKind::TimedOut),
                Err(std::io::ErrorKind::WouldBlock),
                Err(std::io::ErrorKind::TimedOut),
                Ok(b"ade\nsegunda\n".to_vec()),
            ],
            i: 0,
        };
        let fim = consumir_linhas(
            fonte,
            MAX_LINHA,
            &parar,
            |l| linhas.push(String::from_utf8_lossy(&l).to_string()),
            || {},
        );
        assert_eq!(fim, FimDeSessao::Fim);
        assert_eq!(
            linhas,
            vec!["primeira metade", "segunda"],
            "os bytes de antes do timeout tem de sobreviver"
        );
    }

    /// Um erro a serio fecha; e a diferenca entre "calado" e "morto".
    #[test]
    fn um_erro_a_serio_fecha_a_sessao() {
        struct FonteQueMorre;
        impl Read for FonteQueMorre {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "reset",
                ))
            }
        }
        let parar = AtomicBool::new(false);
        let fim = consumir_linhas(FonteQueMorre, MAX_LINHA, &parar, |_| {}, || {});
        assert_eq!(fim, FimDeSessao::Erro(std::io::ErrorKind::ConnectionReset));
    }

    #[test]
    fn a_bandeira_de_paragem_termina_a_sessao() {
        struct FonteInfinita;
        impl Read for FonteInfinita {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "calado"))
            }
        }
        let parar = AtomicBool::new(true);
        let fim = consumir_linhas(FonteInfinita, MAX_LINHA, &parar, |_| {}, || {});
        assert_eq!(fim, FimDeSessao::Paragem);
    }
}
