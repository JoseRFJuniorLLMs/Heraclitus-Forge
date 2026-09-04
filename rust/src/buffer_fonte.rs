//! A fila limitada partilhada pelos adapters de recepção (SPEC-0071 §5.4).
//!
//! Existe para a política de descarte estar escrita **uma vez só**. Cada
//! adapter que a copiasse acabaria por a mudar por conta própria, e dois
//! adapters com regras de descarte diferentes são dois comportamentos
//! diferentes debaixo do mesmo nome na §5.4.
//!
//! O tecto é em BYTES e não em número de itens: uma fila de 10 000 mensagens de
//! 8 KiB é 80 MiB, e um tecto em itens não diz nada sobre memória, que é o
//! recurso que realmente acaba.

use std::collections::VecDeque;

use crate::source::Observation;

/// Fila com tecto em bytes que descarta o mais antigo quando enche.
pub(crate) struct FilaLimitada {
    itens: VecDeque<Observation>,
    bytes: usize,
    limite_bytes: usize,
    /// Observações que a fila deitou fora para caber uma nova.
    descartadas: u64,
    /// Observações que a fila NÃO aceitou, deixando o emissor com elas.
    ///
    /// É um contador separado de propósito: descartar e recusar são coisas
    /// diferentes na §5.4. Um descarte é telemetria perdida; uma recusa é
    /// telemetria que o emissor ainda tem e vai reenviar. Somá-los num só
    /// número faria um webhook saudável parecer que estava a perder eventos.
    recusadas: u64,
}

impl FilaLimitada {
    pub(crate) fn nova(limite_bytes: usize) -> Self {
        Self {
            itens: VecDeque::new(),
            bytes: 0,
            limite_bytes,
            descartadas: 0,
            recusadas: 0,
        }
    }

    /// Enfileira, descartando o mais antigo se for preciso.
    ///
    /// Descarta-se o MAIS ANTIGO e não o mais recente: numa detecção, a
    /// mensagem de agora vale mais do que a de há um minuto, e recusar a nova
    /// deixaria o adapter cego exactamente durante o pico que encheu a fila.
    ///
    /// O contrário tem defesa — preservar o início do incidente — mas se o
    /// consumidor estava a acompanhar, o início já foi persistido.
    pub(crate) fn empurrar(&mut self, obs: Observation) {
        let tamanho = obs.wire_bytes();
        // Uma mensagem maior que o limite inteiro entra na mesma, sozinha:
        // recusá-la faria o adapter perder sempre e só as maiores, que
        // costumam ser as mais informativas.
        while self.bytes + tamanho > self.limite_bytes && !self.itens.is_empty() {
            if let Some(velha) = self.itens.pop_front() {
                self.bytes -= velha.wire_bytes();
                self.descartadas += 1;
            }
        }
        self.itens.push_back(obs);
        self.bytes += tamanho;
    }

    /// Enfileira só se couber; devolve `false` quando não coube.
    ///
    /// É o que um transporte com maneira de dizer "espera" deve usar — HTTP com
    /// um 429, por exemplo. Descartar quando havia como recusar seria
    /// inexcusável.
    pub(crate) fn empurrar_se_couber(&mut self, obs: Observation) -> bool {
        let tamanho = obs.wire_bytes();
        if self.bytes + tamanho > self.limite_bytes && !self.itens.is_empty() {
            // A recusa conta-se aqui e não no chamador: um contador que
            // depende de alguém se lembrar de o incrementar acaba por ficar a
            // zero num caminho de erro, e uma recusa invisível é tão má como
            // um descarte invisível.
            self.recusadas += 1;
            return false;
        }
        self.itens.push_back(obs);
        self.bytes += tamanho;
        true
    }

    pub(crate) fn primeiros(&self, quantos: usize) -> Vec<Observation> {
        self.itens.iter().take(quantos).cloned().collect()
    }

    pub(crate) fn frente(&self) -> Option<&Observation> {
        self.itens.front()
    }

    pub(crate) fn remover_frente(&mut self) -> Option<Observation> {
        let obs = self.itens.pop_front()?;
        self.bytes -= obs.wire_bytes();
        Some(obs)
    }

    pub(crate) fn descartadas(&self) -> u64 {
        self.descartadas
    }

    pub(crate) fn recusadas(&self) -> u64 {
        self.recusadas
    }

    pub(crate) fn len(&self) -> usize {
        self.itens.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(payload: &str) -> Observation {
        Observation {
            payload: payload.as_bytes().to_vec(),
            source_sequence: None,
            source_event_id: None,
            observed_at_micros: None,
        }
    }

    #[test]
    fn descarta_o_mais_antigo_e_conta() {
        let mut f = FilaLimitada::nova(20);
        f.empurrar(obs("aaaaaaaaaa")); // 10
        f.empurrar(obs("bbbbbbbbbb")); // 20
        assert_eq!(f.descartadas(), 0);
        f.empurrar(obs("cccccccccc")); // 30 > 20: sai o "a"
        assert_eq!(f.descartadas(), 1);
        let restantes = f.primeiros(10);
        assert_eq!(restantes.len(), 2);
        assert_eq!(String::from_utf8_lossy(&restantes[0].payload), "bbbbbbbbbb");
    }

    /// Recusar as maiores faria perder sempre e so as mais informativas.
    #[test]
    fn uma_mensagem_maior_que_o_tecto_entra_sozinha() {
        let mut f = FilaLimitada::nova(10);
        f.empurrar(obs(&"x".repeat(100)));
        assert_eq!(f.primeiros(10).len(), 1);
    }

    /// Com maneira de dizer "espera", nao se descarta.
    ///
    /// Os dois contadores sao separados de proposito: um descarte e telemetria
    /// PERDIDA; uma recusa e telemetria que o emissor ainda tem. Soma-los faria
    /// um webhook saudavel parecer que estava a perder eventos.
    #[test]
    fn empurrar_se_couber_recusa_em_vez_de_descartar() {
        let mut f = FilaLimitada::nova(20);
        assert!(f.empurrar_se_couber(obs("aaaaaaaaaa")));
        assert!(f.empurrar_se_couber(obs("bbbbbbbbbb")));
        assert!(!f.empurrar_se_couber(obs("cccccccccc")), "nao cabe");
        assert_eq!(f.descartadas(), 0, "recusar nao e descartar");
        assert_eq!(f.recusadas(), 1, "mas conta-se na mesma");
        assert_eq!(f.primeiros(10).len(), 2, "o mais antigo continua la");
        assert_eq!(f.len(), 2);
    }

    /// Uma fila vazia aceita sempre o primeiro, mesmo maior que o tecto: senao
    /// um adapter com tecto pequeno nunca receberia nada.
    #[test]
    fn a_fila_vazia_aceita_o_primeiro_mesmo_grande() {
        let mut f = FilaLimitada::nova(5);
        assert!(f.empurrar_se_couber(obs(&"x".repeat(50))));
    }

    #[test]
    fn remover_a_frente_devolve_os_bytes() {
        let mut f = FilaLimitada::nova(100);
        f.empurrar(obs("aaaaa"));
        f.empurrar(obs("bbbbb"));
        assert_eq!(f.bytes, 10);
        assert!(f.remover_frente().is_some());
        assert_eq!(f.bytes, 5, "os bytes tem de voltar; senao a fila 'enche'");
        assert_eq!(f.len(), 1);
        assert!(f.remover_frente().is_some());
        assert_eq!(f.len(), 0);
        assert!(f.remover_frente().is_none());
    }
}
