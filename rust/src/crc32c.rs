//! CRC-32C (Castagnoli, polinomio 0x1EDC6F41).
//!
//! Vive num modulo proprio porque tem UMA responsabilidade e dois clientes: o
//! registo HFB2 e o bloco HDB2. E deteccao de corrupcao ACIDENTAL — bit-rot,
//! disco a falhar, escrita truncada. Nao e autenticidade: um atacante que
//! altere os bytes recalcula o CRC em duas linhas.
//!
//! A autenticidade vem da folha BLAKE3 com separacao de dominio
//! ([`crate::hfb2::record_leaf`]) e da ancora Ed25519. As duas camadas sao
//! deliberadamente distintas e nenhuma substitui a outra: o CRC responde
//! depressa e localmente, a folha responde perante um adversario.

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC-32C (Castagnoli). Vetor de teste: `crc32c(b"123456789") == 0xE306_9283`.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn one_flipped_bit_changes_the_checksum() {
        let mut data = b"heraclitus".to_vec();
        let before = crc32c(&data);
        data[3] ^= 1;
        assert_ne!(before, crc32c(&data));
    }
}
