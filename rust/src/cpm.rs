//! CPM — Canonical Persistence Model (CPM-100/200/300/500) for the Operational
//! Fact store.
//!
//! This is the canonical realization of the CPM spec suite where its fields
//! actually belong: a **Forge Operational Fact** already carries an `event_id`
//! (`fact_id`), knowledge/ontology versions, a `confidence`, a legal timestamp
//! receipt (`carimbo_tempo_legal`) and a raw observation — exactly the CRF v2
//! fixed-metadata + TLV slots. The record wraps the existing zero-copy
//! [`crate::fbfact`] body as its **pristine payload** and adds the two things
//! Forge's `.hdb` block lacked: the CPM-200 physical-corruption lane
//! (**CRC-32C Castagnoli**, distinct from the BLAKE3 Merkle/crypto lane) and
//! fixed-offset, scan-without-decode metadata + forward-compatible TLV.
//!
//! ## CRF v2 layout (CPM-100 §2)
//! ```text
//! Record Header (32 B)                Fixed Metadata (32 B)
//! 0x00 crc32c        u32              0x20 var_metadata_len u32
//! 0x04 record_size   u32              0x24 payload_len      u32
//! 0x08 lsn           u64              0x28 event_id         [u8;16]
//! 0x10 hlc_timestamp u64              0x38 knowledge_ver    u16
//! 0x18 header_len    u16              0x3A ontology_ver     u16
//! 0x1A reserved      u16              0x3C confidence_raw   u16
//! 0x1C flags         u32              0x3E alignment_pad    u16
//! 0x40                 var_metadata (TLV) | pristine_payload (fbfact body)
//! ```
//! Two deliberate spec-deviations (the doc contradicts itself): the fixed prefix
//! is **64 B** (the offset table runs to 0x40; the prose "24 B/56 B" is a typo),
//! and the authenticated region for CRC + Merkle leaf is `record[4..]`
//! (everything but crc32c) — CPM-200 says exclude *only* the crc bytes, so the
//! literal leaf formula `RecordHeader[4..28]` (which drops `flags`) is a typo.

use serde_json::Value;

use crate::error::HeraclitusError;

/// Record Header size (CPM-100 §2, offsets `0x00`..`0x20`).
pub const RECORD_HEADER_LEN: usize = 32;
/// Fixed Metadata size (offsets `0x20`..`0x40`).
pub const FIXED_META_LEN: usize = 32;
/// Fixed prefix = Record Header + Fixed Metadata (`0x00`..`0x40`).
pub const FIXED_PREFIX_LEN: usize = RECORD_HEADER_LEN + FIXED_META_LEN; // 64
/// Upper bound on one record (segments roll well before this).
pub const MAX_RECORD_SIZE: usize = 512 * 1024 * 1024;

// ---- flags bitmask (CPM-300 §1) ---------------------------------------------
pub const FLAG_COMPRESSED: u32 = 1 << 0;
pub const FLAG_ENCRYPTED: u32 = 1 << 1;
pub const FLAG_DELETED: u32 = 1 << 2;

// ---- canonical TLV tags (CPM-300 §2) ----------------------------------------
pub const TLV_CAUSAL_PARENTS: u16 = 0x0001;
pub const TLV_GEOMETRIC_EMBEDDINGS: u16 = 0x0002;
pub const TLV_LEGAL_DIGITAL_RECEIPT: u16 = 0x0003;
pub const TLV_ORIGIN_TENANT_ID: u16 = 0x0004;

/// One Type-Length-Value field. Unknown tags are skipped by length on decode,
/// never rejected — the source of the format's forward-compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub tag: u16,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(tag: u16, value: impl Into<Vec<u8>>) -> Self {
        Self { tag, value: value.into() }
    }
}

/// A Canonical Record (CRF v2). `event_id` is 16 raw canonical bytes (CPM-500).
#[derive(Debug, Clone, PartialEq)]
pub struct CpmRecord {
    pub lsn: u64,
    pub hlc: u64,
    pub flags: u32,
    pub event_id: [u8; 16],
    pub knowledge_ver: u16,
    pub ontology_ver: u16,
    pub confidence_raw: u16,
    pub tlvs: Vec<Tlv>,
    /// Pristine payload — stored verbatim (CPM-200-INV-001). For Forge this is
    /// the [`crate::fbfact`] body of the Operational Fact.
    pub payload: Vec<u8>,
}

impl CpmRecord {
    /// `confidence_raw / u16::MAX` (CPM-100, `0x3C`).
    pub fn confidence(&self) -> f32 {
        self.confidence_raw as f32 / u16::MAX as f32
    }

    /// Value of the first TLV with `tag`, if present.
    pub fn tlv(&self, tag: u16) -> Option<&[u8]> {
        self.tlvs.iter().find(|t| t.tag == tag).map(|t| t.value.as_slice())
    }

    fn encode_tlvs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for t in &self.tlvs {
            out.extend_from_slice(&t.tag.to_le_bytes());
            out.extend_from_slice(&(t.value.len() as u32).to_le_bytes());
            out.extend_from_slice(&t.value);
        }
        out
    }

    /// Encode a full CRF v2 record: stamps `record_size`, `header_len` (64) and
    /// the CRC32C over the authenticated region (`record[4..record_size]`).
    pub fn encode(&self) -> Vec<u8> {
        let var = self.encode_tlvs();
        let total = FIXED_PREFIX_LEN + var.len() + self.payload.len();
        let mut buf = vec![0u8; FIXED_PREFIX_LEN];
        // [0..4] crc32c filled last
        buf[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        buf[8..16].copy_from_slice(&self.lsn.to_le_bytes());
        buf[16..24].copy_from_slice(&self.hlc.to_le_bytes());
        buf[24..26].copy_from_slice(&(FIXED_PREFIX_LEN as u16).to_le_bytes());
        buf[28..32].copy_from_slice(&self.flags.to_le_bytes());
        buf[32..36].copy_from_slice(&(var.len() as u32).to_le_bytes());
        buf[36..40].copy_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf[40..56].copy_from_slice(&self.event_id);
        buf[56..58].copy_from_slice(&self.knowledge_ver.to_le_bytes());
        buf[58..60].copy_from_slice(&self.ontology_ver.to_le_bytes());
        buf[60..62].copy_from_slice(&self.confidence_raw.to_le_bytes());
        buf.extend_from_slice(&var);
        buf.extend_from_slice(&self.payload);
        let crc = crc32c(&buf[4..]);
        buf[..4].copy_from_slice(&crc.to_le_bytes());
        buf
    }
}

/// Result of decoding one CRF v2 record from the head of a slice.
pub enum CpmDecoded {
    Record(CpmRecord, usize),
    Torn,
}

/// BLAKE3 Merkle leaf for a CRF v2 record (CPM-200 §3): hash over the
/// authenticated region (`record[4..record_size]`, all but crc32c).
pub fn record_leaf(record: &[u8]) -> [u8; 32] {
    let size = u32::from_le_bytes(record[4..8].try_into().unwrap()) as usize;
    *blake3::hash(&record[4..size]).as_bytes()
}

/// Decode a CRF v2 record. Validates CRC32C over the authenticated region, so a
/// flip in any field but the crc yields [`CpmDecoded::Torn`].
pub fn decode_record(buf: &[u8]) -> CpmDecoded {
    if buf.len() < FIXED_PREFIX_LEN {
        return CpmDecoded::Torn;
    }
    let stored_crc = u32::from_le_bytes(buf[..4].try_into().unwrap());
    let record_size = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    if !(FIXED_PREFIX_LEN..=MAX_RECORD_SIZE).contains(&record_size) {
        return CpmDecoded::Torn;
    }
    let var_len = u32::from_le_bytes(buf[32..36].try_into().unwrap()) as usize;
    let payload_len = u32::from_le_bytes(buf[36..40].try_into().unwrap()) as usize;
    if FIXED_PREFIX_LEN + var_len + payload_len != record_size {
        return CpmDecoded::Torn;
    }
    if buf.len() < record_size {
        return CpmDecoded::Torn;
    }
    if crc32c(&buf[4..record_size]) != stored_crc {
        return CpmDecoded::Torn;
    }
    let var_start = FIXED_PREFIX_LEN;
    let payload_start = var_start + var_len;
    let tlvs = match parse_tlvs(&buf[var_start..payload_start]) {
        Some(t) => t,
        None => return CpmDecoded::Torn,
    };
    let rec = CpmRecord {
        lsn: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        hlc: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        flags: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
        event_id: buf[40..56].try_into().unwrap(),
        knowledge_ver: u16::from_le_bytes(buf[56..58].try_into().unwrap()),
        ontology_ver: u16::from_le_bytes(buf[58..60].try_into().unwrap()),
        confidence_raw: u16::from_le_bytes(buf[60..62].try_into().unwrap()),
        tlvs,
        payload: buf[payload_start..record_size].to_vec(),
    };
    CpmDecoded::Record(rec, record_size)
}

fn parse_tlvs(mut buf: &[u8]) -> Option<Vec<Tlv>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 6 {
            return None;
        }
        let tag = u16::from_le_bytes(buf[..2].try_into().unwrap());
        let len = u32::from_le_bytes(buf[2..6].try_into().unwrap()) as usize;
        let end = 6usize.checked_add(len)?;
        if buf.len() < end {
            return None;
        }
        out.push(Tlv { tag, value: buf[6..end].to_vec() });
        buf = &buf[end..];
    }
    Some(out)
}

// ---- CPM-200 §2 physical lane: CRC-32C Castagnoli (poly 0x1EDC6F41) ----------

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC-32C (Castagnoli). Check value: `crc32c(b"123456789") == 0xE306_9283`.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

// ---- Fact <-> CRF v2 mapping (this is where "os campos batem") ---------------

fn sget<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut n = v;
    for k in path {
        n = n.get(*k)?;
    }
    n.as_str()
}

/// Trailing integer of a version label, e.g. `"v9"` -> 9, `"...-v1.0.0"` -> 1.
fn version_u16(s: Option<&str>) -> u16 {
    let s = match s {
        Some(s) => s,
        None => return 0,
    };
    // take the last run of ASCII digits
    let digits: String = s
        .rsplit(|c: char| !c.is_ascii_digit())
        .find(|part| !part.is_empty())
        .unwrap_or("")
        .chars()
        .take(5)
        .collect();
    digits.parse::<u16>().unwrap_or(0)
}

/// Stable 16-byte event id from a Fact's `fact_id`: parse a UUID if it is one,
/// else derive a deterministic id from BLAKE3 (so any id string maps cleanly).
fn event_id_bytes(fact_id: Option<&str>) -> [u8; 16] {
    if let Some(s) = fact_id {
        if let Ok(u) = uuid::Uuid::parse_str(s) {
            return *u.as_bytes();
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&blake3::hash(s.as_bytes()).as_bytes()[..16]);
        return id;
    }
    [0u8; 16]
}

/// Map an Operational Fact (`serde_json::Value`) to a CRF v2 record. The full
/// fact body is preserved verbatim as the pristine payload (fbfact), while the
/// CPM-promoted fields populate the fixed metadata and TLV zone.
pub fn fact_to_record(fact: &Value) -> CpmRecord {
    let lsn = fact
        .get("fact.time")
        .and_then(|t| t.get("log_sequence_number"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let hlc = fact
        .get("fact.time")
        .and_then(|t| t.get("system_timestamp"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as u64;
    let confidence = fact.get("fact.confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let confidence_raw = (confidence.clamp(0.0, 1.0) * u16::MAX as f64).round() as u16;

    let mut tlvs = Vec::new();
    // 0x0003 Legal Digital Receipt <- ICP-Brasil/SERPRO timestamp receipt.
    if let Some(carimbo) = sget(fact, &["fact.evidence", "carimbo_tempo_legal"]) {
        tlvs.push(Tlv::new(TLV_LEGAL_DIGITAL_RECEIPT, carimbo.as_bytes().to_vec()));
    }
    // 0x0004 Origin Tenant Id <- the pipeline/source that produced the fact.
    if let Some(src) = sget(fact, &["fact.lineage", "input_source"]) {
        tlvs.push(Tlv::new(TLV_ORIGIN_TENANT_ID, src.as_bytes().to_vec()));
    }

    CpmRecord {
        lsn,
        hlc,
        flags: 0,
        event_id: event_id_bytes(sget(fact, &["fact_id"])),
        knowledge_ver: version_u16(sget(fact, &["fact.knowledge_version"])),
        ontology_ver: version_u16(sget(fact, &["fact.ontology_version"])),
        confidence_raw,
        tlvs,
        payload: crate::fbfact::encode(fact), // pristine fact body
    }
}

/// Reconstruct the Operational Fact from a CRF v2 record's pristine payload.
pub fn record_to_fact(rec: &CpmRecord) -> Result<Value, HeraclitusError> {
    crate::fbfact::decode(&rec.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_fact() -> Value {
        json!({
            "fact_id": "019f035c-1823-7fe9-8c54-02b2d1acc30c",
            "fact.identity": {"actor.id":"guest","actor.name":"guest","target.id":"prod","source.ip":null},
            "fact.time": {"system_timestamp": 1782467794979937i64, "log_sequence_number": 14812346u64},
            "fact.behavior": {"class":"privilege_violation","action":"authorization.failure","risk_level":"Medium"},
            "fact.evidence": {"raw_observation_hash":"b3:b1cab9dd351d","carimbo_tempo_legal":"icp_brasil_serpro_tst_recibo"},
            "fact.lineage": {"transformation_steps":["parse","normalize","behavior","emit"],
                             "input_source":"br.gov.heraclitus.pipelines.postgresql-v1.0.0","matched_rule":"pg_permission_denied"},
            "fact.confidence": 0.972,
            "fact.knowledge_version":"br.gov.heraclitus.pipelines.postgresql-v1.0.0",
            "fact.reasoning_version":"reasoner-core-v6.0",
            "fact.ontology_version":"v9"
        })
    }

    #[test]
    fn crc32c_known_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn fact_fields_map_onto_crf2_slots() {
        let fact = sample_fact();
        let rec = fact_to_record(&fact);
        assert_eq!(rec.lsn, 14_812_346);
        assert_eq!(rec.hlc, 1_782_467_794_979_937);
        assert_eq!(rec.ontology_ver, 9); // "v9" -> 9
        assert!((rec.confidence() - 0.972).abs() < 1e-3);
        // fact_id is a real UUID -> its 16 canonical bytes
        assert_eq!(rec.event_id, *uuid::Uuid::parse_str("019f035c-1823-7fe9-8c54-02b2d1acc30c").unwrap().as_bytes());
        // the legal timestamp receipt rides in TLV 0x0003
        assert_eq!(rec.tlv(TLV_LEGAL_DIGITAL_RECEIPT), Some(&b"icp_brasil_serpro_tst_recibo"[..]));
        // the origin pipeline rides in TLV 0x0004
        assert_eq!(rec.tlv(TLV_ORIGIN_TENANT_ID).unwrap(), b"br.gov.heraclitus.pipelines.postgresql-v1.0.0");
    }

    #[test]
    fn fact_round_trips_through_crf2_record() {
        let fact = sample_fact();
        let bytes = fact_to_record(&fact).encode();
        match decode_record(&bytes) {
            CpmDecoded::Record(rec, consumed) => {
                assert_eq!(consumed, bytes.len());
                let back = record_to_fact(&rec).unwrap();
                // pristine payload preserves the whole fact body losslessly
                assert_eq!(back["fact.behavior"]["action"], fact["fact.behavior"]["action"]);
                assert_eq!(back["fact.confidence"], fact["fact.confidence"]);
                assert_eq!(back["fact.evidence"]["carimbo_tempo_legal"], fact["fact.evidence"]["carimbo_tempo_legal"]);
                assert_eq!(back["fact.lineage"]["transformation_steps"], fact["fact.lineage"]["transformation_steps"]);
            }
            CpmDecoded::Torn => panic!("valid record decoded as Torn"),
        }
    }

    #[test]
    fn physical_lane_crc32c_catches_bit_rot() {
        // Every authenticated byte flipped must be rejected by the CRC32C lane.
        let bytes = fact_to_record(&sample_fact()).encode();
        for i in 4..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            assert!(matches!(decode_record(&t), CpmDecoded::Torn), "bit-rot at {i} slipped the CRC32C lane");
        }
    }

    #[test]
    fn crypto_lane_merkle_leaf_catches_field_tamper() {
        // A tamper that fixes up the CRC still moves the BLAKE3 Merkle leaf.
        let bytes = fact_to_record(&sample_fact()).encode();
        let leaf0 = record_leaf(&bytes);
        let mut t = bytes.clone();
        t[40] ^= 0x01; // flip event_id
        let size = u32::from_le_bytes(t[4..8].try_into().unwrap()) as usize;
        let new_crc = crc32c(&t[4..size]).to_le_bytes();
        t[..4].copy_from_slice(&new_crc);
        assert!(matches!(decode_record(&t), CpmDecoded::Record(..)), "crc was repaired");
        assert_ne!(leaf0, record_leaf(&t), "Merkle leaf must move under field tamper");
    }

    #[test]
    fn unknown_tlv_tag_is_preserved() {
        let mut rec = fact_to_record(&sample_fact());
        rec.tlvs.push(Tlv::new(0xBEEF, b"future".to_vec()));
        let bytes = rec.encode();
        match decode_record(&bytes) {
            CpmDecoded::Record(got, _) => {
                assert_eq!(got.tlv(0xBEEF), Some(&b"future"[..]));
                assert!(record_to_fact(&got).is_ok(), "pristine payload readable past unknown TLV");
            }
            CpmDecoded::Torn => panic!("unknown TLV must be skipped, not rejected"),
        }
    }
}
