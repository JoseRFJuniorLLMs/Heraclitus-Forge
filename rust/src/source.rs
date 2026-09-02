//! Typed source adapters and the production Fabric supervisor.
//!
//! Adapters only observe and checkpoint sources. Parsing, HFB2 persistence and
//! telemetry emission stay above this boundary, so an adapter can never claim
//! delivery before the caller has durably appended the observation.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DatasourceIdentity {
    pub tenant_id: String,
    pub datasource_id: String,
    pub sensor_id: String,
}

impl DatasourceIdentity {
    pub fn validate(&self) -> Result<(), AdapterError> {
        for (field, value) in [
            ("tenant_id", &self.tenant_id),
            ("datasource_id", &self.datasource_id),
            ("sensor_id", &self.sensor_id),
        ] {
            if value.trim().is_empty() {
                return Err(AdapterError::InvalidConfig(format!(
                    "{field} nao pode ser vazio"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCapabilities {
    pub ordered: bool,
    pub reliable_transport: bool,
    pub source_sequence: bool,
    pub source_timestamp: bool,
    pub backpressure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub payload: Vec<u8>,
    pub source_sequence: Option<String>,
    pub source_event_id: Option<String>,
    pub observed_at_micros: Option<u64>,
}

impl Observation {
    pub fn wire_bytes(&self) -> usize {
        self.payload.len()
            + self.source_sequence.as_ref().map_or(0, String::len)
            + self.source_event_id.as_ref().map_or(0, String::len)
            + self.observed_at_micros.map_or(0, |_| 8)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAck {
    /// Adapter-owned opaque cursor. It only becomes durable after the caller
    /// has persisted every observation in the associated batch.
    pub cursor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBatch {
    pub observations: Vec<Observation>,
    pub ack: Option<SourceAck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatasourceState {
    Starting,
    Healthy,
    Delayed,
    Silent,
    Drifted,
    Degraded,
    Quarantined,
    Stopped,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCounters {
    pub observed: u64,
    pub acknowledged: u64,
    pub backpressure_events: u64,
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHealthSample {
    pub state: DatasourceState,
    pub last_observed_at_micros: Option<u64>,
    pub last_checkpoint: Option<String>,
    pub counters: SourceCounters,
    pub last_error_code: Option<String>,
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("configuracao invalida: {0}")]
    InvalidConfig(String),
    #[error("adapter duplicado: {0}")]
    DuplicateDatasource(String),
    #[error("adapter desconhecido: {0}")]
    UnknownDatasource(String),
    #[error("cursor recusado: {0}")]
    InvalidAck(String),
    #[error("backpressure: limite {limit_bytes} bytes; tentativa {attempted_bytes} bytes")]
    Backpressure {
        limit_bytes: usize,
        attempted_bytes: usize,
    },
    #[error("I/O da fonte: {0}")]
    Io(#[from] std::io::Error),
}

pub trait SourceAdapter: Send {
    fn identity(&self) -> &DatasourceIdentity;
    fn capabilities(&self) -> SourceCapabilities;
    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError>;
    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError>;
    fn health(&self) -> SourceHealthSample;
}

const FILE_FINGERPRINT_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileCheckpoint {
    source: PathBuf,
    offset: u64,
    fingerprint: String,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileCursor {
    offset: u64,
    fingerprint: String,
    generation: u64,
    observations: u64,
}

/// Production `file-tail` adapter extracted from the standalone ingestor.
/// Polling never advances the durable offset: only `checkpoint()` may do so,
/// after the caller has appended the complete batch to HFB2.
pub struct FileTailAdapter {
    identity: DatasourceIdentity,
    source: PathBuf,
    checkpoint_path: PathBuf,
    offset: u64,
    fingerprint: String,
    generation: u64,
    pending: Option<FileCursor>,
    health: SourceHealthSample,
}

impl FileTailAdapter {
    pub fn open(
        identity: DatasourceIdentity,
        source: impl Into<PathBuf>,
        checkpoint_path: impl Into<PathBuf>,
        from_start: bool,
    ) -> Result<Self, AdapterError> {
        identity.validate()?;
        let source = source.into();
        let checkpoint_path = checkpoint_path.into();
        let size = std::fs::metadata(&source)?.len();
        let restored = load_file_checkpoint(&checkpoint_path).filter(|state| {
            state.source == source
                && state.offset <= size
                && file_fingerprint(&source, state.offset)
                    .is_ok_and(|current| current == state.fingerprint)
        });
        let (offset, fingerprint, generation) = if let Some(state) = restored {
            (state.offset, state.fingerprint, state.generation)
        } else {
            let offset = if from_start { 0 } else { size };
            (offset, file_fingerprint(&source, offset)?, 0)
        };
        Ok(Self {
            identity,
            source,
            checkpoint_path,
            offset,
            fingerprint,
            generation,
            pending: None,
            health: SourceHealthSample {
                state: DatasourceState::Starting,
                last_observed_at_micros: None,
                last_checkpoint: None,
                counters: SourceCounters::default(),
                last_error_code: None,
            },
        })
    }

    fn detect_rotation(&mut self) -> Result<(), AdapterError> {
        let size = std::fs::metadata(&self.source)?.len();
        let matches =
            size >= self.offset && file_fingerprint(&self.source, self.offset)? == self.fingerprint;
        if !matches {
            self.offset = 0;
            self.fingerprint = file_fingerprint(&self.source, 0)?;
            self.generation = self.generation.saturating_add(1);
            self.pending = None;
        }
        Ok(())
    }
}

impl SourceAdapter for FileTailAdapter {
    fn identity(&self) -> &DatasourceIdentity {
        &self.identity
    }

    fn capabilities(&self) -> SourceCapabilities {
        SourceCapabilities {
            ordered: true,
            reliable_transport: true,
            source_sequence: true,
            source_timestamp: false,
            backpressure: true,
        }
    }

    fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
        self.detect_rotation()?;
        let mut reader = BufReader::new(std::fs::File::open(&self.source)?);
        reader.seek(SeekFrom::Start(self.offset))?;
        let mut observations = Vec::new();
        let mut cursor = self.offset;
        let mut line = Vec::new();
        while observations.len() < limit {
            line.clear();
            let count = reader.read_until(b'\n', &mut line)?;
            if count == 0 || !line.ends_with(b"\n") {
                break;
            }
            let start = cursor;
            cursor = cursor.saturating_add(count as u64);
            while line
                .last()
                .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
            {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let sequence = format!("{}:{}", self.generation, start);
            observations.push(Observation {
                payload: line.clone(),
                source_sequence: Some(sequence.clone()),
                source_event_id: Some(format!("{}:{sequence}", self.source.display())),
                observed_at_micros: None,
            });
        }
        let pending = FileCursor {
            offset: cursor,
            fingerprint: file_fingerprint(&self.source, cursor)?,
            generation: self.generation,
            observations: observations.len() as u64,
        };
        let ack = SourceAck {
            cursor: serde_json::to_string(&pending)
                .map_err(|error| AdapterError::InvalidAck(error.to_string()))?,
        };
        self.pending = Some(pending);
        self.health.counters.observed = self
            .health
            .counters
            .observed
            .saturating_add(observations.len() as u64);
        self.health.state = DatasourceState::Healthy;
        Ok(ObservationBatch {
            observations,
            ack: Some(ack),
        })
    }

    fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
        let cursor: FileCursor = serde_json::from_str(&ack.cursor)
            .map_err(|error| AdapterError::InvalidAck(error.to_string()))?;
        if self.pending.as_ref() != Some(&cursor)
            || cursor.generation != self.generation
            || cursor.offset < self.offset
        {
            return Err(AdapterError::InvalidAck(
                "cursor nao corresponde ao ultimo batch observado".into(),
            ));
        }
        save_file_checkpoint(
            &self.checkpoint_path,
            &FileCheckpoint {
                source: self.source.clone(),
                offset: cursor.offset,
                fingerprint: cursor.fingerprint.clone(),
                generation: cursor.generation,
            },
        )?;
        self.offset = cursor.offset;
        self.fingerprint = cursor.fingerprint;
        self.health.counters.acknowledged = self
            .health
            .counters
            .acknowledged
            .saturating_add(cursor.observations);
        self.health.last_checkpoint = Some(ack.cursor);
        self.pending = None;
        Ok(())
    }

    fn health(&self) -> SourceHealthSample {
        self.health.clone()
    }
}

fn file_fingerprint(path: &Path, offset: u64) -> std::io::Result<String> {
    let upto = offset.min(FILE_FINGERPRINT_BYTES as u64) as usize;
    if upto == 0 {
        return Ok("new".into());
    }
    let mut file = std::fs::File::open(path)?;
    let mut prefix = vec![0; upto];
    let read = file.read(&mut prefix)?;
    if read < upto {
        return Ok(format!("short:{read}"));
    }
    Ok(blake3::hash(&prefix).to_hex()[..16].to_owned())
}

fn load_file_checkpoint(path: &Path) -> Option<FileCheckpoint> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn save_file_checkpoint(path: &Path, checkpoint: &FileCheckpoint) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(checkpoint).map_err(std::io::Error::other)?)?;
        file.sync_all()?;
    }
    atomic_replace(&tmp, path)?;
    if let Some(parent) = parent {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that stay
    // alive for the duration of the call. Flags request atomic replacement and
    // a durable flush through the Windows filesystem cache.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Fair, single-owner supervisor. Each cycle polls every enabled datasource at
/// most once; a slow or empty source cannot starve the others.
#[derive(Default)]
pub struct SourceSupervisor {
    adapters: BTreeMap<String, Box<dyn SourceAdapter>>,
}

impl SourceSupervisor {
    pub fn register(&mut self, adapter: Box<dyn SourceAdapter>) -> Result<(), AdapterError> {
        adapter.identity().validate()?;
        let key = adapter.identity().datasource_id.clone();
        if self.adapters.contains_key(&key) {
            return Err(AdapterError::DuplicateDatasource(key));
        }
        self.adapters.insert(key, adapter);
        Ok(())
    }

    pub fn poll_cycle(
        &mut self,
        limit_per_source: usize,
    ) -> Vec<(DatasourceIdentity, Result<ObservationBatch, AdapterError>)> {
        self.adapters
            .values_mut()
            .map(|adapter| (adapter.identity().clone(), adapter.poll(limit_per_source)))
            .collect()
    }

    pub fn checkpoint(&mut self, datasource_id: &str, ack: SourceAck) -> Result<(), AdapterError> {
        self.adapters
            .get_mut(datasource_id)
            .ok_or_else(|| AdapterError::UnknownDatasource(datasource_id.into()))?
            .checkpoint(ack)
    }

    pub fn health(&self) -> Vec<(DatasourceIdentity, SourceHealthSample)> {
        self.adapters
            .values()
            .map(|adapter| (adapter.identity().clone(), adapter.health()))
            .collect()
    }
}

/// In-memory bounded handoff. Full means backpressure, never an invisible
/// discard. Callers may later add an encrypted spill implementation behind the
/// same API without changing source adapters.
pub struct BoundedObservationBuffer {
    limit_bytes: usize,
    used_bytes: usize,
    queue: VecDeque<Observation>,
    backpressure_events: u64,
}

impl BoundedObservationBuffer {
    pub fn new(limit_bytes: usize) -> Result<Self, AdapterError> {
        if limit_bytes == 0 {
            return Err(AdapterError::InvalidConfig(
                "buffer_limit_bytes deve ser maior que zero".into(),
            ));
        }
        Ok(Self {
            limit_bytes,
            used_bytes: 0,
            queue: VecDeque::new(),
            backpressure_events: 0,
        })
    }

    pub fn push(&mut self, observation: Observation) -> Result<(), AdapterError> {
        let bytes = observation.wire_bytes();
        let attempted = self.used_bytes.saturating_add(bytes);
        if attempted > self.limit_bytes {
            self.backpressure_events = self.backpressure_events.saturating_add(1);
            return Err(AdapterError::Backpressure {
                limit_bytes: self.limit_bytes,
                attempted_bytes: attempted,
            });
        }
        self.used_bytes = attempted;
        self.queue.push_back(observation);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Observation> {
        let observation = self.queue.pop_front()?;
        self.used_bytes = self.used_bytes.saturating_sub(observation.wire_bytes());
        Some(observation)
    }

    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    pub fn backpressure_events(&self) -> u64 {
        self.backpressure_events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(id: &str) -> DatasourceIdentity {
        DatasourceIdentity {
            tenant_id: "tenant-a".into(),
            datasource_id: id.into(),
            sensor_id: "sensor-a".into(),
        }
    }

    struct FakeAdapter {
        identity: DatasourceIdentity,
        payload: Option<Vec<u8>>,
        checkpoints: Vec<String>,
    }

    impl SourceAdapter for FakeAdapter {
        fn identity(&self) -> &DatasourceIdentity {
            &self.identity
        }

        fn capabilities(&self) -> SourceCapabilities {
            SourceCapabilities {
                ordered: true,
                reliable_transport: true,
                source_sequence: true,
                source_timestamp: false,
                backpressure: true,
            }
        }

        fn poll(&mut self, limit: usize) -> Result<ObservationBatch, AdapterError> {
            let observations = self
                .payload
                .take()
                .filter(|_| limit > 0)
                .map(|payload| Observation {
                    payload,
                    source_sequence: Some("1".into()),
                    source_event_id: Some("source:1".into()),
                    observed_at_micros: None,
                })
                .into_iter()
                .collect();
            Ok(ObservationBatch {
                observations,
                ack: Some(SourceAck { cursor: "1".into() }),
            })
        }

        fn checkpoint(&mut self, ack: SourceAck) -> Result<(), AdapterError> {
            self.checkpoints.push(ack.cursor);
            Ok(())
        }

        fn health(&self) -> SourceHealthSample {
            SourceHealthSample {
                state: DatasourceState::Healthy,
                last_observed_at_micros: None,
                last_checkpoint: self.checkpoints.last().cloned(),
                counters: SourceCounters::default(),
                last_error_code: None,
            }
        }
    }

    fn fake(id: &str, byte: u8) -> Box<dyn SourceAdapter> {
        Box::new(FakeAdapter {
            identity: identity(id),
            payload: Some(vec![byte]),
            checkpoints: Vec::new(),
        })
    }

    #[test]
    fn supervisor_polls_every_source_once_per_cycle() {
        let mut supervisor = SourceSupervisor::default();
        supervisor.register(fake("a", 1)).unwrap();
        supervisor.register(fake("b", 2)).unwrap();
        let cycle = supervisor.poll_cycle(10);
        assert_eq!(cycle.len(), 2);
        assert_eq!(cycle[0].1.as_ref().unwrap().observations[0].payload, [1]);
        assert_eq!(cycle[1].1.as_ref().unwrap().observations[0].payload, [2]);
    }

    #[test]
    fn duplicate_datasource_is_rejected() {
        let mut supervisor = SourceSupervisor::default();
        supervisor.register(fake("same", 1)).unwrap();
        assert!(matches!(
            supervisor.register(fake("same", 2)),
            Err(AdapterError::DuplicateDatasource(_))
        ));
    }

    #[test]
    fn full_buffer_applies_backpressure_without_dropping_existing_data() {
        let mut buffer = BoundedObservationBuffer::new(4).unwrap();
        let first = Observation {
            payload: vec![1, 2, 3, 4],
            source_sequence: None,
            source_event_id: None,
            observed_at_micros: None,
        };
        buffer.push(first.clone()).unwrap();
        assert!(matches!(
            buffer.push(Observation {
                payload: vec![5],
                source_sequence: None,
                source_event_id: None,
                observed_at_micros: None,
            }),
            Err(AdapterError::Backpressure { .. })
        ));
        assert_eq!(buffer.backpressure_events(), 1);
        assert_eq!(buffer.used_bytes(), 4);
        assert_eq!(buffer.pop(), Some(first));
        assert_eq!(buffer.used_bytes(), 0);
    }

    #[test]
    fn file_tail_repeats_until_ack_then_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.log");
        let state = dir.path().join("source.state");
        std::fs::write(&source, b"one\ntwo\n").unwrap();

        let mut adapter = FileTailAdapter::open(identity("file-a"), &source, &state, true).unwrap();
        let first = adapter.poll(1).unwrap();
        assert_eq!(first.observations[0].payload, b"one");
        let repeated = adapter.poll(1).unwrap();
        assert_eq!(repeated.observations[0].payload, b"one");
        adapter.checkpoint(repeated.ack.unwrap()).unwrap();

        let mut reopened =
            FileTailAdapter::open(identity("file-a"), &source, &state, true).unwrap();
        let second = reopened.poll(1).unwrap();
        assert_eq!(second.observations[0].payload, b"two");
        assert_ne!(
            first.observations[0].source_sequence,
            second.observations[0].source_sequence
        );
    }

    #[test]
    fn file_tail_waits_for_a_complete_line() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("partial.log");
        let state = dir.path().join("partial.state");
        std::fs::write(&source, b"unfinished").unwrap();
        let mut adapter = FileTailAdapter::open(identity("file-b"), &source, &state, true).unwrap();
        assert!(adapter.poll(10).unwrap().observations.is_empty());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(b" line\n")
            .unwrap();
        assert_eq!(
            adapter.poll(10).unwrap().observations[0].payload,
            b"unfinished line"
        );
    }

    #[test]
    fn checkpoint_replacement_survives_more_than_one_ack() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("many.log");
        let state = dir.path().join("many.state");
        std::fs::write(&source, b"one\ntwo\n").unwrap();
        let mut adapter = FileTailAdapter::open(identity("file-c"), &source, &state, true).unwrap();
        for _ in 0..2 {
            let batch = adapter.poll(1).unwrap();
            adapter.checkpoint(batch.ack.unwrap()).unwrap();
        }
        let persisted = load_file_checkpoint(&state).unwrap();
        assert_eq!(persisted.offset, 8);
        assert!(!PathBuf::from(format!("{}.tmp", state.display())).exists());
    }
}
