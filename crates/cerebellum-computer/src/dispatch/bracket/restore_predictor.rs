//! Real restore timings for app-use needs-front brackets only.

use super::latency::{RestoreLatencies, RESTORE_SAMPLES};
use cerebellum_core::format_floor::{floor_path, module_directory, DurableFormat, FormatFloor};
use cerebellum_core::private_fs;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

pub const RESTORE_LATENCY_FORMAT: DurableFormat = DurableFormat::new("restore-latency", 1);
const TREE: &str = "restore-latency";
const FILE_NAME: &str = "samples.json";
const MAX_DOCUMENT_BYTES: u64 = 512;
const WRITE_INTERVAL: Duration = Duration::from_secs(1);
pub(super) const RECALIBRATION_INTERVAL: Duration = Duration::from_secs(60);

static PROCESS_PREDICTOR: OnceLock<RestorePredictor> = OnceLock::new();

/// Load timing history at module startup. A missing or invalid file is empty;
/// the store and its floor are not created until the first sample is written.
pub fn load_needs_front_restore_predictor(data_home: Option<&Path>) {
    PROCESS_PREDICTOR.get_or_init(|| RestorePredictor::open(data_home));
}

pub(crate) fn needs_front_restore_predictor() -> &'static RestorePredictor {
    // Entry points without production startup use an in-memory predictor.
    PROCESS_PREDICTOR.get_or_init(|| RestorePredictor::open(None))
}

pub(crate) struct RestorePredictor {
    file: Option<StoreFile>,
    state: Mutex<State>,
}

struct State {
    samples: RestoreLatencies,
    last_write: Option<Instant>,
    persisted_maximum: Option<u64>,
    last_calibration: Option<Instant>,
    calibrating: bool,
}

impl RestorePredictor {
    pub(super) fn open(data_home: Option<&Path>) -> Self {
        let file = data_home.map(|home| StoreFile {
            path: module_directory(home).join(TREE).join(FILE_NAME),
            floor: FormatFloor::at(floor_path(home, TREE)),
        });
        let samples = file.as_ref().and_then(StoreFile::read);
        // A newer writer's document is still unusable as a predictor, but
        // should not be overwritten by an older process.
        let (file, samples) = match samples {
            Some(document) if document.version > RESTORE_LATENCY_FORMAT.version => (None, None),
            Some(document) if document.version == RESTORE_LATENCY_FORMAT.version => {
                (file, Some(document.samples_ms))
            }
            _ => (file, None),
        };
        let mut history = RestoreLatencies::new();
        for sample in samples.into_iter().flatten() {
            history.record(sample);
        }
        let persisted_maximum = history.maximum();
        Self {
            file,
            state: Mutex::new(State {
                samples: history,
                last_write: None,
                persisted_maximum,
                last_calibration: None,
                calibrating: false,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn maximum(&self) -> Option<u64> {
        self.state().samples.maximum()
    }

    pub(super) fn try_calibrate(
        &self,
        measured: Option<u64>,
        now: Instant,
    ) -> Option<Calibration<'_>> {
        let mut state = self.state();
        if state.calibrating
            || state.samples.maximum() != measured
            || (measured.is_some()
                && state.last_calibration.is_some_and(|last| {
                    now.saturating_duration_since(last) < RECALIBRATION_INTERVAL
                }))
        {
            return None;
        }
        state.calibrating = true;
        state.last_calibration = Some(now);
        Some(Calibration(self))
    }

    pub(super) fn record(&self, sample: u64, calibration_bound: Option<u64>, now: Instant) {
        let mut state = self.state();
        let mut dropped_slow_sample = false;
        if let Some(bound) = calibration_bound {
            let mut retained = RestoreLatencies::new();
            for older in state.samples.oldest_first() {
                if older <= bound {
                    retained.record(older);
                } else {
                    dropped_slow_sample = true;
                }
            }
            state.samples = retained;
        }
        state.samples.record(sample);
        if let Some(file) = &self.file {
            // A restart should not forget a newly observed worst case or
            // bring back stale slow samples that calibration just cleared.
            let new_peak = state
                .persisted_maximum
                .is_some_and(|previous| sample > previous);
            if dropped_slow_sample
                || new_peak
                || state
                    .last_write
                    .is_none_or(|last| now.saturating_duration_since(last) >= WRITE_INTERVAL)
            {
                state.last_write = Some(now);
                // Absence of a persisted hint must not block safe in-memory use.
                if file.write(&state.samples).is_ok() {
                    state.persisted_maximum = state.samples.maximum();
                }
            }
        }
    }
}

pub(super) struct Calibration<'a>(&'a RestorePredictor);

impl Drop for Calibration<'_> {
    fn drop(&mut self) {
        self.0.state().calibrating = false;
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u64,
    samples_ms: Vec<u64>,
}

struct StoreFile {
    path: PathBuf,
    floor: FormatFloor,
}

impl StoreFile {
    fn read(&self) -> Option<Document> {
        let metadata = fs::symlink_metadata(&self.path).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_DOCUMENT_BYTES {
            return None;
        }
        let mut bytes = Vec::new();
        File::open(&self.path)
            .ok()?
            .take(MAX_DOCUMENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            return None;
        }
        let document: Document = serde_json::from_slice(&bytes).ok()?;
        (document.samples_ms.len() <= RESTORE_SAMPLES).then_some(document)
    }

    fn write(&self, samples: &RestoreLatencies) -> io::Result<()> {
        self.floor
            .raise(RESTORE_LATENCY_FORMAT)
            .map_err(io::Error::other)?;
        let bytes = serde_json::to_vec(&Document {
            version: RESTORE_LATENCY_FORMAT.version,
            samples_ms: samples.oldest_first().collect(),
        })?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .path
            .with_file_name(format!(".samples-{}-{sequence}.tmp", std::process::id()));
        let mut file = private_fs::create_new_file(&temporary)?;
        let result = file.write_all(&bytes).and_then(|()| file.sync_all());
        drop(file);
        let result = result.and_then(|()| fs::rename(&temporary, &self.path));
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}
