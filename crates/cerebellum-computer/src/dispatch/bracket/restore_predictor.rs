//! Real restore timings for app-use needs-front brackets only.
//!
//! The history on disk is a hint, never an authority: it can only make the
//! admission check stricter. Every persisted sample must look like something
//! this module measured (within [`MIN_RESTORE_SAMPLE_MS`] and
//! [`MAX_RESTORE_SAMPLE_MS`], with a measurement time no later than the
//! time it is read, with no allowance), and only samples younger than
//! [`RESTORE_SAMPLE_MAX_AGE`] count.
//! A document that fails any check is ignored as a whole, which leaves the
//! predictor cold: the next eligible call calibrates instead of trusting a
//! reserve.

use super::latency::RESTORE_SAMPLES;
use cerebellum_core::format_floor::{floor_path, module_directory, DurableFormat, FormatFloor};
use cerebellum_core::private_fs;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Version 2 stores when each sample was measured, so stale samples can be
/// dropped. Version 1 was never released; a version-1 file is ignored and
/// replaced at the next write rather than migrated.
pub const RESTORE_LATENCY_FORMAT: DurableFormat = DurableFormat::new("restore-latency", 2);
const TREE: &str = "restore-latency";
const FILE_NAME: &str = "samples.json";
const MAX_DOCUMENT_BYTES: u64 = 1024;
const WRITE_INTERVAL: Duration = Duration::from_secs(1);
pub(super) const RECALIBRATION_INTERVAL: Duration = Duration::from_secs(60);

/// The smallest restore cost, in milliseconds, that a sample may claim.
///
/// Putting the person's application back is a cross-process activation
/// through the window server, confirmed by polling the frontmost application
/// every [`super::FRONTING_POLL_MS`]. 40 ms is a conservative lower bound for
/// that round trip on a real desk. A smaller value in the file is therefore
/// not a measurement but a damaged or edited file; trusting it would shrink
/// the reserve held back for the restore, so such a file is ignored as a
/// whole. Recorded samples are raised to this floor before they are kept, so
/// an unusually quick restore only ever makes the reserve larger. A floor set
/// too high costs a refused or calibrating call, never a looser admission.
pub(super) const MIN_RESTORE_SAMPLE_MS: u64 = 40;

/// The largest restore cost, in milliseconds, that a sample may claim.
/// Every value above the 200 ms fronting bound has the same effect (the
/// bracket refuses and may calibrate), so recorded samples are capped here,
/// and a larger value in the file is not one this module wrote.
pub(super) const MAX_RESTORE_SAMPLE_MS: u64 = 10_000;

/// How long a restore sample counts. Restore cost follows the desk's load,
/// display setup and OS version, which change over days, so a sample older
/// than a week says little about the next restore. Older samples are dropped
/// when the file is loaded and stop counting in memory; when none is younger,
/// the predictor is cold again and the next eligible call calibrates.
pub(super) const RESTORE_SAMPLE_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

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
    /// Oldest first, at most [`RESTORE_SAMPLES`].
    samples: VecDeque<Sample>,
    last_write: Option<Instant>,
    persisted_maximum: Option<u64>,
    last_calibration: Option<Instant>,
    calibrating: bool,
}

/// One restore's cost and the wall-clock time it was measured, in
/// milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    ms: u64,
    at_unix_ms: u64,
}

impl Sample {
    fn fresh_at(self, now_unix_ms: u64) -> bool {
        now_unix_ms.saturating_sub(self.at_unix_ms) < duration_ms(RESTORE_SAMPLE_MAX_AGE)
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map(duration_ms)
        .unwrap_or_default()
}

fn maximum_of(samples: &VecDeque<Sample>, now_unix_ms: u64) -> Option<u64> {
    samples
        .iter()
        .filter(|sample| sample.fresh_at(now_unix_ms))
        .map(|sample| sample.ms)
        .max()
}

impl RestorePredictor {
    pub(super) fn open(data_home: Option<&Path>) -> Self {
        Self::open_at(data_home, unix_ms(SystemTime::now()))
    }

    /// A predictor loaded from `data_home`'s history, for tests outside this
    /// module that must not touch the process-wide one.
    #[cfg(test)]
    pub(crate) fn open_for_test(data_home: &Path) -> Self {
        Self::open(Some(data_home))
    }

    pub(super) fn open_at(data_home: Option<&Path>, now_unix_ms: u64) -> Self {
        let file = data_home.map(|home| StoreFile {
            path: module_directory(home).join(TREE).join(FILE_NAME),
            floor: FormatFloor::at(floor_path(home, TREE)),
        });
        let loaded = file.as_ref().map_or(Loaded::Unusable, StoreFile::read);
        let (file, samples) = match loaded {
            // A newer writer's document is unusable as a predictor, but
            // must not be overwritten by an older process.
            Loaded::Newer => (None, VecDeque::new()),
            Loaded::Current(samples) => (file, usable_samples(samples, now_unix_ms)),
            Loaded::Unusable => (file, VecDeque::new()),
        };
        let persisted_maximum = maximum_of(&samples, now_unix_ms);
        Self {
            file,
            state: Mutex::new(State {
                samples,
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

    /// The largest sample younger than [`RESTORE_SAMPLE_MAX_AGE`], or `None`
    /// (cold) when there is none.
    pub(super) fn maximum(&self) -> Option<u64> {
        self.maximum_at(unix_ms(SystemTime::now()))
    }

    pub(super) fn maximum_at(&self, now_unix_ms: u64) -> Option<u64> {
        maximum_of(&self.state().samples, now_unix_ms)
    }

    pub(super) fn try_calibrate(
        &self,
        measured: Option<u64>,
        now: Instant,
    ) -> Option<Calibration<'_>> {
        let mut state = self.state();
        if state.calibrating
            || maximum_of(&state.samples, unix_ms(SystemTime::now())) != measured
            || state
                .last_calibration
                .is_some_and(|last| now.saturating_duration_since(last) < RECALIBRATION_INTERVAL)
        {
            return None;
        }
        state.calibrating = true;
        state.last_calibration = Some(now);
        Some(Calibration(self))
    }

    /// Keep one restore's cost, raised to [`MIN_RESTORE_SAMPLE_MS`] and
    /// capped at [`MAX_RESTORE_SAMPLE_MS`]. `calibration_bound` is set by a
    /// successful in-bound calibration, which drops older samples above it.
    pub(super) fn record(&self, sample: u64, calibration_bound: Option<u64>, now: Instant) {
        self.record_at(sample, calibration_bound, now, unix_ms(SystemTime::now()));
    }

    pub(super) fn record_at(
        &self,
        sample: u64,
        calibration_bound: Option<u64>,
        now: Instant,
        now_unix_ms: u64,
    ) {
        let sample = sample.clamp(MIN_RESTORE_SAMPLE_MS, MAX_RESTORE_SAMPLE_MS);
        let mut state = self.state();
        state.samples.retain(|older| older.fresh_at(now_unix_ms));
        let mut dropped_slow_sample = false;
        if let Some(bound) = calibration_bound {
            state.samples.retain(|older| {
                let keep = older.ms <= bound;
                dropped_slow_sample |= !keep;
                keep
            });
        }
        state.samples.push_back(Sample {
            ms: sample,
            at_unix_ms: now_unix_ms,
        });
        while state.samples.len() > RESTORE_SAMPLES {
            state.samples.pop_front();
        }
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
                    state.persisted_maximum = maximum_of(&state.samples, now_unix_ms);
                }
            }
        }
    }
}

/// The loaded samples that count, or none when any of them could not have
/// been written by this module: a cost outside the allowed range (zero
/// included) or a measurement time later than now. There is no allowance
/// for a clock step: a sample dated even a moment ahead is not one this
/// module wrote, and a wall clock stepped back only costs a calibration.
/// Stale samples are dropped one by one; a file of only stale samples leaves
/// the predictor cold.
fn usable_samples(samples: Vec<Sample>, now_unix_ms: u64) -> VecDeque<Sample> {
    if samples.iter().any(|sample| {
        !(MIN_RESTORE_SAMPLE_MS..=MAX_RESTORE_SAMPLE_MS).contains(&sample.ms)
            || sample.at_unix_ms > now_unix_ms
    }) {
        return VecDeque::new();
    }
    samples
        .into_iter()
        .filter(|sample| sample.fresh_at(now_unix_ms))
        .collect()
}

pub(super) struct Calibration<'a>(&'a RestorePredictor);

impl Drop for Calibration<'_> {
    fn drop(&mut self) {
        self.0.state().calibrating = false;
    }
}

/// Only the version, read first so a newer writer's document is recognised
/// whatever shape it has.
#[derive(Deserialize)]
struct VersionProbe {
    version: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u64,
    samples: Vec<Sample>,
}

/// What the file held, before the samples themselves are checked.
enum Loaded {
    /// Missing, unreadable, malformed, too large, or an older version.
    Unusable,
    /// Written by a newer build.
    Newer,
    Current(Vec<Sample>),
}

struct StoreFile {
    path: PathBuf,
    floor: FormatFloor,
}

impl StoreFile {
    fn read(&self) -> Loaded {
        let Some(bytes) = self.read_bytes() else {
            return Loaded::Unusable;
        };
        let Ok(probe) = serde_json::from_slice::<VersionProbe>(&bytes) else {
            return Loaded::Unusable;
        };
        if probe.version > RESTORE_LATENCY_FORMAT.version {
            return Loaded::Newer;
        }
        if probe.version < RESTORE_LATENCY_FORMAT.version {
            return Loaded::Unusable;
        }
        match serde_json::from_slice::<Document>(&bytes) {
            Ok(document) if document.samples.len() <= RESTORE_SAMPLES => {
                Loaded::Current(document.samples)
            }
            _ => Loaded::Unusable,
        }
    }

    fn read_bytes(&self) -> Option<Vec<u8>> {
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
        (bytes.len() as u64 <= MAX_DOCUMENT_BYTES).then_some(bytes)
    }

    fn write(&self, samples: &VecDeque<Sample>) -> io::Result<()> {
        self.floor
            .raise(RESTORE_LATENCY_FORMAT)
            .map_err(io::Error::other)?;
        let bytes = serde_json::to_vec(&Document {
            version: RESTORE_LATENCY_FORMAT.version,
            samples: samples.iter().copied().collect(),
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
