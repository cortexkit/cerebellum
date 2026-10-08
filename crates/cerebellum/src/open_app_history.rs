//! Optional, machine-local launch timings. No application display text or paths
//! enter this store; a bundle and its verified signer are the only identifiers.

use crate::computer_grants::AppIdentity;
use cerebellum_computer::app_state::source::OpenAppBounds;
use cerebellum_core::format_floor::{DurableFormat, FormatFloor};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const LAUNCH_HISTORY_FORMAT: DurableFormat = DurableFormat::new("open-app-launch-history", 1);
const FILE_NAME: &str = "open_app_launch_history.json";
const MAX_APPS: usize = 200;
const MAX_LAUNCHES: usize = 20;
// Two minutes accommodates cold starts without letting stale or censored
// timings hold an interactive request indefinitely. This is a TOTAL budget.
const CEILING_MS: u64 = 120_000;
const MAX_BYTES: u64 = 2 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static HEALTH: AtomicU8 = AtomicU8::new(0);

pub fn durable_history_health() -> &'static str {
    match HEALTH.load(Ordering::Acquire) {
        1 => "loaded",
        2 => "unreadable",
        3 => "write_failed",
        _ => "not_opened",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppKey {
    bundle_id: String,
    signer: Signer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Signer {
    Apple,
    Team(String),
}

impl AppKey {
    pub(crate) fn verified(bundle: &str, identity: &AppIdentity) -> Option<Self> {
        if identity.ad_hoc {
            return None;
        }
        let signer = if identity.apple_anchored {
            Signer::Apple
        } else {
            Signer::Team(
                identity
                    .team_id
                    .as_ref()
                    .filter(|id| !id.is_empty())?
                    .clone(),
            )
        };
        Some(Self {
            bundle_id: bundle.to_ascii_lowercase(),
            signer,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Launched,
    AlreadyRunning,
    LaunchedNoWindow,
    LaunchFailed,
    Cancelled,
}

impl Outcome {
    pub(crate) fn from_reply(outcome: &str) -> Option<Self> {
        Some(match outcome {
            "launched" => Self::Launched,
            "already_running" => Self::AlreadyRunning,
            "launched_no_window" => Self::LaunchedNoWindow,
            "launch_failed" => Self::LaunchFailed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub process_started_ms: Option<u64>,
    pub first_window_ms: Option<u64>,
    // A timeout is a censored observation, not evidence that readiness took
    // zero time. Retain its budget even when no process or window was seen.
    pub timeout_floor_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    observation: Observation,
    outcome: Outcome,
    timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppHistory {
    key: AppKey,
    launches: Vec<Launch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u64,
    // Oldest to newest by launch order, independent of wall-clock adjustments.
    apps: Vec<AppHistory>,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            version: LAUNCH_HISTORY_FORMAT.version,
            apps: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Advice {
    pub bounds: OpenAppBounds,
    pub usual_ready_ms: Option<u64>,
}

fn percentile(samples: &mut [u64], percent: usize) -> Option<u64> {
    samples.sort_unstable();
    let rank = (samples.len() * percent).div_ceil(100);
    rank.checked_sub(1).map(|index| samples[index])
}

fn timeout_sample(observation: &Observation) -> Option<u64> {
    observation.timeout_floor_ms
}

fn advice(launches: &[Launch]) -> Advice {
    let defaults = OpenAppBounds::default();
    let mut successful: Vec<_> = launches
        .iter()
        .filter_map(|launch| {
            // Already-running replies are recorded but are not cold-start evidence.
            matches!(launch.outcome, Outcome::Launched)
                .then_some(launch.observation.first_window_ms)
                .flatten()
        })
        .collect();
    let usual_ready_ms = percentile(&mut successful, 50);
    let mut samples = successful.clone();
    samples.extend(
        launches
            .iter()
            .filter_map(|launch| timeout_sample(&launch.observation)),
    );
    let learned = if samples.len() >= 3 {
        percentile(&mut samples, 90).unwrap_or(0).saturating_mul(2)
    } else {
        0
    };
    // Even one timeout must increase the next budget. Waiting for three cold
    // starts would repeat a known-too-short wait on the very next retry.
    let timeout_floor = launches
        .iter()
        .filter_map(|launch| timeout_sample(&launch.observation))
        .max()
        .unwrap_or(0)
        .saturating_mul(2);
    let default_ms = defaults.ready_timeout.as_millis() as u64;
    let deadline_ms = default_ms.max(learned).max(timeout_floor).min(CEILING_MS);
    let mut bounds = defaults;
    if deadline_ms > default_ms {
        bounds.ready_timeout = Duration::from_millis(deadline_ms);
        // The native launcher clips both stages to the single total deadline,
        // allowing a slow process OR a slow first window to use the extra time.
        bounds.process_timeout = bounds.ready_timeout;
        bounds.window_timeout = bounds.ready_timeout;
    }
    Advice {
        bounds,
        usual_ready_ms,
    }
}

struct State {
    document: Option<Document>,
    path: Option<PathBuf>,
    floor: FormatFloor,
    production: bool,
}

pub(crate) struct LaunchHistory(Mutex<State>);

impl LaunchHistory {
    pub(crate) fn in_memory() -> Self {
        Self(Mutex::new(State {
            document: Some(Document::default()),
            path: None,
            floor: FormatFloor::isolated(),
            production: false,
        }))
    }

    pub(crate) fn production() -> Self {
        match cerebellum_core::journal::journal_data_path(FILE_NAME) {
            Ok(path) => Self::open(path, true),
            Err(_) => {
                HEALTH.store(2, Ordering::Release);
                Self(Mutex::new(State {
                    document: None,
                    path: None,
                    floor: FormatFloor::isolated(),
                    production: true,
                }))
            }
        }
    }

    fn open(path: PathBuf, production: bool) -> Self {
        let document = load(&path).ok();
        if production {
            HEALTH.store(if document.is_some() { 1 } else { 2 }, Ordering::Release);
        }
        Self(Mutex::new(State {
            document,
            floor: FormatFloor::governing(&path),
            path: Some(path),
            production,
        }))
    }

    #[cfg(test)]
    pub(crate) fn at(path: PathBuf) -> Self {
        Self::open(path, false)
    }

    pub(crate) fn advice(&self, key: &AppKey) -> Advice {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let launches = state
            .document
            .as_ref()
            .and_then(|d| d.apps.iter().find(|a| &a.key == key))
            .map(|a| a.launches.as_slice())
            .unwrap_or(&[]);
        advice(launches)
    }

    pub(crate) fn record(&self, key: AppKey, observation: Observation, outcome: Outcome) -> bool {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(document) = state.document.as_mut() else {
            return false;
        };
        let mut app = document
            .apps
            .iter()
            .position(|app| app.key == key)
            .map(|index| document.apps.remove(index))
            .unwrap_or(AppHistory {
                key,
                launches: Vec::new(),
            });
        app.launches.push(Launch {
            observation,
            outcome,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        });
        if app.launches.len() > MAX_LAUNCHES {
            app.launches.remove(0);
        }
        document.apps.push(app);
        if document.apps.len() > MAX_APPS {
            document.apps.remove(0);
        }
        let result = if let Some(path) = &state.path {
            save(path, &state.floor, state.document.as_ref().unwrap())
        } else {
            Ok(())
        };
        if result.is_err() {
            // Never overwrite unreadable data or use unpersisted observations as
            // though learning were healthy. Future launches use default bounds.
            state.document = None;
            if state.production {
                HEALTH.store(3, Ordering::Release);
            }
            return false;
        }
        true
    }
}

fn load(path: &PathBuf) -> io::Result<Document> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Document::default()),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(io::Error::other("launch history too large"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value["version"].as_u64() != Some(LAUNCH_HISTORY_FORMAT.version) {
        return Err(io::Error::other(
            "unsupported open-app-launch-history version",
        ));
    }
    let document: Document = serde_json::from_value(value)?;
    if document.apps.len() > MAX_APPS
        || document
            .apps
            .iter()
            .any(|a| a.launches.is_empty() || a.launches.len() > MAX_LAUNCHES)
    {
        return Err(io::Error::other("invalid launch history bounds"));
    }
    Ok(document)
}

fn save(path: &PathBuf, floor: &FormatFloor, document: &Document) -> io::Result<()> {
    floor
        .raise(LAUNCH_HISTORY_FORMAT)
        .map_err(io::Error::other)?;
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("missing history directory"))?;
    cerebellum_core::private_fs::create_dir_all(directory)?;
    let temporary = directory.join(format!(
        ".open-app-history.{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
        file.write_all(&serde_json::to_vec(document)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(team: &str) -> AppIdentity {
        AppIdentity {
            team_id: Some(team.into()),
            designated_requirement: format!("identifier com.editor and team {team}"),
            ad_hoc: false,
            apple_anchored: false,
        }
    }

    fn key(bundle: &str, team: &str) -> AppKey {
        AppKey::verified(bundle, &identity(team)).unwrap()
    }

    fn record(history: &LaunchHistory, key: AppKey, ready: u64) {
        assert!(history.record(
            key,
            Observation {
                process_started_ms: Some(10),
                first_window_ms: Some(ready),
                timeout_floor_ms: None
            },
            Outcome::Launched
        ));
    }

    fn scratch(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ck-launch-history-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn fewer_than_three_successes_use_default_then_p90_doubles() {
        let history = LaunchHistory::in_memory();
        let app = key("com.editor", "REALTEAM");
        for ready in [25_000, 30_000] {
            record(&history, app.clone(), ready);
            assert_eq!(history.advice(&app).bounds, OpenAppBounds::default());
        }
        record(&history, app.clone(), 35_000);
        let advice = history.advice(&app);
        assert_eq!(advice.bounds.ready_timeout, Duration::from_secs(70));
        assert_eq!(advice.usual_ready_ms, Some(30_000));
    }

    #[test]
    fn p90_uses_nearest_rank_instead_of_the_single_worst_launch() {
        let history = LaunchHistory::in_memory();
        let app = key("com.editor", "REALTEAM");
        for _ in 0..9 {
            record(&history, app.clone(), 30_000);
        }
        record(&history, app.clone(), 90_000);
        assert_eq!(
            history.advice(&app).bounds.ready_timeout,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn timeout_as_floor_increases_the_very_next_launch_deadline() {
        let history = LaunchHistory::in_memory();
        let app = key("com.editor", "REALTEAM");
        assert!(history.record(
            app.clone(),
            Observation {
                timeout_floor_ms: Some(40_000),
                ..Observation::default()
            },
            Outcome::LaunchFailed
        ));
        let advice = history.advice(&app);
        assert_eq!(advice.bounds.ready_timeout, Duration::from_secs(80));
        assert_eq!(advice.usual_ready_ms, None);
        record(&history, app.clone(), 30_000);
        record(&history, app.clone(), 35_000);
        assert_eq!(
            history.advice(&app).bounds.ready_timeout,
            Duration::from_secs(80)
        );
    }

    #[test]
    fn ceiling_caps_successes_and_saturates_timeout_samples() {
        let history = LaunchHistory::in_memory();
        let app = key("com.editor", "REALTEAM");
        for _ in 0..3 {
            record(&history, app.clone(), 100_000);
        }
        assert_eq!(
            history.advice(&app).bounds.ready_timeout,
            Duration::from_secs(120)
        );
        assert!(history.record(
            app.clone(),
            Observation {
                timeout_floor_ms: Some(u64::MAX),
                ..Observation::default()
            },
            Outcome::LaunchFailed
        ));
        assert_eq!(
            history.advice(&app).bounds.ready_timeout,
            Duration::from_secs(120)
        );
    }

    #[test]
    fn signer_bound_history_does_not_follow_a_resigned_bundle() {
        let history = LaunchHistory::in_memory();
        let real = key("com.editor", "REALTEAM");
        let impostor = key("com.editor", "OTHERTM");
        for _ in 0..3 {
            record(&history, real.clone(), 50_000);
        }
        assert_eq!(
            history.advice(&real).bounds.ready_timeout,
            Duration::from_secs(100)
        );
        assert!(history.advice(&impostor).usual_ready_ms.is_none());
        assert_eq!(history.advice(&impostor).bounds, OpenAppBounds::default());
        let mut apple = identity("REALTEAM");
        apple.team_id = None;
        apple.apple_anchored = true;
        assert!(history
            .advice(&AppKey::verified("com.editor", &apple).unwrap())
            .usual_ready_ms
            .is_none());
    }

    #[test]
    fn last_twenty_launches_and_least_recently_launched_app_are_bounded() {
        let history = LaunchHistory::in_memory();
        let oldest = key("com.oldest", "REALTEAM");
        record(&history, oldest.clone(), 60_000);
        for n in 0..199 {
            record(&history, key(&format!("com.app{n}"), "REALTEAM"), 10);
        }
        // Refresh one old app; launch order, not alphabetical order, governs eviction.
        let refreshed = key("com.app0", "REALTEAM");
        record(&history, refreshed.clone(), 10);
        record(&history, key("com.new", "REALTEAM"), 10);
        assert!(history.advice(&oldest).usual_ready_ms.is_none());
        assert!(history.advice(&refreshed).usual_ready_ms.is_some());
        for n in 0..30 {
            record(&history, refreshed.clone(), n);
        }
        let state = history.0.lock().unwrap();
        let document = state.document.as_ref().unwrap();
        assert_eq!(document.apps.len(), 200);
        let launches = &document.apps.last().unwrap().launches;
        assert_eq!(launches.len(), 20);
        assert_eq!(launches[0].observation.first_window_ms, Some(10));
        assert_eq!(launches[19].observation.first_window_ms, Some(29));
    }

    #[test]
    fn already_running_and_failed_launches_do_not_teach_cold_start_readiness() {
        let history = LaunchHistory::in_memory();
        let app = key("com.editor", "REALTEAM");
        for outcome in [Outcome::AlreadyRunning, Outcome::LaunchFailed] {
            assert!(history.record(
                app.clone(),
                Observation {
                    first_window_ms: Some(90_000),
                    ..Observation::default()
                },
                outcome
            ));
        }
        assert_eq!(history.advice(&app).bounds, OpenAppBounds::default());
        assert_eq!(history.advice(&app).usual_ready_ms, None);
    }

    #[test]
    fn lazy_private_store_roundtrips_and_raises_its_format_floor() {
        let root = scratch("roundtrip");
        let path = root.join(FILE_NAME);
        let floor_path = root.join("format-floor.json");
        let history = LaunchHistory::at(path.clone());
        history.0.lock().unwrap().floor = FormatFloor::at(&floor_path);
        assert!(!path.exists());
        assert!(!floor_path.exists());
        let app = key("com.editor", "REALTEAM");
        for _ in 0..3 {
            record(&history, app.clone(), 35_000);
        }
        assert_eq!(
            cerebellum_core::format_floor::read_floors(&floor_path)
                .unwrap()
                .get(LAUNCH_HISTORY_FORMAT.name),
            Some(&1)
        );
        let reopened = LaunchHistory::at(path.clone());
        assert_eq!(reopened.advice(&app).usual_ready_ms, Some(35_000));
        assert_eq!(
            reopened.advice(&app).bounds.ready_timeout,
            Duration::from_secs(70)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_or_newer_store_is_not_overwritten_and_floor_failure_writes_nothing() {
        let root = scratch("unreadable");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(FILE_NAME);
        let app = key("com.editor", "REALTEAM");
        for bytes in [b"not json".as_slice(), b"{\"version\":2,\"apps\":[]}"] {
            fs::write(&path, bytes).unwrap();
            let history = LaunchHistory::at(path.clone());
            assert_eq!(history.advice(&app).bounds, OpenAppBounds::default());
            assert!(!history.record(app.clone(), Observation::default(), Outcome::LaunchFailed));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        fs::remove_file(&path).unwrap();
        let history = LaunchHistory::at(path.clone());
        let blocker = root.join("blocker");
        fs::write(&blocker, b"file").unwrap();
        history.0.lock().unwrap().floor = FormatFloor::at(blocker.join("format-floor.json"));
        assert!(!history.record(app.clone(), Observation::default(), Outcome::LaunchFailed));
        assert!(!path.exists());
        assert_eq!(history.advice(&app).bounds, OpenAppBounds::default());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resource_pins_the_reader_format_and_retention_limits() {
        let resource: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../resources/open-app-launch-history-v1.json"
        ))
        .unwrap();
        assert_eq!(resource["format"], LAUNCH_HISTORY_FORMAT.name);
        assert_eq!(resource["version"], LAUNCH_HISTORY_FORMAT.version);
        assert_eq!(resource["max_apps"], MAX_APPS);
        assert_eq!(resource["max_launches_per_app"], MAX_LAUNCHES);
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::Outcome;

    #[test]
    fn admission_refusals_are_not_launch_outcomes() {
        for refusal in [
            "consent_pending",
            "consent_denied",
            "screen_locked",
            "module_draining",
            "route_closed",
            "url_scheme_refused",
            "audit_unavailable",
            "consent_unavailable",
            "invalid_request",
        ] {
            assert!(Outcome::from_reply(refusal).is_none(), "{refusal}");
        }
        for launch in [
            "launched",
            "already_running",
            "launched_no_window",
            "launch_failed",
            "cancelled",
        ] {
            assert!(Outcome::from_reply(launch).is_some(), "{launch}");
        }
    }
}
