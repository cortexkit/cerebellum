//! Scope-level provenance for model-provider consent. This store records no content.
//!
//! Broca asks, before a model call, whether the calling scope has read private
//! content; a wrong "no" sends private content to a provider the person never
//! approved. So every doubt answers "yes, from every source": an unreadable
//! file, a failed or late write, a missing in-use marker, or a previous process
//! that did not shut down cleanly.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_core::format_floor::{DurableFormat, FormatFloor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{AcceptedBindFacts, Frame, ModuleError, Planes};

pub(crate) const QUERY: &str = "private_content.query";
pub(crate) const CAPABILITY: &str = "private-content-marks/v1";
/// Version 2 keeps head marks apart from run marks. Version 1 files (a single
/// `scopes` map) are still read, and are rewritten as version 2 only by the
/// first write, which raises the format floor first.
pub const PRIVATE_CONTENT_FORMAT: DurableFormat = DurableFormat::new("private-content-marks", 2);
const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const REFRESH_MS: u64 = 60 * 60 * 1000;
const FILE_NAME: &str = "private-content-marks.json";
/// Present while a process that may deliver content is running; removed only
/// by a clean shutdown that persisted every mark it made.
const MARKER_NAME: &str = "private-content-running.json";
const MAX_BYTES: u64 = 8 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    PersonBrowser,
    DesktopApp,
    SignedInSite,
}

const SOURCES: [Source; 3] = [
    Source::PersonBrowser,
    Source::DesktopApp,
    Source::SignedInSite,
];

/// How long a scope's mark is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Retention {
    /// A head agent (or another long-lived agent scope) keeps what it read in
    /// its context for its whole life, so its marks never expire. There is
    /// one entry per such scope, so the store grows with the number of heads,
    /// not the number of reads.
    Head,
    /// A codemode run or flow: kept 24 hours after its latest read.
    Run,
}

type Marks = BTreeMap<String, BTreeMap<Source, u64>>;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u64,
    heads: Marks,
    runs: Marks,
}

/// The first stored shape: one map, every entry kept 24 hours.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentV1 {
    version: u64,
    scopes: Marks,
}

impl Document {
    fn empty() -> Self {
        Self {
            version: PRIVATE_CONTENT_FORMAT.version,
            ..Self::default()
        }
    }

    fn marks(&self, retention: Retention) -> &Marks {
        match retention {
            Retention::Head => &self.heads,
            Retention::Run => &self.runs,
        }
    }

    fn marks_mut(&mut self, retention: Retention) -> &mut Marks {
        match retention {
            Retention::Head => &mut self.heads,
            Retention::Run => &mut self.runs,
        }
    }

    fn sources<'a>(&'a self, scope: &'a str) -> impl Iterator<Item = Source> + 'a {
        [&self.heads, &self.runs]
            .into_iter()
            .filter_map(move |marks| marks.get(scope))
            .flat_map(|marks| marks.keys().copied())
    }

    /// Adds every mark of `other`, keeping the later time of a shared mark.
    fn merge(&mut self, other: &Document) {
        for retention in [Retention::Head, Retention::Run] {
            for (scope, sources) in other.marks(retention) {
                let mine = self.marks_mut(retention).entry(scope.clone()).or_default();
                for (source, time) in sources {
                    let entry = mine.entry(*source).or_insert(*time);
                    *entry = (*entry).max(*time);
                }
            }
        }
    }
}

/// Reads the marks file. `Ok(None)` means there is no file yet.
fn load(path: &Path) -> io::Result<Option<Document>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid private-content marks");
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid());
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    let document = match value.get("version").and_then(Value::as_u64) {
        // Read as head marks, which never expire: version 1 did not record
        // whether a scope was a head, and a head's marks must not lapse.
        Some(1) => {
            let old: DocumentV1 = serde_json::from_value(value)?;
            debug_assert_eq!(old.version, 1);
            Document {
                heads: old.scopes,
                ..Document::empty()
            }
        }
        Some(2) => serde_json::from_value(value)?,
        _ => return Err(invalid()),
    };
    if document
        .heads
        .keys()
        .chain(document.runs.keys())
        .any(|scope| scope.is_empty())
    {
        return Err(invalid());
    }
    Ok(Some(document))
}

/// Written atomically, owner-only: a temporary file, synced, renamed over the
/// target, then the directory synced.
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let directory = path.parent().expect("private-content directory");
    let temporary = path.with_extension(format!(
        "{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> io::Result<()> {
        cerebellum_core::private_fs::create_dir_all(directory)?;
        let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        // Windows cannot open a directory for syncing; its replace is the
        // durability boundary, as it is for the format floor writer.
        #[cfg(unix)]
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(temporary);
    }
    written
}

/// The in-use marker. A successor that finds it answers every query as marked
/// until `fail_closed_until_ms`: this process may have delivered content whose
/// marks never reached the file. Any field this build does not understand, or
/// an unreadable marker, counts as 24 hours from when it was found, so the
/// marker needs no format floor.
#[derive(Serialize, Deserialize)]
struct Marker {
    started_ms: u64,
    fail_closed_until_ms: u64,
}

fn read_marker(path: &Path, now: u64) -> u64 {
    match fs::read(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(_) => now + RETENTION_MS,
        Ok(bytes) => match serde_json::from_slice::<Marker>(&bytes) {
            Ok(marker) => marker
                .fail_closed_until_ms
                .max(marker.started_ms.saturating_add(RETENTION_MS)),
            Err(_) => now + RETENTION_MS,
        },
    }
}

fn write_marker(path: &Path, started_ms: u64, fail_closed_until_ms: u64) -> io::Result<()> {
    let bytes = serde_json::to_vec(&Marker {
        started_ms,
        fail_closed_until_ms,
    })
    .expect("marker serializes");
    write_atomically(path, &bytes)
}

struct State {
    /// The newest marks, always updated before a reply leaves.
    document: Document,
    /// The marks as last read from or written to the file.
    persisted: Document,
    /// Failed or late writes so far. A write clears `write_failed` only if no
    /// other write failed after it began.
    failures: u64,
    /// A write failed or missed its deadline since the last successful write.
    write_failed: bool,
    /// The file exists but could not be read. Its marks are unknown, and
    /// head marks never expire, so it is never written over: every query
    /// answers marked until a retry reads it. Only an operator replaces it.
    load_failed: bool,
    /// This process's in-use marker could not be written.
    marker_missing: bool,
    /// Some mark made by this process may not be on disk, so a clean shutdown
    /// keeps the in-use marker.
    unpersisted: bool,
    /// A previous process left its in-use marker: answer everything marked
    /// until then.
    inherited_until_ms: u64,
    started_ms: u64,
}

impl State {
    fn new(started_ms: u64) -> Self {
        Self {
            document: Document::empty(),
            persisted: Document::empty(),
            failures: 0,
            write_failed: false,
            load_failed: false,
            marker_missing: false,
            unpersisted: false,
            inherited_until_ms: 0,
            started_ms,
        }
    }

    fn fails_closed(&self, now: u64) -> bool {
        self.write_failed
            || self.marker_missing
            || self.load_failed
            || now < self.inherited_until_ms
    }
}

pub(crate) struct PrivateContent {
    state: Mutex<State>,
    // Disk work never holds the memory lock: Broca must not wait for a platform
    // read, consent answer or filesystem write to decide where content may go.
    workers: crate::blocking_permits::PermitPool,
    path: Option<PathBuf>,
    floor: FormatFloor,
    write_deadline_ms: AtomicU64,
    #[cfg(test)]
    pub(crate) write_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl PrivateContent {
    pub(crate) fn in_memory() -> Self {
        Self {
            state: Mutex::new(State::new(crate::wall_clock_ms())),
            workers: crate::blocking_permits::PermitPool::new(1),
            path: None,
            floor: FormatFloor::isolated(),
            write_deadline_ms: AtomicU64::new(crate::budgets::PRIVATE_CONTENT_WRITE.cap_ms),
            #[cfg(test)]
            write_hook: Mutex::new(None),
        }
    }

    pub(crate) fn production() -> Self {
        match cerebellum_core::platform_dirs::data_home() {
            Some(home) => Self::open(
                cerebellum_core::format_floor::module_directory(&home)
                    .join("private-content")
                    .join(FILE_NAME),
            ),
            // Without a data home nothing survives a restart, and no marker
            // can tell the next start so: answer everything marked for good.
            None => {
                let store = Self::in_memory();
                store.state.lock().unwrap().marker_missing = true;
                store
            }
        }
    }

    /// Opens the store at startup, before the first route is served: loads
    /// the marks, honours a marker a previous process left, and writes this
    /// process's own marker.
    pub(crate) fn open(path: PathBuf) -> Self {
        Self::open_at(path, crate::wall_clock_ms())
    }

    pub(crate) fn open_at(path: PathBuf, now: u64) -> Self {
        let store = Self {
            path: Some(path.clone()),
            floor: FormatFloor::at(
                path.parent()
                    .expect("marks directory")
                    .join(cerebellum_core::format_floor::FORMAT_FLOOR_FILE),
            ),
            ..Self::in_memory()
        };
        let marker = path.with_file_name(MARKER_NAME);
        let inherited = read_marker(&marker, now);
        let marker_written = write_marker(&marker, now, now + RETENTION_MS).is_ok();
        {
            let mut state = store.state.lock().unwrap();
            *state = State::new(now);
            state.inherited_until_ms = inherited;
            state.marker_missing = !marker_written;
            match load(&path) {
                Ok(Some(document)) => {
                    state.persisted = document.clone();
                    state.document = document;
                }
                Ok(None) => {}
                Err(_) => state.load_failed = true,
            }
            prune(&mut state.document, now);
        }
        store
    }

    fn marker_path(&self) -> Option<PathBuf> {
        self.path
            .as_ref()
            .map(|path| path.with_file_name(MARKER_NAME))
    }

    pub(crate) fn health(&self) -> &'static str {
        let state = self.state.lock().unwrap();
        let now = crate::wall_clock_ms();
        if state.write_failed || state.marker_missing || state.load_failed {
            "unreadable"
        } else if now < state.inherited_until_ms {
            "unclean_shutdown"
        } else {
            "loaded"
        }
    }

    /// Called by the draining (SIGTERM) teardown after the last reply. Removes
    /// the in-use marker only when every mark this process made reached the
    /// file and no earlier unclean shutdown's window is still open; otherwise
    /// the next start keeps answering everything marked.
    pub(crate) fn shut_down_cleanly(&self) {
        self.shut_down_cleanly_at(crate::wall_clock_ms());
    }

    pub(crate) fn shut_down_cleanly_at(&self, now: u64) {
        let Some(marker) = self.marker_path() else {
            return;
        };
        let state = self.state.lock().unwrap();
        if state.unpersisted || state.fails_closed(now) {
            return;
        }
        let _ = fs::remove_file(&marker);
        #[cfg(unix)]
        if let Some(directory) = marker.parent() {
            let _ = File::open(directory).and_then(|directory| directory.sync_all());
        }
    }

    /// The scopes holding head marks and run marks, in that order.
    #[cfg(test)]
    pub(crate) fn state_for_test(&self) -> (Vec<String>, Vec<String>) {
        let state = self.state.lock().unwrap();
        (
            state.document.heads.keys().cloned().collect(),
            state.document.runs.keys().cloned().collect(),
        )
    }

    #[cfg(test)]
    pub(crate) fn write_idle(&self) -> bool {
        self.workers.available() == 1
    }

    /// A shared build server's disk can take longer than the production
    /// deadline to sync while it flushes build output. Tests of durability,
    /// rather than of the deadline, lengthen it so they cannot flake into the
    /// fail-closed path.
    #[cfg(test)]
    pub(crate) fn set_write_deadline(&self, deadline: Duration) {
        self.write_deadline_ms
            .store(deadline.as_millis() as u64, Ordering::Relaxed);
    }

    pub(crate) fn answer(&self, scopes: &[&str], now: u64) -> Value {
        let mut state = self.state.lock().unwrap();
        prune(&mut state.document, now);
        let sources: BTreeSet<_> = if state.fails_closed(now) {
            SOURCES.into_iter().collect()
        } else {
            scopes
                .iter()
                .flat_map(|scope| state.document.sources(scope))
                .collect()
        };
        json!({"private_content": !sources.is_empty(), "sources": sources})
    }

    /// Marks one scope directly. Replies mark through `mark_delivered`.
    #[cfg(test)]
    pub(crate) async fn mark(self: &Arc<Self>, scope: &str, retention: Retention, source: Source) {
        self.mark_at(scope, retention, source, crate::wall_clock_ms())
            .await;
    }

    #[cfg(test)]
    pub(crate) async fn mark_at(
        self: &Arc<Self>,
        scope: &str,
        retention: Retention,
        source: Source,
        now: u64,
    ) {
        self.mark_all(&[(scope.to_owned(), retention)], source, now)
            .await;
    }

    /// Records `source` for every target in memory, then waits a bounded time
    /// for the file to catch up when it must.
    async fn mark_all(self: &Arc<Self>, targets: &[(String, Retention)], source: Source, now: u64) {
        if let Some(failures) = self.record(targets, &[source], now) {
            self.write(failures, now).await;
        }
    }

    /// Records the marks in memory. Returns the failure count to write
    /// against when the file must be written, `None` when it need not be.
    fn record(&self, targets: &[(String, Retention)], sources: &[Source], now: u64) -> Option<u64> {
        let mut state = self.state.lock().unwrap();
        prune(&mut state.document, now);
        let mut needed = false;
        for (scope, retention) in targets {
            for source in sources {
                state
                    .document
                    .marks_mut(*retention)
                    .entry(scope.clone())
                    .or_default()
                    .insert(*source, now);
                // Memory always holds the newest timestamp, but the file is
                // rewritten only for a new (scope, source) pair or, for a run,
                // when the persisted timestamp is at least an hour old, so
                // repeated reads do not each wait on the disk. After a crash a
                // run's mark can therefore expire up to an hour early against
                // its 24-hour retention. Head marks never expire, so once on
                // disk they never need rewriting.
                let saved = state
                    .persisted
                    .marks(*retention)
                    .get(scope)
                    .and_then(|marks| marks.get(source));
                needed |= match (retention, saved) {
                    (_, None) => true,
                    (Retention::Head, Some(_)) => false,
                    (Retention::Run, Some(saved)) => now.saturating_sub(*saved) >= REFRESH_MS,
                };
            }
        }
        self.path.as_ref()?;
        let repairable = state.write_failed || state.marker_missing || state.load_failed;
        (needed || repairable).then_some(state.failures)
    }

    async fn write(self: &Arc<Self>, failures: u64, now: u64) {
        // One deadline covers waiting for the single writer permit and the
        // write itself, so a slow or hung disk delays a content reply by at
        // most this phase. Writes are serialized by the one-permit pool: each
        // snapshots the whole document, so a later write never loses an
        // earlier one's marks. A hung write keeps its permit until its thread
        // really ends; later marks wait out their deadline and fail closed
        // without starting more blocking jobs.
        let store = Arc::clone(self);
        let written = tokio::time::timeout(
            Duration::from_millis(self.write_deadline_ms.load(Ordering::Relaxed)),
            async move {
                let permit = store.workers.acquire().await;
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    #[cfg(test)]
                    {
                        let hook = store.write_hook.lock().unwrap().clone();
                        if let Some(hook) = hook {
                            hook();
                        }
                    }
                    let written = store.persist(failures);
                    if written.is_err() {
                        store.extend_marker(now);
                    }
                    written
                })
                .await
            },
        )
        .await;
        if !matches!(written, Ok(Ok(Ok(())))) {
            // The reply is sent anyway; the store instead answers every
            // query as marked until a later write succeeds, and keeps its
            // in-use marker so a restart does too.
            self.fail_closed();
        }
    }

    fn fail_closed(&self) {
        let mut state = self.state.lock().unwrap();
        state.failures += 1;
        state.write_failed = true;
        state.unpersisted = true;
    }

    /// After a failed write, a successor that finds this process's marker
    /// must fail closed for 24 hours from the failure, not only from this
    /// process's start. Best effort: the disk may be what failed.
    fn extend_marker(&self, now: u64) {
        let Some(marker) = self.marker_path() else {
            return;
        };
        let started = self.state.lock().unwrap().started_ms;
        let _ = write_marker(&marker, started, now + RETENTION_MS);
    }

    /// Writes the current document atomically. `failures` is the failure
    /// count seen when the mark that needed this write was recorded.
    fn persist(&self, failures: u64) -> io::Result<()> {
        let path = self.path.as_ref().expect("durable marks path");
        if self.state.lock().unwrap().load_failed {
            // The file's marks were never read. Read them now, or leave the
            // file alone: writing this process's marks over it would erase
            // every scope it recorded.
            let loaded = load(path)?;
            let mut state = self.state.lock().unwrap();
            if let Some(loaded) = loaded {
                state.document.merge(&loaded);
                state.persisted = loaded;
            }
            state.load_failed = false;
        }
        let marker_missing = self.state.lock().unwrap().marker_missing;
        if marker_missing {
            let marker = self.marker_path().expect("durable marker path");
            let started = self.state.lock().unwrap().started_ms;
            write_marker(&marker, started, started + RETENTION_MS)?;
            self.state.lock().unwrap().marker_missing = false;
        }
        let document = self.state.lock().unwrap().document.clone();
        let bytes = serde_json::to_vec(&document).expect("marks serialize");
        if bytes.len() as u64 > MAX_BYTES {
            return Err(io::Error::other("private-content marks exceed size limit"));
        }
        self.floor
            .raise(PRIVATE_CONTENT_FORMAT)
            .map_err(io::Error::other)?;
        write_atomically(path, &bytes)?;
        // Recorded while still holding the writer permit, so the persisted
        // copy always matches the newest file on disk.
        let mut state = self.state.lock().unwrap();
        state.persisted = document;
        // If another mark's write failed or timed out after this mark read the
        // failure count, this write does not clear the failed state; the next
        // write, which reads the updated count, can.
        if state.failures == failures {
            state.write_failed = false;
        }
        Ok(())
    }
}

/// Run marks lapse 24 hours after their latest read; head marks never do.
fn prune(document: &mut Document, now: u64) {
    document.runs.retain(|_, sources| {
        sources.retain(|_, timestamp| now.saturating_sub(*timestamp) < RETENTION_MS);
        !sources.is_empty()
    });
}

/// Inspect the returned payload, not the requested action or its outcome: an
/// input refusal can still return the application's changed state.
fn carries_content(reply: &Value) -> bool {
    let text = reply.get("state_text").and_then(Value::as_str);
    text.is_some_and(|text| !text.is_empty())
        || reply
            .pointer("/image/data_b64")
            .and_then(Value::as_str)
            .is_some_and(|image| !image.is_empty())
        || reply
            .pointer("/detail/hit_name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
        || reply.get("read_page").is_some_and(carries_content)
}

/// The computer_use refusals that stay unmarked, each with the only top-level
/// fields and `detail` fields it may carry. Each is built from fixed strings,
/// the caller's own argument names and internal step names, never from what
/// the desktop reports:
/// - `invalid_request` {field, reason}: `computer_capability/mod.rs`
///   `invalid_read_state_request`, `element_actions.rs` and `takeover.rs`
///   `invalid`; `field` is the caller's argument name, `reason` a fixed code.
/// - `screen_locked`: `mod.rs` `screen_locked_reply`, fixed text.
/// - `audit_unavailable` {remedy}: `mod.rs` `read_audit_unavailable_reply` and
///   the list_apps refusal, `open_app.rs` after a launch; fixed text.
/// - `permission_missing`: `permissions.rs` `refusal`; the permission and its
///   state are fixed vocabulary, the remedy names a System Settings pane.
/// - `blocking_capacity_exhausted`: `quarantine.rs` `capacity_exhausted_reply`;
///   step and call are internal names.
/// - `cancelled` with no other field: `mod.rs`, a call stopped before work.
///
/// The same outcome with any other field marks: other builders of these
/// outcomes add fields (for example an app's name in a consent refusal).
const DESKTOP_REFUSALS_WITHOUT_APP_TEXT: &[(&str, &[&str], &[&str])] = &[
    ("invalid_request", &["field", "reason"], &[]),
    ("screen_locked", &["reason", "remedy"], &[]),
    ("audit_unavailable", &["remedy"], &[]),
    (
        "permission_missing",
        &["detail", "remedy"],
        &["permission", "state"],
    ),
    (
        "blocking_capacity_exhausted",
        &["detail", "remedy"],
        &["dispatched", "step", "call"],
    ),
    ("cancelled", &[], &[]),
];

fn desktop_reply_is_content_free(reply: &Value) -> bool {
    let Some(fields) = reply.as_object() else {
        return false;
    };
    let Some(outcome) = reply.get("outcome").and_then(Value::as_str) else {
        return false;
    };
    let Some((_, allowed, detail_allowed)) = DESKTOP_REFUSALS_WITHOUT_APP_TEXT
        .iter()
        .find(|(refusal, _, _)| *refusal == outcome)
    else {
        return false;
    };
    let detail_free = match reply.get("detail") {
        None => true,
        Some(Value::Object(detail)) => detail.iter().all(|(field, value)| {
            detail_allowed.contains(&field.as_str()) && !value.is_object() && !value.is_array()
        }),
        Some(_) => false,
    };
    detail_free
        && fields.iter().all(|(field, value)| {
            field == "outcome"
                || (allowed.contains(&field.as_str())
                    && (field == "detail" || !value.is_object() && !value.is_array()))
        })
}

pub(crate) enum ReplyPlane {
    PersonBrowser,
    // Linux does not enable desktop-app access in production, but tests still
    // exercise the desktop-app reply path.
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "windows", test)),
        allow(dead_code)
    )]
    DesktopApp,
    /// The agent's own browser, answering the call that read the page: the
    /// calling route's profile is the one that was read.
    OwnBrowser,
    /// A retained own-browser reply replayed by call key. Retained replies are
    /// found by principal and call key alone, so the receiving route's profile
    /// may not be the one that read the page; it always counts as a signed-in
    /// site.
    OwnBrowserReplay,
}

pub(crate) fn replay_plane(reply: &Value) -> ReplyPlane {
    let reply = reply.get("result").unwrap_or(reply);
    let reply = reply.get("structuredContent").unwrap_or(reply);
    if reply["browser"] == "user" {
        ReplyPlane::PersonBrowser
    } else if reply.get("context").is_some() {
        ReplyPlane::OwnBrowserReplay
    } else {
        ReplyPlane::DesktopApp
    }
}

pub(crate) async fn send_reply(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    plane: ReplyPlane,
    writer: &tokio::sync::mpsc::Sender<Frame>,
    address: (u8, u16, u32, u64),
    reply: Value,
) -> Result<(), ModuleError> {
    let (ver, channel, epoch, corr) = address;
    let response = crate::tool_response_frame(ver, channel, epoch, corr, reply)?;
    let delivered: Value = serde_json::from_slice(&response.body).map_err(ModuleError::Json)?;
    mark_delivered(planes, facts, plane, &delivered).await;
    crate::send(writer, response).await
}

/// Codemode runs and flows keep their marks 24 hours; heads and other agent
/// scopes keep theirs for life. An unstamped route counts as a head.
fn retention(stamp: &subc_protocol::scope::ScopeStamp) -> Retention {
    if stamp.attributes.run_id.is_some()
        || stamp.attributes.flow_id.is_some()
        || stamp.kind == subc_protocol::scope::ScopeKind::Ephemeral
    {
        Retention::Run
    } else {
        Retention::Head
    }
}

/// The scope a screenshot capture on `facts` belongs to, or `None` when the
/// route carries no scope stamp.
///
/// A capture made under a scope is resolvable by that scope's union, and by
/// nothing else; a route without a stamp names no scope, so its captures get
/// no handle: one minted there could never be resolved.
pub(crate) fn capture_scope(facts: &AcceptedBindFacts) -> Option<String> {
    facts.scope.as_ref().map(|stamp| stamp.scope_ref.clone())
}

/// The scopes a reply delivered to `facts` marks: the calling scope, and the
/// parent it names. A run's or flow's output returns to the agent that started
/// it, so that agent's scope holds the content too, and its other runs inherit
/// the mark through it. The parent named by the stamp is marked whatever its
/// link state: marking a scope that did not receive the content only costs a
/// consent card, while missing the real head would leak.
fn mark_targets(facts: &AcceptedBindFacts) -> Vec<(String, Retention)> {
    let Some(stamp) = facts.scope.as_ref() else {
        return vec![(facts.identity.conversation_key.clone(), Retention::Head)];
    };
    let mut targets = vec![(stamp.scope_ref.clone(), retention(stamp))];
    if let Some(parent) = &stamp.parent {
        if parent.scope_ref != stamp.scope_ref {
            targets.push((parent.scope_ref.clone(), Retention::Head));
        }
    }
    targets
}

pub(crate) async fn mark_delivered(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    plane: ReplyPlane,
    delivered: &Value,
) {
    let delivered = delivered.get("result").unwrap_or(delivered);
    let reply = delivered.get("structuredContent").unwrap_or(delivered);
    let content = carries_content(reply)
        || delivered
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(|parts| {
                parts.iter().any(|part| {
                    part["type"] == "image"
                        && part["data"].as_str().is_some_and(|data| !data.is_empty())
                })
            });
    let source = match plane {
        ReplyPlane::PersonBrowser => content.then_some(Source::PersonBrowser),
        // The production computer plane delivers replies that violate their
        // schema unchanged, and app text appears in many fields (app lists,
        // matched apps, candidates), so every desktop reply marks unless it is
        // a refusal known to carry none.
        ReplyPlane::DesktopApp => {
            (content || !desktop_reply_is_content_free(reply)).then_some(Source::DesktopApp)
        }
        ReplyPlane::OwnBrowser => {
            let profile = crate::browser_signed_in::SignedInDomains::profile_name(&facts.identity);
            (content
                && planes
                    .signed_in
                    .has_login_evidence(&facts.identity.agent_project_id, &profile))
            .then_some(Source::SignedInSite)
        }
        ReplyPlane::OwnBrowserReplay => content.then_some(Source::SignedInSite),
    };
    if let Some(source) = source {
        planes
            .private_content
            .mark_all(&mark_targets(facts), source, crate::wall_clock_ms())
            .await;
    }
}

impl PrivateContent {
    /// Copies a run's marks to the parent Broca names for it, so the parent
    /// and its other runs answer marked too. The answer never waits for the
    /// copy to reach the file.
    fn propagate(self: &Arc<Self>, scope: &str, parent: &str, now: u64) {
        let sources: Vec<Source> = {
            let mut state = self.state.lock().unwrap();
            prune(&mut state.document, now);
            let mine: BTreeSet<_> = state.document.sources(scope).collect();
            mine.into_iter().collect()
        };
        if sources.is_empty() || scope == parent {
            return;
        }
        if let Some(failures) = self.record(&[(parent.to_owned(), Retention::Head)], &sources, now)
        {
            let store = Arc::clone(self);
            tokio::spawn(async move { store.write(failures, now).await });
        }
    }
}

pub(crate) fn is_broca(principal: &Option<subc_protocol::Principal>) -> bool {
    matches!(principal, Some(subc_protocol::Principal::Reserved { module_id }) if module_id == "broca")
}

pub(crate) fn bind_admitted(
    principal: &Option<subc_protocol::Principal>,
    target: &subc_protocol::RouteTarget,
) -> bool {
    is_broca(principal)
        && matches!(target, subc_protocol::RouteTarget::ManagementSurface { module_id } if module_id == "cerebellum")
}

pub(crate) async fn handle(
    frame: &Frame,
    writer: &tokio::sync::mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    request: &serde_json::Map<String, Value>,
) -> Result<(), ModuleError> {
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    if !is_broca(&facts.principal) {
        return crate::send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            "private-content queries need reserved:broca",
        )
        .await;
    }
    let parsed = (|| {
        let params = request
            .get("params")
            .and_then(Value::as_object)
            .ok_or(("params", "wrong_type"))?;
        if let Some(field) = params
            .keys()
            .find(|field| !matches!(field.as_str(), "scope_ref" | "parent_scope_ref"))
        {
            return Err((field.as_str(), "unknown_field"));
        }
        let scope = match params.get("scope_ref") {
            Some(Value::String(scope)) if !scope.is_empty() => scope.as_str(),
            Some(Value::String(_)) => return Err(("scope_ref", "empty_value")),
            Some(_) => return Err(("scope_ref", "wrong_type")),
            None => return Err(("scope_ref", "missing_field")),
        };
        let parent = match params.get("parent_scope_ref") {
            Some(Value::String(scope)) if !scope.is_empty() => Some(scope.as_str()),
            Some(Value::String(_)) => return Err(("parent_scope_ref", "empty_value")),
            Some(_) => return Err(("parent_scope_ref", "wrong_type")),
            None => None,
        };
        Ok((scope, parent))
    })();
    let (scope, parent) = match parsed {
        Ok(parsed) => parsed,
        Err((field, reason)) => {
            return crate::send_invalid_request_response(
                writer, ver, channel, epoch, corr, field, reason,
            )
            .await
        }
    };
    let scopes = scope_union(planes, scope, parent);
    let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let reply = planes
        .private_content
        .answer(&scopes, crate::wall_clock_ms());
    crate::send_tool_response(writer, ver, channel, epoch, corr, reply).await
}

/// The scopes a query for `scope` covers.
///
/// Both Broca operations answer from this one union: `private_content.query`
/// asks whether any of these scopes read private content, and `image.resolve`
/// lets a handle captured under any of them be fetched. Keeping it in one
/// place means a handle's reach and a mark's reach cannot drift apart.
///
/// The union is the requested scope; for every route bound with that scope ref
/// whose linked head still resolves, that head's scope; and the parent Broca
/// names, for a run that never opened a cerebellum route (for example, source
/// pasted after a head's read). A run's marks are copied to that named parent
/// on the way, so its other runs inherit them.
pub(crate) fn scope_union(planes: &Planes, scope: &str, parent: Option<&str>) -> Vec<String> {
    let now = crate::wall_clock_ms();
    let runs: Vec<_> = planes
        .routes
        .inner
        .read()
        .unwrap()
        .values()
        .filter_map(|facts| facts.scope.as_ref())
        .filter(|stamp| stamp.scope_ref == scope)
        .cloned()
        .collect();
    let mut scopes: Vec<String> = vec![scope.to_owned()];
    for run in &runs {
        if let Some(head) = planes
            .routes
            .run_head(run)
            .ok()
            .and_then(|head| head.scope.map(|stamp| stamp.scope_ref))
        {
            scopes.push(head);
        }
        if let Some(parent) = &run.parent {
            scopes.push(parent.scope_ref.clone());
        }
    }
    if let Some(parent) = parent {
        planes.private_content.propagate(scope, parent, now);
        scopes.push(parent.to_owned());
    }
    scopes
}
