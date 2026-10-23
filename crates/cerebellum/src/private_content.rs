//! Scope-level provenance for model-provider consent. This store records no content.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_core::format_floor::{DurableFormat, FormatFloor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{AcceptedBindFacts, Frame, ModuleError, Planes};

pub(crate) const QUERY: &str = "private_content.query";
pub(crate) const CAPABILITY: &str = "private-content-marks/v1";
pub const PRIVATE_CONTENT_FORMAT: DurableFormat = DurableFormat::new("private-content-marks", 1);
const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const REFRESH_MS: u64 = 60 * 60 * 1000;
const FILE_NAME: &str = "private-content-marks.json";
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

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u64,
    scopes: BTreeMap<String, BTreeMap<Source, u64>>,
}

struct State {
    document: Document,
    persisted: Document,
    failures: u64,
}

pub(crate) struct PrivateContent {
    state: Mutex<State>,
    unreadable: AtomicBool,
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
            state: Mutex::new(State {
                document: Document {
                    version: PRIVATE_CONTENT_FORMAT.version,
                    ..Document::default()
                },
                persisted: Document::default(),
                failures: 0,
            }),
            unreadable: AtomicBool::new(false),
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
            None => {
                let store = Self::in_memory();
                store.unreadable.store(true, Ordering::Release);
                store
            }
        }
    }

    pub(crate) fn open(path: PathBuf) -> Self {
        let loaded = (|| -> io::Result<Document> {
            let file = match File::open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Document {
                        version: PRIVATE_CONTENT_FORMAT.version,
                        ..Document::default()
                    })
                }
                Err(error) => return Err(error),
            };
            let mut bytes = Vec::new();
            file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
            let document: Document = serde_json::from_slice(&bytes)?;
            if bytes.len() as u64 > MAX_BYTES
                || document.version != PRIVATE_CONTENT_FORMAT.version
                || document.scopes.keys().any(|scope| scope.is_empty())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid private-content marks",
                ));
            }
            Ok(document)
        })();
        let store = Self {
            path: Some(path.clone()),
            floor: FormatFloor::at(
                path.parent()
                    .expect("marks directory")
                    .join(cerebellum_core::format_floor::FORMAT_FLOOR_FILE),
            ),
            ..Self::in_memory()
        };
        {
            let mut state = store.state.lock().unwrap();
            match loaded {
                Ok(document) => state.document = document,
                Err(_) => store.unreadable.store(true, Ordering::Release),
            }
            prune(&mut state.document, crate::wall_clock_ms());
            state.persisted = state.document.clone();
        }
        store
    }

    pub(crate) fn health(&self) -> &'static str {
        if self.unreadable.load(Ordering::Acquire) {
            "unreadable"
        } else {
            "loaded"
        }
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

    fn answer(&self, scope: &str, heads: &[String], now: u64) -> Value {
        let mut state = self.state.lock().unwrap();
        prune(&mut state.document, now);
        let sources: BTreeSet<_> = if self.unreadable.load(Ordering::Acquire) {
            SOURCES.into_iter().collect()
        } else {
            std::iter::once(scope)
                .chain(heads.iter().map(String::as_str))
                .filter_map(|scope| state.document.scopes.get(scope))
                .flat_map(|marks| marks.keys().copied())
                .collect()
        };
        json!({"private_content": !sources.is_empty(), "sources": sources})
    }

    pub(crate) async fn mark(self: &Arc<Self>, scope: &str, source: Source) {
        self.mark_at(scope, source, crate::wall_clock_ms()).await;
    }

    pub(crate) async fn mark_at(self: &Arc<Self>, scope: &str, source: Source, now: u64) {
        let failures = {
            let mut state = self.state.lock().unwrap();
            prune(&mut state.document, now);
            state
                .document
                .scopes
                .entry(scope.to_owned())
                .or_default()
                .insert(source, now);
            // Memory always holds the newest timestamp, but the file is
            // rewritten only for a new (scope, source) pair or when the
            // persisted timestamp is at least an hour old, so repeated reads
            // do not each wait on the disk. After a crash a mark can therefore
            // expire up to an hour early against its 24-hour retention.
            let fresh = state
                .persisted
                .scopes
                .get(scope)
                .and_then(|marks| marks.get(&source))
                .is_some_and(|saved| now.saturating_sub(*saved) < REFRESH_MS);
            if self.path.is_none() || (fresh && !self.unreadable.load(Ordering::Acquire)) {
                return;
            }
            state.failures
        };
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
                    store.persist(failures)
                })
                .await
            },
        )
        .await;
        if !matches!(written, Ok(Ok(Ok(())))) {
            // The reply is sent anyway; the store instead answers every
            // query as marked until a later write succeeds.
            self.fail_closed();
        }
    }

    fn fail_closed(&self) {
        let mut state = self.state.lock().unwrap();
        state.failures += 1;
        self.unreadable.store(true, Ordering::Release);
    }

    /// Writes the current document atomically. `failures` is the failure
    /// count seen when the mark that needed this write was recorded.
    fn persist(&self, failures: u64) -> io::Result<()> {
        let document = self.state.lock().unwrap().document.clone();
        let bytes = serde_json::to_vec(&document).expect("marks serialize");
        let path = self.path.as_ref().expect("durable marks path");
        let directory = path.parent().expect("marks directory");
        let temporary = path.with_extension(format!(
            "{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let written = (|| -> io::Result<()> {
            if bytes.len() as u64 > MAX_BYTES {
                return Err(io::Error::other("private-content marks exceed size limit"));
            }
            self.floor
                .raise(PRIVATE_CONTENT_FORMAT)
                .map_err(io::Error::other)?;
            cerebellum_core::private_fs::create_dir_all(directory)?;
            let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
            file.write_all(&bytes)?;
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
            return written;
        }
        // Recorded while still holding the writer permit, so the persisted
        // copy always matches the newest file on disk.
        let mut state = self.state.lock().unwrap();
        state.persisted = document;
        // If another mark's write failed or timed out after this mark read the
        // failure count, this write does not clear the unreadable state; the
        // next write, which reads the updated count, can.
        if state.failures == failures {
            self.unreadable.store(false, Ordering::Release);
        }
        Ok(())
    }
}

fn prune(document: &mut Document, now: u64) {
    document.scopes.retain(|_, sources| {
        sources.retain(|_, timestamp| now.saturating_sub(*timestamp) < RETENTION_MS);
        !sources.is_empty()
    });
}

/// Inspect the returned payload, not the requested action or its outcome: an
/// input refusal can still return the application's changed state.
fn carries_content(reply: &Value) -> bool {
    let text = reply.get("state_text").and_then(Value::as_str);
    text.is_some_and(|text| !text.is_empty() && text != crate::computer_capability::DIFF_UNREADABLE)
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

pub(crate) enum ReplyPlane {
    PersonBrowser,
    // Linux does not enable desktop-app access in production, but tests still
    // exercise the desktop-app reply path.
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "windows", test)),
        allow(dead_code)
    )]
    DesktopApp,
    OwnBrowser,
}

pub(crate) fn replay_plane(reply: &Value) -> ReplyPlane {
    let reply = reply.get("result").unwrap_or(reply);
    let reply = reply.get("structuredContent").unwrap_or(reply);
    if reply["browser"] == "user" {
        ReplyPlane::PersonBrowser
    } else if reply.get("context").is_some() {
        ReplyPlane::OwnBrowser
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

pub(crate) async fn mark_delivered(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    plane: ReplyPlane,
    delivered: &Value,
) {
    let delivered = delivered.get("result").unwrap_or(delivered);
    let reply = delivered.get("structuredContent").unwrap_or(delivered);
    if carries_content(reply)
        || delivered
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(|parts| {
                parts.iter().any(|part| {
                    part["type"] == "image"
                        && part["data"].as_str().is_some_and(|data| !data.is_empty())
                })
            })
    {
        let source = match plane {
            ReplyPlane::PersonBrowser => Some(Source::PersonBrowser),
            ReplyPlane::DesktopApp => Some(Source::DesktopApp),
            ReplyPlane::OwnBrowser => {
                let profile =
                    crate::browser_signed_in::SignedInDomains::profile_name(&facts.identity);
                planes
                    .signed_in
                    .has_login_evidence(&facts.identity.agent_project_id, &profile)
                    .then_some(Source::SignedInSite)
            }
        };
        if let Some(source) = source {
            let scope = facts
                .scope
                .as_ref()
                .map(|stamp| stamp.scope_ref.as_str())
                .unwrap_or(&facts.identity.conversation_key);
            planes.private_content.mark(scope, source).await;
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
    let mut heads: Vec<_> = runs
        .iter()
        .filter_map(|run| planes.routes.run_head(run).ok())
        .filter_map(|head| head.scope.map(|stamp| stamp.scope_ref))
        .collect();
    // Broca knows the linked parent even when the run never opened a
    // Cerebellum route (for example, source pasted after a head's read).
    if let Some(parent) = parent {
        heads.push(parent.to_owned());
    }
    let reply = planes
        .private_content
        .answer(scope, &heads, crate::wall_clock_ms());
    crate::send_tool_response(writer, ver, channel, epoch, corr, reply).await
}
