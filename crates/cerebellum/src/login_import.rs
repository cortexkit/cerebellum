//! Encrypted Chromium-cookie transfer for `browser.import_login`.
//!
//! Cookie values never leave SQLite. Presence queries read only `host_key` and
//! `has_expires`; transfer prunes a byte-for-byte copy and lets SQLite move the
//! surviving rows between stores owned by the same browser binary.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::cingulate_client::desk::Ending;
use crate::profile_custody::{
    ProfileCustodyAcquisition, ProfileCustodyKey, ProfileCustodyLocks, ProfileCustodyRelease,
};

const COOKIES_RELATIVE_PATH: &str = "Default/Cookies";
const SQLITE_PROGRAM: &str = "/usr/bin/sqlite3";
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);

/// The registry-owned durable profile and the root that coordinates its custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableProfileLocation {
    pub managed_root: PathBuf,
    pub profile_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSource {
    pub id: &'static str,
    pub display_name: &'static str,
    pub data_directory: PathBuf,
    pub executable: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ImportSettings {
    pub sqlite_program: PathBuf,
    pub transfer_timeout: Duration,
    pub application_support: PathBuf,
    pub safari_store: PathBuf,
    pub browsers: Vec<BrowserSource>,
}

impl ImportSettings {
    pub fn production(home: &Path) -> Self {
        let application_support = home.join("Library/Application Support");
        Self {
            sqlite_program: PathBuf::from(SQLITE_PROGRAM),
            transfer_timeout: TRANSFER_TIMEOUT,
            safari_store: home.join("Library/Cookies/Cookies.binarycookies"),
            application_support,
            browsers: vec![
                BrowserSource {
                    id: "chrome",
                    display_name: "Google Chrome",
                    data_directory: PathBuf::from("Google/Chrome"),
                    executable: PathBuf::from(
                        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    ),
                },
                BrowserSource {
                    id: "chrome_canary",
                    display_name: "Chrome Canary",
                    data_directory: PathBuf::from("Google/Chrome Canary"),
                    executable: PathBuf::from(
                        "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
                    ),
                },
                BrowserSource {
                    id: "brave",
                    display_name: "Brave",
                    data_directory: PathBuf::from("BraveSoftware/Brave-Browser"),
                    executable: PathBuf::from(
                        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                    ),
                },
                BrowserSource {
                    id: "edge",
                    display_name: "Microsoft Edge",
                    data_directory: PathBuf::from("Microsoft Edge"),
                    executable: PathBuf::from(
                        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                    ),
                },
                BrowserSource {
                    id: "chromium",
                    display_name: "Chromium",
                    data_directory: PathBuf::from("Chromium"),
                    executable: PathBuf::from(
                        "/Applications/Chromium.app/Contents/MacOS/Chromium",
                    ),
                },
                BrowserSource {
                    id: "arc",
                    display_name: "Arc",
                    data_directory: PathBuf::from("Arc/User Data"),
                    executable: PathBuf::from("/Applications/Arc.app/Contents/MacOS/Arc"),
                },
            ],
        }
    }

    #[doc(hidden)]
    pub fn for_test(
        sqlite_program: PathBuf,
        application_support: PathBuf,
        safari_store: PathBuf,
        browsers: Vec<BrowserSource>,
    ) -> Self {
        Self {
            sqlite_program,
            transfer_timeout: TRANSFER_TIMEOUT,
            application_support,
            safari_store,
            browsers,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserPresence {
    pub browser: String,
    pub name: String,
    pub persistent_rows: u64,
    pub session_rows: u64,
    pub transfer: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub origin: String,
    pub outcome: String,
    pub browser: Option<String>,
    pub domains_matched: Vec<String>,
    pub rows: u64,
    pub browsers: Vec<BrowserPresence>,
    pub remedy: Option<&'static str>,
    /// Only on `consent_pending`: the consent card still open.
    pub ask_id: Option<String>,
    pub reason: Option<&'static str>,
    pub busy_detail: Option<cortexkit_resource_busy::ResourceBusy>,
}

impl ImportResult {
    pub fn to_value(&self) -> Value {
        let mut value = json!({
            "outcome": self.outcome,
            "domains_matched": self.domains_matched,
        });
        let object = value.as_object_mut().expect("result is an object");
        if let Some(browser) = &self.browser {
            object.insert("browser".to_string(), Value::String(browser.clone()));
        }
        if self.outcome == "transferred" {
            object.insert("rows".to_string(), Value::from(self.rows));
        }
        if let Some(remedy) = self.remedy {
            object.insert("remedy".to_string(), Value::String(remedy.to_string()));
        }
        if let Some(ask_id) = &self.ask_id {
            object.insert("ask_id".to_string(), Value::String(ask_id.clone()));
        }
        if let Some(detail) = &self.busy_detail {
            detail
                .validate()
                .expect("browser profile refusal must be valid");
            object.insert(
                "detail".to_string(),
                serde_json::to_value(detail).expect("serialize resource busy"),
            );
        }
        if let Some(reason) = self.reason {
            object.insert("reason".to_string(), Value::String(reason.to_string()));
        }
        value
    }

    pub fn refusal(origin: &str, code: &'static str, remedy: &'static str) -> Self {
        Self {
            origin: origin.to_string(),
            outcome: code.to_string(),
            browser: None,
            domains_matched: Vec::new(),
            rows: 0,
            browsers: Vec::new(),
            remedy: Some(remedy),
            ask_id: None,
            reason: None,
            busy_detail: None,
        }
    }
}

pub fn reply_schema(launch_refusal: Value) -> Value {
    json!({
        "type":"object",
        "properties":{
            "outcome":{"type":"string","enum":["transferred","consent_pending","cancelled","denied","hand_off","no_answer","not_put_to_anyone","undeliverable","profile_not_durable","session_open","consent_unavailable","unrecognized_answer","question_withdrawn","launch_binary_unsupported","profile_busy","resource_busy","transfer_failed","invalid_origin","internal_failure"]},
            "domains_matched":{"type":"array","items":{"type":"string"}},
            "browser":{"type":"string"},
            "rows":{"type":"integer"},
            "remedy":{"type":"string"},
            "ask_id":{"type":"string"},
            "reason":{"type":"string"},
            "relaunched":{
                "type":["object","null"],"properties":{
                    "browser_session_id":{"type":"string"},
                    "restored_url":{"type":["string","null"]}
                },"required":["browser_session_id","restored_url"],"additionalProperties":false
            },
            "detail":{"anyOf":[launch_refusal,crate::browser::resource_busy_detail_schema(),{"type":"object","properties":{"reason":{"type":"string"},"remedy":{"type":"string"}},"required":["reason","remedy"],"additionalProperties":false}]}
        },
        "required":["outcome"],"additionalProperties":false
    })
}

pub enum PreparedImport {
    Ready(LoginImportPlan),
    Refused(ImportResult),
}

pub trait ProfileWriteObserver: Send + Sync {
    fn before_profile_write(&self, pruned_store: &Path) -> io::Result<()>;
}

impl<F> ProfileWriteObserver for F
where
    F: Fn(&Path) -> io::Result<()> + Send + Sync,
{
    fn before_profile_write(&self, pruned_store: &Path) -> io::Result<()> {
        self(pruned_store)
    }
}

#[derive(Default)]
struct NoopProfileWriteObserver;

impl ProfileWriteObserver for NoopProfileWriteObserver {
    fn before_profile_write(&self, _pruned_store: &Path) -> io::Result<()> {
        Ok(())
    }
}

pub struct LoginImportPlan {
    origin: String,
    host: String,
    domains: Vec<String>,
    project_id: String,
    /// The browser the login is copied into.
    launch_executable: PathBuf,
    location: DurableProfileLocation,
    settings: ImportSettings,
    presence: Vec<BrowserPresence>,
    observer: Arc<dyn ProfileWriteObserver>,
}

impl LoginImportPlan {
    pub fn presence(&self) -> &[BrowserPresence] {
        &self.presence
    }

    pub fn domains_matched(&self) -> &[String] {
        &self.domains
    }

    pub fn question(&self, _agent: &str) -> Value {
        import_question(&self.origin, &self.host, &self.presence)
    }

    pub fn refusal(&self, code: &'static str, remedy: &'static str) -> ImportResult {
        self.result(code, None, 0, Some(remedy))
    }

    /// What the consent answer is about, in one string compared exactly: the
    /// origin, and the browser the login is copied into. A consent answer
    /// that arrives after its call returned is used only by a retry that
    /// matches it. The browser copied from is the person's choice inside the
    /// answer, and is checked again against what is copyable at the retry.
    pub fn consent_parameters(&self) -> String {
        json!([self.origin, self.launch_executable.display().to_string()]).to_string()
    }

    /// The reply when the person has not answered within the call's wait:
    /// nothing was copied, and the card `ask_id` stays open.
    pub fn pending(&self, ask_id: String) -> ImportResult {
        let mut result = self.result(
            "consent_pending",
            None,
            0,
            Some(crate::computer_grants::LOGIN_CONSENT_PENDING_REMEDY),
        );
        result.ask_id = Some(ask_id);
        result
    }

    pub fn permits_transfer(&self, decision: Option<&str>) -> bool {
        decision
            .and_then(|value| value.strip_prefix("transfer:"))
            .is_some_and(|id| {
                self.presence
                    .iter()
                    .any(|browser| browser.browser == id && browser.transfer == "available")
            })
    }

    /// The result for however the consent card ended.
    ///
    /// Only an answer is read as a decision. The other endings are reported
    /// as themselves rather than as `denied`: a refusal tells the caller not
    /// to ask again, which is wrong for a person who was asked and stayed
    /// silent, and wrong in the other direction for a card nobody was shown,
    /// where asking again reaches nobody again. A choice the card did not
    /// offer is not read as a refusal either.
    pub fn conclude(self, ending: &Ending) -> ImportResult {
        let word = match ending {
            Ending::Granted { choice_id } => return self.decide(Some(choice_id)),
            Ending::Declined { choice_id } if choice_id == IMPORT_DECLINE => {
                return self.decide(Some(choice_id))
            }
            Ending::Declined { .. } => "unrecognized_answer",
            Ending::NoAnswer => "no_answer",
            Ending::NotPutToAnyone => "not_put_to_anyone",
            Ending::DeliveryFailed => "undeliverable",
            Ending::Withdrawn => "question_withdrawn",
            Ending::NoCard(why) => {
                let mut result = self.result("consent_unavailable", None, 0, why.remedy());
                result.reason = why.reason();
                return result;
            }
        };
        self.result(word, None, 0, Some(unanswered_remedy(word)))
    }

    /// Cancellation is not a person's denial and must not suggest another ask.
    pub fn cancelled(self) -> ImportResult {
        self.result("cancelled", None, 0, None)
    }

    pub fn decide(self, decision: Option<&str>) -> ImportResult {
        match decision {
            Some("hand_off") => self.result("hand_off", None, 0, None),
            Some("deny") | None => self.result("denied", None, 0, None),
            Some(value) => {
                let Some(browser_id) = value.strip_prefix("transfer:") else {
                    return self.result("denied", None, 0, None);
                };
                if !self
                    .presence
                    .iter()
                    .any(|browser| browser.browser == browser_id && browser.transfer == "available")
                {
                    return self.result("denied", None, 0, None);
                }
                match self.transfer(browser_id) {
                    Ok(rows) => {
                        self.result("transferred", Some(browser_id.to_string()), rows, None)
                    }
                    Err(TransferError::ResourceBusy(detail)) => {
                        let mut result =
                            self.result("resource_busy", Some(browser_id.to_string()), 0, None);
                        result.busy_detail = Some(detail);
                        result
                    }
                    Err(TransferError::ProfileBusy) => self.result(
                        "profile_busy",
                        Some(browser_id.to_string()),
                        0,
                        Some("close every browser session using this durable profile, then retry"),
                    ),
                    Err(TransferError::TimedOut) => {
                        let mut result = self.result("transfer_failed", Some(browser_id.to_string()), 0, Some("cookie transfer timed out; retry once the local SQLite service responds"));
                        result.reason = Some("transfer_timed_out");
                        result
                    }
                    Err(TransferError::Failed) => self.result(
                        "transfer_failed",
                        Some(browser_id.to_string()),
                        0,
                        Some("use hand_off so the person can log in through browser.present"),
                    ),
                }
            }
        }
    }

    #[doc(hidden)]
    pub fn with_profile_write_observer_for_test(
        mut self,
        observer: Arc<dyn ProfileWriteObserver>,
    ) -> Self {
        self.observer = observer;
        self
    }

    fn result(
        &self,
        outcome: &str,
        browser: Option<String>,
        rows: u64,
        remedy: Option<&'static str>,
    ) -> ImportResult {
        ImportResult {
            origin: self.origin.clone(),
            outcome: outcome.to_string(),
            browser,
            domains_matched: self.domains.clone(),
            rows,
            browsers: self.presence.clone(),
            remedy,
            ask_id: None,
            reason: None,
            busy_detail: None,
        }
    }

    fn transfer(&self, browser_id: &str) -> Result<u64, TransferError> {
        let source = self
            .settings
            .browsers
            .iter()
            .find(|browser| browser.id == browser_id)
            .ok_or(TransferError::Failed)?;
        let source_store = self
            .settings
            .application_support
            .join(&source.data_directory)
            .join(COOKIES_RELATIVE_PATH);
        let target_store = self.location.profile_directory.join(COOKIES_RELATIVE_PATH);

        let deadline = Instant::now() + self.settings.transfer_timeout;
        let mut locks = ProfileCustodyLocks::open_filesystem(&self.location.managed_root)
            .map_err(|_| TransferError::Failed)?;
        let holder = locks.mint_holder().map_err(|_| TransferError::Failed)?;
        let mut claim = match locks
            .acquire(ProfileCustodyKey::durable(&self.project_id), holder)
            .map_err(|_| TransferError::Failed)?
        {
            ProfileCustodyAcquisition::Acquired(claim) => claim,
            ProfileCustodyAcquisition::ProfileBusy { holder_id } => {
                if let Some(detail) = crate::profile_custody::lease_refusal(holder_id.as_str()) {
                    return Err(TransferError::ResourceBusy(detail));
                }
                return Err(TransferError::ProfileBusy);
            }
        };
        crate::profile_custody::lease_deadline(claim.holder_id().as_str(), deadline);
        if locks
            .bind_profile_directory(&mut claim, &self.location.profile_directory)
            .is_err()
        {
            let _ = locks.release_exact(&claim);
            return Err(TransferError::Failed);
        }

        let transferred = transfer_store(
            &self.settings.sqlite_program,
            &source_store,
            &target_store,
            &self.domains,
            self.observer.as_ref(),
            deadline,
        )
        .map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                TransferError::TimedOut
            } else {
                TransferError::Failed
            }
        });
        let released = locks.release_exact(&claim);
        if !matches!(released, Ok(ProfileCustodyRelease::Released)) {
            return Err(TransferError::Failed);
        }
        transferred
    }
}

/// What a caller should do after a consent question that ended without an
/// answer. Each ending has its own remedy because they are opposite: a person
/// who was asked may answer the next question, while a question nobody was
/// shown will reach nobody however many times it is put.
fn unanswered_remedy(ending: &str) -> &'static str {
    match ending {
        "no_answer" => "nothing was copied; the answer is unavailable or was lost. Ask again when they are available.",
        "not_put_to_anyone" => "nothing was copied; the question was shown to no one, and putting it again reaches no one either until the caller's consent route can put it to a person.",
        "unrecognized_answer" => "nothing was copied; the answer was not one the card offered. Retry this call to ask again.",
        "question_withdrawn" => "nothing was copied; the card was withdrawn before it was answered. Retry this call to ask again.",
        _ => "nothing was copied; the question could not be sent. Retry once; if it fails again, the module needs attention.",
    }
}

/// The import card's decline option, which is also its default.
const IMPORT_DECLINE: &str = "deny";

/// The consent card for copying a login for `origin` into the agent's browser.
///
/// One grant per browser the login can be copied from, plus signing in by
/// hand; `presence` says which browsers hold a login and why the others can't
/// give one.
pub(crate) fn import_question(origin: &str, host: &str, presence: &[BrowserPresence]) -> Value {
    use crate::consent_card::*;
    let mut grants: Vec<_> = presence
        .iter()
        .filter(|b| b.transfer == "available")
        .map(|b| {
            ConsentOption::grant(
                format!("transfer:{}", b.browser),
                format!("Copy my login from {}", b.name),
            )
        })
        .collect();
    let mut hand_off_step = format!("Call browser_use with action present for {origin}.");
    if hand_off_step.chars().count() > 200 {
        // When the origin makes the instruction exceed the display limit,
        // refer to the origin recorded in the consent card's scope instead.
        hand_off_step =
            "Call browser_use with action present for the origin in this consent card's scope."
                .to_string();
    }
    grants.push(
        ConsentOption::grant("hand_off", "I'll sign in myself").with_next_step(hand_off_step),
    );
    let mut facts: Vec<_> = presence
        .iter()
        .map(|b| {
            Fact::new(
                &b.name,
                match b.reason {
                    Some("different_keychain_item") => "can't be copied (different keychain)",
                    Some("session_only") if b.session_rows > 0 => "only a temporary login is saved",
                    Some("session_only") => "nothing saved",
                    Some("os_protected") => "macOS protects this browser's data",
                    Some("unreadable") => "can't read saved logins",
                    Some("safari_transfer_unsupported") => "can't be copied from Safari",
                    _ if b.transfer == "available" => "login available",
                    _ => "can't be copied",
                },
            )
        })
        .collect();
    facts.push(Fact::new("Privacy", "No cookie value is read by the agent"));
    ConsentCard {
        title: format!("Copy your {host} login?"),
        prompt: format!(
            "Copy your {host} login from a browser on this Mac into the agent's browser."
        ),
        target: Target {
            kind: TargetKind::Site,
            label: host.to_string(),
        },
        facts,
        grants,
        decline: ConsentOption::decline(IMPORT_DECLINE, "Don't allow"),
        expires_in: crate::consent_card::LOGIN_CARD_LIFETIME,
        material_damage: true,
        // The import call waits on the answer (up to
        // `computer_grants::CONSENT_PARK_LIMIT`), so the agent is blocked
        // until the person decides or that wait ends.
        urgency: Urgency::High,
        // The plan the answer applies to is prepared for this one origin: the
        // cookie domains it copies are derived from it.
        scope: Scope::new().with("origin", origin),
        duration: None,
    }
    .render()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransferError {
    ProfileBusy,
    ResourceBusy(cortexkit_resource_busy::ResourceBusy),
    TimedOut,
    Failed,
}

pub fn new_ask_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "browser-login-import-consent-{}",
        NEXT.fetch_add(1, Ordering::Relaxed) + 1
    )
}

pub fn prepare_import(
    origin: &str,
    project_id: &str,
    launch_executable: &Path,
    location: DurableProfileLocation,
    settings: ImportSettings,
) -> PreparedImport {
    let Some(host) = origin_host(origin) else {
        return PreparedImport::Refused(ImportResult::refusal(
            origin,
            "invalid_origin",
            "supply one canonical http or https origin",
        ));
    };
    let Some(_launch_source) = settings
        .browsers
        .iter()
        .find(|source| same_executable(launch_executable, &source.executable))
    else {
        return PreparedImport::Refused(ImportResult::refusal(
            origin,
            "launch_binary_unsupported",
            "configure a supported Chromium-family browser executable",
        ));
    };
    let domains = domain_candidates(&host);
    let presence = discover_presence(&settings, launch_executable, &domains);
    PreparedImport::Ready(LoginImportPlan {
        origin: origin.to_string(),
        host,
        domains,
        project_id: project_id.to_string(),
        launch_executable: launch_executable.to_path_buf(),
        location,
        settings,
        presence,
        observer: Arc::new(NoopProfileWriteObserver),
    })
}

pub fn profile_precondition(origin: &str, durable: bool) -> Result<(), Box<ImportResult>> {
    if !durable {
        return Err(Box::new(ImportResult::refusal(
            origin,
            "profile_not_durable",
            "bind a primary route with a durable browser profile",
        )));
    }
    Ok(())
}

fn discover_presence(
    settings: &ImportSettings,
    launch_executable: &Path,
    domains: &[String],
) -> Vec<BrowserPresence> {
    let mut presence = Vec::new();
    for source in &settings.browsers {
        let store = settings
            .application_support
            .join(&source.data_directory)
            .join(COOKIES_RELATIVE_PATH);
        let Some(result) = read_existing_store(&store, |store| {
            chromium_presence(&settings.sqlite_program, store, domains)
        }) else {
            continue;
        };
        match result {
            Ok((persistent_rows, session_rows)) => {
                let (transfer, reason) = if persistent_rows == 0 {
                    ("unsupported", Some("session_only"))
                } else if !same_executable(&source.executable, launch_executable) {
                    ("unsupported", Some("different_keychain_item"))
                } else {
                    ("available", None)
                };
                presence.push(BrowserPresence {
                    browser: source.id.to_string(),
                    name: source.display_name.to_string(),
                    persistent_rows,
                    session_rows,
                    transfer,
                    reason,
                });
            }
            Err(error) => presence.push(BrowserPresence {
                browser: source.id.to_string(),
                name: source.display_name.to_string(),
                persistent_rows: 0,
                session_rows: 0,
                transfer: "unsupported",
                reason: Some(store_read_failure_reason(&error)),
            }),
        }
    }

    if let Some(result) = read_existing_store(&settings.safari_store, copied_safari_domains) {
        match result {
            Ok(found) => {
                let persistent_rows = found
                    .iter()
                    .filter(|domain| domains.iter().any(|candidate| candidate == *domain))
                    .count() as u64;
                if persistent_rows > 0 {
                    presence.push(BrowserPresence {
                        browser: "safari".to_string(),
                        name: "Safari".to_string(),
                        persistent_rows,
                        session_rows: 0,
                        transfer: "unsupported",
                        reason: Some("safari_transfer_unsupported"),
                    });
                }
            }
            Err(error) => presence.push(BrowserPresence {
                browser: "safari".to_string(),
                name: "Safari".to_string(),
                persistent_rows: 0,
                session_rows: 0,
                transfer: "unsupported",
                reason: Some(store_read_failure_reason(&error)),
            }),
        }
    }
    presence
}

fn read_existing_store<T>(
    store: &Path,
    read: impl FnOnce(&Path) -> io::Result<T>,
) -> Option<io::Result<T>> {
    // Path::exists hides permission errors as absence. A protected profile must
    // remain visible in the card, even when macOS denies directory traversal.
    match fs::metadata(store) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => Some(Err(error)),
        Ok(_) => Some(read(store)),
    }
}

fn store_read_failure_reason(error: &io::Error) -> &'static str {
    if error.kind() == io::ErrorKind::PermissionDenied {
        "os_protected"
    } else {
        "unreadable"
    }
}

fn chromium_presence(
    sqlite_program: &Path,
    source_store: &Path,
    domains: &[String],
) -> io::Result<(u64, u64)> {
    let temporary = PrivateTempDir::new("presence")?;
    let copied = temporary.path().join("Cookies");
    copy_store_private(sqlite_program, source_store, &copied)?;
    let query = format!(
        "SELECT COALESCE(SUM(CASE WHEN has_expires = 1 THEN 1 ELSE 0 END),0) || '|' || COALESCE(SUM(CASE WHEN has_expires = 0 THEN 1 ELSE 0 END),0) FROM cookies WHERE host_key IN ({});",
        sql_values(domains)
    );
    let output = sqlite_read(sqlite_program, &copied, &query)?;
    let Some((persistent, session)) = output.trim().split_once('|') else {
        return Err(io::Error::other("unexpected SQLite count output"));
    };
    Ok((parse_count(persistent)?, parse_count(session)?))
}

fn transfer_store(
    sqlite_program: &Path,
    source_store: &Path,
    target_store: &Path,
    domains: &[String],
    observer: &dyn ProfileWriteObserver,
    deadline: Instant,
) -> io::Result<u64> {
    let temporary = PrivateTempDir::new("transfer")?;
    let pruned = temporary.path().join("Cookies");
    copy_store_private_until(sqlite_program, source_store, &pruned, deadline)?;
    sqlite_write_until(
        sqlite_program,
        &pruned,
        &format!(
            "BEGIN IMMEDIATE; DELETE FROM cookies WHERE has_expires != 1 OR host_key NOT IN ({}); COMMIT;",
            sql_values(domains)
        ),
        deadline,
    )?;
    let rows = parse_count(
        sqlite_read_until(
            sqlite_program,
            &pruned,
            "SELECT COUNT(*) FROM cookies;",
            deadline,
        )?
        .trim(),
    )?;
    observer.before_profile_write(&pruned)?;

    let Some(parent) = target_store.parent() else {
        return Err(io::Error::other("cookie store has no parent directory"));
    };
    fs::create_dir_all(parent)?;
    if !target_store.exists() {
        let staging = unique_path(parent, ".Cookies.import");
        if let Err(error) = copy_private(&pruned, &staging) {
            let _ = fs::remove_file(&staging);
            return Err(error);
        }
        match fs::rename(&staging, target_store) {
            Ok(()) => return Ok(rows),
            Err(error) => {
                let _ = fs::remove_file(&staging);
                return Err(error);
            }
        }
    }

    let source_columns = cookie_columns(sqlite_program, &pruned, deadline)?;
    let target_columns = cookie_columns(sqlite_program, target_store, deadline)?;
    if source_columns.is_empty() || source_columns != target_columns {
        return Err(io::Error::other("cookie store schemas differ"));
    }
    let columns = source_columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(",");
    let attached_uri = sqlite_uri(&pruned);
    let sql = format!(
        "ATTACH DATABASE {} AS imported; BEGIN IMMEDIATE; \
         DELETE FROM main.cookies WHERE EXISTS (SELECT 1 FROM imported.cookies AS source \
         WHERE source.host_key = main.cookies.host_key AND source.name = main.cookies.name \
         AND source.path = main.cookies.path); \
         INSERT INTO main.cookies ({columns}) SELECT {columns} FROM imported.cookies; \
         COMMIT; DETACH DATABASE imported;",
        sql_literal(&attached_uri)
    );
    sqlite_write_until(sqlite_program, target_store, &sql, deadline)?;
    Ok(rows)
}

fn cookie_columns(
    sqlite_program: &Path,
    store: &Path,
    deadline: Instant,
) -> io::Result<Vec<String>> {
    let output = sqlite_read_until(
        sqlite_program,
        store,
        "SELECT name FROM pragma_table_info('cookies') ORDER BY cid;",
        deadline,
    )?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn sqlite_read(program: &Path, store: &Path, sql: &str) -> io::Result<String> {
    // Not `-readonly`: every store this reads is a private copy or the route's
    // own closed profile store, and a read-only connection cannot roll back a
    // hot journal, so it would refuse the one copy that most needs recovering.
    sqlite_read_until(program, store, sql, Instant::now() + TRANSFER_TIMEOUT)
}

#[cfg(test)]
fn sqlite_write(program: &Path, store: &Path, sql: &str) -> io::Result<String> {
    sqlite_read_until(program, store, sql, Instant::now() + TRANSFER_TIMEOUT)
}

fn sqlite_read_until(
    program: &Path,
    store: &Path,
    sql: &str,
    deadline: Instant,
) -> io::Result<String> {
    sqlite(program, None, store.as_os_str(), sql, deadline)
}

fn sqlite_write_until(
    program: &Path,
    store: &Path,
    sql: &str,
    deadline: Instant,
) -> io::Result<String> {
    sqlite_read_until(program, store, sql, deadline)
}

fn sqlite(
    program: &Path,
    mode: Option<&OsStr>,
    store: &OsStr,
    sql: &str,
    deadline: Instant,
) -> io::Result<String> {
    let mut command = Command::new(program);
    crate::launch_nonce::without_launch_nonce(&mut command);
    command.arg("-batch");
    if let Some(mode) = mode {
        command.arg(mode);
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "SQLite transfer timed out",
        ));
    }
    let mut child = command
        .arg(store)
        .arg(sql)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child.stdout.take().expect("SQLite stdout is piped");
    // Drain concurrently so a full pipe cannot stop SQLite from exiting.
    // Dropping this thread's handle on timeout does not wait for a blocked read.
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output)?;
        Ok::<_, io::Error>(output)
    });
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            // macOS security-policy evaluation can leave a child blocked in
            // the kernel even after a kill signal. Do not wait indefinitely for
            // its exit: that would undo the operation deadline.
            let _ = child.kill();
            std::thread::sleep(Duration::from_millis(10));
            let _ = child.try_wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SQLite transfer timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = reader
        .join()
        .map_err(|_| io::Error::other("SQLite stdout reader panicked"))??;
    if !status.success() {
        return Err(io::Error::other("SQLite could not read the cookie store"));
    }
    String::from_utf8(output).map_err(|_| io::Error::other("SQLite returned non-UTF-8"))
}

/// The URI form of a store path for `ATTACH`, which needs a URI to carry a
/// path with unusual characters. No `immutable=1`: that flag tells SQLite the
/// file cannot change, so it skips hot-journal and WAL recovery and answers
/// from whatever bytes are on disk, which for a store copied from under a
/// running browser is the last checkpointed state or a half-applied commit,
/// returned without error. The copies here are private, so nothing holds a
/// lock on them and the flag buys nothing it does not cost.
fn sqlite_uri(path: &Path) -> String {
    format!("file:{}", path.to_string_lossy())
}

/// Copy a Chromium cookie store into a private directory as a consistent
/// database, not merely as a file.
///
/// A running browser holds its stores open with a rollback journal in
/// truncate mode (`<store>-journal`, zero bytes between transactions, the
/// pre-images of a transaction in flight otherwise). Copying the main file
/// alone drops the one thing that lets SQLite undo a commit caught half-way,
/// so the journal is copied with the store, and any WAL sidecars a differently
/// configured browser might keep; opening the copy afterwards rolls a hot
/// journal back to the last committed state.
///
/// A plain copy of a file another process is writing is a snapshot of nothing
/// in particular, and a hot journal covers only the commit it was written for.
/// So the store is read twice and the copy is accepted only when both reads
/// agree byte for byte: a commit landing during the copy changes the bytes
/// between reads and the copy is retried. The browser batches cookie writes
/// seconds apart, so a retry converges; a store that will not hold still is
/// refused. That check is what the tests cannot stage (it needs a writer
/// racing the copy), so it is reasoned rather than proven; the journal
/// rollback and the damage refusal below are the fenced halves. A copy that
/// SQLite still reports as damaged is refused as an error, which the caller
/// reports as unreadable rather than as a count or a transfer of rows nobody
/// can decrypt.
fn copy_store_private(sqlite_program: &Path, source: &Path, destination: &Path) -> io::Result<()> {
    copy_store_private_until(
        sqlite_program,
        source,
        destination,
        Instant::now() + TRANSFER_TIMEOUT,
    )
}

fn copy_store_private_until(
    sqlite_program: &Path,
    source: &Path,
    destination: &Path,
    deadline: Instant,
) -> io::Result<()> {
    let journal = sidecar_path(source, "-journal");
    if journal.exists() {
        copy_private(&journal, &sidecar_path(destination, "-journal"))?;
    }
    copy_private(source, destination)?;
    let mut attempts = 0;
    loop {
        let again = fs::read(source)?;
        if again == fs::read(destination)? {
            break;
        }
        attempts += 1;
        if attempts == 3 {
            return Err(io::Error::other(
                "the cookie store kept changing while it was being copied",
            ));
        }
        fs::remove_file(destination)?;
        copy_private(source, destination)?;
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(source, suffix);
        if sidecar.exists() {
            copy_private(&sidecar, &sidecar_path(destination, suffix))?;
        }
    }
    // The CLI reports a damaged page either as a non-"ok" verdict or by
    // failing outright; both are the same answer here.
    match sqlite_read_until(sqlite_program, destination, "PRAGMA quick_check;", deadline) {
        Ok(verdict) if verdict.trim() == "ok" => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Err(error),
        Ok(_) | Err(_) => Err(io::Error::other(
            "the copied cookie store is not consistent",
        )),
    }
}

fn sidecar_path(store: &Path, suffix: &str) -> PathBuf {
    let mut name = store.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn parse_count(value: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| io::Error::other("invalid SQLite count"))
}

fn sql_values(values: &[String]) -> String {
    values
        .iter()
        .map(|value| sql_literal(value))
        .collect::<Vec<_>>()
        .join(",")
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn same_executable(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn valid_import_origin(origin: &str) -> bool {
    crate::classification::canonical_grant_origin(origin).as_deref() == Some(origin)
}

pub(crate) fn origin_host(origin: &str) -> Option<String> {
    if !valid_import_origin(origin) {
        return None;
    }
    let authority = origin.split_once("://")?.1;
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        return Some(format!("[{}]", &rest[..close]));
    }
    Some(
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
            .to_string(),
    )
}

fn domain_candidates(host: &str) -> Vec<String> {
    if host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        return vec![host.to_string()];
    }
    let labels = host.split('.').collect::<Vec<_>>();
    let mut domains = Vec::new();
    for index in 0..labels.len().saturating_sub(1) {
        let domain = labels[index..].join(".");
        domains.push(domain.clone());
        domains.push(format!(".{domain}"));
    }
    if domains.is_empty() {
        domains.push(host.to_string());
    }
    domains
}

fn copied_safari_domains(path: &Path) -> io::Result<Vec<String>> {
    let temporary = PrivateTempDir::new("safari-presence")?;
    let copied = temporary.path().join("Cookies.binarycookies");
    copy_private(path, &copied)?;
    safari_domains(&copied)
}

fn safari_domains(path: &Path) -> io::Result<Vec<String>> {
    let bytes = fs::read(path)?;
    if bytes.len() < 8 || &bytes[..4] != b"cook" {
        return Err(io::Error::other("invalid binarycookies header"));
    }
    let page_count = be_u32(&bytes, 4)? as usize;
    let table_end = 8_usize
        .checked_add(
            page_count
                .checked_mul(4)
                .ok_or_else(|| io::Error::other("page table overflow"))?,
        )
        .ok_or_else(|| io::Error::other("page table overflow"))?;
    if table_end > bytes.len() {
        return Err(io::Error::other("truncated binarycookies page table"));
    }
    let mut cursor = table_end;
    let mut domains = Vec::new();
    for index in 0..page_count {
        let page_size = be_u32(&bytes, 8 + index * 4)? as usize;
        let end = cursor
            .checked_add(page_size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| io::Error::other("truncated binarycookies page"))?;
        parse_safari_page(&bytes[cursor..end], &mut domains)?;
        cursor = end;
    }
    Ok(domains)
}

fn parse_safari_page(page: &[u8], domains: &mut Vec<String>) -> io::Result<()> {
    if page.len() < 8 {
        return Err(io::Error::other("short binarycookies page"));
    }
    let count = le_u32(page, 4)? as usize;
    let offsets_end = 8_usize
        .checked_add(
            count
                .checked_mul(4)
                .ok_or_else(|| io::Error::other("cookie table overflow"))?,
        )
        .ok_or_else(|| io::Error::other("cookie table overflow"))?;
    if offsets_end > page.len() {
        return Err(io::Error::other("truncated cookie offset table"));
    }
    for index in 0..count {
        let start = le_u32(page, 8 + index * 4)? as usize;
        let size = le_u32(page, start)? as usize;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= page.len())
            .ok_or_else(|| io::Error::other("truncated cookie record"))?;
        if size < 36 {
            return Err(io::Error::other("short cookie record"));
        }
        let domain_offset = le_u32(page, start + 16)? as usize;
        let domain_start = start
            .checked_add(domain_offset)
            .filter(|offset| *offset < end)
            .ok_or_else(|| io::Error::other("invalid cookie domain offset"))?;
        let domain_end = page[domain_start..end]
            .iter()
            .position(|byte| *byte == 0)
            .map(|length| domain_start + length)
            .ok_or_else(|| io::Error::other("unterminated cookie domain"))?;
        let domain = std::str::from_utf8(&page[domain_start..domain_end])
            .map_err(|_| io::Error::other("cookie domain is not UTF-8"))?;
        domains.push(domain.to_ascii_lowercase());
    }
    Ok(())
}

fn be_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::other("truncated big-endian integer"))?;
    Ok(u32::from_be_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

fn le_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::other("truncated little-endian integer"))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    fn new(label: &str) -> io::Result<Self> {
        let root = std::env::temp_dir();
        for _ in 0..32 {
            let path = unique_path(&root, &format!("ck-login-import-{label}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    if let Err(error) = set_private_directory_permissions(&path) {
                        let _ = fs::remove_dir_all(&path);
                        return Err(error);
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a private login-import directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn unique_path(parent: &Path, prefix: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    parent.join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed) + 1
    ))
}

fn copy_private(source: &Path, destination: &Path) -> io::Result<()> {
    let mut source_file = OpenOptions::new().read(true).open(source)?;
    let mut destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    io::copy(&mut source_file, &mut destination_file)?;
    destination_file.sync_all()?;
    set_private_file_permissions(destination)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use std::sync::Mutex;

    use crate::browser_session::*;

    struct ImportProcess(Arc<Mutex<Vec<&'static str>>>);
    impl OwnedBrowserProcess for ImportProcess {
        fn navigate(
            &mut self,
            _: &str,
            url: &str,
            _: NavigationWait,
            _: u64,
            tracker: &mut crate::browser::Tracker,
        ) -> Result<(), NavigationDriveError> {
            self.0.lock().unwrap().push("navigate");
            tracker.main_frame_navigated(None, url.to_string());
            tracker.load(std::time::Instant::now());
            Ok(())
        }
        fn generation_matches(&self) -> bool {
            true
        }
        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            self.0.lock().unwrap().push("close");
            Ok(())
        }
        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            Ok(true)
        }
        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
        fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
            Ok("https://x.com/page".into())
        }
        fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
            Ok(())
        }
        fn cookie_names_for_origin(
            &mut self,
            _: &str,
            _: &str,
            _: u64,
        ) -> Result<std::collections::BTreeSet<String>, NavigationDriveError> {
            Ok(Default::default())
        }
    }
    struct ImportCleanup;
    impl SessionCleanup for ImportCleanup {
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            Ok(SessionCleanupOutcome::Complete)
        }
    }
    struct ImportLauncher {
        events: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }
    impl BrowserSessionLauncher for ImportLauncher {
        fn launch(&self, _: &crate::AcceptedBindFacts, _: &str) -> Result<LaunchedBrowser, Value> {
            self.events.lock().unwrap().push("launch");
            if self.fail {
                return Err(json!({"outcome":"executable_missing"}));
            }
            Ok(LaunchedBrowser {
                process: Box::new(ImportProcess(self.events.clone())),
                cleanup: Box::new(ImportCleanup),
                executable_identity_checkpoints:
                    crate::browser_launch::ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
            })
        }
    }

    async fn open_import_case(
        decision: &str,
        presented: bool,
        fail: bool,
        granted: bool,
    ) -> (Value, Value, String, Vec<&'static str>) {
        let root = TestRoot::new("open-session");
        let chrome = source("chrome", "Chrome", root.path());
        let data = root.path().join("data");
        create_store(
            &cookie_store(&data, &chrome),
            &[Cookie {
                host: ".x.com",
                name: "session",
                path: "/",
                persistent: true,
                encrypted: b"secret",
            }],
        );
        let profile = root.path().join("managed/profile");
        fs::create_dir_all(&profile).unwrap();
        let mut planes = crate::tests::management_bound_planes(4, 1);
        let mut facts = planes.routes.get(4, 1).unwrap();
        facts.identity.profile_disposition = cerebellum_core::identity::ProfileDisposition::Durable;
        let config = crate::browser_config::BrowserConfig {
            executable_path: Some(chrome.executable.clone()),
            expected_identity: None,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
        };
        planes.browser_config = Some(config.clone());
        planes.browser = Arc::new(
            crate::browser::BrowserPlane::with_session_gate(
                planes.sessions.clone(),
                planes.lease_clock.clone(),
                100,
            )
            .with_shared_grants(planes.management.browser_grants()),
        );
        if granted {
            planes
                .management
                .browser_grants()
                .lock()
                .await
                .replace(crate::authorization::ActionGrant::new(
                    "restore",
                    1,
                    &facts.identity.conversation_key,
                    crate::authorization::Severity::new(1, false, false),
                    ["https://x.com"],
                ))
                .unwrap();
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        planes.launch_service = Some(Arc::new(ImportLauncher {
            events: events.clone(),
            fail: false,
        }));
        let launched =
            crate::handle_browser_control(BROWSER_LAUNCH, &json!({}), &facts, &planes).await;
        assert_eq!(launched["outcome"], "launched", "{launched}");
        let old_id = launched["browser_session_id"].as_str().unwrap().to_string();
        events.lock().unwrap().clear();
        planes.launch_service = Some(Arc::new(ImportLauncher {
            events: events.clone(),
            fail,
        }));
        if presented {
            planes
                .sessions
                .present(
                    &facts.identity.conversation_key,
                    "https://x.com",
                    100,
                    planes.lease_clock.as_ref(),
                )
                .unwrap();
        }
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            &facts.identity.agent_project_id,
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile.clone(),
            },
            ImportSettings::for_test(
                PathBuf::from(SQLITE_PROGRAM),
                data,
                root.path().join("safari"),
                vec![chrome.clone()],
            ),
        ) else {
            panic!("plan")
        };
        assert!(plan.permits_transfer(Some("transfer:chrome")));
        let copy_events = events.clone();
        let plan = plan.with_profile_write_observer_for_test(Arc::new(move |_: &Path| {
            let mut events = copy_events.lock().unwrap();
            assert_eq!(
                *events,
                ["close"],
                "copy must follow graceful close and precede launch"
            );
            events.push("copy");
            Ok(())
        }));
        planes = crate::computer_grants::tests::CardService::install(planes, 4, 1);
        let facts = planes.routes.get(4, 1).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let cancel = crate::CancelHandle::pending();
        let request = crate::computer_grants::tests::with_live(crate::complete_login_import(
            &planes,
            &facts,
            &tx,
            4,
            1,
            plan,
            Some(cancel.clone()),
        ));
        let answer = async {
            let question = planes.consent_test.as_ref().unwrap().card(4, 1).await;
            assert!(
                events.lock().unwrap().is_empty(),
                "browser closed before consent"
            );
            if decision == "cancel" {
                cancel.cancel();
                return;
            }
            let ending = match decision {
                "no_answer" => crate::cingulate_client::ScriptedAnswer::NoAnswer,
                "not_put_to_anyone" => crate::cingulate_client::ScriptedAnswer::NotPutToAnyone,
                "undeliverable" => crate::cingulate_client::ScriptedAnswer::Undeliverable,
                _ => {
                    crate::cingulate_client::ScriptedAnswer::Answered(json!({"decision":decision}))
                }
            };
            assert!(planes
                .consent_test
                .as_ref()
                .unwrap()
                .answer(question.header.corr, ending));
        };
        let (reply, ()) = tokio::join!(request, answer);
        crate::browser::validate_browser_result(crate::management::IMPORT_LOGIN, &reply).unwrap();
        let status = planes.sessions.status(
            &facts.identity.conversation_key,
            planes.lease_clock.as_ref(),
            std::time::SystemTime::now(),
        );
        if reply["outcome"] == "transferred" {
            assert_eq!(
                encrypted_hex(&profile.join(COOKIES_RELATIVE_PATH), "session"),
                "736563726574"
            );
        }
        let recorded = events.lock().unwrap().clone();
        (reply, status, old_id, recorded)
    }

    #[tokio::test]
    async fn import_open_session_closes_copies_and_relaunches() {
        let (reply, status, old, events) =
            open_import_case("transfer:chrome", false, false, false).await;
        assert_eq!(reply["outcome"], "transferred");
        assert_eq!(events, ["close", "copy", "launch"]);
        assert_eq!(status["outcome"], "ready");
        assert_eq!(
            reply["relaunched"]["browser_session_id"],
            status["browser_session_id"]
        );
        assert_ne!(status["browser_session_id"], old);
        assert!(reply["relaunched"]["restored_url"].is_null());
        for malformed in [
            json!({"browser_session_id": 7, "restored_url": null}),
            json!({"browser_session_id":"id"}),
            json!({"browser_session_id":"id","restored_url":null,"extra":true}),
        ] {
            let mut invalid = reply.clone();
            invalid["relaunched"] = malformed;
            assert!(crate::browser::validate_browser_result(
                crate::management::IMPORT_LOGIN,
                &invalid
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn import_restores_url_only_with_a_grant() {
        let (reply, _, _, events) = open_import_case("transfer:chrome", false, false, true).await;
        assert_eq!(
            reply["relaunched"]["restored_url"], "https://x.com/page",
            "{reply}"
        );
        assert_eq!(events, ["close", "copy", "launch", "navigate"]);
    }

    #[tokio::test]
    async fn import_deny_and_hand_off_leave_open_session_untouched() {
        for decision in ["deny", "hand_off", "transfer:unknown", "cancel"] {
            let (reply, status, old, events) =
                open_import_case(decision, false, false, false).await;
            assert_eq!(
                reply["outcome"],
                if decision == "hand_off" {
                    "hand_off"
                } else if decision == "transfer:unknown" {
                    "unrecognized_answer"
                } else if decision == "cancel" {
                    "cancelled"
                } else {
                    "denied"
                }
            );
            if decision == "cancel" {
                assert!(reply.get("remedy").is_none());
            }
            assert_eq!(status["outcome"], "ready");
            assert_eq!(status["browser_session_id"], old);
            assert!(events.is_empty());
        }
    }

    /// Every way the consent question can end without an answer is reported as
    /// that ending, never as `denied`, and copies nothing.
    ///
    /// The endings call for opposite next steps: a refusal should not be asked
    /// again, a person who stayed silent may answer next time, and a question
    /// nobody was shown is shown to nobody next time either. Reported as
    /// `denied`, a question the carrier never put to anyone told the agent the
    /// person had refused.
    #[tokio::test]
    async fn an_import_question_that_ended_unanswered_is_never_reported_as_denied() {
        // Script the card's ending, then check its wire outcome and remedy.
        // Silence, requester refusal and transport failure are not declines.
        let cases = [
            ("deny", "denied", None),
            (
                "no_answer",
                "no_answer",
                Some("Ask again when they are available"),
            ),
            (
                "not_put_to_anyone",
                "not_put_to_anyone",
                Some("shown to no one"),
            ),
            ("undeliverable", "undeliverable", Some("could not be sent")),
            (
                "some_future_word",
                "unrecognized_answer",
                Some("could not be read"),
            ),
        ];
        for (decision, outcome, remedy) in cases {
            let (reply, status, old, events) =
                open_import_case(decision, false, false, false).await;
            assert_eq!(reply["outcome"], outcome, "{decision}: {reply}");
            match remedy {
                Some(remedy) => assert!(
                    reply["remedy"]
                        .as_str()
                        .unwrap_or_default()
                        .contains(remedy),
                    "{decision}: {reply}"
                ),
                None => assert!(reply.get("remedy").is_none(), "{decision}: {reply}"),
            }
            if decision == "not_put_to_anyone" {
                let remedy = reply["remedy"].as_str().unwrap().to_lowercase();
                for loop_word in ["ask again", "retry", "wait"] {
                    assert!(
                        !remedy.contains(loop_word),
                        "a question nobody was shown sends the caller round a loop: {remedy}"
                    );
                }
            }
            // Nothing was copied, and the agent's open browser session, which a
            // transfer would close first, is still the same one.
            assert!(events.is_empty(), "{decision}: {events:?}");
            assert!(reply.get("rows").is_none(), "{decision}: {reply}");
            assert_eq!(status["outcome"], "ready", "{decision}");
            assert_eq!(status["browser_session_id"], old, "{decision}");
        }
    }

    #[tokio::test]
    async fn import_presented_session_is_not_closed() {
        let (reply, status, old, events) =
            open_import_case("transfer:chrome", true, false, false).await;
        assert_eq!(reply["outcome"], "session_open");
        assert_eq!(status["browser_session_id"], old);
        assert_eq!(status["outcome"], "ready");
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn import_relaunch_failure_preserves_transferred_outcome() {
        let (reply, status, _, events) =
            open_import_case("transfer:chrome", false, true, false).await;
        assert_eq!(reply["outcome"], "transferred");
        assert!(reply["relaunched"].is_null());
        assert_eq!(reply["detail"]["outcome"], "executable_missing");
        assert_ne!(status["outcome"], "ready");
        assert_eq!(events, ["close", "copy", "launch"]);
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = unique_path(&std::env::temp_dir(), &format!("login-import-test-{label}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn import_origin_must_name_a_site() {
        assert!(!valid_import_origin("null"));
        assert!(!valid_import_origin("https://example.test/path"));
        assert!(valid_import_origin("https://example.test"));
    }

    #[cfg(unix)]
    #[test]
    fn opaque_import_origin_never_invokes_cookie_store_reader() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestRoot::new("opaque-origin-no-store-read");
        let browser = source("chrome", "Chrome", root.path());
        let application_support = root.path().join("Application Support");
        let store = cookie_store(&application_support, &browser);
        fs::create_dir_all(store.parent().unwrap()).unwrap();
        fs::write(&store, b"fixture store").unwrap();
        let read_marker = root.path().join("store-was-read");
        let reader = root.path().join("sqlite-reader");
        fs::write(
            &reader,
            format!("#!/bin/sh\ntouch '{}'\nexit 1\n", read_marker.display()),
        )
        .unwrap();
        fs::set_permissions(&reader, fs::Permissions::from_mode(0o700)).unwrap();
        let settings = ImportSettings::for_test(
            reader,
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![browser.clone()],
        );
        let result = prepare_import(
            "null",
            "project-1",
            &browser.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: root.path().join("managed/profile"),
            },
            settings,
        );
        assert!(
            matches!(result, PreparedImport::Refused(ref refusal) if refusal.outcome == "invalid_origin")
        );
        assert!(!read_marker.exists(), "cookie store reader was invoked");
    }

    #[derive(Clone, Copy)]
    struct Cookie<'a> {
        host: &'a str,
        name: &'a str,
        path: &'a str,
        persistent: bool,
        encrypted: &'a [u8],
    }

    fn source(id: &'static str, name: &'static str, root: &Path) -> BrowserSource {
        let executable = root.join(format!("{id}-browser"));
        fs::write(&executable, b"fixture executable").unwrap();
        BrowserSource {
            id,
            display_name: name,
            data_directory: PathBuf::from(id),
            executable,
        }
    }

    fn cookie_store(application_support: &Path, source: &BrowserSource) -> PathBuf {
        application_support
            .join(&source.data_directory)
            .join(COOKIES_RELATIVE_PATH)
    }

    fn create_store(path: &Path, cookies: &[Cookie<'_>]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut sql = String::from(
            "CREATE TABLE cookies(\
             host_key TEXT NOT NULL,\
             name TEXT NOT NULL,\
             path TEXT NOT NULL,\
             has_expires INTEGER NOT NULL,\
             encrypted_value BLOB NOT NULL,\
             value TEXT NOT NULL DEFAULT '');",
        );
        for cookie in cookies {
            let encrypted = cookie
                .encrypted
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            sql.push_str(&format!(
                "INSERT INTO cookies(host_key,name,path,has_expires,encrypted_value,value) \
                 VALUES({},{},{},{},X'{}','');",
                sql_literal(cookie.host),
                sql_literal(cookie.name),
                sql_literal(cookie.path),
                u8::from(cookie.persistent),
                encrypted,
            ));
        }
        sqlite_write(Path::new(SQLITE_PROGRAM), path, &sql).unwrap();
    }

    fn encrypted_hex(path: &Path, name: &str) -> String {
        sqlite_read(
            Path::new(SQLITE_PROGRAM),
            path,
            &format!(
                "SELECT hex(encrypted_value) FROM cookies WHERE name = {};",
                sql_literal(name)
            ),
        )
        .unwrap()
        .trim()
        .to_string()
    }

    #[test]
    fn presence_reads_host_key_and_nothing_else() {
        let root = TestRoot::new("presence");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let brave = source("brave", "Brave", root.path());
        let planted = b"PLANTED_COOKIE_SECRET";
        let chrome_store = cookie_store(&application_support, &chrome);
        create_store(
            &chrome_store,
            &[Cookie {
                host: ".x.com",
                name: "session",
                path: "/",
                persistent: true,
                encrypted: planted,
            }],
        );
        create_store(
            &cookie_store(&application_support, &brave),
            &[
                Cookie {
                    host: "x.com",
                    name: "auth",
                    path: "/",
                    persistent: true,
                    encrypted: b"brave-secret",
                },
                Cookie {
                    host: "other.test",
                    name: "irrelevant",
                    path: "/",
                    persistent: true,
                    encrypted: b"irrelevant-secret",
                },
            ],
        );
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![chrome.clone(), brave],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        fs::create_dir_all(&profile).unwrap();
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };

        assert_eq!(plan.presence().len(), 2);
        assert_eq!(plan.presence()[0].persistent_rows, 1);
        assert_eq!(plan.presence()[1].persistent_rows, 1);
        let source_bytes = fs::read(&chrome_store).unwrap();
        assert!(
            source_bytes
                .windows(planted.len())
                .any(|window| window == planted),
            "the planted fixture secret did not land in the source store"
        );
        let rendered = serde_json::to_vec(plan.presence()).unwrap();
        assert!(!rendered
            .windows(planted.len())
            .any(|window| window == planted));
        assert!(!String::from_utf8(rendered)
            .unwrap()
            .contains("encrypted_value"));
    }

    /// Presence is read from a private copy of the store, and Chromium keeps a
    /// zero-byte rollback journal beside an idle store. The journal must ride
    /// along with the copy (a hot one is what makes the copy consistent), and
    /// an idle one must not change the answer.
    #[test]
    fn an_idle_journal_beside_the_store_rides_with_the_copy_and_hides_nothing() {
        let root = TestRoot::new("idle-journal");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let store = cookie_store(&application_support, &chrome);
        create_store(
            &store,
            &[Cookie {
                host: ".x.com",
                name: "session",
                path: "/",
                persistent: true,
                encrypted: b"secret",
            }],
        );
        fs::write(sidecar_path(&store, "-journal"), b"").unwrap();
        let (persistent, session) =
            chromium_presence(Path::new(SQLITE_PROGRAM), &store, &[".x.com".to_string()]).unwrap();
        assert_eq!((persistent, session), (1, 0));
    }

    /// The journal is the half of the copy that makes it a snapshot: a browser
    /// killed or copied mid-commit leaves a hot journal holding the pre-images
    /// of the pages it was rewriting, and SQLite undoes the commit from it on
    /// the next open. A copy that carries the store without the journal would
    /// read the half-applied pages as truth. The fixture builds that journal by
    /// hand from the page as it stood before a second row was added, so the
    /// copy must roll back to one row while the file alone says two.
    #[test]
    fn a_hot_journal_rides_with_the_copy_and_rolls_the_store_back() {
        let root = TestRoot::new("hot-journal");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let store = cookie_store(&application_support, &chrome);
        let cookie = |name: &'static str| Cookie {
            host: ".x.com",
            name,
            path: "/",
            persistent: true,
            encrypted: b"secret",
        };
        create_store(&store, &[cookie("first")]);
        let read = |sql: &str| {
            sqlite_read(Path::new(SQLITE_PROGRAM), &store, sql)
                .unwrap()
                .trim()
                .to_string()
        };
        let page_size: usize = read("PRAGMA page_size;").parse().unwrap();
        let page_count: u32 = read("PRAGMA page_count;").parse().unwrap();
        let leaf: usize = read("SELECT rootpage FROM sqlite_master WHERE name = 'cookies';")
            .parse()
            .unwrap();
        let before = fs::read(&store).unwrap();
        let pre_image = &before[(leaf - 1) * page_size..leaf * page_size];

        // The second row lands on the same leaf page; the journal written
        // below is exactly what SQLite would have written before touching it.
        sqlite_write(
            Path::new(SQLITE_PROGRAM),
            &store,
            "INSERT INTO cookies(host_key,name,path,has_expires,encrypted_value,value) \
             VALUES('.x.com','second','/',1,X'00','');",
        )
        .unwrap();
        assert_eq!(read("PRAGMA page_count;"), page_count.to_string());
        assert_eq!(read("SELECT COUNT(*) FROM cookies;"), "2");

        let nonce: u32 = 0x5eed_1234;
        let sector: usize = 512;
        let mut journal = Vec::new();
        journal.extend_from_slice(&[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
        journal.extend_from_slice(&1u32.to_be_bytes());
        journal.extend_from_slice(&nonce.to_be_bytes());
        journal.extend_from_slice(&page_count.to_be_bytes());
        journal.extend_from_slice(&(sector as u32).to_be_bytes());
        journal.extend_from_slice(&(page_size as u32).to_be_bytes());
        journal.resize(sector, 0);
        journal.extend_from_slice(&(leaf as u32).to_be_bytes());
        journal.extend_from_slice(pre_image);
        let mut checksum = nonce;
        let mut offset = page_size - 200;
        while offset > 0 {
            checksum = checksum.wrapping_add(u32::from(pre_image[offset]));
            offset = offset.saturating_sub(200);
        }
        journal.extend_from_slice(&checksum.to_be_bytes());
        fs::write(sidecar_path(&store, "-journal"), &journal).unwrap();

        let (persistent, _) =
            chromium_presence(Path::new(SQLITE_PROGRAM), &store, &[".x.com".to_string()]).unwrap();
        assert_eq!(
            persistent, 1,
            "the copy must be read through the rolled-back journal, not the file as found"
        );
    }

    /// A copy taken while the browser was mid-write is not a snapshot of
    /// anything. The tear here lands on a page the cookie query never reads,
    /// so the count alone would come back looking right; the consistency
    /// check on the whole copy is what turns it into a refusal, and the caller
    /// reports unreadable rather than a number.
    #[test]
    fn a_torn_copy_is_refused_even_where_the_cookie_rows_still_read() {
        let root = TestRoot::new("torn-copy");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let store = cookie_store(&application_support, &chrome);
        create_store(
            &store,
            &[Cookie {
                host: ".x.com",
                name: "session",
                path: "/",
                persistent: true,
                encrypted: b"secret",
            }],
        );
        // A second table on its own page, then that page zeroed: the cookies
        // b-tree is intact, the file is not.
        sqlite_write(
            Path::new(SQLITE_PROGRAM),
            &store,
            "CREATE TABLE meta(k TEXT); INSERT INTO meta VALUES('m');",
        )
        .unwrap();
        let page_size: u64 = sqlite_read(Path::new(SQLITE_PROGRAM), &store, "PRAGMA page_size;")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let meta_page: u64 = sqlite_read(
            Path::new(SQLITE_PROGRAM),
            &store,
            "SELECT rootpage FROM sqlite_master WHERE name = 'meta';",
        )
        .unwrap()
        .trim()
        .parse()
        .unwrap();
        let mut bytes = fs::read(&store).unwrap();
        let start = usize::try_from((meta_page - 1) * page_size).unwrap();
        let end = usize::try_from(meta_page * page_size).unwrap();
        bytes[start..end].fill(0);
        fs::write(&store, &bytes).unwrap();
        assert_eq!(
            sqlite_read(
                Path::new(SQLITE_PROGRAM),
                &store,
                "SELECT COUNT(*) FROM cookies WHERE has_expires = 1;"
            )
            .unwrap()
            .trim(),
            "1",
            "the fixture must leave the cookie rows readable, or it proves nothing about the check"
        );

        let error = chromium_presence(Path::new(SQLITE_PROGRAM), &store, &[".x.com".to_string()])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the copied cookie store is not consistent"
        );
    }

    #[test]
    fn session_only_rows_are_not_offered() {
        let root = TestRoot::new("session-only");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        create_store(
            &cookie_store(&application_support, &chrome),
            &[Cookie {
                host: ".x.com",
                name: "temporary",
                path: "/",
                persistent: false,
                encrypted: b"session-only",
            }],
        );
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![chrome.clone()],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        fs::create_dir_all(&profile).unwrap();
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };

        assert_eq!(plan.presence()[0].persistent_rows, 0);
        assert_eq!(plan.presence()[0].session_rows, 1);
        assert_eq!(plan.presence()[0].reason, Some("session_only"));
        let question = plan.question("agent-1").to_string();
        assert!(!question.contains("transfer:chrome"));
        assert!(question.contains("hand_off"));
    }

    #[test]
    fn transfer_is_offered_only_for_the_launch_binary() {
        let root = TestRoot::new("binary-match");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let brave = source("brave", "Brave", root.path());
        create_store(
            &cookie_store(&application_support, &brave),
            &[Cookie {
                host: ".x.com",
                name: "auth",
                path: "/",
                persistent: true,
                encrypted: b"brave",
            }],
        );
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![chrome.clone(), brave],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        fs::create_dir_all(&profile).unwrap();
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };

        assert_eq!(plan.presence()[0].browser, "brave");
        assert_eq!(plan.presence()[0].reason, Some("different_keychain_item"));
        assert!(!plan
            .question("agent-1")
            .to_string()
            .contains("transfer:brave"));
    }

    #[test]
    fn transfer_copies_rows_unchanged() {
        let root = TestRoot::new("unchanged");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let source_store = cookie_store(&application_support, &chrome);
        let encrypted = b"v10\x00\xffciphertext";
        create_store(
            &source_store,
            &[Cookie {
                host: ".x.com",
                name: "auth",
                path: "/",
                persistent: true,
                encrypted,
            }],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        let target = profile.join(COOKIES_RELATIVE_PATH);
        create_store(
            &target,
            &[Cookie {
                host: ".x.com",
                name: "auth",
                path: "/",
                persistent: true,
                encrypted: b"old",
            }],
        );
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![chrome.clone()],
        );
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };

        let before = encrypted_hex(&source_store, "auth");
        let result = plan.decide(Some("transfer:chrome"));
        assert_eq!(result.outcome, "transferred");
        assert_eq!(result.rows, 1);
        assert_eq!(encrypted_hex(&target, "auth"), before);
    }

    #[test]
    fn transfer_prunes_before_the_store_touches_the_profile_path() {
        let root = TestRoot::new("prune-first");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        create_store(
            &cookie_store(&application_support, &chrome),
            &[
                Cookie {
                    host: ".x.com",
                    name: "keep",
                    path: "/",
                    persistent: true,
                    encrypted: b"keep",
                },
                Cookie {
                    host: ".x.com",
                    name: "session",
                    path: "/",
                    persistent: false,
                    encrypted: b"drop-session",
                },
                Cookie {
                    host: ".other.test",
                    name: "other",
                    path: "/",
                    persistent: true,
                    encrypted: b"drop-domain",
                },
            ],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        fs::create_dir_all(&profile).unwrap();
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![chrome.clone()],
        );
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observer_values = Arc::clone(&observed);
        let plan = plan.with_profile_write_observer_for_test(Arc::new(move |store: &Path| {
            let value = sqlite_read(
                Path::new(SQLITE_PROGRAM),
                store,
                "SELECT host_key || '|' || name || '|' || has_expires FROM cookies;",
            )?;
            observer_values.lock().unwrap().push(value);
            Ok(())
        }));

        let result = plan.decide(Some("transfer:chrome"));
        assert_eq!(result.outcome, "transferred");
        assert_eq!(observed.lock().unwrap().as_slice(), [".x.com|keep|1\n"]);
    }

    #[test]
    fn durable_profile_can_reach_consent() {
        assert!(profile_precondition("https://x.com", true).is_ok());
    }

    #[test]
    fn an_unreadable_browser_does_not_fail_the_op() {
        let root = TestRoot::new("unreadable");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let brave = source("brave", "Brave", root.path());
        let unreadable = cookie_store(&application_support, &brave);
        fs::create_dir_all(unreadable.parent().unwrap()).unwrap();
        fs::write(&unreadable, b"not a sqlite store").unwrap();
        create_store(
            &cookie_store(&application_support, &chrome),
            &[Cookie {
                host: ".x.com",
                name: "auth",
                path: "/",
                persistent: true,
                encrypted: b"chrome",
            }],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        fs::create_dir_all(&profile).unwrap();
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![chrome.clone(), brave],
        );
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };

        assert_eq!(plan.presence().len(), 2);
        assert_eq!(plan.presence()[0].transfer, "available");
        assert_eq!(plan.presence()[1].reason, Some("unreadable"));
        let card = plan.question("agent");
        assert_eq!(
            card["params"]["facts"][1]["value"],
            "can't read saved logins"
        );
        assert_eq!(plan.decide(Some("transfer:chrome")).outcome, "transferred");
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_stores_are_os_protected_without_invoking_sqlite() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestRoot::new("os-protected");
        let application_support = root.path().join("Application Support");
        let browser = source("chrome", "Google Chrome", root.path());
        let store = cookie_store(&application_support, &browser);
        fs::create_dir_all(store.parent().unwrap()).unwrap();
        fs::write(&store, b"fixture store").unwrap();
        let safari_store = root.path().join("Safari.binarycookies");
        fs::write(&safari_store, b"fixture store").unwrap();
        let marker = root.path().join("sqlite-was-invoked");
        let reader = root.path().join("sqlite-reader");
        fs::write(
            &reader,
            format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&reader, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&safari_store, fs::Permissions::from_mode(0o000)).unwrap();
        for path in [&store, &safari_store] {
            assert_eq!(
                fs::File::open(path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "fixture must exercise a real denied read, not just mode bits"
            );
        }

        let settings = ImportSettings::for_test(
            reader.clone(),
            application_support,
            safari_store,
            vec![browser.clone()],
        );
        let prepare = |settings| {
            let PreparedImport::Ready(plan) = prepare_import(
                "https://x.com",
                "project-1",
                &browser.executable,
                DurableProfileLocation {
                    managed_root: root.path().join("managed"),
                    profile_directory: root.path().join("managed/profile"),
                },
                settings,
            ) else {
                panic!("supported fixture browser");
            };
            plan
        };
        let plan = prepare(settings.clone());
        assert_eq!(plan.presence().len(), 2);
        for presence in plan.presence() {
            assert_eq!(presence.reason, Some("os_protected"));
            assert_eq!(presence.transfer, "unsupported");
        }
        let card = plan.question("agent");
        for fact in card["params"]["facts"].as_array().unwrap().iter().take(2) {
            assert_eq!(fact["value"], "macOS protects this browser's data");
        }
        assert!(!marker.exists(), "SQLite must not run on a denied store");

        // A traversally denied directory must not hide an installed browser.
        fs::set_permissions(store.parent().unwrap(), fs::Permissions::from_mode(0o000)).unwrap();
        let plan = prepare(settings.clone());
        fs::set_permissions(store.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(plan.presence()[0].reason, Some("os_protected"));
        assert!(
            !marker.exists(),
            "SQLite must not run on a denied directory"
        );

        // The marker observes a real child invocation once the store is readable.
        fs::set_permissions(&store, fs::Permissions::from_mode(0o600)).unwrap();
        let plan = prepare(settings);
        assert_eq!(plan.presence()[0].reason, Some("unreadable"));
        assert!(marker.exists(), "the SQLite invocation control did not run");
    }

    #[test]
    fn a_missing_agent_store_is_created_from_the_pruned_copy() {
        let root = TestRoot::new("missing-target");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        create_store(
            &cookie_store(&application_support, &chrome),
            &[
                Cookie {
                    host: ".x.com",
                    name: "keep",
                    path: "/",
                    persistent: true,
                    encrypted: b"keep",
                },
                Cookie {
                    host: ".other.test",
                    name: "drop",
                    path: "/",
                    persistent: true,
                    encrypted: b"drop",
                },
            ],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        fs::create_dir_all(&profile).unwrap();
        let target = profile.join(COOKIES_RELATIVE_PATH);
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            root.path().join("Safari.binarycookies"),
            vec![chrome.clone()],
        );
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };

        assert_eq!(plan.decide(Some("transfer:chrome")).outcome, "transferred");
        assert!(target.exists());
        assert_eq!(
            sqlite_read(
                Path::new(SQLITE_PROGRAM),
                &target,
                "SELECT host_key || '|' || name FROM cookies;"
            )
            .unwrap(),
            ".x.com|keep\n"
        );
    }

    #[test]
    fn deny_and_hand_off_copy_nothing() {
        let root = TestRoot::new("no-copy");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        create_store(
            &cookie_store(&application_support, &chrome),
            &[Cookie {
                host: ".x.com",
                name: "source",
                path: "/",
                persistent: true,
                encrypted: b"source",
            }],
        );
        let profile = root.path().join("managed/profiles/profile-1");
        let target = profile.join(COOKIES_RELATIVE_PATH);
        create_store(
            &target,
            &[Cookie {
                host: ".x.com",
                name: "existing",
                path: "/",
                persistent: true,
                encrypted: b"existing",
            }],
        );
        let baseline = fs::read(&target).unwrap();
        for decision in ["deny", "hand_off"] {
            let settings = ImportSettings::for_test(
                PathBuf::from(SQLITE_PROGRAM),
                application_support.clone(),
                root.path().join("Safari.binarycookies"),
                vec![chrome.clone()],
            );
            let PreparedImport::Ready(plan) = prepare_import(
                "https://x.com",
                "project-1",
                &chrome.executable,
                DurableProfileLocation {
                    managed_root: root.path().join("managed"),
                    profile_directory: profile.clone(),
                },
                settings,
            ) else {
                panic!("supported fixture browser");
            };
            let mut plan = plan;
            for (browser, name, reason, session_rows) in [
                ("canary", "Chrome Canary", "different_keychain_item", 0),
                ("brave", "Brave", "session_only", 0),
                ("edge", "Microsoft Edge", "session_only", 1),
                ("unreadable", "Unreadable browser", "unreadable", 0),
                ("safari", "Safari", "safari_transfer_unsupported", 0),
            ] {
                plan.presence.push(BrowserPresence {
                    browser: browser.into(),
                    name: name.into(),
                    persistent_rows: 0,
                    session_rows,
                    transfer: "unsupported",
                    reason: Some(reason),
                });
            }
            let card = plan.question("agent_private");
            let facts = &card["params"]["facts"];
            assert_eq!(facts[0]["value"], "login available");
            assert_eq!(facts[1]["value"], "can't be copied (different keychain)");
            assert_eq!(facts[2]["value"], "nothing saved");
            assert_eq!(facts[3]["value"], "only a temporary login is saved");
            assert_eq!(facts[4]["value"], "can't read saved logins");
            assert_eq!(facts[5]["value"], "can't be copied from Safari");
            assert_eq!(facts[6]["value"], "No cookie value is read by the agent");
            crate::consent_card::assert_contract(
                &card,
                &["transfer:chrome", "hand_off", "deny"],
                "deny",
            );
            assert_eq!(card["params"]["urgency"], "high");
            assert_eq!(card["params"]["scope"], json!({"origin": "https://x.com"}));
            let banned = [
                "agent_",
                "persistent row",
                "different_keychain_item",
                "session_only",
                "source",
                "existing",
            ];
            let leaks = |text: &str| banned.iter().any(|token| text.contains(token));
            for token in banned {
                assert!(leaks(&format!("fixture {token}")));
            }
            let text = json!([
                card["params"]["title"],
                card["params"]["prompt"],
                card["params"]["facts"]
            ])
            .to_string();
            assert!(!leaks(&text), "{text}");
            assert_eq!(card["params"]["options"][1]["effect"], "grant");
            assert_eq!(
                plan.decide(Some(decision)).outcome,
                decision.replace("deny", "denied")
            );
            assert_eq!(fs::read(&target).unwrap(), baseline);
        }
    }

    #[test]
    fn unsupported_launch_binary_is_a_typed_refusal() {
        let root = TestRoot::new("unsupported");
        let chrome = source("chrome", "Google Chrome", root.path());
        let unknown = root.path().join("unknown-browser");
        fs::write(&unknown, b"unknown").unwrap();
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            root.path().join("Application Support"),
            root.path().join("Safari.binarycookies"),
            vec![chrome],
        );
        let result = prepare_import(
            "https://x.com",
            "project-1",
            &unknown,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: root.path().join("managed/profiles/profile-1"),
            },
            settings,
        );
        let PreparedImport::Refused(result) = result else {
            panic!("unknown launch binary must be refused");
        };
        assert_eq!(result.outcome, "launch_binary_unsupported");
    }

    #[test]
    fn safari_presence_is_listed_but_never_transferable() {
        let root = TestRoot::new("safari");
        let application_support = root.path().join("Application Support");
        let chrome = source("chrome", "Google Chrome", root.path());
        let safari = root.path().join("Cookies.binarycookies");
        let domain = b".x.com\0";
        let record_size = 36 + domain.len();
        let mut record = vec![0_u8; record_size];
        record[..4].copy_from_slice(&(record_size as u32).to_le_bytes());
        record[16..20].copy_from_slice(&36_u32.to_le_bytes());
        record[36..].copy_from_slice(domain);
        let mut page = vec![0_u8; 12];
        page[4..8].copy_from_slice(&1_u32.to_le_bytes());
        page[8..12].copy_from_slice(&12_u32.to_le_bytes());
        page.extend_from_slice(&record);
        let mut binarycookies = b"cook".to_vec();
        binarycookies.extend_from_slice(&1_u32.to_be_bytes());
        binarycookies.extend_from_slice(&(page.len() as u32).to_be_bytes());
        binarycookies.extend_from_slice(&page);
        fs::write(&safari, binarycookies).unwrap();
        let profile = root.path().join("managed/profiles/profile-1");
        fs::create_dir_all(&profile).unwrap();
        let settings = ImportSettings::for_test(
            PathBuf::from(SQLITE_PROGRAM),
            application_support,
            safari,
            vec![chrome.clone()],
        );
        let PreparedImport::Ready(plan) = prepare_import(
            "https://x.com",
            "project-1",
            &chrome.executable,
            DurableProfileLocation {
                managed_root: root.path().join("managed"),
                profile_directory: profile,
            },
            settings,
        ) else {
            panic!("supported fixture browser");
        };

        assert_eq!(plan.presence().len(), 1);
        assert_eq!(plan.presence()[0].browser, "safari");
        assert_eq!(plan.presence()[0].persistent_rows, 1);
        assert_eq!(plan.presence()[0].transfer, "unsupported");
        assert_eq!(
            plan.presence()[0].reason,
            Some("safari_transfer_unsupported")
        );
        assert!(!plan
            .question("agent")
            .to_string()
            .contains("transfer:safari"));
    }

    #[test]
    fn parent_domains_are_matched_without_a_psl_dependency() {
        assert_eq!(
            domain_candidates("login.accounts.x.com"),
            [
                "login.accounts.x.com",
                ".login.accounts.x.com",
                "accounts.x.com",
                ".accounts.x.com",
                "x.com",
                ".x.com",
            ]
        );
    }
}

#[cfg(all(test, unix))]
mod deadline_tests {
    use super::*;

    #[test]
    fn sqlite_large_stdout_is_drained_before_child_exit() {
        let program = crate::content_named_fixture::content_named_fixture(
            "sqlite-large-stdout",
            "sqlite",
            b"#!/bin/sh\nexec /usr/bin/awk 'BEGIN { for (i = 0; i < 16384; i++) print \"0123456789abcdef\" }'\n",
            0o700,
        );
        let start = Instant::now();
        let output = sqlite_read_until(
            &program,
            Path::new("/tmp/unused-cookie-store"),
            "PRAGMA quick_check;",
            start + Duration::from_secs(2),
        )
        .expect("large SQLite output must not block behind a full stdout pipe");
        assert_eq!(output, "0123456789abcdef\n".repeat(16384));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn sqlite_transfer_deadline_bounds_a_silent_child() {
        let program = crate::content_named_fixture::content_named_fixture(
            "sqlite-deadline",
            "sqlite",
            b"#!/bin/sh\nexec /bin/sleep 2\n",
            0o700,
        );
        let start = Instant::now();
        let error = sqlite_read_until(
            &program,
            Path::new("/tmp/unused-cookie-store"),
            "SELECT 1;",
            start + Duration::from_millis(40),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "silent SQLite exceeded the transfer deadline"
        );
    }
}
