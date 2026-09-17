//! Encrypted Chromium-cookie transfer for `browser.import_login`.
//!
//! Cookie values never leave SQLite. Presence queries read only `host_key` and
//! `has_expires`; transfer prunes a byte-for-byte copy and lets SQLite move the
//! surviving rows between stores owned by the same browser binary.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::profile_custody::{
    ProfileCustodyAcquisition, ProfileCustodyKey, ProfileCustodyLocks, ProfileCustodyRelease,
};

pub const ELICITATION_DEADLINE: Duration = Duration::from_secs(300);
const COOKIES_RELATIVE_PATH: &str = "Default/Cookies";
const SQLITE_PROGRAM: &str = "/usr/bin/sqlite3";

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
    pub application_support: PathBuf,
    pub safari_store: PathBuf,
    pub browsers: Vec<BrowserSource>,
}

impl ImportSettings {
    pub fn production(home: &Path) -> Self {
        let application_support = home.join("Library/Application Support");
        Self {
            sqlite_program: PathBuf::from(SQLITE_PROGRAM),
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
        }
    }
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

    pub fn question(&self, ask_id: &str, agent: &str) -> Value {
        let options = self
            .presence
            .iter()
            .filter(|browser| browser.transfer == "available")
            .map(|browser| format!("transfer:{}", browser.browser))
            .chain(["hand_off".to_string(), "deny".to_string()])
            .collect::<Vec<_>>();
        let descriptions = self
            .presence
            .iter()
            .map(|browser| {
                let availability = browser.reason.unwrap_or(browser.transfer);
                format!(
                    "{}: {} persistent row(s), {availability}",
                    browser.name, browser.persistent_rows
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        json!({
            "jsonrpc": "2.0",
            "id": ask_id,
            "method": "elicitation/create",
            "params": {
                "message": format!(
                    "Allow agent {agent} to import the persistent login for {} from a browser on this Mac? {}. No cookie value will be decrypted by the agent.",
                    self.host,
                    descriptions,
                ),
                "domain": self.host,
                "browsers": self.presence,
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "decision": {
                            "type": "string",
                            "enum": options,
                        }
                    },
                    "required": ["decision"],
                    "additionalProperties": false,
                },
            },
        })
    }

    pub fn refusal(&self, code: &'static str, remedy: &'static str) -> ImportResult {
        self.result(code, None, 0, Some(remedy))
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
                    Err(TransferError::ProfileBusy) => self.result(
                        "profile_busy",
                        Some(browser_id.to_string()),
                        0,
                        Some("close every browser session using this durable profile, then retry"),
                    ),
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

        let mut locks = ProfileCustodyLocks::open_filesystem(&self.location.managed_root)
            .map_err(|_| TransferError::Failed)?;
        let holder = locks.mint_holder().map_err(|_| TransferError::Failed)?;
        let mut claim = match locks
            .acquire(ProfileCustodyKey::durable(&self.project_id), holder)
            .map_err(|_| TransferError::Failed)?
        {
            ProfileCustodyAcquisition::Acquired(claim) => claim,
            ProfileCustodyAcquisition::ProfileBusy { .. } => {
                return Err(TransferError::ProfileBusy)
            }
        };
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
        )
        .map_err(|_| TransferError::Failed);
        let released = locks.release_exact(&claim);
        if !matches!(released, Ok(ProfileCustodyRelease::Released)) {
            return Err(TransferError::Failed);
        }
        transferred
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferError {
    ProfileBusy,
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
        location,
        settings,
        presence,
        observer: Arc::new(NoopProfileWriteObserver),
    })
}

pub fn profile_precondition(
    origin: &str,
    durable: bool,
    session_open: bool,
) -> Result<(), Box<ImportResult>> {
    if !durable {
        return Err(Box::new(ImportResult::refusal(
            origin,
            "profile_not_durable",
            "bind a primary route with a durable browser profile",
        )));
    }
    if session_open {
        return Err(Box::new(ImportResult::refusal(
            origin,
            "session_open",
            "browser.close",
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
        if !store.exists() {
            continue;
        }
        match chromium_presence(&settings.sqlite_program, &store, domains) {
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
            Err(_) => presence.push(BrowserPresence {
                browser: source.id.to_string(),
                name: source.display_name.to_string(),
                persistent_rows: 0,
                session_rows: 0,
                transfer: "unsupported",
                reason: Some("unreadable"),
            }),
        }
    }

    if settings.safari_store.exists() {
        match copied_safari_domains(&settings.safari_store) {
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
            Err(_) => presence.push(BrowserPresence {
                browser: "safari".to_string(),
                name: "Safari".to_string(),
                persistent_rows: 0,
                session_rows: 0,
                transfer: "unsupported",
                reason: Some("unreadable"),
            }),
        }
    }
    presence
}

fn chromium_presence(
    sqlite_program: &Path,
    source_store: &Path,
    domains: &[String],
) -> io::Result<(u64, u64)> {
    let temporary = PrivateTempDir::new("presence")?;
    let copied = temporary.path().join("Cookies");
    copy_private(source_store, &copied)?;
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
) -> io::Result<u64> {
    let temporary = PrivateTempDir::new("transfer")?;
    let pruned = temporary.path().join("Cookies");
    copy_private(source_store, &pruned)?;
    sqlite_write(
        sqlite_program,
        &pruned,
        &format!(
            "BEGIN IMMEDIATE; DELETE FROM cookies WHERE has_expires != 1 OR host_key NOT IN ({}); COMMIT;",
            sql_values(domains)
        ),
    )?;
    let rows =
        parse_count(sqlite_read(sqlite_program, &pruned, "SELECT COUNT(*) FROM cookies;")?.trim())?;
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

    let source_columns = cookie_columns(sqlite_program, &pruned)?;
    let target_columns = cookie_columns(sqlite_program, target_store)?;
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
    sqlite_write(sqlite_program, target_store, &sql)?;
    Ok(rows)
}

fn cookie_columns(sqlite_program: &Path, store: &Path) -> io::Result<Vec<String>> {
    let output = sqlite_read(
        sqlite_program,
        store,
        "SELECT name FROM pragma_table_info('cookies') ORDER BY cid;",
    )?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn sqlite_read(program: &Path, store: &Path, sql: &str) -> io::Result<String> {
    let uri = sqlite_uri(store);
    sqlite(
        program,
        Some(OsStr::new("-readonly")),
        OsStr::new(&uri),
        sql,
    )
}

fn sqlite_write(program: &Path, store: &Path, sql: &str) -> io::Result<String> {
    sqlite(program, None, store.as_os_str(), sql)
}

fn sqlite(program: &Path, mode: Option<&OsStr>, store: &OsStr, sql: &str) -> io::Result<String> {
    let mut command = Command::new(program);
    command.arg("-batch");
    if let Some(mode) = mode {
        command.arg(mode);
    }
    let output = command.arg(store).arg(sql).output()?;
    if !output.status.success() {
        return Err(io::Error::other("SQLite could not read the cookie store"));
    }
    String::from_utf8(output.stdout).map_err(|_| io::Error::other("SQLite returned non-UTF-8"))
}

fn sqlite_uri(path: &Path) -> String {
    format!("file:{}?immutable=1", path.to_string_lossy())
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

fn origin_host(origin: &str) -> Option<String> {
    if crate::classification::canonical_origin(origin).as_deref() != Some(origin) {
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

    use std::sync::Mutex;

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
        let question = plan.question("ask", "agent-1").to_string();
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
            .question("ask", "agent-1")
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
    fn transfer_refused_while_the_session_is_open() {
        let refusal = profile_precondition("https://x.com", true, true).unwrap_err();
        assert_eq!(refusal.outcome, "session_open");
        assert_eq!(refusal.remedy, Some("browser.close"));
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
        assert_eq!(plan.decide(Some("transfer:chrome")).outcome, "transferred");
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
            .question("ask", "agent")
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
