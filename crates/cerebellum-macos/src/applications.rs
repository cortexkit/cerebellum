//! Installed bundle metadata and LaunchServices application opening.
//!
//! Inventory reads only Info.plist. Signature validation is a separate operation
//! performed only on the bundle selected for launch. No shell or child spawn is
//! used: NSWorkspace asks LaunchServices to create the app's own process.

use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::msg_send;
use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::{AnyClass, AnyObject};
use objc2_foundation::{NSArray, NSError, NSString, NSURL};

#[derive(Debug, Clone)]
pub struct InstalledApplication {
    pub name: String,
    pub bundle_identifier: String,
    pub path: PathBuf,
    pub version: Option<String>,
    pub build_version: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct InstalledApplicationList {
    pub apps: Vec<InstalledApplication>,
    pub complete: bool,
    pub unreadable: Vec<InstalledInventoryFailure>,
}

/// A bundle or directory omitted from an incomplete inventory, never its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledInventoryFailure {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Default)]
struct InventoryProgress {
    list: InstalledApplicationList,
    reading: PathBuf,
}

fn unreadable(sink: &Mutex<InventoryProgress>, path: &Path, reason: impl Into<String>) {
    sink.lock()
        .unwrap()
        .list
        .unreadable
        .push(InstalledInventoryFailure {
            path: path.to_owned(),
            reason: reason.into(),
        });
}

/// Snapshot partial progress even when a filesystem read stalls past the bound.
pub fn installed_applications(timeout: Duration) -> InstalledApplicationList {
    let result = Arc::new(Mutex::new(InventoryProgress {
        reading: PathBuf::from("/Applications"),
        ..Default::default()
    }));
    let sink = result.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    let deadline = Instant::now() + timeout;
    let spawned = std::thread::Builder::new()
        .name("installed-apps".into())
        .spawn(move || {
            let mut roots = vec![
                PathBuf::from("/Applications"),
                PathBuf::from("/System/Applications"),
                PathBuf::from("/System/Applications/Utilities"),
            ];
            if let Some(home) = std::env::var_os("HOME") {
                roots.push(PathBuf::from(home).join("Applications"));
            }
            let mut complete = true;
            for root in roots {
                complete &= scan(&root, 1, deadline, &sink);
                if Instant::now() >= deadline {
                    unreadable(
                        &sink,
                        &root,
                        "inventory deadline exceeded while scanning this directory",
                    );
                    complete = false;
                    break;
                }
            }
            complete &= Instant::now() < deadline;
            sink.lock().unwrap().list.complete = complete;
            let _ = tx.send(());
        });
    let failure = match spawned {
        Ok(_) => rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .err()
            .map(|error| {
                format!("inventory worker did not finish within its time budget: {error}")
            }),
        Err(error) => Some(format!("inventory worker could not start: {error}")),
    };
    let progress = result.lock().unwrap();
    let mut snapshot = progress.list.clone();
    if let Some(reason) = failure {
        snapshot.complete = false;
        snapshot.unreadable.push(InstalledInventoryFailure {
            path: progress.reading.clone(),
            reason,
        });
    }
    snapshot.apps.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.path.cmp(&b.path))
    });
    snapshot.apps.dedup_by(|a, b| a.path == b.path);
    snapshot
        .unreadable
        .sort_by(|a, b| a.path.cmp(&b.path).then(a.reason.cmp(&b.reason)));
    snapshot.unreadable.dedup();
    snapshot
}

fn scan(root: &Path, depth: usize, deadline: Instant, sink: &Mutex<InventoryProgress>) -> bool {
    sink.lock().unwrap().reading = root.to_owned();
    if Instant::now() >= deadline {
        unreadable(
            sink,
            root,
            "inventory deadline exceeded; directory was not fully scanned",
        );
        return false;
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(error) => {
            unreadable(sink, root, format!("cannot read directory: {error}"));
            return false;
        }
    };
    let mut complete = true;
    for entry in entries {
        if Instant::now() >= deadline {
            unreadable(
                sink,
                root,
                "inventory deadline exceeded; directory was not fully scanned",
            );
            return false;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                unreadable(sink, root, format!("cannot read directory entry: {error}"));
                complete = false;
                continue;
            }
        };
        let path = entry.path();
        sink.lock().unwrap().reading = path.clone();
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        {
            match metadata(&path) {
                Ok(app) => sink.lock().unwrap().list.apps.push(app),
                Err(reason) => {
                    unreadable(sink, &path.join("Contents/Info.plist"), reason);
                    complete = false;
                }
            }
        } else if depth > 0 {
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => complete &= scan(&path, depth - 1, deadline, sink),
                Ok(_) => {}
                Err(error) => {
                    unreadable(sink, &path, format!("cannot read entry type: {error}"));
                    complete = false;
                }
            }
        }
        sink.lock().unwrap().reading = root.to_owned();
    }
    complete
}

fn metadata(path: &Path) -> Result<InstalledApplication, String> {
    autoreleasepool(|_| {
        let plist_path = path.join("Contents/Info.plist");
        let plist = NSString::from_str(plist_path.to_str().ok_or("Info.plist path is not UTF-8")?);
        let class =
            AnyClass::get(c"NSDictionary").ok_or("Foundation dictionary class unavailable")?;
        // SAFETY: this documented plist reader returns nil or an owned dictionary.
        let dictionary: Option<Retained<AnyObject>> =
            unsafe { msg_send![class, dictionaryWithContentsOfFile: &*plist] };
        let dictionary = dictionary.ok_or("Info.plist is unreadable or not a valid dictionary")?;
        let string = |key: &str| -> Option<String> {
            let key = NSString::from_str(key);
            // SAFETY: dictionary lookup returns a borrowed object kept live by
            // the dictionary. Check its class before reading as NSString.
            let value: *mut AnyObject = unsafe { msg_send![&*dictionary, objectForKey: &*key] };
            if value.is_null() {
                return None;
            }
            let is_string: bool =
                unsafe { msg_send![value, isKindOfClass: AnyClass::get(c"NSString")?] };
            if !is_string {
                return None;
            }
            Some(unsafe { &*value.cast::<NSString>() }.to_string())
        };
        let bundle_identifier = string("CFBundleIdentifier")
            .filter(|id| !id.is_empty())
            .ok_or("CFBundleIdentifier is missing, empty or not a string")?;
        let name = string("CFBundleDisplayName")
            .or_else(|| string("CFBundleName"))
            .unwrap_or_else(|| {
                path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
        Ok(InstalledApplication {
            name,
            bundle_identifier,
            path: path.to_owned(),
            version: string("CFBundleShortVersionString"),
            build_version: string("CFBundleVersion"),
        })
    })
}

/// Read declared schemes from the selected bundle, without consulting the
/// machine's default handlers. Every Objective-C value is class-checked before
/// it is interpreted as an array, dictionary or string.
pub fn application_url_schemes(path: &Path) -> Result<Vec<String>, String> {
    autoreleasepool(|_| {
        let plist_path = path.join("Contents/Info.plist");
        let plist = NSString::from_str(plist_path.to_str().ok_or("invalid_bundle_path")?);
        let dictionary: Option<Retained<AnyObject>> = unsafe {
            msg_send![AnyClass::get(c"NSDictionary").ok_or("dictionary_unavailable")?, dictionaryWithContentsOfFile: &*plist]
        };
        let dictionary = dictionary.ok_or("unreadable_url_types")?;
        let types: *mut AnyObject = unsafe {
            msg_send![&*dictionary, objectForKey: &*NSString::from_str("CFBundleURLTypes")]
        };
        if types.is_null() {
            return Ok(Vec::new());
        }
        let array_class = AnyClass::get(c"NSArray").ok_or("array_unavailable")?;
        let dictionary_class = AnyClass::get(c"NSDictionary").ok_or("dictionary_unavailable")?;
        let string_class = AnyClass::get(c"NSString").ok_or("string_unavailable")?;
        let is_array: bool = unsafe { msg_send![types, isKindOfClass: array_class] };
        if !is_array {
            return Err("invalid_url_types".into());
        }
        let mut schemes = Vec::new();
        let types = unsafe { &*types.cast::<NSArray<AnyObject>>() };
        for entry in types.iter() {
            let is_dictionary: bool =
                unsafe { msg_send![&*entry, isKindOfClass: dictionary_class] };
            if !is_dictionary {
                return Err("invalid_url_type".into());
            }
            let values: *mut AnyObject = unsafe {
                msg_send![&*entry, objectForKey: &*NSString::from_str("CFBundleURLSchemes")]
            };
            if values.is_null() {
                continue;
            }
            let is_array: bool = unsafe { msg_send![values, isKindOfClass: array_class] };
            if !is_array {
                return Err("invalid_url_schemes".into());
            }
            for value in unsafe { &*values.cast::<NSArray<AnyObject>>() }.iter() {
                let is_string: bool = unsafe { msg_send![&*value, isKindOfClass: string_class] };
                if !is_string {
                    return Err("invalid_url_scheme".into());
                }
                schemes.push(
                    unsafe { &*(&*value as *const AnyObject).cast::<NSString>() }.to_string(),
                );
            }
        }
        Ok(schemes)
    })
}

/// Read-only AppKit process metadata, refreshed by pid from the kernel rather
/// than NSWorkspace's notification-maintained list (our worker has no run loop).
/// Unlike SCShareableContent, this cannot request Screen Recording.
pub fn workspace_running_applications() -> Result<Vec<crate::RunningApplication>, String> {
    let pids = crate::all_process_ids().map_err(|_| "process_table_unavailable".to_string())?;
    autoreleasepool(|_| {
        let class = AnyClass::get(c"NSRunningApplication").ok_or("workspace_unavailable")?;
        Ok(pids
            .into_iter()
            .filter_map(|pid| {
                let pid = i32::try_from(pid).ok()?;
                // SAFETY: documented read-only pid lookup and properties; retained
                // instances live through every read, and nothing is activated.
                let app: Option<Retained<AnyObject>> =
                    unsafe { msg_send![class, runningApplicationWithProcessIdentifier: pid] };
                let app = app?;
                let policy: isize = unsafe { msg_send![&*app, activationPolicy] };
                let id: Option<Retained<NSString>> = unsafe { msg_send![&*app, bundleIdentifier] };
                let name: Option<Retained<NSString>> = unsafe { msg_send![&*app, localizedName] };
                Some(crate::RunningApplication {
                    pid: pid as u32,
                    bundle_identifier: id?.to_string(),
                    name: name?.to_string(),
                    regular: Some(policy == 0),
                })
            })
            .collect())
    })
}

#[derive(Debug, Clone, Copy)]
pub struct ApplicationOpenResult {
    pub pid: u32,
    pub already_running: bool,
    pub has_window: bool,
    pub frontmost: bool,
    pub process_started_ms: u64,
    pub first_window_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RunningApplicationInstance {
    pub pid: u32,
    pub start_time_micros: u64,
    pub executable_path: PathBuf,
}

/// Bind each executable read to a kernel process generation, not a display name.
pub fn running_application_instances(
    bundle: &str,
) -> Result<Vec<RunningApplicationInstance>, String> {
    workspace_running_applications()?
        .into_iter()
        .filter(|app| app.bundle_identifier.eq_ignore_ascii_case(bundle))
        .map(|app| {
            let start_time_micros =
                crate::process_start_time_micros(app.pid).ok_or("process_identity_unavailable")?;
            let executable_path = crate::process_executable_path(app.pid)
                .ok()
                .flatten()
                .ok_or("process_executable_unavailable")?
                .canonicalize()
                .map_err(|_| "process_executable_unavailable")?;
            if crate::process_start_time_micros(app.pid) != Some(start_time_micros) {
                return Err("process_generation_changed".into());
            }
            Ok(RunningApplicationInstance {
                pid: app.pid,
                start_time_micros,
                executable_path,
            })
        })
        .collect()
}

fn verify_bundle_process(path: &Path, pid: u32, start_time_micros: u64) -> Result<(), String> {
    if crate::process_start_time_micros(pid) != Some(start_time_micros) {
        return Err("process_generation_changed".into());
    }
    let executable = crate::process_executable_path(pid)
        .ok()
        .flatten()
        .ok_or("process_executable_unavailable")?;
    let path = path.canonicalize().map_err(|_| "invalid_bundle_path")?;
    let executable = executable
        .canonicalize()
        .map_err(|_| "process_executable_unavailable")?;
    if !executable.starts_with(&path) || executable == path {
        return Err("process_outside_selected_bundle".into());
    }
    if crate::process_start_time_micros(pid) != Some(start_time_micros) {
        return Err("process_generation_changed".into());
    }
    Ok(())
}

/// Observe an already selected process without asking the OS to open anything.
pub fn inspect_running_application(
    path: &Path,
    bundle: &str,
    pid: u32,
    start_time_micros: u64,
) -> Result<ApplicationOpenResult, String> {
    let running = running_application_instances(bundle)?;
    if !matches!(running.as_slice(), [instance] if instance.pid == pid && instance.start_time_micros == start_time_micros)
    {
        return Err("running_application_changed".into());
    }
    let has_window = process_has_window(pid);
    verify_bundle_process(path, pid, start_time_micros)?;
    Ok(ApplicationOpenResult {
        pid,
        already_running: true,
        has_window,
        frontmost: crate::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok())
            == Some(pid),
        process_started_ms: 0,
        first_window_ms: has_window.then_some(0),
    })
}

/// Open the exact selected URL. The completion pid, not a shell child or a
/// guessed name match, identifies the process whose first window is awaited.
pub fn open_application(
    path: &Path,
    bundle: &str,
    activates: bool,
    process_timeout: Duration,
    window_timeout: Duration,
    ready_timeout: Duration,
) -> Result<ApplicationOpenResult, String> {
    open_application_with_url(
        path,
        bundle,
        None,
        activates,
        process_timeout,
        window_timeout,
        ready_timeout,
    )
}

// Keep the URL launch and plain launch on the same bounded implementation.
#[allow(clippy::too_many_arguments)]
pub fn open_application_with_url(
    path: &Path,
    bundle: &str,
    page_url: Option<&str>,
    activates: bool,
    process_timeout: Duration,
    window_timeout: Duration,
    ready_timeout: Duration,
) -> Result<ApplicationOpenResult, String> {
    open_application_with_url_checked(
        path,
        bundle,
        page_url,
        activates,
        process_timeout,
        window_timeout,
        ready_timeout,
        None,
    )
}

/// Deliver a URL by bundle path, refusing to label a replacement process as already running.
#[allow(clippy::too_many_arguments)]
pub fn open_running_application_with_url(
    path: &Path,
    bundle: &str,
    page_url: &str,
    pid: u32,
    start_time_micros: u64,
    process_timeout: Duration,
    window_timeout: Duration,
    ready_timeout: Duration,
) -> Result<ApplicationOpenResult, String> {
    open_application_with_url_checked(
        path,
        bundle,
        Some(page_url),
        false,
        process_timeout,
        window_timeout,
        ready_timeout,
        Some((pid, start_time_micros)),
    )
}

fn verify_running_snapshot(
    running: &[RunningApplicationInstance],
    expected: (u32, u64),
) -> Result<(), String> {
    if matches!(running, [instance] if (instance.pid, instance.start_time_micros) == expected) {
        Ok(())
    } else {
        Err("running_application_changed".into())
    }
}

#[allow(clippy::too_many_arguments)]
fn open_application_with_url_checked(
    path: &Path,
    bundle: &str,
    page_url: Option<&str>,
    activates: bool,
    process_timeout: Duration,
    window_timeout: Duration,
    ready_timeout: Duration,
    expected: Option<(u32, u64)>,
) -> Result<ApplicationOpenResult, String> {
    let started = Instant::now();
    let ready_deadline = started + ready_timeout;
    let matching = running_application_instances(bundle)?;
    if let Some(expected) = expected {
        verify_running_snapshot(&matching, expected)?;
    }
    if matching.len() > 1 {
        return Err("multiple_running_instances".into());
    }
    let already_running = !matching.is_empty();
    if let Some(instance) = matching.first() {
        verify_bundle_process(path, instance.pid, instance.start_time_micros)?;
    }
    let pid = if page_url.is_none() && !matching.is_empty() {
        let app = &matching[0];
        app.pid
    } else {
        let (tx, rx) = mpsc::sync_channel(1);
        let url = NSURL::fileURLWithPath(&NSString::from_str(
            path.to_str().ok_or("invalid_bundle_path")?,
        ));
        let workspace_class = AnyClass::get(c"NSWorkspace").ok_or("workspace_unavailable")?;
        let config_class =
            AnyClass::get(c"NSWorkspaceOpenConfiguration").ok_or("configuration_unavailable")?;
        autoreleasepool(|_| {
            // SAFETY: documented AppKit constructors and properties. The copied
            // block transfers only the pid/error text, never an ObjC pointer.
            let workspace: Retained<AnyObject> =
                unsafe { msg_send![workspace_class, sharedWorkspace] };
            let config: Retained<AnyObject> = unsafe { msg_send![config_class, configuration] };
            unsafe {
                let _: () = msg_send![&*config, setActivates: activates];
            }
            let completion = RcBlock::new(move |app: *mut AnyObject, error: *mut NSError| {
                let result = if !error.is_null() {
                    Err("launch_failed".to_string())
                } else if app.is_null() {
                    Err("launch_returned_no_process".to_string())
                } else {
                    let pid: i32 = unsafe { msg_send![&*app, processIdentifier] };
                    u32::try_from(pid).map_err(|_| "invalid_process_id".into())
                };
                let _ = tx.send(result);
            });
            unsafe {
                if let Some(page) = page_url {
                    let page: Option<Retained<NSURL>> = msg_send![AnyClass::get(c"NSURL").ok_or("URL_class_unavailable")?, URLWithString: &*NSString::from_str(page)];
                    let page = page.ok_or("invalid_page_url")?;
                    let pages = NSArray::from_retained_slice(&[page]);
                    let _: () = msg_send![&*workspace, openURLs: &*pages, withApplicationAtURL: &*url, configuration: &*config, completionHandler: &*completion];
                } else {
                    let _: () = msg_send![&*workspace, openApplicationAtURL: &*url, configuration: &*config, completionHandler: &*completion];
                }
            }
            Ok::<(), String>(())
        })?;
        rx.recv_timeout(bounded_wait(
            Instant::now(),
            process_timeout,
            ready_deadline,
        ))
        .map_err(|_| "process_timeout")??
    };
    let start_time_micros =
        crate::process_start_time_micros(pid).ok_or("process_identity_unavailable")?;
    if matching.first().is_some_and(|instance| {
        instance.pid != pid || instance.start_time_micros != start_time_micros
    }) {
        return Err("process_generation_changed".into());
    }
    // LaunchServices can reuse another installation despite an exact URL.
    // Never report that process as the selected, signer-approved bundle.
    verify_bundle_process(path, pid, start_time_micros)?;
    let process_started_ms = started.elapsed().as_millis() as u64;
    let now = Instant::now();
    let deadline = now + bounded_wait(now, window_timeout, ready_deadline);
    let has_window = loop {
        if process_has_window(pid) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
        );
    };
    verify_bundle_process(path, pid, start_time_micros)?;
    if let Some(expected) = expected {
        verify_running_snapshot(&running_application_instances(bundle)?, expected)?;
    }
    Ok(ApplicationOpenResult {
        pid,
        already_running,
        has_window,
        process_started_ms,
        first_window_ms: has_window.then(|| started.elapsed().as_millis() as u64),
        frontmost: crate::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok())
            == Some(pid),
    })
}

fn bounded_wait(now: Instant, stage_timeout: Duration, ready_deadline: Instant) -> Duration {
    stage_timeout.min(ready_deadline.saturating_duration_since(now))
}

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGWindowListCopyWindowInfo(option: u32, relative: u32) -> *mut NSArray<AnyObject>;
}
#[link(name = "System")]
extern "C" {
    fn responsibility_get_pid_responsible_for_pid(pid: i32) -> i32;
}

fn process_has_window(pid: u32) -> bool {
    autoreleasepool(|_| {
        // SAFETY: Copy returns an owned CFArray, toll-free bridged to NSArray.
        // Window metadata (owner pid and layer only) is readable without TCC.
        let windows = unsafe { Retained::from_raw(CGWindowListCopyWindowInfo(16, 0)) };
        let Some(windows) = windows else {
            return false;
        };
        let owner = NSString::from_str("kCGWindowOwnerPID");
        let layer = NSString::from_str("kCGWindowLayer");
        windows.iter().any(|window| {
            let owner: Option<Retained<AnyObject>> =
                unsafe { msg_send![&*window, objectForKey: &*owner] };
            let layer: Option<Retained<AnyObject>> =
                unsafe { msg_send![&*window, objectForKey: &*layer] };
            match (owner, layer) {
                (Some(owner), Some(layer)) => {
                    let owner: u32 = unsafe { msg_send![&*owner, unsignedIntValue] };
                    let layer: i32 = unsafe { msg_send![&*layer, intValue] };
                    owner == pid && layer == 0
                }
                _ => false,
            }
        })
    })
}

/// Attribution probe: a LaunchServices app should be responsible for itself,
/// rather than inheriting the agent's permission attribution.
pub fn responsible_pid(pid: u32) -> Option<u32> {
    let pid = i32::try_from(pid).ok()?;
    // SAFETY: pid-in, pid-out; no pointers or ownership.
    let responsible = unsafe { responsibility_get_pid_responsible_for_pid(pid) };
    u32::try_from(responsible).ok().filter(|pid| *pid > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_and_window_waits_share_one_total_launch_deadline() {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(120);
        assert_eq!(
            bounded_wait(started, Duration::from_secs(120), deadline),
            Duration::from_secs(120)
        );
        assert_eq!(
            bounded_wait(
                started + Duration::from_secs(90),
                Duration::from_secs(120),
                deadline
            ),
            Duration::from_secs(30)
        );
        assert_eq!(
            bounded_wait(deadline, Duration::from_secs(120), deadline),
            Duration::ZERO
        );
        assert_eq!(
            bounded_wait(
                deadline + Duration::from_secs(1),
                Duration::from_secs(120),
                deadline
            ),
            Duration::ZERO
        );
        assert_eq!(
            bounded_wait(started, Duration::from_secs(10), deadline),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn page_schemes_come_only_from_the_selected_bundles_url_types() {
        let root = std::env::temp_dir().join(format!("ck-page-schemes-{}", std::process::id()));
        let contents = root.join("Contents");
        std::fs::create_dir_all(&contents).unwrap();
        let path = contents.join("Info.plist");
        std::fs::write(&path, "<plist><dict><key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>x-apple.systempreferences</string><string>synthetic-editor</string></array></dict></array></dict></plist>").unwrap();
        assert_eq!(
            application_url_schemes(&root).unwrap(),
            ["x-apple.systempreferences", "synthetic-editor"]
        );
        std::fs::write(
            &path,
            "<plist><dict><key>CFBundleURLTypes</key><string>not an array</string></dict></plist>",
        )
        .unwrap();
        assert!(application_url_schemes(&root).is_err());
        std::fs::write(&path, "<plist><dict></dict></plist>").unwrap();
        assert!(application_url_schemes(&root).unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installed_scan_reads_only_plists_and_one_subfolder_level() {
        let root = std::env::temp_dir().join(format!("ck-app-inventory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        fn app(root: &Path, name: &str) {
            let contents = root.join(format!("{name}.app/Contents"));
            std::fs::create_dir_all(&contents).unwrap();
            std::fs::write(contents.join("Info.plist"),format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleName</key><string>{name}</string><key>CFBundleIdentifier</key><string>com.example.{name}</string></dict></plist>")).unwrap();
            // Invalid non-plist contents are irrelevant to inventory.
            std::fs::write(contents.join("secret"), b"not metadata").unwrap();
        }
        app(&root, "Direct");
        app(&root.join("Folder"), "Nested");
        app(&root.join("Folder/Deeper"), "Excluded");
        app(&root.join("Direct.app/Contents"), "InsideBundle");
        let result = Mutex::new(InventoryProgress::default());
        assert!(scan(
            &root,
            1,
            Instant::now() + Duration::from_secs(2),
            &result
        ));
        let mut names: Vec<_> = result
            .lock()
            .unwrap()
            .list
            .apps
            .iter()
            .map(|app| app.name.clone())
            .collect();
        names.sort();
        assert_eq!(names, ["Direct", "Nested"]);
        let expired = Mutex::new(InventoryProgress::default());
        assert!(!scan(&root, 1, Instant::now(), &expired));
        assert!(expired.lock().unwrap().list.apps.is_empty());
        assert_eq!(expired.lock().unwrap().list.unreadable[0].path, root);
        assert!(expired.lock().unwrap().list.unreadable[0]
            .reason
            .contains("deadline exceeded"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installed_scan_reports_each_bad_plist_without_losing_readable_apps() {
        let root =
            std::env::temp_dir().join(format!("ck-app-inventory-failures-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (name, plist) in [
            ("Good", Some("<plist><dict><key>CFBundleIdentifier</key><string>com.example.Good</string></dict></plist>")),
            ("Missing", None),
            ("NoIdentifier", Some("<plist><dict><key>CFBundleName</key><string>NoIdentifier</string></dict></plist>")),
        ] {
            let contents = root.join(format!("{name}.app/Contents"));
            std::fs::create_dir_all(&contents).unwrap();
            if let Some(plist) = plist {
                std::fs::write(contents.join("Info.plist"), plist).unwrap();
            }
        }
        let result = Mutex::new(InventoryProgress::default());
        assert!(!scan(
            &root,
            1,
            Instant::now() + Duration::from_secs(2),
            &result
        ));
        let progress = result.lock().unwrap();
        assert_eq!(progress.list.apps.len(), 1);
        assert_eq!(progress.list.apps[0].name, "Good");
        assert_eq!(progress.list.unreadable.len(), 2);
        for (name, reason) in [
            ("Missing", "Info.plist is unreadable"),
            ("NoIdentifier", "CFBundleIdentifier is missing"),
        ] {
            assert!(
                progress.list.unreadable.iter().any(|failure| failure.path
                    == root.join(format!("{name}.app/Contents/Info.plist"))
                    && failure.reason.starts_with(reason)),
                "{:?}",
                progress.list.unreadable
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn selected_bundle_process_requires_both_containment_and_same_generation() {
        let pid = std::process::id();
        let start = crate::process_start_time_micros(pid).unwrap();
        let executable = crate::process_executable_path(pid).unwrap().unwrap();
        let parent = executable.parent().unwrap();
        assert!(verify_bundle_process(parent, pid, start).is_ok());
        assert_eq!(
            verify_bundle_process(parent, pid, start + 1).unwrap_err(),
            "process_generation_changed"
        );
        assert_eq!(
            verify_bundle_process(&parent.join("other-copy.app"), pid, start).unwrap_err(),
            "invalid_bundle_path"
        );
        assert_eq!(
            verify_bundle_process(Path::new(env!("CARGO_MANIFEST_DIR")), pid, start).unwrap_err(),
            "process_outside_selected_bundle"
        );
    }

    #[test]
    fn installed_metadata_reads_both_version_keys() {
        let root = std::env::temp_dir().join(format!("ck-app-versions-{}", std::process::id()));
        let contents = root.join("Versioned.app/Contents");
        std::fs::create_dir_all(&contents).unwrap();
        std::fs::write(contents.join("Info.plist"), "<plist><dict><key>CFBundleIdentifier</key><string>com.example.Versioned</string><key>CFBundleShortVersionString</key><string>0.20.23</string><key>CFBundleVersion</key><string>1234.5</string></dict></plist>").unwrap();
        let app = metadata(&root.join("Versioned.app")).unwrap();
        assert_eq!(app.version.as_deref(), Some("0.20.23"));
        assert_eq!(app.build_version.as_deref(), Some("1234.5"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn running_url_snapshot_rejects_new_or_reused_processes() {
        let original = RunningApplicationInstance {
            pid: 42,
            start_time_micros: 123,
            executable_path: "/Applications/Fixture.app/Contents/MacOS/Fixture".into(),
        };
        let expected = (original.pid, original.start_time_micros);
        assert!(verify_running_snapshot(std::slice::from_ref(&original), expected).is_ok());
        let mut additional = original.clone();
        additional.pid += 1;
        assert!(verify_running_snapshot(&[original.clone(), additional], expected).is_err());
        let mut replacement = original;
        replacement.start_time_micros += 1;
        assert!(verify_running_snapshot(&[replacement], expected).is_err());
        assert!(verify_running_snapshot(&[], expected).is_err());
    }
}
