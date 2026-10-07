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
}

#[derive(Debug, Clone, Default)]
pub struct InstalledApplicationList {
    pub apps: Vec<InstalledApplication>,
    pub complete: bool,
}

/// Snapshot partial progress even when a filesystem read stalls past the bound.
pub fn installed_applications(timeout: Duration) -> InstalledApplicationList {
    let result = Arc::new(Mutex::new(InstalledApplicationList::default()));
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
                    complete = false;
                    break;
                }
            }
            complete &= Instant::now() < deadline;
            sink.lock().unwrap().complete = complete;
            let _ = tx.send(());
        });
    if spawned.is_ok() {
        let _ = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
    let mut snapshot = result.lock().unwrap().clone();
    snapshot.apps.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.path.cmp(&b.path))
    });
    snapshot.apps.dedup_by(|a, b| a.path == b.path);
    snapshot
}

fn scan(
    root: &Path,
    depth: usize,
    deadline: Instant,
    sink: &Mutex<InstalledApplicationList>,
) -> bool {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    let mut complete = true;
    for entry in entries {
        if Instant::now() >= deadline {
            return false;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        {
            match metadata(&path) {
                Some(app) => sink.lock().unwrap().apps.push(app),
                None => complete = false,
            }
        } else if depth > 0 && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            complete &= scan(&path, depth - 1, deadline, sink);
        }
    }
    complete
}

fn metadata(path: &Path) -> Option<InstalledApplication> {
    autoreleasepool(|_| {
        let plist = NSString::from_str(path.join("Contents/Info.plist").to_str()?);
        let class = AnyClass::get(c"NSDictionary")?;
        // SAFETY: this documented plist reader returns nil or an owned dictionary.
        let dictionary: Option<Retained<AnyObject>> =
            unsafe { msg_send![class, dictionaryWithContentsOfFile: &*plist] };
        let dictionary = dictionary?;
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
        let bundle_identifier = string("CFBundleIdentifier").filter(|id| !id.is_empty())?;
        let name = string("CFBundleDisplayName")
            .or_else(|| string("CFBundleName"))
            .unwrap_or_else(|| {
                path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
        Some(InstalledApplication {
            name,
            bundle_identifier,
            path: path.to_owned(),
        })
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
}

/// Open the exact selected URL. The completion pid, not a shell child or a
/// guessed name match, identifies the process whose first window is awaited.
pub fn open_application(
    path: &Path,
    bundle: &str,
    activates: bool,
    process_timeout: Duration,
    window_timeout: Duration,
) -> Result<ApplicationOpenResult, String> {
    let running = workspace_running_applications()?;
    let matching: Vec<_> = running
        .iter()
        .filter(|app| app.bundle_identifier == bundle)
        .collect();
    if matching.len() > 1 {
        return Err("multiple_running_instances".into());
    }
    let already_running = !matching.is_empty();
    let pid = if let Some(app) = matching.first() {
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
                let _: () = msg_send![&*workspace, openApplicationAtURL: &*url, configuration: &*config, completionHandler: &*completion];
            }
        });
        rx.recv_timeout(process_timeout)
            .map_err(|_| "process_timeout")??
    };
    let deadline = Instant::now() + window_timeout;
    let has_window = loop {
        if process_has_window(pid) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    Ok(ApplicationOpenResult {
        pid,
        already_running,
        has_window,
        frontmost: crate::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok())
            == Some(pid),
    })
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
        let result = Mutex::new(InstalledApplicationList::default());
        assert!(scan(
            &root,
            1,
            Instant::now() + Duration::from_secs(2),
            &result
        ));
        let mut names: Vec<_> = result
            .lock()
            .unwrap()
            .apps
            .iter()
            .map(|app| app.name.clone())
            .collect();
        names.sort();
        assert_eq!(names, ["Direct", "Nested"]);
        let expired = Mutex::new(InstalledApplicationList::default());
        assert!(!scan(&root, 1, Instant::now(), &expired));
        assert!(expired.lock().unwrap().apps.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
