use super::{shell_image, version::image_version, Principal};
use crate::platform::windows::app_state::windows::{eligible_state, is_default_desktop};
use crate::platform::{ProcessGrant, TargetCandidate, TargetResolution, UnreadableReason};
use cerebellum_windows::{
    child_window_numbers, desktop_window_numbers, lock_image_file, retain_image_process,
    window_identity_facts, windows_system_directory, AuthenticodeFacts, FileIdentity,
    ImageMappingReading, LockedImageFile, ProcessStartTime, RetainedProcessHandle,
    WindowIdentityFacts,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
pub const IDENTITY_BOUND: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum IdentityError {
    Deadline,
    ReadingUnavailable,
    ProcessChanged,
    ImageMappingStatus(i32),
    AuthenticodeStatus(i32),
    Shell,
}

#[derive(Clone, Debug)]
pub struct LiveIdentity {
    pub principal: Principal,
    pub image_path: PathBuf,
    pub image_name: String,
    pub original_filename: Option<String>,
    pub display_name: String,
    pub generation: u64,
}

impl LiveIdentity {
    pub fn grant(&self, pid: u32) -> ProcessGrant {
        ProcessGrant {
            pid,
            bundle_identity: self.principal.to_string(),
            process_generation_evidence: self.generation.to_string(),
        }
    }

    pub fn matches_grant(&self, grant: &ProcessGrant) -> bool {
        grant.bundle_identity == self.principal.to_string()
            && grant.process_generation_evidence == self.generation.to_string()
    }
}

fn remaining(deadline: Instant) -> Result<Duration, IdentityError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or(IdentityError::Deadline)
}

// WinTrust and filesystem opens cannot be cancelled. Keep the worker occupied
// until they really return, so repeated timeouts cannot pile up blocked reads.
fn within_deadline<T: Send + 'static>(
    deadline: Instant,
    work: impl FnOnce() -> Result<T, IdentityError> + Send + 'static,
) -> Result<T, IdentityError> {
    static OCCUPIED: AtomicBool = AtomicBool::new(false);
    struct Occupied;
    impl Drop for Occupied {
        fn drop(&mut self) {
            OCCUPIED.store(false, Ordering::Release);
        }
    }
    remaining(deadline)?;
    if OCCUPIED.swap(true, Ordering::Acquire) {
        return Err(IdentityError::ReadingUnavailable);
    }
    let occupied = Occupied;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("windows-image-identity".into())
        .spawn(move || {
            let result = work();
            drop(occupied);
            let _ = send.send(result);
        })
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    let result = receive
        .recv_timeout(remaining(deadline)?)
        .map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => IdentityError::Deadline,
            std::sync::mpsc::RecvTimeoutError::Disconnected => IdentityError::ReadingUnavailable,
        })?;
    remaining(deadline)?;
    result
}

pub fn live_identity(pid: u32, deadline: Instant) -> Result<LiveIdentity, IdentityError> {
    within_deadline(deadline, move || {
        let process = retain_image_process(pid).map_err(|_| IdentityError::ReadingUnavailable)?;
        read_identity(&process, deadline)
    })
}

fn current_generation(process: &RetainedProcessHandle) -> Result<u64, IdentityError> {
    if !process.process_wait_pending() {
        return Err(IdentityError::ProcessChanged);
    }
    match process.creation_time() {
        ProcessStartTime::Started(generation) => Ok(generation),
        _ => Err(IdentityError::ReadingUnavailable),
    }
}

fn mapped_id(
    process: &RetainedProcessHandle,
    file: &LockedImageFile,
) -> Result<FileIdentity, IdentityError> {
    match process
        .image_mapping(file)
        .map_err(|_| IdentityError::ReadingUnavailable)?
    {
        ImageMappingReading::SameFile(id) => Ok(id),
        ImageMappingReading::NtStatus(status) => Err(IdentityError::ImageMappingStatus(status)),
    }
}

fn read_identity(
    process: &RetainedProcessHandle,
    deadline: Instant,
) -> Result<LiveIdentity, IdentityError> {
    remaining(deadline)?;
    let generation = current_generation(process)?;
    let path = process
        .image_path()
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    let image_name = image_name(&path)?;
    if shell_image(&image_name) {
        return Err(IdentityError::Shell);
    }
    let file = lock_image_file(&path).map_err(|_| IdentityError::ReadingUnavailable)?;
    let file_id = mapped_id(process, &file)?;
    let image_path = file
        .final_path()
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    if shell_image(&self::image_name(&image_path)?) {
        return Err(IdentityError::Shell);
    }

    let mut reader = file.read_only_handle();
    let metadata = reader
        .metadata()
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    if metadata.len() > MAX_IMAGE_BYTES {
        return Err(IdentityError::ReadingUnavailable);
    }
    let mut image = Vec::new();
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    reader
        .take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut image)
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    if image.len() as u64 != metadata.len() {
        return Err(IdentityError::ReadingUnavailable);
    }
    let version = image_version(&image).map_err(|()| IdentityError::ReadingUnavailable)?;
    let original_filename = version.original_filename;
    if original_filename.as_deref().is_some_and(shell_image) {
        return Err(IdentityError::Shell);
    }
    remaining(deadline)?;

    let unsigned = || Principal::Unsigned {
        sha256: Sha256::digest(&image).into(),
        image_name: image_name.clone(),
    };
    let package = process
        .package_fields()
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    let principal = if let Some(package) = package {
        let (family, application) = package
            .aumid
            .split_once('!')
            .ok_or(IdentityError::ReadingUnavailable)?;
        if family != package.family || application.is_empty() || application.contains('!') {
            return Err(IdentityError::ReadingUnavailable);
        }
        Principal::Packaged {
            family: package.family,
            application: application.to_owned(),
        }
    } else {
        match file
            .authenticode_facts(&image_path)
            .map_err(|_| IdentityError::ReadingUnavailable)?
        {
            AuthenticodeFacts::Signer(signer) => {
                if signer.common_name.is_empty() && signer.organization.is_empty() {
                    return Err(IdentityError::ReadingUnavailable);
                }
                match &original_filename {
                    Some(program) => Principal::Signed {
                        root: Sha256::digest(&signer.root_der).into(),
                        cn: signer.common_name,
                        organization: signer.organization,
                        program: program.clone(),
                    },
                    None => unsigned(),
                }
            }
            AuthenticodeFacts::EmbeddedAndCatalogAbsent if !version.has_certificate_table => {
                unsigned()
            }
            AuthenticodeFacts::Status(status) => {
                return Err(IdentityError::AuthenticodeStatus(status))
            }
            _ => return Err(IdentityError::ReadingUnavailable),
        }
    };
    remaining(deadline)?;
    if mapped_id(process, &file)? != file_id || current_generation(process)? != generation {
        return Err(IdentityError::ProcessChanged);
    }
    let display_name = version.description.unwrap_or_else(|| image_name.clone());
    Ok(LiveIdentity {
        principal,
        image_path,
        image_name,
        original_filename,
        display_name,
        generation,
    })
}

fn image_name(path: &Path) -> Result<String, IdentityError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or(IdentityError::ReadingUnavailable)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameProof {
    root: (u32, u32, u32),
    host_generation: Option<u64>,
    hosted: Option<(u32, u32, u32)>,
    process_generation: u64,
}

impl FrameProof {
    pub(crate) fn content_window_and_thread(&self) -> (u32, u32) {
        let (window, _, thread) = self.hosted.unwrap_or(self.root);
        (window, thread)
    }
}

pub(crate) fn frame_target_pid(root: &WindowIdentityFacts) -> Result<u32, IdentityError> {
    if root.class == "ApplicationFrameWindow" {
        frame_parts(root).map(|(_, child)| child.pid)
    } else {
        Ok(root.pid)
    }
}

fn window_key(window: &WindowIdentityFacts) -> (u32, u32, u32) {
    (window.number, window.pid, window.tid)
}

fn frame_parts(root: &WindowIdentityFacts) -> Result<(u64, WindowIdentityFacts), IdentityError> {
    let host = retain_image_process(root.pid).map_err(|_| IdentityError::ReadingUnavailable)?;
    let generation = current_generation(&host)?;
    let system = windows_system_directory().map_err(|_| IdentityError::ReadingUnavailable)?;
    let host_file = lock_image_file(&system.join("ApplicationFrameHost.exe"))
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    // A process with the same basename is not the system frame host.
    mapped_id(&host, &host_file)?;
    let mut child = None;
    for number in child_window_numbers(root.number) {
        let facts = window_identity_facts(number).map_err(|_| IdentityError::ReadingUnavailable)?;
        if facts.class == "Windows.UI.Core.CoreWindow"
            && facts.pid != root.pid
            && child.replace(facts).is_some()
        {
            return Err(IdentityError::ReadingUnavailable);
        }
    }
    let now = window_identity_facts(root.number).map_err(|_| IdentityError::ReadingUnavailable)?;
    if now.class != root.class
        || window_key(root) != window_key(&now)
        || current_generation(&host)? != generation
    {
        return Err(IdentityError::ProcessChanged);
    }
    Ok((generation, child.ok_or(IdentityError::ReadingUnavailable)?))
}

/// Bind an HWND to the caller's retained, still-live process. Re-read and
/// compare the complete proof immediately before using the window again.
pub fn frame_proof(
    process: &RetainedProcessHandle,
    pid: u32,
    number: u32,
) -> Result<Option<FrameProof>, IdentityError> {
    if process.pid() != pid || pid == 0 {
        return Err(IdentityError::ProcessChanged);
    }
    let process_generation = current_generation(process)?;
    let root = window_identity_facts(number).map_err(|_| IdentityError::ReadingUnavailable)?;
    let (host_generation, hosted) = if root.class == "ApplicationFrameWindow" {
        let (generation, child) = frame_parts(&root)?;
        if child.pid != pid {
            return Ok(None);
        }
        (Some(generation), Some(window_key(&child)))
    } else if root.pid == pid {
        (None, None)
    } else {
        return Ok(None);
    };
    if current_generation(process)? != process_generation {
        return Err(IdentityError::ProcessChanged);
    }
    Ok(Some(FrameProof {
        root: window_key(&root),
        host_generation,
        hosted,
        process_generation,
    }))
}

#[derive(Debug)]
pub struct RunningIdentity {
    pub pid: u32,
    pub identity: LiveIdentity,
    pub window_count: usize,
}

#[derive(Debug, Default)]
pub struct IdentityInventory {
    pub apps: Vec<RunningIdentity>,
    pub unreadable: Vec<String>,
    pub blocked: Vec<String>,
    pub unattributed_windows: usize,
}

pub fn identity_inventory(deadline: Instant) -> Result<IdentityInventory, IdentityError> {
    within_deadline(deadline, move || read_inventory(deadline, None))
}

type ListedIdentity = (u32, LiveIdentity, bool);

/// Listing may omit unreadable identities; target resolution still needs the
/// entire inventory to rule out another process with the same principal.
pub(crate) fn running_list(deadline: Instant) -> Result<Vec<ListedIdentity>, IdentityError> {
    let progress = Arc::new(Mutex::new(None));
    let worker = Arc::clone(&progress);
    let result = within_deadline(deadline, move || read_inventory(deadline, Some(&worker)));
    if !matches!(result, Ok(_) | Err(IdentityError::Deadline)) || !is_default_desktop() {
        return Err(IdentityError::ReadingUnavailable);
    }
    let mut progress = progress
        .lock()
        .map_err(|_| IdentityError::ReadingUnavailable)?;
    progress.take().ok_or(IdentityError::ReadingUnavailable)
}

fn read_inventory(
    deadline: Instant,
    listing: Option<&Mutex<Option<Vec<ListedIdentity>>>>,
) -> Result<IdentityInventory, IdentityError> {
    if !is_default_desktop() {
        return Err(IdentityError::ReadingUnavailable);
    }
    let mut inventory = IdentityInventory::default();
    let mut windows = BTreeMap::<u32, Vec<WindowIdentityFacts>>::new();
    let mut frames = BTreeSet::new();
    for number in desktop_window_numbers().map_err(|_| IdentityError::ReadingUnavailable)? {
        remaining(deadline)?;
        let Ok(root) = window_identity_facts(number) else {
            inventory.unattributed_windows += 1;
            continue;
        };
        match eligible_state(&root) {
            Ok(Some(_)) => (),
            Ok(None) => continue,
            Err(_) => {
                inventory.unattributed_windows += 1;
                continue;
            }
        }
        let pid = if root.class == "ApplicationFrameWindow" {
            match frame_parts(&root) {
                Ok((_, child)) => {
                    frames.insert(number);
                    child.pid
                }
                Err(_) => {
                    inventory.unattributed_windows += 1;
                    continue;
                }
            }
        } else {
            root.pid
        };
        windows.entry(pid).or_default().push(root);
    }
    let foreground = if let Some(list) = listing {
        *list.lock().map_err(|_| IdentityError::ReadingUnavailable)? = Some(Vec::new());
        cerebellum_windows::foreground_window_number()
    } else {
        None
    };
    for (pid, roots) in windows {
        remaining(deadline)?;
        let process = retain_image_process(pid).ok();
        let path_name = process
            .as_ref()
            .and_then(|p| p.image_path().ok())
            .and_then(|path| image_name(&path).ok());
        let mut names: Vec<_> = roots
            .iter()
            .map(|root| root.title.clone())
            .filter(|title| !title.is_empty())
            .collect();
        names.extend(path_name);
        let Some(process) = process else {
            inventory.unreadable.extend(names);
            inventory.unattributed_windows += 1;
            continue;
        };
        let identity = match read_identity(&process, deadline) {
            Ok(identity) => identity,
            Err(IdentityError::Shell) => {
                inventory.blocked.extend(names);
                continue;
            }
            Err(IdentityError::Deadline) => return Err(IdentityError::Deadline),
            Err(_) => {
                inventory.unreadable.extend(names);
                inventory.unattributed_windows += 1;
                continue;
            }
        };
        let mut frontmost = false;
        let window_count = roots
            .iter()
            .filter(|root| {
                let bound = window_identity_facts(root.number).is_ok_and(|now| {
                    window_key(&now) == window_key(root)
                        && eligible_state(&now).is_ok_and(|s| s.is_some())
                }) && (!frames.contains(&root.number)
                    || frame_proof(&process, pid, root.number).is_ok_and(|proof| proof.is_some()));
                frontmost |= bound && foreground == Some(root.number);
                bound
            })
            .count();
        if window_count != roots.len() {
            inventory.unattributed_windows += roots.len() - window_count;
        }
        if window_count > 0 {
            remaining(deadline)?;
            if let Some(list) = listing {
                if let Some(apps) = list
                    .lock()
                    .map_err(|_| IdentityError::ReadingUnavailable)?
                    .as_mut()
                {
                    apps.push((pid, identity, frontmost));
                }
            } else {
                inventory.apps.push(RunningIdentity {
                    pid,
                    identity,
                    window_count,
                });
            }
        }
    }
    remaining(deadline)?;
    Ok(inventory)
}

pub fn resolve_principal(principal: &Principal, inventory: &IdentityInventory) -> TargetResolution {
    let matches: Vec<_> = inventory
        .apps
        .iter()
        .filter(|app| &app.identity.principal == principal)
        .collect();
    match matches.as_slice() {
        [app] => TargetResolution::Resolved(app.identity.grant(app.pid)),
        [] if inventory.unattributed_windows > 0 => {
            TargetResolution::Unreadable(UnreadableReason::PartialWindowList {
                unreadable_owners: inventory.unattributed_windows,
            })
        }
        [] => TargetResolution::NotRunning,
        apps => TargetResolution::Ambiguous(
            apps.iter()
                .map(|app| TargetCandidate {
                    pid: app.pid,
                    window_count: app.window_count,
                })
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_unsigned_test_image_has_its_own_digest_and_path() {
        let identity = live_identity(std::process::id(), Instant::now() + IDENTITY_BOUND).unwrap();
        let exe = std::env::current_exe().unwrap();
        let expected: [u8; 32] = Sha256::digest(std::fs::read(&exe).unwrap()).into();
        assert_eq!(identity.image_path.file_name(), exe.file_name());
        assert_eq!(
            identity.principal,
            Principal::Unsigned {
                sha256: expected,
                image_name: exe.file_name().unwrap().to_str().unwrap().to_owned(),
            }
        );
    }
}
