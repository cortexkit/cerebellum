use super::super::identity::{
    installed_file_principal, installed_original_filename, shell_image, IdentityError, Principal,
};
use crate::app_state::source::{InstalledApp, InstalledApps};
use cerebellum_windows::{
    file_identity, lock_image_file, package_applications, read_shortcut, registered_packages,
    start_menu_directories, FileIdentity, LockedImageFile, PackageApplication, RegisteredPackage,
};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 4096;
const VERIFY_TIME: Duration = Duration::from_secs(2);
const RETRY_AFTER: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileStamp(FileIdentity, u64);

impl FileStamp {
    fn read(file: &File) -> io::Result<Self> {
        Ok(Self(
            file_identity(file)?,
            file.metadata()?.last_write_time(),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum InstallKind {
    Shortcut,
    Package {
        registration: RegisteredPackage,
        application: PackageApplication,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    title: String,
    entry: PathBuf,
    target: PathBuf,
    stamp: FileStamp,
    shortcut_stamp: Option<FileStamp>,
    kind: InstallKind,
}

/// Evidence pinned to the selected record through consent and dispatch. A
/// concurrent inventory read cannot replace it under the caller's approval.
#[derive(Debug, Eq, PartialEq)]
pub struct InstalledWindowsEntry {
    candidate: Candidate,
    principal: Principal,
    final_path: PathBuf,
}

impl InstalledWindowsEntry {
    pub fn executable_name(&self) -> Option<&str> {
        self.candidate.target.file_name()?.to_str()
    }
}

#[derive(Clone)]
struct ImageFacts {
    principal: Principal,
    original: Option<String>,
}

enum State {
    Pending,
    Read(ImageFacts),
    Blocked,
    Unreadable(Instant),
}

#[derive(Default)]
struct Cache {
    shortcuts: HashMap<FileStamp, State>,
    packages: HashMap<String, HashMap<String, (Candidate, State)>>,
}

impl Cache {
    fn slot(&mut self, candidate: &Candidate) -> Option<&mut State> {
        match &candidate.kind {
            InstallKind::Shortcut => self.shortcuts.get_mut(&candidate.stamp),
            InstallKind::Package {
                registration,
                application,
            } => self
                .packages
                .get_mut(&registration.full_name)?
                .get_mut(&application.id)
                .and_then(|(cached, state)| (cached == candidate).then_some(state)),
        }
    }

    fn insert(&mut self, candidate: &Candidate, state: State) {
        match &candidate.kind {
            InstallKind::Shortcut => {
                self.shortcuts.insert(candidate.stamp, state);
            }
            InstallKind::Package {
                registration,
                application,
            } => {
                self.packages
                    .entry(registration.full_name.clone())
                    .or_default()
                    .insert(application.id.clone(), (candidate.clone(), state));
            }
        }
    }
}

type ReadWork = Box<dyn FnOnce() + Send>;

#[derive(Clone)]
pub(crate) struct LaunchInventory {
    cache: Arc<Mutex<Cache>>,
    verifier: mpsc::SyncSender<Candidate>,
    reader: mpsc::SyncSender<ReadWork>,
    name_blocked: fn(&str) -> bool,
}

impl LaunchInventory {
    pub(crate) fn start(name_blocked: fn(&str) -> bool) -> io::Result<Self> {
        let cache = Arc::new(Mutex::new(Cache::default()));
        let (verifier, receive) = mpsc::sync_channel::<Candidate>(MAX_ENTRIES);
        let verifier_cache = cache.clone();
        std::thread::Builder::new()
            .name("windows-installed-verifier".into())
            .spawn(move || {
                while let Ok(entry) = receive.recv() {
                    let end = Instant::now() + VERIFY_TIME;
                    let state = match inspect(&entry, end) {
                        Ok((_, _, facts)) => State::Read(facts),
                        Err(IdentityError::Shell) => State::Blocked,
                        Err(_) => State::Unreadable(Instant::now()),
                    };
                    if let Ok(mut cache) = verifier_cache.lock() {
                        if let Some(slot @ State::Pending) = cache.slot(&entry) {
                            *slot = state;
                        }
                    }
                }
            })?;
        let (reader, receive) = mpsc::sync_channel::<ReadWork>(1);
        std::thread::Builder::new()
            .name("windows-installed-reader".into())
            .spawn(move || {
                while let Ok(read) = receive.recv() {
                    read();
                }
            })?;
        Ok(Self {
            cache,
            verifier,
            reader,
            name_blocked,
        })
    }

    fn read<T: Send + 'static>(
        &self,
        end: Instant,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (send, receive) = mpsc::sync_channel(1);
        // Do not queue stale reads behind a blocked filesystem or COM call.
        self.reader
            .try_send(Box::new(move || {
                if Instant::now() < end {
                    let _ = send.send(work());
                }
            }))
            .ok()?;
        receive
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .ok()
    }

    pub(in crate::platform::windows) fn listed(&self, timeout: Duration) -> InstalledApps {
        let end = Instant::now() + timeout;
        let inventory = self.clone();
        self.read(end, move || inventory.read_list(end))
            .unwrap_or_default()
    }

    fn read_list(&self, end: Instant) -> InstalledApps {
        let mut response = InstalledApps {
            apps: Vec::new(),
            complete: true,
        };
        let scan_end = end.checked_sub(Duration::from_millis(25)).unwrap_or(end);
        let (entries, complete) = candidates(scan_end);
        response.complete = complete;
        for (entry, final_path) in entries {
            if Instant::now() >= end {
                response.complete = false;
                break;
            }
            if self.blocked(&entry, &final_path, None) {
                continue;
            }
            match self.cached(&entry) {
                Some(State::Read(mut facts)) => {
                    // Hard links can share a file cache record but their
                    // names are entry facts, not a property of that record.
                    if let Principal::Unsigned { image_name, .. } = &mut facts.principal {
                        let Some(name) = final_path.file_name().and_then(|name| name.to_str())
                        else {
                            response.complete = false;
                            continue;
                        };
                        *image_name = name.to_owned();
                    }
                    if self.blocked(&entry, &final_path, Some(&facts)) {
                        continue;
                    }
                    let app = InstalledApp {
                        name: entry.title.clone(),
                        bundle_identity: facts.principal.to_string(),
                        path: entry.entry.clone(),
                        version: None,
                        build_version: None,
                        windows_entry: Some(Arc::new(InstalledWindowsEntry {
                            candidate: entry,
                            principal: facts.principal,
                            final_path,
                        })),
                    };
                    response.apps.push(app);
                }
                Some(State::Blocked) => (),
                _ => response.complete = false,
            }
        }
        response
    }

    fn cached(&self, entry: &Candidate) -> Option<State> {
        let mut cache = self.cache.lock().ok()?;
        match cache.slot(entry) {
            Some(State::Read(facts)) => return Some(State::Read(facts.clone())),
            Some(State::Blocked) => return Some(State::Blocked),
            Some(State::Pending) => return None,
            Some(State::Unreadable(time)) if time.elapsed() < RETRY_AFTER => return None,
            _ => (),
        }
        if cache.shortcuts.len() + cache.packages.values().map(HashMap::len).sum::<usize>()
            >= MAX_ENTRIES * 2
        {
            cache
                .shortcuts
                .retain(|_, slot| matches!(slot, State::Pending));
            cache.packages.retain(|_, apps| {
                apps.retain(|_, (_, slot)| matches!(slot, State::Pending));
                !apps.is_empty()
            });
        }
        if self.verifier.try_send(entry.clone()).is_ok() {
            cache.insert(entry, State::Pending);
        }
        None
    }

    fn blocked(&self, entry: &Candidate, final_path: &Path, facts: Option<&ImageFacts>) -> bool {
        let blocked = |name: &str| shell_image(name) || (self.name_blocked)(name);
        let file_blocked = |path: &Path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_none_or(blocked)
        };
        blocked(&entry.title)
            || file_blocked(&entry.target)
            || file_blocked(final_path)
            || facts.is_some_and(|facts| {
                facts.original.as_deref().is_some_and(blocked)
                    || blocked(&facts.principal.to_string())
            })
    }

    pub(super) fn fresh(&self, app: InstalledApp, end: Instant) -> Option<Fresh> {
        let inventory = self.clone();
        self.read(end, move || inventory.read_fresh(app, end))
            .flatten()
    }

    fn read_fresh(&self, app: InstalledApp, end: Instant) -> Option<Fresh> {
        let evidence = app.windows_entry?;
        let entry = &evidence.candidate;
        if app.name != entry.title
            || app.path != entry.entry
            || app.bundle_identity != evidence.principal.to_string()
        {
            return None;
        }
        let entry_lock = match &entry.kind {
            InstallKind::Shortcut => {
                let shortcut = lock_shortcut(&entry.entry).ok()?;
                if entry.shortcut_stamp != Some(FileStamp::read(&shortcut).ok()?) {
                    return None;
                }
                let raw = read_shortcut(&entry.entry).ok()?;
                if !raw.arguments.is_empty() || raw.target != entry.target {
                    return None;
                }
                Some(shortcut)
            }
            InstallKind::Package {
                registration,
                application,
            } => {
                let records = registered_packages()
                    .ok()?
                    .into_iter()
                    .collect::<io::Result<Vec<_>>>()
                    .ok()?;
                let mut registrations = records
                    .into_iter()
                    .filter(|package| package.family == registration.family);
                if registrations.next().as_ref() != Some(registration)
                    || registrations.next().is_some()
                {
                    return None;
                }
                let mut applications = package_applications(&registration.directory)
                    .ok()?
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|app| app.id == application.id);
                if applications.next().as_ref() != Some(application)
                    || applications.next().is_some()
                {
                    return None;
                }
                None
            }
        };
        let (file, final_path, facts) = inspect(entry, end).ok()?;
        if facts.principal != evidence.principal
            || final_path != evidence.final_path
            || self.blocked(entry, &final_path, Some(&facts))
            || Instant::now() >= end
        {
            return None;
        }
        Some(Fresh {
            file,
            final_path,
            principal: facts.principal,
            kind: entry.kind.clone(),
            _entry_lock: entry_lock,
        })
    }
}

pub(super) struct Fresh {
    pub file: LockedImageFile,
    pub final_path: PathBuf,
    pub principal: Principal,
    pub kind: InstallKind,
    _entry_lock: Option<File>,
}

fn inspect(
    candidate: &Candidate,
    end: Instant,
) -> Result<(LockedImageFile, PathBuf, ImageFacts), IdentityError> {
    let unreadable = |_| IdentityError::ReadingUnavailable;
    let lock = lock_image_file(&candidate.target).map_err(unreadable)?;
    let final_path = lock.final_path().map_err(unreadable)?;
    if !local_executable(&final_path)
        || FileStamp::read(lock.read_only_handle()).map_err(unreadable)? != candidate.stamp
    {
        return Err(IdentityError::ReadingUnavailable);
    }
    let (principal, original) = match &candidate.kind {
        InstallKind::Shortcut => installed_file_principal(&lock, &final_path, end)?,
        InstallKind::Package {
            registration,
            application,
        } => {
            // A loose registration does not attest the contents of its directory.
            if registration.development_mode || !(1..=4).contains(&registration.signature_kind) {
                return Err(IdentityError::ReadingUnavailable);
            }
            let directory = registration.directory.canonicalize().map_err(unreadable)?;
            if !final_path.starts_with(&directory)
                || final_path == directory
                || application.aumid != format!("{}!{}", registration.family, application.id)
            {
                return Err(IdentityError::ReadingUnavailable);
            }
            let executable = final_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(IdentityError::ReadingUnavailable)?;
            if shell_image(executable) {
                return Err(IdentityError::Shell);
            }
            (
                Principal::Packaged {
                    family: registration.family.clone(),
                    application: application.id.clone(),
                },
                installed_original_filename(&lock)?,
            )
        }
    };
    if Instant::now() >= end {
        return Err(IdentityError::Deadline);
    }
    Ok((
        lock,
        final_path,
        ImageFacts {
            principal,
            original,
        },
    ))
}

fn local_executable(path: &Path) -> bool {
    path.is_absolute()
        && matches!(path.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        && extension_is(path, "exe")
}

fn extension_is(path: &Path, extension: &str) -> bool {
    path.extension()
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
}

fn discover_target(
    title: String,
    entry: PathBuf,
    target: PathBuf,
    kind: InstallKind,
) -> io::Result<Option<(Candidate, PathBuf)>> {
    if title.is_empty() || !local_executable(&target) {
        return Ok(None);
    }
    let file = lock_image_file(&target)?;
    let final_path = file.final_path()?;
    let stamp = FileStamp::read(file.read_only_handle())?;
    Ok(Some((
        Candidate {
            title,
            entry,
            target,
            stamp,
            shortcut_stamp: None,
            kind,
        },
        final_path,
    )))
}

fn shortcut(path: PathBuf) -> io::Result<Option<(Candidate, PathBuf)>> {
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or(io::ErrorKind::InvalidData)?
        .to_owned();
    let lock = lock_shortcut(&path)?;
    let link = read_shortcut(&path)?;
    if !link.arguments.is_empty() {
        return Ok(None);
    }
    let stamp = FileStamp::read(&lock)?;
    Ok(
        discover_target(name, path, link.target, InstallKind::Shortcut)?.map(
            |(mut entry, path)| {
                entry.shortcut_stamp = Some(stamp);
                (entry, path)
            },
        ),
    )
}

fn lock_shortcut(path: &Path) -> io::Result<File> {
    // FILE_SHARE_READ: keep the link itself stable through the selected launch.
    OpenOptions::new().read(true).share_mode(1).open(path)
}

fn package_entry(
    registration: &RegisteredPackage,
    application: PackageApplication,
) -> io::Result<Option<(Candidate, PathBuf)>> {
    let relative = Path::new(&application.executable);
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Ok(None);
    }
    let target = registration.directory.join(relative);
    discover_target(
        application.id.clone(),
        target.clone(),
        target,
        InstallKind::Package {
            registration: registration.clone(),
            application,
        },
    )
}

fn candidates(end: Instant) -> (Vec<(Candidate, PathBuf)>, bool) {
    let mut discovered = Vec::new();
    let mut complete = true;
    let mut remaining = MAX_ENTRIES;
    let mut record = |result| match result {
        Ok(Some(item)) => discovered.push(item),
        Ok(None) => (),
        Err(_) => complete = false,
    };
    let mut directories = Vec::new();
    for path in start_menu_directories() {
        match path {
            Ok(path) => directories.push(path),
            Err(err) => record(Err(err)),
        }
    }
    let mut visited = HashSet::new();
    directories.reverse();
    'shortcuts: while let Some(directory) = directories.pop() {
        if Instant::now() >= end || remaining == 0 {
            return (discovered, false);
        }
        remaining -= 1;
        if !visited.insert(directory.clone()) {
            continue;
        }
        match std::fs::read_dir(directory) {
            Ok(list) => {
                for entry in list {
                    if Instant::now() >= end || remaining == 0 {
                        break 'shortcuts;
                    }
                    remaining -= 1;
                    match entry.and_then(|entry| Ok((entry.path(), entry.metadata()?))) {
                        // Never follow a reparse point found in the Start menu tree.
                        Ok((_, metadata)) if metadata.file_attributes() & 0x400 != 0 => (),
                        Ok((path, metadata)) if metadata.is_dir() => directories.push(path),
                        Ok((path, metadata))
                            if metadata.is_file() && extension_is(&path, "lnk") =>
                        {
                            record(shortcut(path))
                        }
                        Ok(_) => (),
                        Err(err) => record(Err(err)),
                    }
                }
            }
            Err(err) => record(Err(err)),
        }
    }
    if Instant::now() >= end || remaining == 0 {
        return (discovered, false);
    }
    match registered_packages() {
        Ok(packages) => {
            for package in packages {
                if Instant::now() >= end || remaining == 0 {
                    return (discovered, false);
                }
                remaining -= 1;
                match package {
                    Ok(package) => match package_applications(&package.directory) {
                        Ok(apps) => {
                            for app in apps {
                                if Instant::now() >= end || remaining == 0 {
                                    return (discovered, false);
                                }
                                remaining -= 1;
                                record(app.and_then(|app| package_entry(&package, app)));
                            }
                        }
                        Err(err) => record(Err(err)),
                    },
                    Err(err) => record(Err(err)),
                }
            }
        }
        Err(err) => record(Err(err)),
    }
    (discovered, complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, executable: &str) -> Candidate {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let registration = RegisteredPackage {
            full_name: "Fixture_1.0.0.0_x64__publisher".to_owned(),
            family: "Fixture_publisher".to_owned(),
            directory: r"C:\Fixture".into(),
            signature_kind: 2,
            development_mode: false,
        };
        let application = PackageApplication {
            id: id.to_owned(),
            aumid: format!("{}!{id}", registration.family),
            executable: executable.to_owned(),
        };
        let entry = registration.directory.join(executable);
        Candidate {
            title: id.to_owned(),
            entry: entry.clone(),
            target: entry,
            stamp: FileStamp::read(&file).unwrap(),
            shortcut_stamp: None,
            kind: InstallKind::Package {
                registration,
                application,
            },
        }
    }

    #[test]
    fn package_cache_results_never_cross_application_ids_or_manifest_paths() {
        let allowed = candidate("First", "Neutral.exe");
        let sibling = candidate("Second", "Alfonso.exe");
        let changed = candidate("First", "Different.exe");
        let mut cache = Cache::default();
        cache.insert(
            &allowed,
            State::Read(ImageFacts {
                principal: Principal::Packaged {
                    family: "Fixture_publisher".into(),
                    application: "First".into(),
                },
                original: None,
            }),
        );
        assert!(matches!(cache.slot(&allowed), Some(State::Read(_))));
        assert!(cache.slot(&sibling).is_none());
        assert!(cache.slot(&changed).is_none());
        let inventory =
            LaunchInventory::start(|name| name.eq_ignore_ascii_case("Alfonso.exe")).unwrap();
        assert!(inventory.blocked(&sibling, &sibling.target, None));
        assert!(!inventory.blocked(&allowed, &allowed.target, None));
    }

    #[test]
    fn launch_unbound_source_returns_default_partial_inventory() {
        use crate::app_state::source::AppStateSource;
        let source = super::super::super::app_state::WindowsAppStateSource::new(|_| {
            panic!("reads no installed or running identities")
        });
        let list = source.installed_apps(Duration::from_secs(2));
        assert!(!list.complete && list.apps.is_empty());
    }
}
