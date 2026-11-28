use super::*;
use std::fmt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const PKG_FILE_LIMIT: u64 = 32 * 1024 * 1024;
const RPM_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const RPM_DIAGNOSTIC_LIMIT: usize = 4096;
const RPM_QUERY_LIMIT: Duration = Duration::from_secs(2);
const DPKG: &str = "/var/lib/dpkg";
const RPM_DBS: [&str; 2] = ["/usr/lib/sysimage/rpm", "/var/lib/rpm"];
const RPM: &str = "/usr/bin/rpm";

#[derive(Debug, Default)]
pub(super) struct Database {
    dpkg: Option<DpkgIndex>,
}

#[derive(Debug)]
struct DpkgIndex {
    stamp: ImageKey,
    paths: HashMap<PathBuf, Vec<String>>,
}

impl Database {
    pub(super) fn subject(
        &mut self,
        host: &File,
        target: &File,
        path: &Path,
        exe: &mut File,
        digest: impl Fn(&mut File, ImageKey, Algorithm) -> Result<String, Refusal>,
    ) -> Result<Option<String>, Refusal> {
        let candidates = candidates(path);
        let image = exe.metadata().map_err(|_| AppIdentityUnproven)?;
        let key = image_key(&image);
        if let Some(matched) = self.dpkg_record(host, &candidates)? {
            verify_package_path(host, target, &matched.path, &image)?;
            if digest(exe, key, Algorithm::Md5)? != matched.sum {
                return Err(AppIdentityUnproven);
            }
            return Ok(Some(format!("dpkg:{}", matched.name)));
        }
        let Some(db) = rpm_database(host)? else {
            return Ok(None);
        };
        let rpm_paths = self::candidates(Path::new(RPM));
        let rpm_from_dpkg = self.dpkg_record(host, &rpm_paths)?;
        if let Some(record) = &rpm_from_dpkg {
            verify_rpm_install(host, record, &digest)?;
        }
        let output = query_rpm(host, &db).map_err(|_| AppIdentityUnproven)?;
        if rpm_from_dpkg.is_none() {
            // On an RPM system, trust the protected rpm path enough to run
            // it. Use its inventory only after checking the binary's own
            // installed checksum against that inventory.
            let record = rpm_record(&output, &rpm_paths)
                .map_err(RpmOutputFailure::refusal)?
                .ok_or(AppIdentityUnproven)?;
            verify_rpm_install(host, &record, &digest)?;
        }
        let Some(matched) = rpm_record(&output, &candidates).map_err(RpmOutputFailure::refusal)?
        else {
            return Ok(None);
        };
        verify_package_path(host, target, &matched.path, &image)?;
        if digest(exe, key, matched.algorithm)? != matched.sum {
            return Err(AppIdentityUnproven);
        }
        Ok(Some(format!("rpm:{}", matched.name)))
    }

    fn dpkg_record(
        &mut self,
        root: &File,
        candidates: &[PathBuf],
    ) -> Result<Option<PackageFile>, Refusal> {
        let path = Path::new(DPKG);
        let status = optional_owned(root, &path.join("status"))?;
        if let Some(status) = status {
            if !status
                .metadata()
                .map_err(|_| AppIdentityUnproven)?
                .is_file()
            {
                return Err(AppIdentityUnproven);
            }
        } else {
            // Absence of the database must not make unreadable/incomplete
            // installation records look like an unowned executable.
            if optional_owned(root, &path.join("info"))?.is_some() {
                return Err(AppIdentityUnproven);
            }
            self.dpkg = None;
            return Ok(None);
        }
        let info = path.join("info");
        let dir = walk(root, &info, true).map_err(|_| AppIdentityUnproven)?;
        let meta = dir.metadata().map_err(|_| AppIdentityUnproven)?;
        if !meta.is_dir() {
            return Err(AppIdentityUnproven);
        }
        let stamp = image_key(&meta);
        if self.dpkg.as_ref().is_none_or(|index| index.stamp != stamp) {
            self.dpkg = Some(DpkgIndex::read(&dir, stamp).map_err(|_| AppIdentityUnproven)?);
        }
        let index = self.dpkg.as_ref().ok_or(AppIdentityUnproven)?;
        let mut found: Option<PackageFile> = None;
        for candidate in candidates {
            for package in index.paths.get(candidate).into_iter().flatten() {
                let list = info.join(format!("{package}.list"));
                let bytes = read_owned(root, &list).map_err(|_| AppIdentityUnproven)?;
                if !bytes
                    .split(|b| *b == b'\n')
                    .any(|line| line == candidate.as_os_str().as_bytes())
                {
                    return Err(AppIdentityUnproven);
                }
                let sums = match read_owned(root, &info.join(format!("{package}.md5sums"))) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return Err(PackageChecksumUnavailable)
                    }
                    Err(_) => return Err(AppIdentityUnproven),
                };
                let sum = dpkg_checksum(&sums, candidate)?;
                let name = package
                    .split(':')
                    .next()
                    .ok_or(AppIdentityUnproven)?
                    .to_owned();
                merge_record(
                    &mut found,
                    PackageFile {
                        path: candidate.clone(),
                        name,
                        sum,
                        algorithm: Algorithm::Md5,
                    },
                )?;
            }
        }
        let current = walk(root, &info, true)
            .and_then(|file| file.metadata())
            .map_err(|_| AppIdentityUnproven)?;
        if image_key(&current) != stamp {
            return Err(AppIdentityUnproven);
        }
        Ok(found)
    }
}

impl DpkgIndex {
    fn read(dir: &File, stamp: ImageKey) -> io::Result<Self> {
        let mut paths = HashMap::<PathBuf, Vec<String>>::new();
        for entry in fs::read_dir(fd_path(dir))? {
            let name = entry?.file_name();
            let Some(stem) = name.as_encoded_bytes().strip_suffix(b".list") else {
                continue;
            };
            let package = std::str::from_utf8(stem).map_err(|_| invalid())?;
            let (name_part, arch) = package.split_once(':').unwrap_or((package, "any"));
            if !package_name(name_part) || !package_name(arch) {
                return Err(invalid());
            }
            let list = open_component(dir, &name)?;
            if !protected(&list.metadata()?) {
                return Err(invalid());
            }
            let contents = read_limited(regular_read(&list)?, PKG_FILE_LIMIT)?;
            for line in contents
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
            {
                if !line.starts_with(b"/") {
                    return Err(invalid());
                }
                paths
                    .entry(PathBuf::from(OsStr::from_bytes(line)))
                    .or_default()
                    .push(package.to_owned());
            }
        }
        if image_key(&dir.metadata()?) != stamp {
            return Err(invalid());
        }
        Ok(Self { stamp, paths })
    }
}

struct PackageFile {
    path: PathBuf,
    name: String,
    sum: String,
    algorithm: Algorithm,
}

fn merge_record(found: &mut Option<PackageFile>, record: PackageFile) -> Result<(), Refusal> {
    if let Some(prior) = found {
        if prior.name != record.name
            || prior.sum != record.sum
            || prior.algorithm != record.algorithm
        {
            return Err(AppIdentityUnproven);
        }
    } else {
        *found = Some(record);
    }
    Ok(())
}

fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-' | b'_'))
}

fn candidates(path: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![path.to_owned()];
    for dir in ["bin", "sbin", "lib", "lib64"] {
        let merged = Path::new("/usr").join(dir);
        let legacy = Path::new("/").join(dir);
        if let Ok(rest) = path.strip_prefix(&merged) {
            candidates.push(legacy.join(rest));
        } else if let Ok(rest) = path.strip_prefix(&legacy) {
            candidates.push(merged.join(rest));
        }
    }
    candidates
}

fn optional_owned(root: &File, path: &Path) -> Result<Option<File>, Refusal> {
    match walk(root, path, true) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(AppIdentityUnproven),
    }
}

fn read_limited(file: File, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid());
    }
    Ok(bytes)
}

fn read_owned(root: &File, path: &Path) -> io::Result<Vec<u8>> {
    read_limited(regular_read(&walk(root, path, true)?)?, PKG_FILE_LIMIT)
}

fn dpkg_checksum(sums: &[u8], path: &Path) -> Result<String, Refusal> {
    let expected = path
        .strip_prefix("/")
        .map_err(|_| AppIdentityUnproven)?
        .as_os_str()
        .as_bytes();
    let mut found = None;
    for line in sums.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let Some((sum, name)) = line.split_first_chunk::<34>() else {
            return Err(AppIdentityUnproven);
        };
        if &sum[32..] != b"  " && &sum[32..] != b" *" {
            return Err(AppIdentityUnproven);
        }
        if name == expected && found.replace(checksum(&sum[..32], 32)?).is_some() {
            return Err(AppIdentityUnproven);
        }
    }
    found.ok_or(PackageChecksumUnavailable)
}

fn checksum(sum: &[u8], width: usize) -> Result<String, Refusal> {
    if sum.len() != width || !sum.iter().all(u8::is_ascii_hexdigit) {
        return Err(AppIdentityUnproven);
    }
    Ok(String::from_utf8_lossy(sum).to_ascii_lowercase())
}

fn verify_package_path(
    host: &File,
    target: &File,
    path: &Path,
    image: &Metadata,
) -> Result<(), Refusal> {
    for root in [host, target] {
        let leaf = walk(root, path, true).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ImageReplacedSinceLaunch
            } else {
                AppIdentityUnproven
            }
        })?;
        let metadata = leaf.metadata().map_err(|_| AppIdentityUnproven)?;
        if !metadata.is_file() || !same_file(image, &metadata) {
            return Err(ImageReplacedSinceLaunch);
        }
    }
    Ok(())
}

fn verify_rpm_install(
    root: &File,
    record: &PackageFile,
    digest: impl Fn(&mut File, ImageKey, Algorithm) -> Result<String, Refusal>,
) -> Result<(), Refusal> {
    if record.name != "rpm" {
        return Err(AppIdentityUnproven);
    }
    let leaf = walk(root, Path::new(RPM), true).map_err(|_| AppIdentityUnproven)?;
    let metadata = leaf.metadata().map_err(|_| AppIdentityUnproven)?;
    verify_package_path(root, root, &record.path, &metadata)?;
    let mut file = regular_read(&leaf).map_err(|_| AppIdentityUnproven)?;
    if digest(&mut file, image_key(&metadata), record.algorithm)? != record.sum {
        return Err(AppIdentityUnproven);
    }
    Ok(())
}

fn rpm_database(root: &File) -> Result<Option<PathBuf>, Refusal> {
    let mut selected = None;
    for path in RPM_DBS.map(PathBuf::from) {
        let Some(directory) = optional_owned(root, &path)? else {
            continue;
        };
        if !directory
            .metadata()
            .map_err(|_| AppIdentityUnproven)?
            .is_dir()
        {
            return Err(AppIdentityUnproven);
        }
        // A legacy path may be a symlink to the canonical path. Do not pick
        // one of two distinct databases and silently ignore the other.
        let actual = fs::read_link(fd_path(&directory)).map_err(|_| AppIdentityUnproven)?;
        let populated = rpm_db_files(&directory, "discover database", &path)
            .map_err(|_| AppIdentityUnproven)?;
        if populated.iter().all(|(name, _)| name == ".rpm.lock") {
            continue;
        }
        match selected.as_ref() {
            Some((prior, _)) if prior != &actual => return Err(AppIdentityUnproven),
            Some(_) => (),
            None => selected = Some((actual, path)),
        }
    }
    Ok(selected.map(|(_, path)| path))
}

type RpmDbEntry = (OsString, ImageKey);

#[derive(Debug, PartialEq, Eq)]
enum SnapshotChange {
    Added {
        name: OsString,
        stamp: ImageKey,
    },
    Removed {
        name: OsString,
        stamp: ImageKey,
    },
    Changed {
        name: OsString,
        fields: Vec<&'static str>,
        before: ImageKey,
        after: ImageKey,
    },
}

impl fmt::Display for SnapshotChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added { name, stamp } => write!(f, "added {name:?}: {stamp:?}"),
            Self::Removed { name, stamp } => write!(f, "removed {name:?}: {stamp:?}"),
            Self::Changed {
                name,
                fields,
                before,
                after,
            } => write!(
                f,
                "{name:?} changed {} (before: {before:?}; after: {after:?})",
                fields.join(", ")
            ),
        }
    }
}

#[derive(Debug)]
enum RpmQueryFailure {
    Io {
        stage: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Unprotected {
        stage: &'static str,
        path: PathBuf,
        uid: u32,
        mode: u32,
    },
    NoDatabaseFile(PathBuf),
    DatabaseDirectoryReplaced(PathBuf),
    SnapshotChanged(Box<SnapshotChange>),
    Exited {
        status: ExitStatus,
        stderr: Vec<u8>,
    },
    Stderr {
        status: ExitStatus,
        stderr: Vec<u8>,
    },
    Deadline {
        stderr: Vec<u8>,
    },
    OutputLimit,
}

impl fmt::Display for RpmQueryFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                stage,
                path,
                source,
            } => write!(f, "{stage} at {}: {source}", path.display()),
            Self::Unprotected {
                stage,
                path,
                uid,
                mode,
            } => write!(
                f,
                "{stage} refused {} (uid {uid}, mode {mode:#o})",
                path.display()
            ),
            Self::NoDatabaseFile(path) => {
                write!(f, "no supported database file in {}", path.display())
            }
            Self::DatabaseDirectoryReplaced(path) => write!(
                f,
                "rpm exited 0 with empty stderr, but database directory {} changed device/inode",
                path.display()
            ),
            Self::SnapshotChanged(change) => write!(
                f,
                "rpm exited 0 with empty stderr, but database snapshot changed: {change}"
            ),
            Self::Exited { status, stderr } | Self::Stderr { status, stderr } => write!(
                f,
                "rpm {status}; stderr: {:?}",
                String::from_utf8_lossy(stderr)
            ),
            Self::Deadline { stderr } => write!(
                f,
                "rpm query passed its deadline; stderr: {:?}",
                String::from_utf8_lossy(stderr)
            ),
            Self::OutputLimit => write!(f, "rpm stdout exceeded {RPM_OUTPUT_LIMIT} bytes"),
        }
    }
}

fn rpm_io<'a>(
    stage: &'static str,
    path: &'a Path,
) -> impl FnOnce(io::Error) -> RpmQueryFailure + 'a {
    move |source| RpmQueryFailure::Io {
        stage,
        path: path.to_owned(),
        source,
    }
}

fn protected_rpm_path(
    root: &File,
    stage: &'static str,
    path: &Path,
) -> Result<File, RpmQueryFailure> {
    walk(root, path, true).map_err(rpm_io(stage, path))
}

fn rpm_db_files(
    dir: &File,
    stage: &'static str,
    db: &Path,
) -> Result<Vec<RpmDbEntry>, RpmQueryFailure> {
    let mut files = Vec::new();
    for entry in fs::read_dir(fd_path(dir)).map_err(rpm_io(stage, db))? {
        let name = entry.map_err(rpm_io(stage, db))?.file_name();
        let path = db.join(&name);
        let metadata = open_component(dir, &name)
            .and_then(|file| file.metadata())
            .map_err(rpm_io(stage, &path))?;
        if !metadata.is_file() || !protected(&metadata) {
            return Err(RpmQueryFailure::Unprotected {
                stage,
                path,
                uid: metadata.uid(),
                mode: metadata.mode(),
            });
        }
        let stamp = rpm_file_stamp(&name, image_key(&metadata));
        files.push((name, stamp));
    }
    files.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn snapshot_change(before: &[RpmDbEntry], after: &[RpmDbEntry]) -> Option<SnapshotChange> {
    for (name, old) in before {
        let Ok(position) = after.binary_search_by(|(candidate, _)| candidate.cmp(name)) else {
            return Some(SnapshotChange::Removed {
                name: name.clone(),
                stamp: *old,
            });
        };
        let new = &after[position].1;
        if old != new {
            let fields = [
                (old.dev != new.dev, "device"),
                (old.ino != new.ino, "inode"),
                (old.size != new.size, "size"),
                (old.mtime != new.mtime, "mtime"),
                (old.ctime != new.ctime, "ctime"),
            ]
            .into_iter()
            .filter_map(|(changed, field)| changed.then_some(field))
            .collect();
            return Some(SnapshotChange::Changed {
                name: name.clone(),
                fields,
                before: *old,
                after: *new,
            });
        }
    }
    after
        .iter()
        .find(|(name, _)| {
            before
                .binary_search_by(|(candidate, _)| candidate.cmp(name))
                .is_err()
        })
        .map(|(name, stamp)| SnapshotChange::Added {
            name: name.clone(),
            stamp: *stamp,
        })
}

fn rpm_file_stamp(name: &OsStr, mut key: ImageKey) -> ImageKey {
    if name == "rpmdb.sqlite-shm" {
        // SQLite updates its shared-memory index and reader locks during a
        // query. Keep exact stamps for the database and its write-ahead log,
        // where package records live; still check this sidecar's identity and size.
        key.mtime = (0, 0);
        key.ctime = (0, 0);
    }
    key
}

fn query_rpm(root: &File, db: &Path) -> Result<Vec<u8>, RpmQueryFailure> {
    let rpm = Path::new(RPM);
    let image = protected_rpm_path(root, "verify rpm executable path ownership", rpm)?;
    let metadata = image
        .metadata()
        .map_err(rpm_io("stat rpm executable", rpm))?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0 {
        return Err(RpmQueryFailure::Unprotected {
            stage: "verify rpm executable type and mode",
            path: rpm.to_owned(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        });
    }
    // No user macro, plugin, or HOME configuration. Read the system database
    // with one complete query: rpm's nonzero -qf status cannot distinguish
    // an unowned file from a broken database.
    let rc = Path::new("/usr/lib/rpm/rpmrc");
    let macros = Path::new("/usr/lib/rpm/macros");
    for config in [rc, macros] {
        let meta = protected_rpm_path(root, "verify rpm configuration path ownership", config)?
            .metadata()
            .map_err(rpm_io("stat rpm configuration", config))?;
        if !meta.is_file() {
            return Err(RpmQueryFailure::Unprotected {
                stage: "verify rpm configuration file type",
                path: config.to_owned(),
                uid: meta.uid(),
                mode: meta.mode(),
            });
        }
    }
    let directory = protected_rpm_path(
        root,
        "verify database directory path ownership before rpm",
        db,
    )?;
    let before = rpm_db_files(&directory, "read protected database files before rpm", db)?;
    if !before.iter().any(|(file, _)| {
        matches!(
            file.as_bytes(),
            b"rpmdb.sqlite" | b"Packages" | b"Packages.db"
        )
    }) {
        return Err(RpmQueryFailure::NoDatabaseFile(db.to_owned()));
    }
    let mut child = Command::new(RPM)
        .env_clear()
        .args(["--rcfile"])
        .arg(rc)
        .args(["--macros"])
        .arg(macros)
        .args(["--noplugins", "--dbpath"])
        .arg(db)
        .args([
            "-qa",
            "--qf",
            "%{NAME}\\t%{FILEDIGESTALGO}\\n[%{FILENAMES:shescape}\\t%{FILEDIGESTS}\\n]",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(rpm_io("spawn rpm", rpm))?;
    let output = match collect_rpm(&mut child) {
        Ok(output) => output,
        Err(failure) => {
            let _ = child.kill();
            if child.try_wait().ok().flatten().is_none() {
                // A killed child on stalled storage may not become waitable
                // by the query deadline. Reap it without holding up dispatch.
                let _ = std::thread::Builder::new().spawn(move || child.wait());
            }
            return Err(failure);
        }
    };
    let current = protected_rpm_path(
        root,
        "verify database directory path ownership after rpm",
        db,
    )?;
    if !same_file(
        &directory
            .metadata()
            .map_err(rpm_io("stat original database directory after rpm", db))?,
        &current
            .metadata()
            .map_err(rpm_io("stat current database directory after rpm", db))?,
    ) {
        return Err(RpmQueryFailure::DatabaseDirectoryReplaced(db.to_owned()));
    }
    let after = rpm_db_files(&current, "read protected database files after rpm", db)?;
    if let Some(change) = snapshot_change(&before, &after) {
        return Err(RpmQueryFailure::SnapshotChanged(Box::new(change)));
    }
    Ok(output)
}

fn collect_rpm(child: &mut Child) -> Result<Vec<u8>, RpmQueryFailure> {
    let deadline = Instant::now() + RPM_QUERY_LIMIT;
    let rpm = Path::new(RPM);
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| rpm_io("open rpm stdout", rpm)(invalid()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| rpm_io("open rpm stderr", rpm)(invalid()))?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        // SAFETY: Both descriptors name owned pipes; fcntl changes only status flags.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(rpm_io("configure nonblocking rpm pipe", rpm)(
                io::Error::last_os_error(),
            ));
        }
    }
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let mut eof = false;
    let mut diagnostics_closed = false;
    let mut buffer = [0; 8192];
    loop {
        let Some(budget) = deadline.checked_duration_since(Instant::now()) else {
            return Err(RpmQueryFailure::Deadline {
                stderr: diagnostics,
            });
        };
        if !diagnostics_closed {
            match stderr.read(&mut buffer) {
                Ok(0) => diagnostics_closed = true,
                Ok(n) => {
                    let remaining = RPM_DIAGNOSTIC_LIMIT - diagnostics.len();
                    diagnostics.extend_from_slice(&buffer[..n.min(remaining)]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(rpm_io("read rpm stderr", rpm)(e)),
            }
        }
        if !eof {
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(n) if output.len() + n <= RPM_OUTPUT_LIMIT => {
                    output.extend_from_slice(&buffer[..n]);
                    continue;
                }
                Ok(_) => return Err(RpmQueryFailure::OutputLimit),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(rpm_io("read rpm stdout", rpm)(e)),
            }
        }
        if eof && diagnostics_closed {
            if let Some(status) = child
                .try_wait()
                .map_err(rpm_io("wait for rpm exit status", rpm))?
            {
                if !status.success() {
                    return Err(RpmQueryFailure::Exited {
                        status,
                        stderr: diagnostics,
                    });
                }
                // rpm can emit database errors without returning a nonzero status.
                if !diagnostics.is_empty() {
                    return Err(RpmQueryFailure::Stderr {
                        status,
                        stderr: diagnostics,
                    });
                }
                return Ok(output);
            }
        }
        std::thread::sleep(budget.min(Duration::from_millis(2)));
    }
}

#[derive(Debug)]
enum RpmOutputFailure {
    Malformed { offset: usize, field: &'static str },
    MissingChecksum { path: PathBuf },
}

impl RpmOutputFailure {
    fn refusal(self) -> Refusal {
        match self {
            Self::Malformed { .. } => AppIdentityUnproven,
            Self::MissingChecksum { .. } => PackageChecksumUnavailable,
        }
    }
}

impl fmt::Display for RpmOutputFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { offset, field } => write!(f, "rpm exited 0 with empty stderr, but stdout has invalid {field} in the record at byte {offset}"),
            Self::MissingChecksum { path } => write!(f, "rpm recorded {} without a file checksum", path.display()),
        }
    }
}

fn rpm_record(
    mut output: &[u8],
    candidates: &[PathBuf],
) -> Result<Option<PackageFile>, RpmOutputFailure> {
    let mut package = None;
    let mut found = None;
    let length = output.len();
    while !output.is_empty() {
        let offset = length - output.len();
        let malformed = |field| RpmOutputFailure::Malformed { offset, field };
        let path = if output.starts_with(b"'") {
            Some(rpm_path(&mut output).map_err(|_| malformed("quoted pathname"))?)
        } else {
            None
        };
        let (line, rest) = split_byte(output, b'\n').map_err(|_| malformed("record terminator"))?;
        output = rest;
        let (left, right) = split_byte(line, b'\t').map_err(|_| malformed("field separator"))?;
        let Some(path) = path else {
            let name = std::str::from_utf8(left).map_err(|_| malformed("package name"))?;
            if !package_name(name)
                || (right != b"(none)"
                    && (right.is_empty() || !right.iter().all(u8::is_ascii_digit)))
            {
                return Err(malformed("package name or digest algorithm"));
            }
            package = Some((name, right));
            continue;
        };
        if !left.is_empty() {
            return Err(malformed("pathname separator"));
        }
        let (name, algorithm) = package.ok_or_else(|| malformed("missing package header"))?;
        if right != b"(none)" && !right.iter().all(u8::is_ascii_hexdigit) {
            return Err(malformed("file checksum characters"));
        }
        let Some(path) = candidates
            .iter()
            .find(|candidate| candidate.as_os_str().as_bytes() == path)
        else {
            continue;
        };
        if right.is_empty() || right == b"(none)" {
            return Err(RpmOutputFailure::MissingChecksum { path: path.clone() });
        }
        let (algorithm, width) = match algorithm {
            b"(none)" | b"1" => (Algorithm::Md5, 32),
            b"8" => (Algorithm::Sha256, 64),
            b"9" => (Algorithm::Sha384, 96),
            b"10" => (Algorithm::Sha512, 128),
            b"11" => (Algorithm::Sha224, 56),
            _ => return Err(malformed("unsupported file digest algorithm")),
        };
        merge_record(
            &mut found,
            PackageFile {
                path: path.clone(),
                name: name.to_owned(),
                sum: checksum(right, width).map_err(|_| malformed("file checksum width"))?,
                algorithm,
            },
        )
        .map_err(|_| malformed("conflicting file record"))?;
    }
    Ok(found)
}

fn split_byte(text: &[u8], delimiter: u8) -> Result<(&[u8], &[u8]), Refusal> {
    let end = text
        .iter()
        .position(|byte| *byte == delimiter)
        .ok_or(AppIdentityUnproven)?;
    Ok((&text[..end], &text[end + 1..]))
}

// Decode rpm's single-quoted shescape field as data, never as shell syntax.
// Quoting keeps embedded newlines and tabs from creating extra record fields.
fn rpm_path(input: &mut &[u8]) -> Result<Vec<u8>, Refusal> {
    let mut remaining = &input[1..];
    let mut path = Vec::new();
    loop {
        let (segment, rest) = split_byte(remaining, b'\'')?;
        path.extend_from_slice(segment);
        if let Some(rest) = rest.strip_prefix(b"\\''") {
            path.push(b'\'');
            remaining = rest;
        } else {
            *input = rest;
            return if path.starts_with(b"/") && !path.contains(&0) {
                Ok(path)
            } else {
                Err(AppIdentityUnproven)
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tests::{checked, require_hosted_runner, Scratch};

    #[test]
    fn usr_merge_candidates_are_exact_and_bidirectional() {
        for prefix in ["bin", "sbin", "lib", "lib64"] {
            let old = PathBuf::from(format!("/{prefix}/nested/app"));
            let new = PathBuf::from(format!("/usr/{prefix}/nested/app"));
            assert_eq!(candidates(&old), [old.clone(), new.clone()]);
            assert_eq!(candidates(&new), [new, old]);
        }
        for unowned in [
            "/usr/local/bin/fixture",
            "/opt/fixture",
            "/home/runner/bin/fixture",
        ] {
            assert_eq!(candidates(Path::new(unowned)), [PathBuf::from(unowned)]);
        }
    }

    #[test]
    fn dpkg_checksums_are_exact_and_report_a_missing_record() {
        let records = b"900150983cd24fb0d6963f7d28e17f72  bin/a b\n";
        assert_eq!(
            dpkg_checksum(records, Path::new("/bin/a b")).unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            dpkg_checksum(records, Path::new("/bin/a")),
            Err(PackageChecksumUnavailable)
        );
        assert_eq!(
            dpkg_checksum(b"malformed\n", Path::new("/bin/a")),
            Err(AppIdentityUnproven)
        );
    }

    #[test]
    fn rpm_query_requires_a_complete_record_and_uses_the_header_algorithm() {
        let paths = candidates(Path::new("/usr/bin/fi'x\nture"));
        let sum = "9f".repeat(32);
        let output = format!("Example\t8\n'/bin/fi'\\''x\nture'\t{sum}\n");
        let record = rpm_record(output.as_bytes(), &paths).unwrap().unwrap();
        assert_eq!(record.path, Path::new("/bin/fi'x\nture"));
        assert_eq!(record.name, "Example");
        assert_eq!(record.algorithm, Algorithm::Sha256);
        assert_eq!(record.sum, sum);
        let output = "Legacy\t(none)\n'/bin/fi'\\''x\nture'\t900150983cd24fb0d6963f7d28e17f72\n";
        assert_eq!(
            rpm_record(output.as_bytes(), &paths)
                .unwrap()
                .unwrap()
                .algorithm,
            Algorithm::Md5
        );
        for (output, failure) in [
            (
                "Example\t8\n'/bin/fi'\\''x\nture'\t\n",
                PackageChecksumUnavailable,
            ),
            (
                "Example\t8\n'/bin/fi'\\''x\nture'\tbad\n",
                AppIdentityUnproven,
            ),
            ("Example\t8\n'/bin/fi'\\''x\nture'\t", AppIdentityUnproven),
            ("broken stderr as stdout\n", AppIdentityUnproven),
        ] {
            assert_eq!(
                rpm_record(output.as_bytes(), &paths)
                    .err()
                    .map(RpmOutputFailure::refusal),
                Some(failure)
            );
        }
        assert!(rpm_record(b"Other\t8\n'/bin/other'\t\n", &paths)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rpm_snapshot_distinguishes_sqlite_reader_bookkeeping_from_database_changes() {
        let before = ImageKey {
            dev: 8,
            ino: 42,
            size: 32768,
            mtime: (10, 20),
            ctime: (10, 20),
        };
        let after_read = ImageKey {
            mtime: (10, 30),
            ctime: (10, 30),
            ..before
        };
        let shared_memory = OsStr::new("rpmdb.sqlite-shm");
        assert_eq!(
            rpm_file_stamp(shared_memory, before),
            rpm_file_stamp(shared_memory, after_read),
            "a query may update the SQLite read-lock index"
        );
        for filename in ["rpmdb.sqlite", "rpmdb.sqlite-wal", "Packages", "other-shm"] {
            let path = OsStr::new(filename);
            assert_ne!(
                rpm_file_stamp(path, before),
                rpm_file_stamp(path, after_read),
                "{filename} must retain its timestamp evidence"
            );
        }
        for changed in [
            ImageKey { dev: 9, ..before },
            ImageKey { ino: 43, ..before },
            ImageKey { size: 0, ..before },
        ] {
            assert_ne!(
                rpm_file_stamp(shared_memory, before),
                rpm_file_stamp(shared_memory, changed),
                "the shared-memory file must not be replaced or resized"
            );
        }
    }

    #[test]
    fn a_nonzero_rpm_exit_never_produces_an_unowned_result() {
        for code in [0, 7] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", &format!("printf 'db error' >&2; exit {code}")])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            match collect_rpm(&mut child).unwrap_err() {
                RpmQueryFailure::Exited { status, stderr } if code != 0 => {
                    assert_eq!(status.code(), Some(code));
                    assert_eq!(stderr, b"db error");
                }
                RpmQueryFailure::Stderr { status, stderr } if code == 0 => {
                    assert!(status.success());
                    assert_eq!(stderr, b"db error");
                }
                error => panic!("unexpected diagnostic: {error}"),
            }
        }
    }

    #[test]
    fn rpm_snapshot_diagnostic_names_the_changed_file_and_fields() {
        let key = ImageKey {
            dev: 8,
            ino: 42,
            size: 0,
            mtime: (10, 20),
            ctime: (10, 20),
        };
        let name = OsString::from("rpmdb.sqlite-wal");
        let before = vec![(name.clone(), key)];
        let after = vec![(
            name.clone(),
            ImageKey {
                size: 8192,
                ctime: (10, 30),
                ..key
            },
        )];
        assert_eq!(
            snapshot_change(&before, &after),
            Some(SnapshotChange::Changed {
                name: name.clone(),
                fields: vec!["size", "ctime"],
                before: key,
                after: after[0].1
            })
        );
        assert_eq!(
            snapshot_change(&before, &[]),
            Some(SnapshotChange::Removed {
                name: name.clone(),
                stamp: key
            })
        );
        assert_eq!(
            snapshot_change(&[], &after),
            Some(SnapshotChange::Added {
                name,
                stamp: after[0].1
            })
        );
    }

    #[test]
    #[ignore = "requires sudo, rpm/rpmbuild and a private mount namespace on GitHub-hosted Ubuntu"]
    fn native_rpm_reads_real_file_digests_from_a_system_database() {
        require_hosted_runner();
        let scratch = Scratch::new();
        let spec = scratch.0.join("fixture.spec");
        fs::write(&spec, "Name: ck-fixture\nVersion: 1\nRelease: 1\nSummary: Test file ownership\nLicense: MIT\nBuildArch: noarch\n%description\nTest file ownership\n%install\nmkdir -p %{buildroot}/usr/share/ck-fixture\nprintf abc > %{buildroot}/usr/share/ck-fixture/proof\n%files\n/usr/share/ck-fixture/proof\n").unwrap();
        checked(
            Command::new("rpmbuild")
                .arg("--define")
                .arg(format!("_topdir {}", scratch.0.display()))
                .args(["--define", "_binary_filedigest_algorithm 8", "-bb"])
                .arg(&spec),
        );
        let db = scratch.0.join("rpmdb");
        fs::create_dir(&db).unwrap();
        checked(
            Command::new(RPM)
                .arg("--dbpath")
                .arg(&db)
                .args(["--initdb", "--noplugins"]),
        );
        checked(
            Command::new(RPM)
                .arg("--dbpath")
                .arg(&db)
                .args([
                    "-i",
                    "--justdb",
                    "--nodeps",
                    "--noscripts",
                    "--notriggers",
                    "--noplugins",
                ])
                .arg(scratch.0.join("RPMS/noarch/ck-fixture-1-1.noarch.rpm")),
        );
        // The scratch DB is exposed through protected /mnt instead of the
        // intentionally writable /tmp. The bind is local to this test process.
        checked(Command::new("mount").arg("--bind").arg(&db).arg("/mnt"));
        let _mount = crate::identity::tests::TestMount("/mnt");
        let root = open_path(Path::new("/")).unwrap();
        let output = query_rpm(&root, Path::new("/mnt")).unwrap_or_else(|cause| {
            let files: Vec<_> = fs::read_dir(&db).unwrap().filter_map(Result::ok).map(|entry| entry.file_name()).collect();
            panic!("querying the private RPM fixture database mounted at /mnt (uid {}): {cause}; database entries after query: {files:?}", crate::bridge::read_effective_uid());
        });
        let record = rpm_record(
            &output,
            &candidates(Path::new("/usr/share/ck-fixture/proof")),
        )
        .unwrap_or_else(|cause| panic!("reading the native fixture RPM record: {cause}"))
        .expect("rpm exited 0 with empty stderr, but the populated fixture database did not list /usr/share/ck-fixture/proof");
        assert_eq!(record.name, "ck-fixture");
        assert_eq!(record.algorithm, Algorithm::Sha256);
        assert_eq!(
            record.sum,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
