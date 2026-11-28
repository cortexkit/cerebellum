//! Resolve a desktop launch from protected files, never the daemon's PATH.

use super::*;
use crate::session::Environment;
use std::collections::{BTreeMap, HashSet};

const ENTRY_LIMIT: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchRefusal {
    Unsupported,
    Identity(Refusal),
    Ambiguous,
    NotInstalled,
}

impl LaunchRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unsupported => "launch_entry_unsupported",
            Self::Identity(reason) => reason.reason(),
            Self::Ambiguous => "ambiguous_app",
            Self::NotInstalled => "no_installed_app_named",
        }
    }
}

impl From<Refusal> for LaunchRefusal {
    fn from(reason: Refusal) -> Self {
        Self::Identity(reason)
    }
}

struct Entry {
    path: PathBuf,
    file: File,
    key: ImageKey,
    bytes: Vec<u8>,
}

impl Entry {
    fn read(path: PathBuf, leaf: &File) -> io::Result<Self> {
        let mut file = regular_read(leaf)?;
        let meta = file.metadata()?;
        let key = image_key(&meta);
        if meta.len() > ENTRY_LIMIT {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file).take(ENTRY_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > ENTRY_LIMIT || image_key(&file.metadata()?) != key {
            return Err(invalid());
        }
        Ok(Self {
            path,
            file,
            key,
            bytes,
        })
    }

    fn sha256(&self) -> sha2::digest::Output<Sha256> {
        Sha256::digest(&self.bytes)
    }
}

struct Program {
    path: PathBuf,
    _file: File,
    key: ImageKey,
    subject: String,
}

/// A consent answer is for one resolved entry and one program. Hold both
/// original descriptors so unlinking their paths cannot recycle their inodes.
pub struct Snapshot {
    name: String,
    entry_path: PathBuf,
    entry_key: ImageKey,
    entry_sha256: sha2::digest::Output<Sha256>,
    _entry: File,
    program: Program,
    arguments: Vec<OsString>,
}

impl Snapshot {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn subject(&self) -> &str {
        &self.program.subject
    }
    pub fn executable(&self) -> &Path {
        &self.program.path
    }
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub fn recheck(&self, reader: &IdentityReader) -> Result<(), Refusal> {
        let root = open_path(Path::new("/")).map_err(|_| AppIdentityUnproven)?;
        self.recheck_at(reader, &root)
    }

    fn recheck_at(&self, reader: &IdentityReader, root: &File) -> Result<(), Refusal> {
        let leaf = walk(root, &self.entry_path, true).map_err(|_| StaleReference)?;
        let entry = Entry::read(self.entry_path.clone(), &leaf).map_err(|_| StaleReference)?;
        if entry.key != self.entry_key || entry.sha256() != self.entry_sha256 {
            return Err(StaleReference);
        }
        let program =
            program_at(reader, root, self.executable()).map_err(|_| ImageReplacedSinceLaunch)?;
        if program.key != self.program.key || program.subject != self.subject() {
            return Err(ImageReplacedSinceLaunch);
        }
        Ok(())
    }

    pub fn check_stopped(
        &self,
        reader: &IdentityReader,
        started: ProcessGeneration,
    ) -> Result<(), Refusal> {
        self.recheck(reader)?;
        let app = reader
            .prove(started.pid)
            .map_err(|_| ImageReplacedSinceLaunch)?;
        if app.generation != started
            || app.exe_device != self.program.key.dev
            || app.exe_inode != self.program.key.ino
            || app.subject != self.subject()
        {
            return Err(ImageReplacedSinceLaunch);
        }
        Ok(())
    }

    /// Catch path changes while logind is confirming the active session and
    /// lock state, without repeating the package queries just performed.
    pub fn check_paths_unchanged(&self) -> Result<(), Refusal> {
        let root = open_path(Path::new("/")).map_err(|_| AppIdentityUnproven)?;
        for (path, expected, reason) in [
            (self.entry_path.as_path(), self.entry_key, StaleReference),
            (
                self.executable(),
                self.program.key,
                ImageReplacedSinceLaunch,
            ),
        ] {
            let leaf = walk(&root, path, true).map_err(|_| reason)?;
            if image_key(&leaf.metadata().map_err(|_| reason)?) != expected {
                return Err(reason);
            }
        }
        Ok(())
    }
}

pub fn resolve(
    reader: &IdentityReader,
    env: &Environment,
    target: &str,
) -> Result<Snapshot, LaunchRefusal> {
    let root = open_path(Path::new("/")).map_err(|_| AppIdentityUnproven)?;
    resolve_at(reader, &root, env, target.trim())
}

fn resolve_at(
    reader: &IdentityReader,
    root: &File,
    env: &Environment,
    target: &str,
) -> Result<Snapshot, LaunchRefusal> {
    let qualified = is_subject(target);
    let data_dirs = env
        .get("XDG_DATA_DIRS")
        .map(String::as_str)
        .filter(|dirs| !dirs.is_empty())
        .unwrap_or("/usr/local/share:/usr/share");
    let mut seen = HashSet::new();
    let mut named = Vec::new();
    let mut by_id = Vec::new();
    let mut found = None;
    for data in data_dirs
        .split(':')
        .map(Path::new)
        .filter(|path| path.is_absolute())
    {
        let applications = data.join("applications");
        let Ok(directory) = walk(root, &applications, false) else {
            continue;
        };
        let export = data.ends_with("flatpak/exports/share")
            || fs::read_link(fd_path(&directory))
                .is_ok_and(|path| path.ends_with("flatpak/exports/share/applications"));
        for (id, path) in desktop_files(&directory, &applications) {
            let id_match =
                !qualified && (id == target || id.strip_suffix(".desktop") == Some(target));
            if export && id_match {
                return Err(AppIdentityUnproven.into());
            }
            let (leaf, protected_path) = match walk(root, &path, true) {
                Ok(leaf) => (leaf, true),
                Err(_) if !qualified => {
                    let Ok(leaf) = walk(root, &path, false) else {
                        continue;
                    };
                    (leaf, false)
                }
                Err(_) => continue,
            };
            let Ok(entry) = Entry::read(path, &leaf) else {
                continue;
            };
            let fields = fields(&entry.bytes);
            let name = fields.get("Name").and_then(|name| unescape(name));
            let name_match = !qualified
                && name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(target));
            if export || fields.contains_key("X-Flatpak") {
                if id_match || name_match {
                    return Err(AppIdentityUnproven.into());
                }
                continue;
            }
            if !protected_path
                || !seen.insert(id.clone())
                || flag(&fields, "Hidden")
                || flag(&fields, "NoDisplay")
            {
                continue;
            }
            if id_match {
                by_id.push((entry, name.unwrap_or(id)));
            } else if name_match {
                named.push((entry, name.unwrap_or(id)));
            } else if qualified {
                if let Ok(snapshot) = snapshot(reader, root, entry, name.unwrap_or(id)) {
                    if snapshot.subject() == target && found.replace(snapshot).is_some() {
                        return Err(LaunchRefusal::Ambiguous);
                    }
                }
            }
        }
    }
    if !by_id.is_empty() {
        named = by_id;
    }
    let mut problem = None;
    for (entry, name) in named {
        match snapshot(reader, root, entry, name) {
            Ok(snapshot) => {
                if found.is_some() {
                    return Err(LaunchRefusal::Ambiguous);
                }
                found = Some(snapshot);
            }
            Err(reason) => {
                problem.get_or_insert(reason);
            }
        }
    }
    found.ok_or(problem.unwrap_or(LaunchRefusal::NotInstalled))
}

fn desktop_files(directory: &File, applications: &Path) -> Vec<(String, PathBuf)> {
    let mut result = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let Ok(children) = fs::read_dir(fd_path(directory).join(&relative)) else {
            continue;
        };
        for child in children.flatten() {
            let name = child.file_name();
            let path = relative.join(&name);
            let Ok(kind) = child.file_type() else {
                continue;
            };
            // Do not follow directory symlinks (including loops). A desktop
            // file may itself be an export symlink to the installed entry.
            if kind.is_dir() {
                pending.push(path);
            } else if (kind.is_file() || kind.is_symlink())
                && path.extension() == Some(OsStr::new("desktop"))
            {
                if let Some(id) = path.to_str() {
                    result.push((id.replace('/', "-"), applications.join(path)));
                }
            }
        }
    }
    result.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    result
}

fn fields(bytes: &[u8]) -> BTreeMap<&str, &str> {
    let mut fields = BTreeMap::new();
    let Ok(text) = std::str::from_utf8(bytes) else {
        return fields;
    };
    let mut desktop = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            if desktop {
                break;
            }
            desktop = line == "[Desktop Entry]";
        } else if desktop && !line.starts_with('#') {
            if let Some((key, value)) = line.split_once('=') {
                fields.insert(key.trim_end(), value.trim_start());
            }
        }
    }
    fields
}

fn flag(fields: &BTreeMap<&str, &str>, key: &str) -> bool {
    fields
        .get(key)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn snapshot(
    reader: &IdentityReader,
    root: &File,
    mut entry: Entry,
    name: String,
) -> Result<Snapshot, LaunchRefusal> {
    let fields = fields(&entry.bytes);
    if fields.get("Type") != Some(&"Application") || flag(&fields, "Terminal") {
        return Err(LaunchRefusal::Unsupported);
    }
    let mut packages = reader.packages.lock().map_err(|_| AppIdentityUnproven)?;
    let entry_fd = entry.file.as_raw_fd();
    let checksum = |file: &mut File, key, algorithm| {
        if file.as_raw_fd() == entry_fd {
            if key != entry.key {
                return Err(StaleReference);
            }
            return Ok(match algorithm {
                Algorithm::Md5 => format!("{:x}", Md5::digest(&entry.bytes)),
                Algorithm::Sha224 => format!("{:x}", Sha224::digest(&entry.bytes)),
                Algorithm::Sha256 => format!("{:x}", Sha256::digest(&entry.bytes)),
                Algorithm::Sha384 => format!("{:x}", Sha384::digest(&entry.bytes)),
                Algorithm::Sha512 => format!("{:x}", Sha512::digest(&entry.bytes)),
            });
        }
        // The RPM reader also checks the rpm program against its own record.
        reader.digest(file, key, algorithm)
    };
    packages
        .launch_subject(root, &entry.path, &mut entry.file, checksum)?
        .ok_or(LaunchRefusal::Unsupported)?;
    if image_key(&entry.file.metadata().map_err(|_| StaleReference)?) != entry.key {
        return Err(StaleReference.into());
    }
    drop(packages);
    let exec = fields.get("Exec").ok_or(LaunchRefusal::Unsupported)?;
    let (path, arguments) = exec_line(exec)?;
    let program = if path.is_absolute() {
        program_at(reader, root, &path)?
    } else {
        let usr = Path::new("/usr/bin").join(&path);
        match walk(root, &usr, true) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                program_at(reader, root, &Path::new("/bin").join(path))?
            }
            _ => program_at(reader, root, &usr)?,
        }
    };
    Ok(Snapshot {
        name,
        entry_path: entry.path.clone(),
        entry_key: entry.key,
        entry_sha256: entry.sha256(),
        _entry: entry.file,
        program,
        arguments,
    })
}

fn program_at(reader: &IdentityReader, root: &File, path: &Path) -> Result<Program, LaunchRefusal> {
    if path.starts_with("/snap") || path.components().any(|part| part == Component::ParentDir) {
        return Err(LaunchRefusal::Unsupported);
    }
    let leaf = walk(root, path, true).map_err(|_| LaunchRefusal::Unsupported)?;
    let actual = fs::read_link(fd_path(&leaf)).map_err(|_| LaunchRefusal::Unsupported)?;
    for path in [path, actual.as_path()] {
        if path.starts_with("/snap")
            || path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| {
                    matches!(
                        name,
                        "env" | "busybox" | "fish" | "ksh" | "csh" | "tcsh" | "ash"
                    )
                })
        {
            return Err(LaunchRefusal::Unsupported);
        }
        check_basename(path).map_err(|reason| match reason {
            InterpreterHostedImage => LaunchRefusal::Unsupported,
            other => other.into(),
        })?;
    }
    let mut file = regular_read(&leaf).map_err(|_| LaunchRefusal::Unsupported)?;
    let meta = file.metadata().map_err(|_| LaunchRefusal::Unsupported)?;
    let key = image_key(&meta);
    let mut magic = [0; 4];
    if meta.mode() & 0o111 == 0 || file.read_exact(&mut magic).is_err() || magic != *b"\x7fELF" {
        return Err(LaunchRefusal::Unsupported);
    }
    let subject = reader
        .packages
        .lock()
        .map_err(|_| AppIdentityUnproven)?
        .launch_subject(root, path, &mut file, |file, key, algorithm| {
            reader.digest(file, key, algorithm)
        })?
        .ok_or(LaunchRefusal::Unsupported)?;
    if subject
        .split_once(':')
        .is_some_and(|(_, name)| name.eq_ignore_ascii_case("alfonso"))
    {
        return Err(OperatorAppBlocked.into());
    }
    if image_key(&file.metadata().map_err(|_| ImageReplacedSinceLaunch)?) != key {
        return Err(ImageReplacedSinceLaunch.into());
    }
    Ok(Program {
        path: path.to_owned(),
        _file: file,
        key,
        subject,
    })
}

fn unescape(text: &str) -> Option<String> {
    let mut result = String::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        result.push(if ch == '\\' {
            match chars.next()? {
                's' => ' ',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                _ => return None,
            }
        } else if ch == '\0' {
            return None;
        } else {
            ch
        });
    }
    Some(result)
}

fn exec_line(value: &str) -> Result<(PathBuf, Vec<OsString>), LaunchRefusal> {
    use LaunchRefusal::Unsupported;
    let text = unescape(value).ok_or(Unsupported)?;
    let mut chars = text.chars().peekable();
    let mut words = Vec::new();
    while chars.peek().is_some() {
        let mut word = String::new();
        if chars.next_if_eq(&'"').is_some() {
            loop {
                let ch = chars.next().ok_or(Unsupported)?;
                match ch {
                    '"' => break,
                    '\\' => {
                        let escaped = chars.next().ok_or(Unsupported)?;
                        if !matches!(escaped, '"' | '`' | '$' | '\\') {
                            return Err(Unsupported);
                        }
                        word.push(escaped);
                    }
                    '`' | '$' => return Err(Unsupported),
                    _ => word.push(ch),
                }
            }
            if chars.peek().is_some_and(|ch| !ch.is_ascii_whitespace()) {
                return Err(Unsupported);
            }
        } else if chars.next_if(|ch| ch.is_ascii_whitespace()).is_some() {
            continue;
        } else {
            while let Some(ch) = chars.next_if(|ch| !ch.is_ascii_whitespace()) {
                if "\"'\\><~|&;$*?#()`".contains(ch) || ch.is_control() {
                    return Err(Unsupported);
                }
                word.push(ch);
            }
        }
        words.push(word);
    }
    let mut words = words.into_iter();
    let program = words.next().ok_or(Unsupported)?;
    if program.is_empty()
        || program.contains(['%', '='])
        || (!program.starts_with('/') && program.contains('/'))
        || matches!(program.as_str(), "." | "..")
    {
        return Err(Unsupported);
    }
    let mut arguments = Vec::new();
    for word in words {
        if matches!(
            word.as_str(),
            "%f" | "%F" | "%u" | "%U" | "%i" | "%c" | "%k"
        ) {
            continue;
        }
        let mut chars = word.chars();
        let mut decoded = String::new();
        while let Some(ch) = chars.next() {
            if ch == '%' && chars.next() != Some('%') {
                return Err(Unsupported);
            }
            decoded.push(ch);
        }
        arguments.push(decoded.into());
    }
    Ok((program.into(), arguments))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_is_literal_and_removes_file_codes_without_adding_empty_arguments() {
        assert_eq!(
            exec_line(r#"fixture --view "a file" %U %% --scale=100%% """#).unwrap(),
            (
                PathBuf::from("fixture"),
                ["--view", "a file", "%", "--scale=100%", ""]
                    .map(OsString::from)
                    .to_vec()
            )
        );
        for invalid in [
            "fixture %Z",
            "fixture --file=%f",
            "fixture test%",
            "./fixture",
            "VAR=1 fixture",
            "fixture 'quoted'",
            "fixture a;command",
            "fixture \"bad $NAME\"",
            "fixture \"unterminated",
        ] {
            assert_eq!(
                exec_line(invalid),
                Err(LaunchRefusal::Unsupported),
                "{invalid}"
            );
        }
    }

    #[test]
    fn flatpak_export_ids_and_marked_entries_take_precedence_even_in_writable_dirs() {
        let temp = std::env::temp_dir().join(format!("ck-flatpak-entries-{}", std::process::id()));
        std::fs::create_dir(&temp).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let _cleanup = Cleanup(temp.clone());
        let root = open_path(&temp).unwrap();
        let reader = IdentityReader::default();
        let flatpak = [
            "/var/lib/flatpak/exports/share",
            "/user/share/flatpak/exports/share",
        ];
        for data in flatpak.into_iter().chain(["/ordinary", "/writable"]) {
            let dir = temp.join(data.trim_start_matches('/')).join("applications");
            fs::create_dir_all(&dir).unwrap();
            let entry = dir.join("org.example.Fixture.desktop");
            let marker = if data == "/writable" {
                "X-Flatpak=org.example.Other"
            } else {
                ""
            };
            fs::write(
                entry,
                format!("[Desktop Entry]\nName=Fixture\nHidden=true\nExec=anything\n{marker}\n"),
            )
            .unwrap();
        }
        for data in flatpak.into_iter().chain(["/writable"]) {
            let env = Environment::from([("XDG_DATA_DIRS".into(), format!("/ordinary:{data}"))]);
            for target in ["org.example.Fixture", "Fixture"] {
                assert_eq!(
                    resolve_at(&reader, &root, &env, target).err(),
                    Some(AppIdentityUnproven.into()),
                    "{data}: {target}"
                );
            }
        }
    }
}
