//! Chrome native-messaging registration shared by the shipped command and the
//! development browser probe.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cerebellum_bridge_protocol::{EXTENSION_ORIGIN, NATIVE_HOST_NAME};
use serde_json::json;

use crate::browsers::HOST_MANIFEST_LOCATIONS;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Register the canonical path of this running executable for the current user.
/// On Linux, returns the Google Chrome manifest path after writing both manifests.
pub fn register_running_executable() -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    let base = linux_config_base()?;
    #[cfg(not(target_os = "linux"))]
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is unset".to_owned())?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate the running executable: {error}"))?;
    let executable = fs::canonicalize(&executable).map_err(|error| {
        format!("could not canonicalize running executable {executable:?}: {error}")
    })?;
    if !executable.is_absolute() {
        return Err("the canonical running executable path is not absolute".into());
    }
    #[cfg(target_os = "linux")]
    {
        let chrome = write_manifest_at(
            &base.join("google-chrome/NativeMessagingHosts"),
            &executable,
        )?;
        write_manifest_at(&base.join("chromium/NativeMessagingHosts"), &executable)?;
        Ok(chrome)
    }
    #[cfg(not(target_os = "linux"))]
    write_manifest(Path::new(&home), &executable)
}

#[cfg(target_os = "linux")]
fn linux_config_base() -> Result<PathBuf, String> {
    let nonempty = |name| std::env::var_os(name).filter(|value| !value.is_empty());
    nonempty("CHROME_CONFIG_HOME")
        .or_else(|| nonempty("XDG_CONFIG_HOME"))
        .map(PathBuf::from)
        .or_else(|| nonempty("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| "HOME is unset".to_owned())
}

/// Write Chrome's manifest below an explicit home directory.
pub fn write_manifest(home: &Path, executable: &Path) -> Result<PathBuf, String> {
    if !home.is_absolute() {
        return Err("HOME must be an absolute path".into());
    }
    let mut enabled = HOST_MANIFEST_LOCATIONS
        .iter()
        .filter(|location| location.enabled);
    let chrome = enabled
        .next()
        .ok_or_else(|| "no browser manifest destination is enabled".to_owned())?;
    if enabled.next().is_some() {
        return Err("more than one browser manifest destination is enabled".into());
    }
    write_manifest_at(&home.join(chrome.home_relative_directory), executable)
}

/// Write a manifest in an explicit directory. The development probe uses this
/// for its isolated Chrome for Testing profile as well as the standard path.
pub fn write_manifest_at(directory: &Path, executable: &Path) -> Result<PathBuf, String> {
    if !directory.is_absolute() || !executable.is_absolute() {
        return Err("manifest directory and host executable must be absolute".into());
    }
    let executable = fs::canonicalize(executable).map_err(|error| {
        format!("could not canonicalize host executable {executable:?}: {error}")
    })?;
    if !executable.is_absolute() || !executable.is_file() {
        return Err("the canonical host executable must be an absolute regular file".into());
    }
    let executable_text = executable
        .to_str()
        .ok_or_else(|| "host executable path is not valid UTF-8".to_owned())?;
    let manifest = json!({
        "name": NATIVE_HOST_NAME,
        "description": "CortexKit Chrome bridge",
        "path": executable_text,
        "type": "stdio",
        "allowed_origins": [EXTENSION_ORIGIN],
    });
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("could not encode the Chrome manifest: {error}"))?;
    bytes.push(b'\n');

    let path = directory.join(format!("{NATIVE_HOST_NAME}.json"));
    reject_symlinks(&path)?;
    if read_safe_existing(&path)?.as_deref() == Some(bytes.as_slice()) {
        return Ok(path);
    }

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(directory)
        .map_err(|error| format!("could not create manifest directory {directory:?}: {error}"))?;
    // Check again after creating parents: no pre-existing component may redirect
    // the manifest into another browser profile or another location.
    reject_symlinks(directory)?;

    let (mut file, mut temporary) = create_temporary(directory)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            format!(
                "could not make temporary manifest {:?} private: {error}",
                temporary.path
            )
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            format!(
                "could not write temporary manifest {:?}: {error}",
                temporary.path
            )
        })?;
    drop(file);

    // A link introduced while the temporary file was written must still be
    // refused. Rename never follows a target symlink, but refusing it preserves
    // the existing path rather than silently replacing somebody else's link.
    let current = read_safe_existing(&path)?;
    if current.as_deref() == Some(bytes.as_slice()) {
        return Ok(path);
    }
    fs::rename(&temporary.path, &path).map_err(|error| {
        format!(
            "could not atomically replace manifest {path:?} from {:?}: {error}",
            temporary.path
        )
    })?;
    temporary.cleanup = false;
    Ok(path)
}

fn reject_symlinks(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("refusing symlink {current:?}"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("could not inspect {current:?}: {error}")),
        }
    }
    Ok(())
}

fn read_safe_existing(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("refusing symlink manifest {path:?}"));
            }
            if !metadata.file_type().is_file() {
                return Err(format!("refusing non-regular manifest {path:?}"));
            }
            #[cfg(unix)]
            if metadata.nlink() != 1 {
                return Err(format!(
                    "refusing manifest with more than one link {path:?}"
                ));
            }
            fs::read(path)
                .map(Some)
                .map_err(|error| format!("could not read existing manifest {path:?}: {error}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "could not inspect existing manifest {path:?}: {error}"
        )),
    }
}

fn create_temporary(directory: &Path) -> Result<(File, TemporaryManifest), String> {
    for _ in 0..100 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            ".{NATIVE_HOST_NAME}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => {
                return Ok((
                    file,
                    TemporaryManifest {
                        path,
                        cleanup: true,
                    },
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "could not create temporary manifest {path:?}: {error}"
                ));
            }
        }
    }
    Err(format!(
        "could not allocate a temporary manifest in {directory:?}"
    ))
}

struct TemporaryManifest {
    path: PathBuf,
    cleanup: bool,
}

impl Drop for TemporaryManifest {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = fs::remove_file(&self.path);
        }
    }
}
