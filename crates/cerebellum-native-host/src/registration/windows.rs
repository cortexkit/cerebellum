use super::{write_manifest_at, NATIVE_HOST_NAME};
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf, Prefix};

pub(super) fn register(executable: &Path) -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|path| !path.is_empty())
        .ok_or_else(|| "LOCALAPPDATA is unset".to_owned())?;
    let directory = PathBuf::from(base).join(r"CortexKit\cerebellum");
    let path = write_manifest_at(&directory, executable)?;
    let key = format!(r"Software\Google\Chrome\NativeMessagingHosts\{NATIVE_HOST_NAME}");
    cerebellum_windows::set_current_user_default_string(
        OsStr::new(&key),
        chrome_path(&path).as_os_str(),
    )
    .map_err(|error| format!("could not set HKCU\\{key}: {error}"))?;
    Ok(path)
}

pub(super) fn chrome_path(path: &Path) -> PathBuf {
    if matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::VerbatimDisk(_)))
    {
        // Chrome's cmd.exe launch cannot use the extended drive path returned
        // by canonicalize. Preserve the rest of the path byte for byte in UTF-16.
        let units: Vec<_> = path.as_os_str().encode_wide().skip(4).collect();
        PathBuf::from(OsString::from_wide(&units))
    } else {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_only_the_extended_drive_prefix() {
        for (input, expected) in [
            (r"\\?\C:\CortexKit\hé.exe", r"C:\CortexKit\hé.exe"),
            (r"C:\CortexKit\host.exe", r"C:\CortexKit\host.exe"),
            (r"\\?\UNC\host\share\exe", r"\\?\UNC\host\share\exe"),
        ] {
            // Compare the actual string, not Path's normalized components.
            assert_eq!(chrome_path(Path::new(input)).as_os_str(), expected);
        }
    }
}
