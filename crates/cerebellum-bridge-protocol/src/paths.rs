use std::io;
use std::path::PathBuf;

/// Locate the Linux bridge socket using the caller's inherited data-home environment.
pub fn linux_socket_path() -> io::Result<PathBuf> {
    Ok(cortexkit_paths::cortexkit_run_dir()
        .map_err(io::Error::other)?
        .join("cerebellum/user-browser.sock"))
}

/// Name the Windows bridge pipe for the current process token user's canonical security identifier (SID).
pub fn windows_pipe_name(user_sid: &str) -> String {
    format!(r"\\.\pipe\cortexkit-cerebellum-user-browser-{user_sid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_socket_path_is_under_the_inherited_run_directory() {
        let path = linux_socket_path().unwrap();
        let directory = path.parent().unwrap();
        assert_eq!(path.file_name().unwrap(), "user-browser.sock");
        assert_eq!(directory.file_name().unwrap(), "cerebellum");
        assert_eq!(
            directory.parent().unwrap(),
            cortexkit_paths::cortexkit_run_dir().unwrap()
        );
    }

    #[test]
    fn windows_pipe_name_is_local_and_specific_to_the_user_sid() {
        let sid = "S-1-5-21-111222333-444555666-777888999-1001";
        assert_eq!(
            windows_pipe_name(sid),
            r"\\.\pipe\cortexkit-cerebellum-user-browser-S-1-5-21-111222333-444555666-777888999-1001"
        );
        assert_ne!(windows_pipe_name(sid), windows_pipe_name("S-1-5-18"));
    }
}
