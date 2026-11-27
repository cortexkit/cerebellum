//! A silent native-messaging relay that authenticates its Chrome parent and the
//! local cerebellum socket server. Cerebellum separately authenticates the host.
//!
//! The host never interprets action payloads. The cerebellum browser bridge owns
//! action admission, epochs, deadlines, cancellation and chunking.

use std::ffi::OsString;
use std::io;

pub mod browsers;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
mod framing;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
pub mod registration;
#[cfg(all(unix, any(target_os = "linux", target_os = "macos", test)))]
mod relay;
#[cfg(all(unix, any(target_os = "linux", target_os = "macos", test)))]
mod transport;

/// Check whether this build can enable the native-messaging bridge.
pub fn check_build_gate() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    linux::build_key()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        #[cfg(target_os = "windows")]
        const REVISION: Option<&str> =
            option_env!("CEREBELLUM_WINDOWS_USER_BROWSER_REVIEW_REVISION");
        #[cfg(not(target_os = "windows"))]
        const REVISION: Option<&str> = None;

        cerebellum_bridge_protocol::classify_bridge_gate(
            REVISION,
            option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"),
        )
        .ok_or_else(unbound_gate)?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn unbound_gate() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "native messaging is not enabled in this build",
    )
}

fn extension_origin(mut args: impl Iterator<Item = OsString>) -> io::Result<String> {
    args.nth(1)
        .and_then(|origin| origin.into_string().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing extension origin"))
}

pub fn run() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run(linux::build_key()?)
    }
    #[cfg(target_os = "macos")]
    {
        macos::run()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        check_build_gate()?;
        let _ = extension_origin(std::env::args_os())?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native messaging transport is unavailable on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_bridge_protocol::EXTENSION_ORIGIN;

    #[test]
    fn uses_argv_one_even_with_chromes_trailing_window_argument() {
        let args = [
            "ck-cerebellum-native-host",
            EXTENSION_ORIGIN,
            "--parent-window=1234",
        ];
        assert_eq!(
            extension_origin(args.into_iter().map(OsString::from)).unwrap(),
            EXTENSION_ORIGIN
        );
    }

    #[test]
    fn rejects_a_missing_origin() {
        assert_eq!(
            extension_origin([OsString::from("ck-cerebellum-native-host")].into_iter())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
