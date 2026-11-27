//! A silent native-messaging relay that authenticates its Chrome parent and the
//! local cerebellum server. Cerebellum separately authenticates the host.
//!
//! The host never interprets action payloads. The cerebellum browser bridge owns
//! action admission, epochs, deadlines, cancellation and chunking.

use std::ffi::OsString;
use std::io;

pub mod browsers;
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
mod framing;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
pub mod registration;
#[cfg(any(
    windows,
    all(unix, any(target_os = "linux", target_os = "macos", test))
))]
mod relay;
#[cfg(any(
    windows,
    all(unix, any(target_os = "linux", target_os = "macos", test))
))]
mod transport;
#[cfg(windows)]
mod windows;

/// Check whether this build can enable the native-messaging bridge.
pub fn check_build_gate() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    linux::build_key()?;
    #[cfg(windows)]
    windows::build_key()?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    cerebellum_bridge_protocol::classify_bridge_gate(
        None,
        option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"),
    )
    .ok_or_else(unbound_gate)?;
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
    #[cfg(windows)]
    {
        windows::run(windows::build_key()?)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
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
