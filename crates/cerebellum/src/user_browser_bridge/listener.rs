#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use super::UserBrowserBridge;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use std::io;

/// Owns the private endpoint and its accept loop. Dropping it stops the listener
/// and connection; it never sends signals to Chrome or closes any browser tab.
pub struct BridgeListener {
    #[cfg(any(target_os = "macos", target_os = "linux", all(unix, test)))]
    pub(super) _socket: super::socket::SocketListener,
    #[cfg(windows)]
    _pipe: super::windows::PipeListener,
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows, all(unix, test))))]
    _unavailable: std::convert::Infallible,
}

impl BridgeListener {
    #[cfg(target_os = "macos")]
    pub fn bind(bridge: UserBrowserBridge) -> io::Result<Self> {
        let path = cortexkit_paths::cortexkit_run_dir()
            .map_err(io::Error::other)?
            .join("cerebellum/user-browser.sock");
        let socket =
            super::socket::SocketListener::bind(bridge, path, super::admission::Admission::MacOs)?;
        Ok(Self { _socket: socket })
    }

    #[cfg(target_os = "linux")]
    pub fn bind(bridge: UserBrowserBridge) -> io::Result<Self> {
        let socket = super::linux::bind(bridge)?;
        Ok(Self { _socket: socket })
    }

    #[cfg(windows)]
    pub fn bind(bridge: UserBrowserBridge) -> io::Result<Self> {
        let pipe = super::windows::bind(bridge)?;
        Ok(Self { _pipe: pipe })
    }
}
