#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use super::UserBrowserBridge;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use std::io;

/// Owns the private endpoint and its accept loop. Dropping it stops the listener
/// and connection; it never sends signals to Chrome or closes any browser tab.
pub struct BridgeListener {
    #[cfg(any(target_os = "macos", all(unix, test)))]
    pub(super) _socket: super::socket::SocketListener,
    #[cfg(not(any(target_os = "macos", all(unix, test))))]
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

    #[cfg(any(target_os = "linux", windows))]
    pub fn bind(_bridge: UserBrowserBridge) -> io::Result<Self> {
        use cerebellum_bridge_protocol::classify_bridge_gate;

        #[cfg(target_os = "linux")]
        const REVISION: Option<&str> = option_env!("CEREBELLUM_LINUX_USER_BROWSER_REVIEW_REVISION");
        #[cfg(windows)]
        const REVISION: Option<&str> =
            option_env!("CEREBELLUM_WINDOWS_USER_BROWSER_REVIEW_REVISION");
        let Some(_key) =
            classify_bridge_gate(REVISION, option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"))
        else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native messaging is not enabled in this build",
            ));
        };

        // A reviewed key cannot admit peers without native process checks.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native messaging peer verification is unavailable",
        ))
    }
}

#[cfg(all(test, any(target_os = "linux", windows)))]
mod tests {
    use super::*;

    #[test]
    fn unbound_build_refuses_to_bind() {
        let error = match BridgeListener::bind(UserBrowserBridge::new()) {
            Ok(_) => panic!("bound a production listener without native process checks"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        // CI also builds with a bound gate; that build still needs the native
        // verifier before it can bind a listener.
        #[cfg(target_os = "linux")]
        let revision = option_env!("CEREBELLUM_LINUX_USER_BROWSER_REVIEW_REVISION");
        #[cfg(windows)]
        let revision = option_env!("CEREBELLUM_WINDOWS_USER_BROWSER_REVIEW_REVISION");
        let gate = cerebellum_bridge_protocol::classify_bridge_gate(
            revision,
            option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"),
        );
        assert_eq!(
            error.to_string(),
            if gate.is_some() {
                "native messaging peer verification is unavailable"
            } else {
                "native messaging is not enabled in this build"
            }
        );
    }
}
