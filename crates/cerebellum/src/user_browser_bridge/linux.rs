use super::admission::Admission;
use super::socket::{SocketListener, SocketPermissions};
use super::{Reason, UserBrowserBridge};
use cerebellum_bridge_protocol::linux::{
    self, PeerIdentity, PeerObservationError, VerifiedHost, VerifyingKey,
};
use cerebellum_bridge_protocol::{classify_bridge_gate, linux_socket_path, HostParentAttestation};
use std::io;
use std::os::fd::AsFd;
use std::path::PathBuf;

#[cfg(feature = "bridge-test-identities")]
mod test_hooks;
#[cfg(test)]
mod tests;

const REVISION: Option<&str> = option_env!("CEREBELLUM_LINUX_USER_BROWSER_REVIEW_REVISION");
const PUBLIC_KEY: Option<&str> = option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY");

pub(super) fn bind(bridge: UserBrowserBridge) -> io::Result<SocketListener> {
    bind_with(bridge, REVISION, PUBLIC_KEY, linux::probe_kernel, endpoint)
}

fn bind_with(
    bridge: UserBrowserBridge,
    revision: Option<&str>,
    public_key: Option<&str>,
    probe: impl FnOnce() -> io::Result<()>,
    endpoint: impl FnOnce() -> io::Result<(PathBuf, SocketPermissions)>,
) -> io::Result<SocketListener> {
    let key = classify_bridge_gate(revision, public_key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "native messaging is not enabled in this build",
        )
    })?;
    probe()?;
    let (path, permissions) = endpoint()?;
    let admission = Admission::linux(key);
    match permissions {
        SocketPermissions::Private => SocketListener::bind(bridge, path, admission),
        #[cfg(feature = "bridge-test-identities")]
        SocketPermissions::Permissive => {
            SocketListener::bind_with_permissions(bridge, path, admission, permissions)
        }
    }
}

fn endpoint() -> io::Result<(PathBuf, SocketPermissions)> {
    #[cfg(feature = "bridge-test-identities")]
    if let Some(endpoint) = test_hooks::endpoint_override()? {
        return Ok(endpoint);
    }
    Ok((linux_socket_path()?, SocketPermissions::Private))
}

pub(super) fn observe_peer(socket: &impl AsFd) -> Result<PeerIdentity, Reason> {
    linux::observe_peer(socket).map_err(|error| match error {
        PeerObservationError::WrongUser => Reason::WrongUser,
        PeerObservationError::Observation(_) => Reason::UnsignedPeer,
    })
}

pub(super) fn verify_host(
    identity: PeerIdentity,
    key: &VerifyingKey,
) -> Result<VerifiedHost, Reason> {
    #[cfg(feature = "bridge-test-identities")]
    test_hooks::checkpoint("step-3").map_err(|_| Reason::UnsignedPeer)?;
    identity.verify_host(key).map_err(|_| Reason::UnsignedPeer)
}

pub(super) fn check_parent(
    host: VerifiedHost,
    parent: &HostParentAttestation,
    key: &VerifyingKey,
) -> Result<(), Reason> {
    #[cfg(feature = "bridge-test-identities")]
    test_hooks::checkpoint("step-3-parent").map_err(|_| Reason::ParentAttestationInvalid)?;
    host.recheck_parent(parent, key)
        .map_err(|_| Reason::ParentAttestationInvalid)
}
