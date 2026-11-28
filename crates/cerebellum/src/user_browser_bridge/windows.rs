use super::admission::{admit, Admission, PeerIdentity};
use super::{Reason, UserBrowserBridge};
use cerebellum_bridge_protocol::windows::{
    self, current_user_sid, PeerObservationError, VerifiedHost, VerifyingKey,
};
use cerebellum_bridge_protocol::{classify_bridge_gate, windows_pipe_name, HostParentAttestation};
use cerebellum_windows::{create_named_pipe_instance, system_time_100ns};
use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::task::{JoinHandle, JoinSet};

#[cfg(feature = "bridge-test-identities")]
mod test_hooks;
#[cfg(test)]
mod tests;

const REVISION: Option<&str> = option_env!("CEREBELLUM_WINDOWS_USER_BROWSER_REVIEW_REVISION");
const PUBLIC_KEY: Option<&str> = option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY");

pub(super) fn bind(bridge: UserBrowserBridge) -> io::Result<PipeListener> {
    bind_with(bridge, REVISION, PUBLIC_KEY, endpoint)
}

fn bind_with(
    bridge: UserBrowserBridge,
    revision: Option<&str>,
    public_key: Option<&str>,
    endpoint: impl FnOnce() -> io::Result<PipeEndpoint>,
) -> io::Result<PipeListener> {
    let key = classify_bridge_gate(revision, public_key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "native messaging is not enabled in this build",
        )
    })?;
    PipeListener::bind(bridge, endpoint()?, Admission::windows(key))
}

fn endpoint() -> io::Result<PipeEndpoint> {
    let user = current_user_sid()?;
    #[cfg(feature = "bridge-test-identities")]
    if let Some(overridden) = test_hooks::endpoint_override(&user)? {
        return Ok(overridden);
    }
    Ok(PipeEndpoint::private(windows_pipe_name(&user), user))
}

struct PipeEndpoint {
    name: String,
    user: String,
    #[cfg(feature = "bridge-test-identities")]
    second_user: Option<String>,
}

impl PipeEndpoint {
    fn private(name: String, user: String) -> Self {
        Self {
            name,
            user,
            #[cfg(feature = "bridge-test-identities")]
            second_user: None,
        }
    }

    fn create(&self, first: bool) -> io::Result<NamedPipeServer> {
        #[cfg(feature = "bridge-test-identities")]
        if let Some(second_user) = &self.second_user {
            return create_named_pipe_instance(&self.name, &[&self.user, second_user], first, true);
        }
        create_named_pipe_instance(&self.name, &[&self.user], first, true)
    }
}

pub(super) struct PipeListener {
    bridge: UserBrowserBridge,
    task: JoinHandle<()>,
}

impl PipeListener {
    fn bind(
        bridge: UserBrowserBridge,
        endpoint: PipeEndpoint,
        admission: Admission,
    ) -> io::Result<Self> {
        let first = endpoint.create(true)?;
        let instance = bridge.clone();
        let task = tokio::spawn(accept_peers(
            first,
            endpoint,
            move |stream, connected_at| {
                let identity = observe_peer(&stream, connected_at);
                admit(instance.clone(), stream, identity, admission.clone())
            },
        ));
        Ok(Self { bridge, task })
    }
}

impl Drop for PipeListener {
    fn drop(&mut self) {
        self.bridge.shutdown();
        self.task.abort();
    }
}

async fn accept_peers<F>(
    mut listening: NamedPipeServer,
    endpoint: PipeEndpoint,
    mut hand_off: impl FnMut(NamedPipeServer, u64) -> F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let mut peers = JoinSet::new();
    loop {
        let connected_at = tokio::select! {
            connected = async {
                listening.connect().await?;
                Ok::<_, io::Error>(system_time_100ns())
            } => connected,
            _ = peers.join_next(), if !peers.is_empty() => continue,
        };

        // Hold the old instance even if connect or replacement creation fails.
        // Closing it first would let another process take the pipe name.
        let mut retry = Duration::from_millis(10);
        if connected_at.is_err() {
            tokio::time::sleep(retry).await;
        }
        let next = loop {
            match endpoint.create(false) {
                Ok(next) => break next,
                Err(_) => {
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(Duration::from_secs(1));
                }
            }
        };
        let connected = std::mem::replace(&mut listening, next);
        if let Ok(connected_at) = connected_at {
            peers.spawn(hand_off(connected, connected_at));
        }
    }
}

fn observe_peer(stream: &NamedPipeServer, connected_at: u64) -> Result<PeerIdentity, Reason> {
    windows::observe_client_peer(stream, connected_at)
        .map(PeerIdentity::Windows)
        .map_err(|error| match error {
            PeerObservationError::WrongUser => Reason::WrongUser,
            PeerObservationError::Observation(_) => Reason::UnsignedPeer,
        })
}

pub(super) fn verify_host(
    identity: windows::PeerIdentity,
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
