use super::session::{read_frame, refuse, serve_session};
use super::{Reason, UserBrowserBridge, HOST_HELLO_DEADLINE};
#[cfg(target_os = "linux")]
use cerebellum_bridge_protocol::linux;
#[cfg(windows)]
use cerebellum_bridge_protocol::windows;
#[cfg(any(target_os = "macos", all(unix, test)))]
use cerebellum_bridge_protocol::ParentAttestation;
use cerebellum_bridge_protocol::{
    Frame, HostParentAttestation, EXTENSION_ORIGIN, PROTOCOL_VERSION,
};
#[cfg(any(target_os = "macos", all(unix, test)))]
use std::os::fd::OwnedFd;
#[cfg(test)]
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) enum PeerIdentity {
    #[cfg(target_os = "macos")]
    MacOs(OwnedFd),
    #[cfg(target_os = "linux")]
    Linux(linux::PeerIdentity),
    #[cfg(windows)]
    Windows(windows::PeerIdentity),
    #[cfg(all(unix, test))]
    Test,
}

pub(super) enum PeerEvidence {
    #[cfg(target_os = "macos")]
    MacOs,
    #[cfg(target_os = "linux")]
    Linux(linux::VerifiedHost),
    #[cfg(windows)]
    Windows(windows::VerifiedHost),
    #[cfg(test)]
    Test {
        #[cfg(unix)]
        _retained: Option<OwnedFd>,
    },
}

#[cfg(test)]
pub(super) type VerifyPeer =
    Arc<dyn Fn(PeerIdentity) -> Result<PeerEvidence, Reason> + Send + Sync>;
#[cfg(test)]
pub(super) type CheckParent =
    Arc<dyn Fn(PeerEvidence, HostParentAttestation) -> Result<(), Reason> + Send + Sync>;

#[derive(Clone)]
pub(super) enum Admission {
    #[cfg(target_os = "macos")]
    MacOs,
    #[cfg(target_os = "linux")]
    Linux {
        key: linux::VerifyingKey,
        workers: blocking::VerificationWorkers,
    },
    #[cfg(windows)]
    Windows {
        key: windows::VerifyingKey,
        workers: blocking::VerificationWorkers,
    },
    #[cfg(test)]
    Injected {
        verify_peer: VerifyPeer,
        check_parent: CheckParent,
        workers: blocking::VerificationWorkers,
    },
}

enum Rejection {
    Refuse(Reason),
    Close,
}

impl From<Reason> for Rejection {
    fn from(reason: Reason) -> Self {
        Self::Refuse(reason)
    }
}

pub(super) async fn admit(
    bridge: UserBrowserBridge,
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    identity: Result<PeerIdentity, Reason>,
    admission: Admission,
) {
    match authenticate(&mut stream, identity, admission).await {
        Ok(()) => serve_session(bridge, stream).await,
        Err(Rejection::Refuse(reason)) => refuse(&mut stream, reason).await,
        Err(Rejection::Close) => (),
    }
}

async fn authenticate(
    stream: &mut (impl AsyncRead + Unpin),
    identity: Result<PeerIdentity, Reason>,
    admission: Admission,
) -> Result<(), Rejection> {
    // Reject a different user before opening or verifying the peer's executable.
    let evidence = admission.verify_peer(identity?).await?;
    let hello = tokio::time::timeout(HOST_HELLO_DEADLINE, read_frame(stream)).await;
    let Ok(Ok(Frame::HostHello {
        protocol,
        extension_origin,
        parent,
    })) = hello
    else {
        return Err(Reason::ProtocolError.into());
    };
    if protocol != PROTOCOL_VERSION {
        return Err(Reason::ProtocolMismatch.into());
    }
    if extension_origin != EXTENSION_ORIGIN {
        return Err(Reason::ExtensionOriginMismatch.into());
    }
    admission.check_parent(evidence, parent).await
}

impl Admission {
    #[cfg(target_os = "linux")]
    pub(super) fn linux(key: linux::VerifyingKey) -> Self {
        Self::Linux {
            key,
            workers: blocking::VerificationWorkers::new(),
        }
    }

    #[cfg(windows)]
    pub(super) fn windows(key: windows::VerifyingKey) -> Self {
        Self::Windows {
            key,
            workers: blocking::VerificationWorkers::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn injected(verify_peer: VerifyPeer, check_parent: CheckParent) -> Self {
        Self::Injected {
            verify_peer,
            check_parent,
            workers: blocking::VerificationWorkers::new(),
        }
    }

    async fn verify_peer(&self, identity: PeerIdentity) -> Result<PeerEvidence, Rejection> {
        match self {
            #[cfg(target_os = "macos")]
            Self::MacOs => tokio::task::spawn_blocking(move || verify_signed_host(identity))
                .await
                .map_err(|_| Rejection::Close)?
                .map_err(Into::into),
            #[cfg(target_os = "linux")]
            Self::Linux { key, workers } => {
                #[cfg(not(test))]
                let PeerIdentity::Linux(identity) = identity;
                #[cfg(test)]
                let PeerIdentity::Linux(identity) = identity
                else {
                    return Err(Reason::UnsignedPeer.into());
                };
                let key = *key;
                workers
                    .run(Reason::UnsignedPeer, move || {
                        super::linux::verify_host(identity, &key).map(PeerEvidence::Linux)
                    })
                    .await
            }
            #[cfg(windows)]
            Self::Windows { key, workers } => {
                let PeerIdentity::Windows(identity) = identity;
                let key = *key;
                workers
                    .run(Reason::UnsignedPeer, move || {
                        super::windows::verify_host(identity, &key).map(PeerEvidence::Windows)
                    })
                    .await
            }
            #[cfg(test)]
            Self::Injected {
                verify_peer,
                workers,
                ..
            } => {
                let verify_peer = verify_peer.clone();
                workers
                    .run(Reason::UnsignedPeer, move || verify_peer(identity))
                    .await
            }
        }
    }

    async fn check_parent(
        &self,
        evidence: PeerEvidence,
        parent: HostParentAttestation,
    ) -> Result<(), Rejection> {
        match self {
            #[cfg(target_os = "macos")]
            Self::MacOs => check_legacy_parent(evidence, parent).map_err(Into::into),
            #[cfg(target_os = "linux")]
            Self::Linux { key, workers } => {
                #[cfg(not(test))]
                let PeerEvidence::Linux(evidence) = evidence;
                #[cfg(test)]
                let PeerEvidence::Linux(evidence) = evidence
                else {
                    return Err(Reason::ParentAttestationInvalid.into());
                };
                let key = *key;
                workers
                    .run(Reason::ParentAttestationInvalid, move || {
                        super::linux::check_parent(evidence, &parent, &key)
                    })
                    .await
            }
            #[cfg(windows)]
            Self::Windows { key, workers } => {
                #[cfg(not(test))]
                let PeerEvidence::Windows(evidence) = evidence;
                #[cfg(test)]
                let PeerEvidence::Windows(evidence) = evidence
                else {
                    return Err(Reason::ParentAttestationInvalid.into());
                };
                let key = *key;
                workers
                    .run(Reason::ParentAttestationInvalid, move || {
                        super::windows::check_parent(evidence, &parent, &key)
                    })
                    .await
            }
            #[cfg(test)]
            Self::Injected {
                check_parent,
                workers,
                ..
            } => {
                let check_parent = check_parent.clone();
                workers
                    .run(Reason::ParentAttestationInvalid, move || {
                        check_parent(evidence, parent)
                    })
                    .await
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_signed_host(identity: PeerIdentity) -> Result<PeerEvidence, Reason> {
    #[cfg(not(test))]
    let PeerIdentity::MacOs(socket) = identity;
    #[cfg(test)]
    let PeerIdentity::MacOs(socket) = identity
    else {
        return Err(Reason::UnsignedPeer);
    };
    cerebellum_macos::peer_satisfies_requirement(
        &socket,
        cerebellum_bridge_protocol::HOST_REQUIREMENT,
        HOST_HELLO_DEADLINE,
    )
    .map(|_| PeerEvidence::MacOs)
    .map_err(|_| Reason::UnsignedPeer)
}

#[cfg(any(target_os = "macos", all(unix, test)))]
pub(super) fn check_legacy_parent(
    _evidence: PeerEvidence,
    parent: HostParentAttestation,
) -> Result<(), Reason> {
    if parent.as_legacy().is_some_and(valid_parent) {
        Ok(())
    } else {
        Err(Reason::ParentAttestationInvalid)
    }
}

#[cfg(any(target_os = "macos", all(unix, test)))]
fn valid_parent(parent: &ParentAttestation) -> bool {
    if parent.pid == 0 || parent.start_time_micros == 0 {
        return false;
    }
    match (&parent.team_id, &parent.probe_cdhash) {
        (Some(team), None) => team == "EQHXZ8M8AV",
        #[cfg(feature = "chrome-for-testing-parent-probe")]
        (None, Some(hash)) => hash == "8f2a5ce4af6d1cd71fe66113dd809e4d106c3106",
        _ => false,
    }
}

#[cfg(any(target_os = "linux", windows, test))]
mod blocking;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wrong_user_is_refused_before_the_verifier_or_hello() {
        let (server, mut client) = tokio::io::duplex(1024);
        let bridge = UserBrowserBridge::new();
        let admission = Admission::injected(
            Arc::new(|_| panic!("a different user's image must not be verified")),
            Arc::new(|_, _| panic!("a different user's parent must not be checked")),
        );
        admit(bridge.clone(), server, Err(Reason::WrongUser), admission).await;
        assert_eq!(
            read_frame(&mut client).await.unwrap(),
            Frame::HostRefused {
                reason: "wrong_user".into(),
            }
        );
        assert_eq!(bridge.connected_epoch(), None);
    }
}
