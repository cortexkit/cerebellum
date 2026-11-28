use super::*;

#[test]
fn peer_must_precede_the_connection_timestamp_before_verification() {
    let pid = std::process::id();
    let own_process = Process::open(pid).unwrap();
    let created = own_process.generation.creation_100ns;
    for timestamp in [created - 1, created] {
        assert!(matches!(
            observe_peer(Ok(pid), timestamp),
            Err(PeerObservationError::Observation(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
    }
    let peer = observe_peer(Ok(pid), created + 1).unwrap();
    assert_eq!(peer.0.generation, own_process.generation);
    assert_eq!(
        peer.0.handle.token_user_sid().unwrap(),
        current_user_sid().unwrap()
    );
    peer.0.require_live().unwrap();
}

#[test]
fn a_retained_handle_observes_exit_without_reopening_the_pid() {
    use std::process::{Command, Stdio};

    let cmd = cerebellum_windows::windows_system_directory()
        .unwrap()
        .join("cmd.exe");
    // A throwaway System32 cmd.exe, not a browser: the test needs a real
    // child to watch exit through a retained handle.
    #[allow(
        clippy::disallowed_methods,
        reason = "spawns System32 cmd.exe as a plain child process, never a browser"
    )]
    let mut child = Command::new(cmd)
        .args(["/d", "/q", "/k"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let process = Process::open(child.id());
    let before = process.as_ref().is_ok_and(|process| {
        process.require_live().is_ok()
            && process.handle.parent_pid().ok() == Some(std::process::id())
    });
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(before, "the child was not live before termination");
    assert!(process.unwrap().require_live().is_err());
}

#[test]
fn parent_recheck_requires_both_pids_and_both_creation_times() {
    let chrome = WindowsProcess {
        pid: 10,
        creation_100ns: 100,
    };
    let launcher = WindowsProcess {
        pid: 20,
        creation_100ns: 200,
    };
    let attestation = |chrome, launcher| {
        PlatformParentAttestation::Windows {
            v: AttestationV1,
            chrome,
            launcher,
        }
        .into()
    };
    let observed = attestation(chrome, launcher);
    require_matching_parent(&observed, &observed).unwrap();
    for other in [
        attestation(WindowsProcess { pid: 11, ..chrome }, launcher),
        attestation(
            WindowsProcess {
                creation_100ns: 101,
                ..chrome
            },
            launcher,
        ),
        attestation(
            chrome,
            WindowsProcess {
                pid: 21,
                ..launcher
            },
        ),
        attestation(
            chrome,
            WindowsProcess {
                creation_100ns: 201,
                ..launcher
            },
        ),
        crate::ParentAttestation {
            team_id: Some("TEAM".into()),
            probe_cdhash: None,
            pid: 20,
            start_time_micros: 200,
        }
        .into(),
    ] {
        assert!(
            require_matching_parent(&other, &observed).is_err(),
            "accepted {other:?}"
        );
    }
}
