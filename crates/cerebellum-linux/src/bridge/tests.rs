use super::*;

#[test]
fn only_bind_probe_maps_unsupported_primitives_to_the_kernel_floor() {
    for errno in [libc::ENOSYS, libc::ENOPROTOOPT, libc::EINVAL] {
        let error = bind_probe::<()>(Err(io::Error::from_raw_os_error(errno))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), "needs Linux 6.5+");
        let observation = PeerObservationError::Observation(io::Error::from_raw_os_error(errno));
        assert!(!observation.to_string().contains("needs Linux 6.5+"));
    }
    for errno in [libc::EPERM, libc::EACCES, libc::ESRCH, libc::ENOENT] {
        let denied = bind_probe::<()>(Err(io::Error::from_raw_os_error(errno))).unwrap_err();
        assert_eq!(denied.raw_os_error(), Some(errno));
        assert!(!denied.to_string().contains("needs Linux 6.5+"));
    }
}

#[test]
fn socket_pidfd_names_the_credential_pid_not_a_substituted_pid() {
    probe_kernel().unwrap();
    let (socket, _other) = UnixStream::pair().unwrap();
    let peer = observe_peer(&socket).unwrap();
    assert_eq!(peer.pid, std::process::id());
    assert!(peer.pidfd.require_pid(peer.pid).is_ok());
    assert!(peer.pidfd.require_pid(peer.pid + 1).is_err());
    assert!(peer.pidfd.require_live().is_ok());
}

#[test]
fn deleted_exe_link_refuses_even_if_the_original_path_is_allowed() {
    let path = Path::new("/opt/google/chrome/chrome");
    assert!(require_named_image(path).is_ok());
    let deleted = Path::new("/opt/google/chrome/chrome (deleted)");
    let error = require_named_image(deleted).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains("needs Linux 6.5+"));
}

#[test]
fn post_hello_requires_all_native_parent_fields_to_match() {
    use cerebellum_bridge_protocol::{
        LinuxBrowser, LinuxPackage, LinuxPackageManager, ParentAttestation,
    };

    let native =
        |browser, pid, start_ticks, name: &str, version: &str| PlatformParentAttestation::Linux {
            v: AttestationV1,
            browser,
            pid,
            start_ticks,
            package: LinuxPackage {
                manager: LinuxPackageManager::Dpkg,
                name: name.into(),
                version: version.into(),
            },
        };
    let browser = LinuxBrowser::Chromium;
    let observed = native(browser, 123, 456, "chromium", "2:132.0~deb12u1");
    assert!(require_matching_parent(&observed.clone().into(), observed.clone()).is_ok());
    for claimed in [
        native(browser, 124, 456, "chromium", "2:132.0~deb12u1"),
        native(browser, 123, 457, "chromium", "2:132.0~deb12u1"),
        native(
            LinuxBrowser::GoogleChrome,
            123,
            456,
            "chromium",
            "2:132.0~deb12u1",
        ),
        native(browser, 123, 456, "google-chrome-stable", "2:132.0~deb12u1"),
        native(browser, 123, 456, "chromium", "2:132.0~deb12u2"),
    ] {
        assert!(require_matching_parent(&claimed.into(), observed.clone()).is_err());
    }
    let legacy = ParentAttestation {
        team_id: None,
        probe_cdhash: None,
        pid: 123,
        start_time_micros: 456,
    };
    assert!(require_matching_parent(&legacy.into(), observed).is_err());
}

#[test]
fn signed_test_parent_is_admitted_only_with_the_test_feature_and_role() {
    use ed25519_dalek::SigningKey;
    use std::os::fd::FromRawFd;

    fn image_with_trailer(signer: &SigningKey, role: PeerRole) -> File {
        // SAFETY: the name is a C string and the successful fd is newly owned.
        let fd = unsafe { libc::memfd_create(c"bridge-image".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: memfd_create succeeded and returned a new descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        peer_trailer::append(&mut file, signer, role, TARGET, "1.0.0").unwrap();
        file
    }

    let key = peer_trailer::parse_public_key(peer_trailer::TEST_PEER_PUBLIC_KEY_HEX).unwrap();
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let test_signer = SigningKey::from_bytes(&seed);
    assert_eq!(test_signer.verifying_key(), key);
    let other_signer = SigningKey::from_bytes(&[1; 32]);
    let pid = std::process::id();
    let mut candidate = ParentProcess {
        pid,
        pidfd: PidFd::open(pid).unwrap(),
        start_ticks: 1234,
        image: image_with_trailer(&test_signer, PeerRole::TestParent),
        path: "/not/a/packaged/browser".into(),
    };
    let result = candidate.attest(&key);
    #[cfg(feature = "bridge-test-identities")]
    assert_eq!(
        result.unwrap(),
        PlatformParentAttestation::LinuxTest {
            v: AttestationV1,
            pid,
            start_ticks: 1234
        }
    );
    #[cfg(not(feature = "bridge-test-identities"))]
    assert!(result.is_err());

    candidate.image = image_with_trailer(&test_signer, PeerRole::Host);
    assert!(candidate.attest(&key).is_err());
    candidate.image = image_with_trailer(&other_signer, PeerRole::TestParent);
    assert!(candidate.attest(&key).is_err());
    assert!(candidate.attest(&other_signer.verifying_key()).is_err());
}
