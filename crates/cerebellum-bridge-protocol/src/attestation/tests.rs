use super::*;
use crate::{decode_body, encode, read_frame, Frame, EXTENSION_ORIGIN, PROTOCOL_VERSION};
use std::io;

const LINUX: &str = r#"{"platform":"linux","v":1,"browser":"google-chrome","pid":4294967295,"start_ticks":18446744073709551615,"package":{"manager":"dpkg","name":"google-chrome-stable","version":"1:142.0.0.0-1"}}"#;
const WINDOWS: &str = r#"{"platform":"windows","v":1,"chrome":{"pid":17,"creation_100ns":133987654321000000},"launcher":{"pid":18,"creation_100ns":133987654322000000}}"#;
const LINUX_TEST: &str = r#"{"platform":"linux-test","v":1,"pid":73,"start_ticks":117}"#;
const WINDOWS_TEST: &str =
    r#"{"platform":"windows-test","v":1,"parent":{"pid":73,"creation_100ns":133987654321000000}}"#;

fn hello(parent: HostParentAttestation) -> Frame {
    Frame::HostHello {
        protocol: PROTOCOL_VERSION,
        extension_origin: EXTENSION_ORIGIN.into(),
        parent,
    }
}

fn hello_body(parent: &str) -> String {
    format!(
        r#"{{"type":"host_hello","protocol":1,"extension_origin":"{EXTENSION_ORIGIN}","parent":{parent}}}"#
    )
}

#[test]
fn macos_legacy_hello_matches_pre_change_framed_bytes() {
    let frame = hello(
        ParentAttestation {
            team_id: Some("EQHXZ8M8AV".into()),
            probe_cdhash: None,
            pid: 12,
            start_time_micros: 34,
        }
        .into(),
    );
    let wire = b"\x00\x00\x00\xc2{\"type\":\"host_hello\",\"protocol\":1,\"extension_origin\":\"chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/\",\"parent\":{\"team_id\":\"EQHXZ8M8AV\",\"probe_cdhash\":null,\"pid\":12,\"start_time_micros\":34}}";
    assert_eq!(encode(&frame).unwrap(), wire);
    assert_eq!(read_frame(&mut wire.as_slice()).unwrap(), frame);
}

fn assert_invalid_parent(parent: &str) {
    assert_eq!(
        decode_body(hello_body(parent).as_bytes())
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData,
        "parent must not decode: {parent}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_decoder_rejects_all_foreign_attestation_forms() {
    for parent in [LINUX, WINDOWS, LINUX_TEST, WINDOWS_TEST] {
        assert_invalid_parent(parent);
    }
}

#[cfg(not(target_os = "macos"))]
fn assert_round_trip(parent: &str, expected: PlatformParentAttestation) {
    let body = hello_body(parent);
    let frame = hello(expected.into());
    assert_eq!(decode_body(body.as_bytes()).unwrap(), frame);
    assert_eq!(&encode(&frame).unwrap()[4..], body.as_bytes());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn native_platform_attestations_round_trip() {
    for (wire, browser, name) in [
        (
            LINUX.into(),
            LinuxBrowser::GoogleChrome,
            "google-chrome-stable",
        ),
        (
            LINUX
                .replace("google-chrome-stable", "chromium")
                .replace("google-chrome", "chromium"),
            LinuxBrowser::Chromium,
            "chromium",
        ),
    ] {
        assert_round_trip(
            &wire,
            PlatformParentAttestation::Linux {
                v: AttestationV1,
                browser,
                pid: u32::MAX,
                start_ticks: u64::MAX,
                package: LinuxPackage {
                    manager: LinuxPackageManager::Dpkg,
                    name: name.into(),
                    version: "1:142.0.0.0-1".into(),
                },
            },
        );
    }
    assert_round_trip(
        WINDOWS,
        PlatformParentAttestation::Windows {
            v: AttestationV1,
            chrome: WindowsProcess {
                pid: 17,
                creation_100ns: 133_987_654_321_000_000,
            },
            launcher: WindowsProcess {
                pid: 18,
                creation_100ns: 133_987_654_322_000_000,
            },
        },
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn native_platform_attestations_deny_invalid_shapes_and_values() {
    for parent in [
        LINUX.replace("\"v\":1", "\"v\":2"),
        WINDOWS.replace("\"v\":1", "\"v\":\"1\""),
        LINUX.replace("\"v\":1,", ""),
        LINUX.replace("\"v\":1", "\"v\":1,\"v\":1"),
        LINUX.replace("\"linux\"", "\"unknown\""),
        LINUX.replace("\"v\":1", "\"v\":1,\"extra\":false"),
        LINUX.replace("\"dpkg\"", "\"rpm\""),
        LINUX.replace("\"google-chrome\"", "\"firefox\""),
        LINUX.replace("\"dpkg\"", "\"dpkg\",\"extra\":false"),
        LINUX.replace("4294967295", "4294967296"),
        LINUX.replace("18446744073709551615", "-1"),
        LINUX.replace("\"v\":1", "\"v\":1,\"team_id\":null"),
        WINDOWS.replace("\"v\":1", "\"v\":1,\"start_ticks\":4"),
        WINDOWS.replace("\"pid\":18", "\"pid\":18,\"extra\":false"),
        WINDOWS.replace(r#"{"pid":17,"creation_100ns":133987654321000000}"#, "[17,133987654321000000]"),
        r#"{"platform":"linux","v":1,"browser":"chromium","pid":73,"start_ticks":117,"package":["dpkg","chromium","1.0"]}"#.into(),
        r#"["linux",1,"chromium",73,117,{"manager":"dpkg","name":"chromium","version":"1.0"}]"#.into(),
        r#"{"platform":"linux","team_id":null,"probe_cdhash":null,"pid":73,"start_time_micros":117}"#.into(),
    ] {
        assert_invalid_parent(&parent);
    }
}

#[cfg(all(not(target_os = "macos"), not(feature = "bridge-test-identities")))]
#[test]
fn decoder_without_the_feature_rejects_both_test_attestations() {
    for parent in [LINUX_TEST, WINDOWS_TEST] {
        assert_invalid_parent(parent);
    }
}

#[cfg(all(not(target_os = "macos"), feature = "bridge-test-identities"))]
#[test]
fn test_attestations_round_trip_but_remain_strict() {
    assert_round_trip(
        LINUX_TEST,
        PlatformParentAttestation::LinuxTest {
            v: AttestationV1,
            pid: 73,
            start_ticks: 117,
        },
    );
    assert_round_trip(
        WINDOWS_TEST,
        PlatformParentAttestation::WindowsTest {
            v: AttestationV1,
            parent: WindowsProcess {
                pid: 73,
                creation_100ns: 133_987_654_321_000_000,
            },
        },
    );

    for parent in [
        LINUX_TEST.replace("\"v\":1", "\"v\":2"),
        LINUX_TEST.replace("\"pid\":73", "\"pid\":73,\"browser\":\"chromium\""),
        WINDOWS_TEST.replace("\"v\":1", "\"v\":2"),
        WINDOWS_TEST.replace("\"pid\":73", "\"pid\":73,\"extra\":true"),
    ] {
        assert_invalid_parent(&parent);
    }
}
