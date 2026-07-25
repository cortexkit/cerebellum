//! Profile-registry acceptance target.
//!
//! The profile module is exposed from the crate root as `cerebellum::profile`,
//! so these tests exercise the same code the library compiles rather than a
//! second private copy included by path.

use cerebellum::profile::{
    implementation_digest_for, verify_implementation_digest, BindFacts, ProfileLifecycle,
    ProfileOutcome, RegistryConfig, REGISTRY_ARTIFACT,
};

fn context(kind: &str, disposition: &str) -> cerebellum::profile::StampedBindContext {
    cerebellum::profile::stamped_bind_context(BindFacts {
        principal: "direct:agent".to_string(),
        conversation_key: "s8-conversation".to_string(),
        agent_project_id: "s8-project".to_string(),
        session_kind: Some(kind.to_string()),
        profile_disposition: Some(disposition.to_string()),
        effective_capability_scope: Some(vec!["browser.navigate".to_string()]),
        provenance: "daemon_attested_spec_a".to_string(),
    })
    .expect("strict bind facts")
}

#[test]
fn immutable_artifact_and_implementation_digest_are_verified() {
    let report = verify_implementation_digest(REGISTRY_ARTIFACT).expect("artifact gate");
    assert_eq!(
        report.implementation_digest,
        implementation_digest_for(REGISTRY_ARTIFACT).unwrap()
    );
    assert!(report.fixture_count >= 20);
}

#[test]
fn invalid_artifact_is_a_non_mutating_gate_failure() {
    let root = std::env::temp_dir().join(format!("ck-s8-invalid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let config = RegistryConfig {
        artifact_bytes: b"{}".to_vec(),
        ..RegistryConfig::default()
    };
    let mut lifecycle = ProfileLifecycle::open_with_config(&root, config).unwrap();
    let invocation = cerebellum::profile::InvocationToken::for_test("invalid-artifact");
    let reservation =
        cerebellum::profile::JournalReservationHandle::for_test(&invocation, "reservation");
    let result = lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable"),
    );
    assert_eq!(
        result,
        cerebellum::profile::PrepareResult::Closed(ProfileOutcome::StorageUnavailable {
            reason_code: "profile_storage_unavailable",
            origin: cerebellum::profile::FailureOrigin::RegistryOrStorage,
        })
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn gate_failure_is_fail_closed_for_all_dispositions() {
    let root = std::env::temp_dir().join(format!("ck-s8-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut lifecycle = ProfileLifecycle::disabled(&root).unwrap();
    let invocation = cerebellum::profile::InvocationToken::for_test("gate");
    let reservation =
        cerebellum::profile::JournalReservationHandle::for_test(&invocation, "reservation");
    for (kind, disposition) in [
        ("primary", "durable"),
        ("subagent", "disposable"),
        ("ephemeral", "none"),
    ] {
        let result =
            lifecycle.prepare_context_open(&invocation, &reservation, &context(kind, disposition));
        assert_eq!(
            result,
            cerebellum::profile::PrepareResult::Closed(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_storage_unavailable",
                origin: cerebellum::profile::FailureOrigin::RegistryOrStorage,
            })
        );
    }
    assert!(!root.join(".ck-browser-profile-v1.json").exists());
    std::fs::remove_dir_all(root).unwrap();
}

/// Report the correct digest when the pin is stale, rather than only that it is.
///
/// The registry's implementation digest covers the bytes of `profile/mod.rs`
/// itself, so *any* edit to that file -- including a comment -- invalidates the
/// pinned value and fails several tests at once with only a mismatch. That is the
/// tamper-evidence working, but the pinned value is checked in, so a legitimate
/// edit has to repin it, and the digest is not recoverable from the failure.
///
/// This test names the value to write into the artifact, so repinning does not
/// require hand-writing a throwaway probe.
#[test]
fn pinned_implementation_digest_matches_the_module_source() {
    let computed =
        cerebellum::profile::implementation_digest_for(cerebellum::profile::REGISTRY_ARTIFACT)
            .expect("implementation bundle builds from the checked-in artifact");
    let artifact: serde_json::Value =
        serde_json::from_slice(cerebellum::profile::REGISTRY_ARTIFACT).expect("artifact is JSON");
    let pinned = artifact["implementation_digest"]["value"]
        .as_str()
        .expect("artifact pins an implementation digest");
    assert_eq!(
        pinned, computed,
        "\nthe pinned implementation digest is stale.\n\
         if the edit to crates/cerebellum/src/profile/mod.rs was intended, set\n\
         implementation_digest.value in crates/cerebellum/resources/\
         ck-browser-profile-registry-v1.json to:\n  {computed}\n"
    );
}
