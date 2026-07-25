//! Profile-registry acceptance target.
//!
//! This test includes the live profile module directly so registry, artifact,
//! and lifecycle conformance can be compiled and tested independently of the
//! browser crate-root wiring.

#[path = "../src/profile/mod.rs"]
mod profile;

use profile::{
    implementation_digest_for, verify_implementation_digest, BindFacts, ProfileLifecycle,
    ProfileOutcome, RegistryConfig, REGISTRY_ARTIFACT,
};

fn context(kind: &str, disposition: &str) -> profile::StampedBindContext {
    profile::stamped_bind_context(BindFacts {
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
    let invocation = profile::InvocationToken::for_test("invalid-artifact");
    let reservation = profile::JournalReservationHandle::for_test(&invocation, "reservation");
    let result = lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable"),
    );
    assert_eq!(
        result,
        profile::PrepareResult::Closed(ProfileOutcome::StorageUnavailable {
            reason_code: "profile_storage_unavailable",
            origin: profile::FailureOrigin::RegistryOrStorage,
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
    let invocation = profile::InvocationToken::for_test("gate");
    let reservation = profile::JournalReservationHandle::for_test(&invocation, "reservation");
    for (kind, disposition) in [
        ("primary", "durable"),
        ("subagent", "disposable"),
        ("ephemeral", "none"),
    ] {
        let result =
            lifecycle.prepare_context_open(&invocation, &reservation, &context(kind, disposition));
        assert_eq!(
            result,
            profile::PrepareResult::Closed(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_storage_unavailable",
                origin: profile::FailureOrigin::RegistryOrStorage,
            })
        );
    }
    assert!(!root.join(".ck-browser-profile-v1.json").exists());
    std::fs::remove_dir_all(root).unwrap();
}
