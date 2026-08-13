//! Profile-registry acceptance target.
//!
//! The profile module is exposed from the crate root as `cerebellum::profile`,
//! so these tests exercise the same code the library compiles rather than a
//! second private copy included by path.

use cerebellum::profile::{
    implementation_digest_for, stamped_bind_context, verify_implementation_digest, BindFacts,
    BindValidationError, ProfileLifecycle, ProfileOutcome, RegistryConfig, REGISTRY_ARTIFACT,
};

/// Bind facts that pass every clause of the strict validator.
///
/// The rejection tests below each spoil exactly one field of this value, so a
/// refusal is attributable to the clause under test rather than to an
/// incidentally malformed fixture.
fn valid_facts() -> BindFacts {
    BindFacts {
        principal: "direct:agent".to_string(),
        conversation_key: "s8-conversation".to_string(),
        agent_project_id: "s8-project".to_string(),
        session_kind: Some("primary".to_string()),
        profile_disposition: Some("durable".to_string()),
        effective_capability_scope: Some(vec!["browser.navigate".to_string()]),
        provenance: "daemon_attested_spec_a".to_string(),
    }
}

fn context(kind: &str, disposition: &str) -> cerebellum::profile::StampedBindContext {
    stamped_bind_context(BindFacts {
        session_kind: Some(kind.to_string()),
        profile_disposition: Some(disposition.to_string()),
        ..valid_facts()
    })
    .expect("strict bind facts")
}

/// The paired positive vector for every rejection below.  Without it a
/// validator that refused unconditionally would satisfy the whole rejection
/// suite, since each of those tests only asserts that some specific refusal
/// came back.
#[test]
fn well_formed_daemon_attested_facts_are_admitted() {
    let context = stamped_bind_context(valid_facts()).expect("valid facts are admitted");
    assert_eq!(context.agent_project_id(), "s8-project");
    assert_eq!(context.conversation_key(), "s8-conversation");
}

/// Facts reconstructed by a compatibility path carry the same shape as attested
/// ones and differ only in provenance, so this clause is the only thing standing
/// between a derived identity and a durable profile keyed on it.
#[test]
fn compatibility_derived_provenance_is_refused() {
    assert_eq!(
        stamped_bind_context(BindFacts {
            provenance: "compatibility_derived".to_string(),
            ..valid_facts()
        }),
        Err(BindValidationError::InvalidProvenance)
    );
}

#[test]
fn each_empty_required_identity_fact_is_refused_by_name() {
    assert_eq!(
        stamped_bind_context(BindFacts {
            principal: String::new(),
            ..valid_facts()
        }),
        Err(BindValidationError::EmptyFact("principal"))
    );
    assert_eq!(
        stamped_bind_context(BindFacts {
            conversation_key: String::new(),
            ..valid_facts()
        }),
        Err(BindValidationError::EmptyFact("conversation_key"))
    );
    assert_eq!(
        stamped_bind_context(BindFacts {
            agent_project_id: String::new(),
            ..valid_facts()
        }),
        Err(BindValidationError::EmptyFact("agent_project_id"))
    );
}

#[test]
fn absent_session_kind_is_refused_rather_than_defaulted() {
    assert_eq!(
        stamped_bind_context(BindFacts {
            session_kind: None,
            ..valid_facts()
        }),
        Err(BindValidationError::MissingFact("session_kind"))
    );
}

#[test]
fn unknown_session_kind_is_refused_rather_than_defaulted() {
    assert_eq!(
        stamped_bind_context(BindFacts {
            session_kind: Some("supervisor".to_string()),
            ..valid_facts()
        }),
        Err(BindValidationError::UnknownSessionKind)
    );
}

#[test]
fn absent_or_unknown_profile_disposition_is_refused() {
    assert_eq!(
        stamped_bind_context(BindFacts {
            profile_disposition: None,
            ..valid_facts()
        }),
        Err(BindValidationError::MissingFact("profile_disposition"))
    );
    assert_eq!(
        stamped_bind_context(BindFacts {
            profile_disposition: Some("shared".to_string()),
            ..valid_facts()
        }),
        Err(BindValidationError::UnknownDisposition)
    );
}

/// Both halves are individually well formed here.  Only the pairing is wrong,
/// which is what would let a subagent or an ephemeral seat reach the durable
/// profile that belongs to the primary session.
#[test]
fn a_kind_paired_with_the_wrong_disposition_is_refused() {
    for (kind, disposition) in [
        ("primary", "disposable"),
        ("primary", "none"),
        ("subagent", "durable"),
        ("ephemeral", "durable"),
        ("ephemeral", "disposable"),
    ] {
        assert_eq!(
            stamped_bind_context(BindFacts {
                session_kind: Some(kind.to_string()),
                profile_disposition: Some(disposition.to_string()),
                ..valid_facts()
            }),
            Err(BindValidationError::IncompatibleKindDisposition),
            "{kind} must not be admitted with a {disposition} profile"
        );
    }
}

#[test]
fn absent_or_malformed_capability_scope_is_refused() {
    assert_eq!(
        stamped_bind_context(BindFacts {
            effective_capability_scope: None,
            ..valid_facts()
        }),
        Err(BindValidationError::MissingFact(
            "effective_capability_scope"
        ))
    );
    assert_eq!(
        stamped_bind_context(BindFacts {
            effective_capability_scope: Some(vec!["browser.navigate".to_string(), String::new()]),
            ..valid_facts()
        }),
        Err(BindValidationError::InvalidScope)
    );
}

/// An explicitly empty scope is a bind that admitted no capability, which is a
/// different fact from a malformed one and must not be conflated with it.
#[test]
fn an_explicitly_empty_capability_scope_is_admitted() {
    assert!(stamped_bind_context(BindFacts {
        effective_capability_scope: Some(Vec::new()),
        ..valid_facts()
    })
    .is_ok());
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

/// A second agent identity gets its own durable profile.
///
/// Per-agent profiles exist so one agent's logins are its own. If the second
/// identity to ask cannot get a profile at all, the feature is one browser per
/// machine wearing a per-agent name.
///
/// This failed against a real machine while every test passed, because both
/// guards it exercises only misfire once a `profiles` directory exists: the
/// uuid collision check treated a resolvable path as an occupied one, and the
/// foreign-directory check treated another agent's own profile as a stranger's.
/// A suite whose fixtures each start from an empty root never reaches either.
#[test]
fn a_second_agent_identity_gets_its_own_durable_profile() {
    let root = std::env::temp_dir().join(format!(
        "ck-two-agents-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("root");

    let config = cerebellum::profile::RegistryConfig {
        uuid_protocol_compatible: true,
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        ..Default::default()
    };

    let mut targets = Vec::new();
    for project in ["pj-agent-one", "pj-agent-two"] {
        let mut lifecycle =
            cerebellum::profile::ProfileLifecycle::open_with_config(&root, config.clone())
                .expect("lifecycle opens");
        let context = stamped_bind_context(BindFacts {
            agent_project_id: project.to_string(),
            conversation_key: format!("conversation-{project}"),
            ..valid_facts()
        })
        .expect("strict bind facts");
        let invocation = cerebellum::profile::InvocationToken::for_test(project);
        let reservation = cerebellum::profile::JournalReservationHandle::for_test(
            &invocation,
            format!("reservation-{project}"),
        );

        match lifecycle.prepare_context_open(&invocation, &reservation, &context) {
            cerebellum::profile::PrepareResult::Prepared(_) => {
                // Observed on disk rather than from the prepared handle, which
                // is opaque: the property is that two directories exist, and a
                // handle reporting two distinct ids would satisfy the assertion
                // with one directory underneath.
                let mut minted: Vec<String> = std::fs::read_dir(root.join("profiles"))
                    .expect("profiles directory")
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect();
                minted.sort();
                targets = minted;
            }
            cerebellum::profile::PrepareResult::Closed(outcome) => {
                panic!("{project} could not get a durable profile: {outcome:?}")
            }
        }
    }

    assert_eq!(
        targets.len(),
        2,
        "two agents should own two profile directories, found: {targets:?}"
    );
    assert_ne!(
        targets[0], targets[1],
        "two agents were given the same profile directory: {targets:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
