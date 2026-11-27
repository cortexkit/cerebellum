use super::*;
use crate::browser_launch::{BrowserLaunchRecoveryFailure, LaunchRecordStage};
use crate::browser_launch_readiness::{
    LaunchReadinessError, ProfileStartupCause, ProfileStartupIndeterminate, ReadinessCleanupStage,
};
use crate::profile::{ArtifactError, RootError, UntrustworthyRegistryReason};

fn assert_declared(reply: &Value) {
    assert_eq!(
        crate::browser::validate_browser_result(crate::browser_session::BROWSER_LAUNCH, reply),
        Ok(()),
        "{reply} is a browser.launch reply the launch schema does not declare"
    );
}

fn registry_errors() -> Vec<RegistryError> {
    let all = vec![
        RegistryError::Root(RootError::NotDirectory),
        RegistryError::Artifact(ArtifactError::InvalidJson),
        RegistryError::Io(io::Error::other("fixture")),
        RegistryError::UnknownField("/profiles/0000-uuid".to_string()),
        RegistryError::UnsupportedState,
        RegistryError::Conflict,
        RegistryError::Untrustworthy(UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts),
        RegistryError::Untrustworthy(UntrustworthyRegistryReason::MalformedRegistry),
        RegistryError::InvalidTransition,
    ];
    // Exhaustive without a wildcard: a new registry error does not compile
    // until it is rendered above.
    for error in &all {
        match error {
            RegistryError::Root(_)
            | RegistryError::Artifact(_)
            | RegistryError::Io(_)
            | RegistryError::UnknownField(_)
            | RegistryError::UnsupportedState
            | RegistryError::Conflict
            | RegistryError::Untrustworthy(_)
            | RegistryError::InvalidTransition => {}
        }
    }
    all
}

#[test]
fn every_profile_lifecycle_refusal_passes_the_launch_reply_schema() {
    let mut replies = vec![ProductionProfileLifecycleError::DataRoot.into_launch_refusal()];
    for error in registry_errors() {
        replies.push(ProductionProfileLifecycleError::Registry(error).into_launch_refusal());
    }
    for reply in &replies {
        assert_declared(reply);
        // Registry errors can carry paths, and profile directories are
        // named by profile UUID; neither may reach the wire as text.
        assert!(reply.get("detail").is_none(), "{reply}");
        assert!(!reply.to_string().contains("uuid"), "{reply}");
    }
}

/// A registry that no longer trusts its root has its own remedy, so it is
/// rendered as that typed refusal rather than as a storage failure.
#[test]
fn an_untrusted_registry_at_open_keeps_its_typed_outcome_and_remedy() {
    let reply = ProductionProfileLifecycleError::Registry(RegistryError::Untrustworthy(
        UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
    ))
    .into_launch_refusal();
    assert_eq!(
        reply["outcome"], "profile_registry_untrusted_root",
        "{reply}"
    );
    assert!(reply["remedy"].is_string(), "{reply}");
}

#[test]
fn every_startup_recovery_refusal_passes_the_launch_reply_schema() {
    let failures = [
        BrowserLaunchRecoveryFailure::JournalOpen,
        BrowserLaunchRecoveryFailure::JournalRead { sequence: 7 },
        BrowserLaunchRecoveryFailure::JournalTerminalization,
        BrowserLaunchRecoveryFailure::ProfileCustodyRelease { sequence: 7 },
        BrowserLaunchRecoveryFailure::ProfileCustodyRetain { sequence: 7 },
        BrowserLaunchRecoveryFailure::InvalidIntent { sequence: 7 },
        BrowserLaunchRecoveryFailure::NewerWriter {
            sequence: 7,
            newer: cerebellum_core::format_floor::NewerWriter {
                format: "launch-attestation",
                found: 6,
                supported: 5,
            },
        },
    ];
    for failure in failures {
        match failure {
            BrowserLaunchRecoveryFailure::JournalOpen
            | BrowserLaunchRecoveryFailure::JournalRead { .. }
            | BrowserLaunchRecoveryFailure::JournalTerminalization
            | BrowserLaunchRecoveryFailure::ProfileCustodyRelease { .. }
            | BrowserLaunchRecoveryFailure::ProfileCustodyRetain { .. }
            | BrowserLaunchRecoveryFailure::InvalidIntent { .. }
            | BrowserLaunchRecoveryFailure::NewerWriter { .. } => {}
        }
        assert_declared(&launch_recovery_refusal(failure));
    }
}

#[test]
fn every_readiness_refusal_passes_the_launch_reply_schema() {
    let causes = [
        ProfileStartupCause::ChildExit,
        ProfileStartupCause::PipeClosed,
        ProfileStartupCause::DeadlineExpired,
    ];
    let mut errors = Vec::new();
    for cause in causes {
        errors.push(AttestedReadinessError::Readiness(
            LaunchReadinessError::ProfileStartupIndeterminate(ProfileStartupIndeterminate::new(
                cause,
            )),
        ));
        errors.push(AttestedReadinessError::Readiness(
            LaunchReadinessError::CleanupFailed {
                primary: Some(ProfileStartupIndeterminate::new(cause)),
                stage: ReadinessCleanupStage::JournalFinalization,
            },
        ));
    }
    for stage in [
        ReadinessCleanupStage::Reap,
        ReadinessCleanupStage::Rollback,
        ReadinessCleanupStage::JournalFinalization,
    ] {
        errors.push(AttestedReadinessError::Readiness(
            LaunchReadinessError::CleanupFailed {
                primary: None,
                stage,
            },
        ));
    }
    errors.push(AttestedReadinessError::Readiness(
        LaunchReadinessError::HandshakeSetupFailed,
    ));
    errors.push(AttestedReadinessError::CleanupFailed {
        primary: AttestedLaunchError::SpawnFailed,
        stage: ReadinessCleanupStage::Reap,
    });
    for claim_kind in ["code_signed", "image_digest"] {
        errors.push(AttestedReadinessError::AttestedLaunch(
            AttestedLaunchError::ExecutableIdentityMismatch {
                claim_kind: claim_kind.to_string(),
                expected_identity: "expected".to_string(),
                observed_identity: "observed".to_string(),
            },
        ));
    }
    errors.push(AttestedReadinessError::AttestedLaunch(
        AttestedLaunchError::PlatformRefused {
            error: crate::browser_launch::PlatformLaunchError::Spawn,
        },
    ));
    for error in [
        AttestedLaunchError::JournalRecordFailed {
            stage: LaunchRecordStage::Intent,
        },
        AttestedLaunchError::SpawnFailed,
        AttestedLaunchError::ImageAttestationFailed {
            expected_identity: "/Applications/Browser.app".to_string(),
        },
        AttestedLaunchError::TerminationOrReapFailed,
        AttestedLaunchError::ReleaseFailed,
    ] {
        errors.push(AttestedReadinessError::AttestedLaunch(error));
    }
    for error in errors {
        let rendered = format!("{error:?}");
        let reply = map_readiness_error(error);
        assert_declared(&reply);
        assert!(
            !reply.to_string().contains("/Applications"),
            "{rendered} leaked its Debug text into {reply}"
        );
    }
}
