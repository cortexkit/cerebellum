use crate::{computer, ComputerReleaseInputs};

/// Collect the release attestations supplied to the compiler and derive the
/// vocabulary mirrors from their independent checked-in sources.
///
/// External identifiers use `option_env!` so a release invocation must
/// supply each attestation before compilation. Starting a binary with a new
/// environment value cannot manufacture a review after the binary was built.
pub(super) fn compiled_release_inputs() -> ComputerReleaseInputs {
    let semantic_actuation_review_revision =
        option_env!("CEREBELLUM_SEMANTIC_ACTUATION_REVIEW_REVISION");
    let windows_actuation_review_revision =
        option_env!("CEREBELLUM_WINDOWS_ACTUATION_REVIEW_REVISION");
    let app_state_review_revision = option_env!("CEREBELLUM_APP_STATE_REVIEW_REVISION");
    let element_addressed_review_revision =
        option_env!("CEREBELLUM_ELEMENT_ADDRESSED_REVIEW_REVISION");
    let takeover_dispatch_review_revision =
        option_env!("CEREBELLUM_TAKEOVER_DISPATCH_REVIEW_REVISION");
    let app_use_fronting_review_revision =
        option_env!("CEREBELLUM_APP_USE_FRONTING_REVIEW_REVISION");
    let release_signing_topology_revision =
        option_env!("CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION");
    release_inputs_from_build_bindings(BuildReleaseBindings {
        attendance_contract_owner: option_env!("CEREBELLUM_ATTENDANCE_CONTRACT_OWNER"),
        attendance_contract_revision: option_env!("CEREBELLUM_ATTENDANCE_CONTRACT_REVISION"),
        input_review_revision: option_env!("CEREBELLUM_INPUT_REVIEW_REVISION"),
        global_dispatch_review_revision: option_env!("CEREBELLUM_GLOBAL_DISPATCH_REVIEW_REVISION"),
        capture_review_revision: option_env!("CEREBELLUM_CAPTURE_REVIEW_REVISION"),
        semantic_actuation_review_revision,
        windows_actuation_review_revision,
        windows_app_identity_review_revision: option_env!(
            "CEREBELLUM_WINDOWS_APP_IDENTITY_REVIEW_REVISION"
        ),
        windows_app_state_review_revision: option_env!(
            "CEREBELLUM_WINDOWS_APP_STATE_REVIEW_REVISION"
        ),
        windows_app_launch_review_revision: option_env!(
            "CEREBELLUM_WINDOWS_APP_LAUNCH_REVIEW_REVISION"
        ),
        windows_capture_review_revision: option_env!("CEREBELLUM_WINDOWS_CAPTURE_REVIEW_REVISION"),
        windows_fronting_review_revision: option_env!(
            "CEREBELLUM_WINDOWS_FRONTING_REVIEW_REVISION"
        ),
        windows_element_addressed_review_revision: option_env!(
            "CEREBELLUM_WINDOWS_ELEMENT_ADDRESSED_REVIEW_REVISION"
        ),
        windows_input_bracket_review_revision: option_env!(
            "CEREBELLUM_WINDOWS_INPUT_BRACKET_REVIEW_REVISION"
        ),
        windows_takeover_review_revision: option_env!(
            "CEREBELLUM_WINDOWS_TAKEOVER_REVIEW_REVISION"
        ),
        app_state_review_revision,
        element_addressed_review_revision,
        takeover_dispatch_review_revision,
        takeover_pointer_fronting_review_revision: option_env!(
            "CEREBELLUM_TAKEOVER_POINTER_FRONTING_REVIEW_REVISION"
        ),
        app_use_fronting_review_revision,
        release_signing_topology_revision,
    })
}

#[derive(Default)]
pub(super) struct BuildReleaseBindings<'a> {
    pub(super) attendance_contract_owner: Option<&'a str>,
    pub(super) attendance_contract_revision: Option<&'a str>,
    pub(super) input_review_revision: Option<&'a str>,
    pub(super) global_dispatch_review_revision: Option<&'a str>,
    pub(super) capture_review_revision: Option<&'a str>,
    pub(super) semantic_actuation_review_revision: Option<&'a str>,
    pub(super) windows_actuation_review_revision: Option<&'a str>,
    pub(super) windows_app_identity_review_revision: Option<&'a str>,
    pub(super) windows_app_state_review_revision: Option<&'a str>,
    pub(super) windows_app_launch_review_revision: Option<&'a str>,
    pub(super) windows_capture_review_revision: Option<&'a str>,
    pub(super) windows_fronting_review_revision: Option<&'a str>,
    pub(super) windows_element_addressed_review_revision: Option<&'a str>,
    pub(super) windows_input_bracket_review_revision: Option<&'a str>,
    pub(super) windows_takeover_review_revision: Option<&'a str>,
    pub(super) app_state_review_revision: Option<&'a str>,
    pub(super) element_addressed_review_revision: Option<&'a str>,
    pub(super) takeover_dispatch_review_revision: Option<&'a str>,
    pub(super) takeover_pointer_fronting_review_revision: Option<&'a str>,
    pub(super) app_use_fronting_review_revision: Option<&'a str>,
    pub(super) release_signing_topology_revision: Option<&'a str>,
}

pub(super) fn release_inputs_from_build_bindings(
    bindings: BuildReleaseBindings<'_>,
) -> ComputerReleaseInputs {
    let computed_vocabulary_digest = computer::platform::computed_vocabulary_sha256();
    ComputerReleaseInputs {
        attendance_contract_owner: bindings.attendance_contract_owner.map(str::to_owned),
        attendance_contract_revision: bindings.attendance_contract_revision.map(str::to_owned),
        input_review_revision: bindings.input_review_revision.map(str::to_owned),
        global_dispatch_review_revision: bindings
            .global_dispatch_review_revision
            .map(str::to_owned),
        capture_review_revision: bindings.capture_review_revision.map(str::to_owned),
        semantic_actuation_review_revision: bindings
            .semantic_actuation_review_revision
            .map(str::to_owned),
        windows_actuation_review_revision: bindings
            .windows_actuation_review_revision
            .map(str::to_owned),
        windows_app_identity_review_revision: bindings
            .windows_app_identity_review_revision
            .map(str::to_owned),
        windows_app_state_review_revision: bindings
            .windows_app_state_review_revision
            .map(str::to_owned),
        windows_app_launch_review_revision: bindings
            .windows_app_launch_review_revision
            .map(str::to_owned),
        windows_capture_review_revision: bindings
            .windows_capture_review_revision
            .map(str::to_owned),
        windows_fronting_review_revision: bindings
            .windows_fronting_review_revision
            .map(str::to_owned),
        windows_element_addressed_review_revision: bindings
            .windows_element_addressed_review_revision
            .map(str::to_owned),
        windows_input_bracket_review_revision: bindings
            .windows_input_bracket_review_revision
            .map(str::to_owned),
        windows_takeover_review_revision: bindings
            .windows_takeover_review_revision
            .map(str::to_owned),
        app_state_review_revision: bindings.app_state_review_revision.map(str::to_owned),
        element_addressed_review_revision: bindings
            .element_addressed_review_revision
            .map(str::to_owned),
        takeover_dispatch_review_revision: bindings
            .takeover_dispatch_review_revision
            .map(str::to_owned),
        takeover_pointer_fronting_review_revision: bindings
            .takeover_pointer_fronting_review_revision
            .map(str::to_owned),
        app_use_fronting_review_revision: bindings
            .app_use_fronting_review_revision
            .map(str::to_owned),
        release_signing_topology_revision: bindings
            .release_signing_topology_revision
            .map(str::to_owned),
        vocabulary_digests: computer::platform::VocabularyDigestInputs {
            // The manifest and computed-artifact mirrors are recalculated from
            // the frozen vocabulary, while the source-lock digest comes from its
            // separate checked-in file. Each is compared with its expected digest.
            manifest_digest: Some(computed_vocabulary_digest.clone()),
            source_lock_digest: computer::platform::implementation_source_lock_digest(),
            computed_artifact_digest: Some(computed_vocabulary_digest),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows_review_bindings() -> BuildReleaseBindings<'static> {
        BuildReleaseBindings {
            windows_app_identity_review_revision: Some("fixture-identity"),
            windows_app_state_review_revision: Some("fixture-state"),
            windows_app_launch_review_revision: Some("fixture-launch"),
            windows_capture_review_revision: Some("fixture-capture"),
            windows_fronting_review_revision: Some("fixture-fronting"),
            windows_element_addressed_review_revision: Some("fixture-element"),
            windows_input_bracket_review_revision: Some("fixture-bracket"),
            windows_takeover_review_revision: Some("fixture-takeover"),
            ..Default::default()
        }
    }

    #[test]
    fn windows_review_bindings_land_in_distinct_fields() {
        let inputs = release_inputs_from_build_bindings(windows_review_bindings());
        assert_eq!(
            inputs.windows_app_identity_review_revision.as_deref(),
            Some("fixture-identity")
        );
        assert_eq!(
            inputs.windows_app_state_review_revision.as_deref(),
            Some("fixture-state")
        );
        assert_eq!(
            inputs.windows_app_launch_review_revision.as_deref(),
            Some("fixture-launch")
        );
        assert_eq!(
            inputs.windows_capture_review_revision.as_deref(),
            Some("fixture-capture")
        );
        assert_eq!(
            inputs.windows_fronting_review_revision.as_deref(),
            Some("fixture-fronting")
        );
        assert_eq!(
            inputs.windows_element_addressed_review_revision.as_deref(),
            Some("fixture-element")
        );
        assert_eq!(
            inputs.windows_input_bracket_review_revision.as_deref(),
            Some("fixture-bracket")
        );
        assert_eq!(
            inputs.windows_takeover_review_revision.as_deref(),
            Some("fixture-takeover")
        );
        assert_eq!(inputs.windows_actuation_review_revision, None);
        assert_eq!(inputs.release_signing_topology_revision, None);
    }
}
