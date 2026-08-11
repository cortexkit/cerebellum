//! macOS 26 startup and capability skeleton.
//!
//! The probe is intentionally data-driven so conformance can exercise stale
//! grants and envelope drift without linking macOS frameworks on other hosts.

use super::*;
use std::collections::BTreeSet;

pub const MACOS_MAJOR_VERSION: u16 = 26;
pub const PRIVATE_ENVELOPE_REVISION: &str = "skylight-macos26-v1";
pub const PRIVATE_PID_POST_SYMBOL: &str = "SLEventPostToPid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupProbeInput {
    pub os_major: u16,
    pub private_envelope_revision: Option<String>,
    pub resolved_private_symbols: BTreeSet<String>,
    pub permission_results: Vec<PermissionProbeResult>,
    /// The process this system attributes our permission grants to, resolved at
    /// runtime rather than assumed, and `None` until it has been.
    ///
    /// It is NOT this module. macOS attributes a grant to the process
    /// responsible for launching ours, so for a daemon-launched module the
    /// grants belong to the daemon, and a probe reporting that truthfully has
    /// to be counted rather than discarded. Naming a fixed process here would
    /// suppress every capability that depends on a grant, silently and
    /// permanently.
    ///
    /// `None` means the attribution has not been established, which is not the
    /// same as knowing it and finding no match: an unestablished attribution
    /// admits no probe result at all, because a grant cannot be credited to a
    /// process nobody has identified.
    pub responsible_process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateEnvelopeStartupProbe {
    pub expected_os_major: u16,
    pub expected_revision: &'static str,
    pub required_symbols: &'static [&'static str],
}

impl Default for PrivateEnvelopeStartupProbe {
    fn default() -> Self {
        Self {
            expected_os_major: MACOS_MAJOR_VERSION,
            expected_revision: PRIVATE_ENVELOPE_REVISION,
            required_symbols: &[PRIVATE_PID_POST_SYMBOL],
        }
    }
}

impl PrivateEnvelopeStartupProbe {
    pub fn run(&self, input: &StartupProbeInput) -> bool {
        input.os_major == self.expected_os_major
            && input.private_envelope_revision.as_deref() == Some(self.expected_revision)
            && self
                .required_symbols
                .iter()
                .all(|symbol| input.resolved_private_symbols.contains(*symbol))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionLivenessProbe {
    pub responsible_process: String,
}

impl PermissionLivenessProbe {
    pub fn run(&self, results: &[PermissionProbeResult]) -> PermissionLivenessReport {
        PermissionLivenessReport::from_results(
            results
                .iter()
                .filter(|result| {
                    result.responsible_process == self.responsible_process && result.off_main
                })
                .cloned(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCapabilityProbe {
    pub os_major: u16,
    pub private_envelope_recognized: bool,
    pub permissions: PermissionLivenessReport,
}

impl StartupCapabilityProbe {
    pub fn run(input: &StartupProbeInput) -> Self {
        let envelope = PrivateEnvelopeStartupProbe::default();
        let permissions = match input.responsible_process.as_deref() {
            Some(process) => PermissionLivenessProbe {
                responsible_process: process.to_string(),
            }
            .run(&input.permission_results),
            None => PermissionLivenessReport::default(),
        };
        Self {
            os_major: input.os_major,
            private_envelope_recognized: envelope.run(input),
            permissions,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacOs26PlatformDriver {
    startup: StartupCapabilityProbe,
}

impl MacOs26PlatformDriver {
    pub fn new(input: &StartupProbeInput) -> Self {
        Self {
            startup: StartupCapabilityProbe::run(input),
        }
    }

    pub fn startup_probe(&self) -> &StartupCapabilityProbe {
        &self.startup
    }

    /// Describe all eight actions, advertising only the ones that can be served.
    ///
    /// A declaration says what an action WOULD need; advertising says it can be
    /// used now. The actions that actuate are described and not advertised,
    /// because no input path exists to serve them yet.
    pub fn declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        let ids = [
            "computer.click",
            "computer.type",
            "computer.keys",
            "computer.scroll",
            "computer.move",
            "computer.drag",
            "computer.screenshot",
            "computer.wait",
        ];
        ids.into_iter()
            .map(|id| self.declaration(id, context))
            .collect()
    }

    fn declaration(
        &self,
        id: &str,
        context: &CapabilityAdvertisementContext,
    ) -> CapabilityDeclaration {
        let action_kind = if id == "computer.drag" {
            ActionKind::MutateDurable
        } else if id == "computer.screenshot" || id == "computer.wait" {
            ActionKind::Observe
        } else {
            ActionKind::Compose
        };
        let retry_class = match id {
            "computer.scroll" => RetryClass::ReconcileBeforeRetry,
            "computer.move" | "computer.screenshot" | "computer.wait" => RetryClass::Idempotent,
            _ => RetryClass::NeverAutomaticRetry,
        };
        // Taken from the frozen vocabulary rather than restated here: a second
        // hand-written table drifts the moment a row changes, and the digest
        // would still only pin the document. An unknown id or unrecognised
        // service name refuses inside the lookup; there is no default set.
        //
        // A lookup that fails SUPPRESSES the capability rather than ending the
        // process. Not knowing which permissions an action needs is a reason not
        // to offer it, and taking the module down would take every other
        // capability with it — including the ones whose permissions resolved.
        let (permissions, permission_lookup_failure) =
            match super::vocabulary::required_permission_services(id) {
                Ok(permissions) => (permissions, None),
                Err(error) => (
                    Vec::new(),
                    Some(format!("required permissions are not resolvable: {error}")),
                ),
            };
        let mut advertised = false;
        let mut suppression_reason = permission_lookup_failure
            .clone()
            .or_else(|| Some("no input dispatch path exists yet".to_string()));
        if permission_lookup_failure.is_some() {
            // Left as it is: the reason below would overwrite a fact the caller
            // needs more than a release-input note.
        } else if id == "computer.wait" {
            advertised = context.inputs.vocabulary_ready();
            suppression_reason =
                (!advertised).then(|| "computer action vocabulary input unresolved".to_string());
        } else if id == "computer.screenshot" {
            // Named separately rather than as one combined reason. The
            // conditions fail for unrelated causes -- a missing release input is
            // a build-time omission, an unresolved permission is a property of
            // the machine -- and a reader given one message for both has to
            // rule out the other by hand.
            let liveness = context
                .startup
                .permissions
                .state(PermissionService::ScreenRecording);
            suppression_reason = if !context.inputs.vocabulary_ready() {
                Some("computer action vocabulary input unresolved".to_string())
            } else if !context.inputs.capture_ready() {
                Some("capture release input unresolved".to_string())
            } else {
                // Matching on the state rather than testing it against Live
                // keeps the accepting case an ordinary arm. A branch that can
                // "never" be reached is a crash waiting for the day the
                // surrounding condition changes.
                match liveness {
                    PermissionLiveness::Live => None,
                    PermissionLiveness::Unavailable => {
                        Some("screen recording permission is not granted".to_string())
                    }
                    PermissionLiveness::GrantedPendingRelaunch => Some(
                        "screen recording permission is granted but not usable until this \
                         process restarts"
                            .to_string(),
                    ),
                    // Nothing denied the permission; no usable reading was
                    // recorded for it. A reading is discarded when it comes from
                    // the process main thread, or when the system attributes the
                    // grant to a process other than the one expected here.
                    PermissionLiveness::Unresolved => {
                        Some("screen recording permission is not established".to_string())
                    }
                }
            };
            advertised = suppression_reason.is_none();
        }
        // Evaluated even though nothing here advertises a dispatch row, so the
        // gate is exercised by the same path that will eventually consult it
        // rather than first running when something depends on its answer.
        let _dispatch_inputs_resolved = context.inputs.input_dispatch_ready();
        CapabilityDeclaration {
            capability_id: id.to_string(),
            action_kind,
            dispatch_modes: if id == "computer.move" {
                vec![DispatchMode::Observed]
            } else if id == "computer.screenshot" || id == "computer.wait" {
                vec![]
            } else {
                vec![DispatchMode::Background, DispatchMode::Observed]
            },
            semantic_path: if matches!(id, "computer.click" | "computer.type" | "computer.scroll") {
                SupportState::Supported
            } else {
                SupportState::Unsupported
            },
            synthetic_background: if self.startup.private_envelope_recognized {
                SupportState::Supported
            } else {
                SupportState::Unsupported
            },
            synthetic_observed: SupportState::ConsentGated,
            required_permissions: permissions,
            retry_class,
            // A capability whose permission requirements could not be read is
            // never advertised, whatever the rest of the gate concluded: a
            // permission that is not known cannot be checked, and offering the
            // capability would promise a check nobody performs.
            advertised: advertised && permission_lookup_failure.is_none(),
            suppression_reason,
        }
    }
}

impl Default for MacOs26PlatformDriver {
    fn default() -> Self {
        Self::new(&StartupProbeInput {
            os_major: MACOS_MAJOR_VERSION,
            private_envelope_revision: None,
            resolved_private_symbols: BTreeSet::new(),
            permission_results: Vec::new(),
            responsible_process: None,
        })
    }
}

impl PlatformDriver for MacOs26PlatformDriver {
    fn capability_declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        self.declarations(context)
    }

    fn read_accessibility_tree(
        &mut self,
        _request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        Err(DriverError::Unsupported("accessibility tree read"))
    }
    fn resolve_element(
        &mut self,
        _request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        Err(DriverError::Unsupported("element resolution"))
    }
    fn dispatch_semantic(
        &mut self,
        _request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("semantic dispatch"))
    }
    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::StartupRefused(
            "private envelope is skeleton-only",
        ))
    }
    fn dispatch_global(
        &mut self,
        _request: SyntheticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::StartupRefused(
            "global dispatch is skeleton-only",
        ))
    }
    fn enumerate_scoped_windows(
        &mut self,
        _request: ScopedWindowEnumerationRequest,
    ) -> Result<Vec<String>, DriverError> {
        Err(DriverError::Unsupported("scoped window enumeration"))
    }
    fn capture_scoped_windows(
        &mut self,
        _request: ScopedWindowCaptureRequest,
    ) -> Result<ScopedCaptureResult, DriverError> {
        Err(DriverError::Unsupported("scoped capture"))
    }
    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        Err(DriverError::Unsupported("focus query"))
    }
    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported("fronting snapshot"))
    }
    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: false,
            raw_hid_live: false,
            self_echo_filter_live: false,
        }
    }
    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Err(DriverError::Unsupported("input observation"))
    }
    fn observe_effect(
        &mut self,
        _request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        Err(DriverError::Unsupported("effect observation"))
    }
    fn verify_attendance(
        &mut self,
        _request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        Err(DriverError::Unsupported("attendance verification"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capability whose permission requirements cannot be read is suppressed,
    /// not advertised, and the process survives.
    ///
    /// The lookup reads the action vocabulary, which contains every id this
    /// driver asks about, so this cannot happen through `declarations` — which
    /// is exactly why it is worth a test. That branch is unreachable there, so
    /// nothing else can tell whether it suppresses, advertises, or ends the
    /// process. Ending it would take down every other capability along with the
    /// one whose permissions could not be read.
    #[test]
    fn a_capability_with_unreadable_permissions_is_suppressed_rather_than_fatal() {
        let driver = MacOs26PlatformDriver::default();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs::default(),
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        let declaration = driver.declaration("computer.not-in-the-vocabulary", &context);

        assert!(
            !declaration.advertised,
            "a capability with unknown permission requirements was advertised"
        );
        assert!(
            declaration.required_permissions.is_empty(),
            "an unresolvable lookup produced a permission list"
        );
        // The reason names the missing fact rather than the release-input note
        // that would otherwise overwrite it: a reader told the wrong cause looks
        // for a build omission instead of a vocabulary one.
        let reason = declaration
            .suppression_reason
            .expect("a suppressed capability states why");
        assert!(
            reason.contains("required permissions are not resolvable"),
            "the suppression reason does not name the permission lookup: {reason}"
        );
    }

    /// A capability in the vocabulary carries the permissions it lists.
    ///
    /// The accepting case. Without it, a driver that suppressed EVERY capability
    /// would satisfy the refusal test and look correct.
    #[test]
    fn a_frozen_capability_carries_the_permissions_the_vocabulary_lists() {
        let driver = MacOs26PlatformDriver::default();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs::default(),
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        let declaration = driver.declaration("computer.click", &context);
        assert_eq!(
            declaration.required_permissions,
            vec![
                PermissionService::Accessibility,
                PermissionService::PostEvent,
                PermissionService::InputMonitoring,
            ]
        );
    }
}
