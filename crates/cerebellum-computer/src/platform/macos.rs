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
        let permissions = PermissionLivenessProbe {
            responsible_process: "cerebellum-computer".to_string(),
        }
        .run(&input.permission_results);
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

    /// Return all eight frozen rows as declarations, while advertising only
    /// read-only rows in this slice. Later slices add dispatch advertisement
    /// after their executor and audit gates exist.
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
        let permissions = match id {
            "computer.screenshot" => vec![PermissionService::ScreenRecording],
            "computer.wait" => vec![],
            _ => vec![
                PermissionService::Accessibility,
                PermissionService::PostEvent,
            ],
        };
        let mut advertised = false;
        let mut suppression_reason =
            Some("dispatch advertisement belongs to a later C1 slice".to_string());
        if id == "computer.wait" {
            advertised = context.inputs.vocabulary_ready();
            suppression_reason =
                (!advertised).then(|| "computer action vocabulary input unresolved".to_string());
        } else if id == "computer.screenshot" {
            advertised = context.inputs.vocabulary_ready()
                && context.inputs.capture_ready()
                && context
                    .startup
                    .permissions
                    .state(PermissionService::ScreenRecording)
                    == PermissionLiveness::Live;
            suppression_reason = (!advertised)
                .then(|| "capture release input or liveness probe unresolved".to_string());
        }
        // Evaluate the dispatch release gate even though this slice deliberately
        // leaves dispatch rows unadvertised; later slices consume this same gate.
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
            advertised,
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
