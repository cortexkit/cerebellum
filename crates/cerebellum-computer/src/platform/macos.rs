//! macOS 26 startup and capability skeleton.
//!
//! The probe is intentionally data-driven so conformance can exercise stale
//! grants and envelope drift without linking macOS frameworks on other hosts.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedAccessibilityElement {
    identifier: Option<String>,
    actions: Vec<String>,
    children: Vec<CachedAccessibilityElement>,
}

#[derive(Debug, Clone)]
struct CachedAccessibilityTree {
    target: ProcessGrant,
    tree: CachedAccessibilityElement,
    unreadable_subtrees: usize,
}

const INCOMPLETE_TREE_UNIQUENESS: &str =
    "element uniqueness cannot be established from an incomplete accessibility tree";

#[derive(Debug, Clone)]
pub struct MacOs26PlatformDriver {
    startup: StartupCapabilityProbe,
    accessibility_trees: BTreeMap<String, CachedAccessibilityTree>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessibilityReaderFailure {
    PermissionDenied,
    ProcessGone,
    ProcessNotInspectable,
    DeadlineExceeded,
    BoundExceeded,
    IncompatibleValue,
    SystemFailure,
}

impl From<AccessibilityReaderFailure> for AccessibilityReadFailure {
    fn from(failure: AccessibilityReaderFailure) -> Self {
        match failure {
            AccessibilityReaderFailure::PermissionDenied => Self::PermissionRequired,
            AccessibilityReaderFailure::ProcessGone => Self::TargetGone,
            AccessibilityReaderFailure::ProcessNotInspectable => Self::TargetNotInspectable,
            AccessibilityReaderFailure::DeadlineExceeded => Self::RetryableDeadlineExceeded,
            // A depth and an element-count limit both mean the reader's bounded
            // traversal policy must change; neither says anything about target liveness.
            AccessibilityReaderFailure::BoundExceeded => Self::TreeExceedsBound,
            AccessibilityReaderFailure::IncompatibleValue => Self::IncompatiblePlatformValue,
            AccessibilityReaderFailure::SystemFailure => Self::PlatformReadFailed,
        }
    }
}

fn accessibility_read_timeout(settle_interval_ms: u32) -> Result<Duration, DriverError> {
    // The interval caps how long AX may block this read. Waiting beforehand
    // would only age the tree and would not make a rejected read more usable.
    <MacOs26PlatformDriver as PlatformDriver>::bounded_duration(u64::from(settle_interval_ms))
}

/// What a platform acceptance means for the caller's dispatch result.
///
/// ACCEPTED IS NOT PERFORMED. The accessibility API returns once the
/// application's handler returns, and some applications return success from a
/// handler that forwards nothing. So acceptance is recorded and the effect is
/// left INDETERMINATE for a separate observation to settle: reporting an effect
/// here would be this layer asserting something it never looked at, and a
/// caller reading that would skip the check that establishes it.
///
/// A separate function rather than a literal at the call site, because the call
/// site can only run against a live application with a granted permission,
/// which no test on an arbitrary machine has. Written here, the meaning of an
/// acceptance is checkable everywhere.
#[cfg(target_os = "macos")]
const fn dispatch_result_for_accepted_action(
    outcome: cerebellum_macos::AxActionRequestOutcome,
) -> DispatchResult {
    match outcome {
        cerebellum_macos::AxActionRequestOutcome::HandlerReturned => DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
        },
    }
}

/// Find an element by exact identifier in a freshly read tree.
///
/// Returns the observation for the condition to be checked against, or absence
/// when the element is not there. Absence is a real observation rather than a
/// failure: an element that has gone answers an absence condition and fails
/// every other, which the evaluator decides.
///
/// A duplicate identifier yields NO observation rather than the first match.
/// Two elements answering to one name means the condition cannot be checked
/// against the element it was written about, and picking one would report an
/// effect belonging to whichever the walk reached first.
#[cfg(target_os = "macos")]
fn observe_element(
    element: &cerebellum_macos::AxElement,
    identifier: &str,
    found: &mut Option<crate::dispatch::post_condition::ObservedElement>,
    duplicate: &mut bool,
) {
    if element.identifier.as_deref() == Some(identifier) {
        if found.is_some() {
            *duplicate = true;
            return;
        }
        *found = Some(crate::dispatch::post_condition::ObservedElement {
            present: true,
            focused: element.focused,
            enabled: element.enabled,
            value: element.value_description.clone(),
        });
    }
    for child in &element.children {
        observe_element(child, identifier, found, duplicate);
    }
}

/// Return an observation root only when absence and uniqueness can be decided.
/// A readable node in a partial tree cannot establish either fact because a
/// matching node may be present below an unreadable element.
#[cfg(target_os = "macos")]
fn observable_ax_root(
    tree: &cerebellum_macos::AxAccessibilityTree,
) -> Option<&cerebellum_macos::AxElement> {
    match tree.completeness {
        cerebellum_macos::AxTreeCompleteness::Complete => Some(&tree.root),
        cerebellum_macos::AxTreeCompleteness::Incomplete { .. } => None,
    }
}

/// Map an action failure onto the driver's typed vocabulary.
///
/// Every `AxActionError` is handled explicitly rather than through a catch-all,
/// so a variant added later stops the build here instead of silently inheriting
/// whichever case happened to be last.
#[cfg(target_os = "macos")]
fn map_ax_action_error(error: cerebellum_macos::AxActionError) -> DriverError {
    use cerebellum_macos::AxActionError;
    match error {
        AxActionError::PermissionNotGranted => {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::PermissionRequired)
        }
        AxActionError::NoSuchProcess { .. } => {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::TargetGone)
        }
        AxActionError::ProcessNotAccessible { .. } => {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::TargetNotInspectable)
        }
        // The element is gone or was never there: a fact about the request
        // rather than about the target, so it is not a read failure.
        AxActionError::ElementNotFound { .. } => DriverError::ElementNotFound,
        // Two elements answer to one identifier, so no action can be delivered
        // to the one that was resolved. Refused rather than guessing, because
        // guessing is how an action lands on a control nobody chose.
        AxActionError::ElementIdentifierAmbiguous { .. } => {
            DriverError::InvalidRequest("the element identifier names more than one element")
        }
        AxActionError::ElementUniquenessUnestablished { .. } => {
            DriverError::InvalidRequest(INCOMPLETE_TREE_UNIQUENESS)
        }
        // The element exists and does not offer this action. Distinct from an
        // application refusing one it does offer: this is answerable before
        // asking, and asking anyway would request something invented.
        AxActionError::ActionNotAdvertised { .. } => {
            DriverError::InvalidRequest("the element does not advertise this action")
        }
        AxActionError::ApplicationRefusedAction { .. } => {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::PlatformReadFailed)
        }
        AxActionError::DeadlineExceeded { .. } => DriverError::AccessibilityUnreadable(
            AccessibilityReadFailure::RetryableDeadlineExceeded,
        ),
        AxActionError::DepthLimitExceeded { .. } | AxActionError::ElementLimitExceeded { .. } => {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::TreeExceedsBound)
        }
        AxActionError::UnexpectedValueType { .. } => DriverError::AccessibilityUnreadable(
            AccessibilityReadFailure::IncompatiblePlatformValue,
        ),
        AxActionError::SystemCallFailed { .. } => {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::PlatformReadFailed)
        }
    }
}

fn root_cache_key(target: &ProcessGrant) -> String {
    // Keyed on the grant's process identity rather than on an accessibility
    // identifier, which is optional and chosen by the application.
    //
    // Including the generation alongside the pid keeps two generations of the
    // same pid on separate keys, so a cache entry cannot be retrieved for a
    // process that merely inherited the identifier. Whether the process behind a
    // key is still the granted one is established by verifying the grant at use,
    // not by this key.
    format!(
        "accessibility-root:{}:{}",
        target.pid, target.process_generation_evidence
    )
}

fn root_degenerate_reason(child_count: u32, unreadable_subtrees: usize) -> Option<String> {
    if unreadable_subtrees > 0 {
        Some(format!(
            "incomplete_accessibility_tree:{unreadable_subtrees}_unreadable_subtrees"
        ))
    } else {
        (child_count == 0).then(|| "missing_children_for_nontrivial_window".to_string())
    }
}

#[cfg(target_os = "macos")]
fn map_ax_read_error(error: cerebellum_macos::AxReadError) -> DriverError {
    let failure = match error {
        cerebellum_macos::AxReadError::PermissionNotGranted => {
            AccessibilityReaderFailure::PermissionDenied
        }
        cerebellum_macos::AxReadError::NoSuchProcess { .. } => {
            AccessibilityReaderFailure::ProcessGone
        }
        cerebellum_macos::AxReadError::ProcessNotAccessible { .. } => {
            AccessibilityReaderFailure::ProcessNotInspectable
        }
        cerebellum_macos::AxReadError::DeadlineExceeded { .. } => {
            AccessibilityReaderFailure::DeadlineExceeded
        }
        cerebellum_macos::AxReadError::DepthLimitExceeded { .. }
        | cerebellum_macos::AxReadError::ElementLimitExceeded { .. } => {
            AccessibilityReaderFailure::BoundExceeded
        }
        cerebellum_macos::AxReadError::UnexpectedValueType { .. } => {
            AccessibilityReaderFailure::IncompatibleValue
        }
        cerebellum_macos::AxReadError::SystemCallFailed { .. } => {
            AccessibilityReaderFailure::SystemFailure
        }
    };
    AccessibilityReadFailure::from(failure).into()
}

#[cfg(target_os = "macos")]
fn cache_ax_element(element: cerebellum_macos::AxElement) -> CachedAccessibilityElement {
    CachedAccessibilityElement {
        identifier: element.identifier,
        actions: element.actions,
        children: element.children.into_iter().map(cache_ax_element).collect(),
    }
}

fn find_cached_element<'a>(
    element: &'a CachedAccessibilityElement,
    identifier: &str,
) -> Option<&'a CachedAccessibilityElement> {
    if element.identifier.as_deref() == Some(identifier) {
        return Some(element);
    }
    element
        .children
        .iter()
        .find_map(|child| find_cached_element(child, identifier))
}

fn resolve_cached_element<'a>(
    tree: &'a CachedAccessibilityTree,
    request: &ElementResolutionRequest,
) -> Result<&'a CachedAccessibilityElement, DriverError> {
    // Resolution feeds semantic actuation. A first visible match cannot be used
    // when another matching element may be hidden below an unreadable subtree.
    if tree.unreadable_subtrees > 0 {
        return Err(DriverError::InvalidRequest(INCOMPLETE_TREE_UNIQUENESS));
    }
    find_cached_element(&tree.tree, &request.element_identifier).ok_or(DriverError::ElementNotFound)
}

#[cfg(target_os = "macos")]
fn verify_cached_tree_owner(target: &ProcessGrant) -> Result<(), DriverError> {
    match super::native::verify_grant(target.pid, target) {
        super::native::GrantVerification::Current => Ok(()),
        super::native::GrantVerification::TargetReplaced => {
            Err(AccessibilityReadFailure::TargetReplaced.into())
        }
        super::native::GrantVerification::TargetGone => {
            Err(AccessibilityReadFailure::TargetGone.into())
        }
        super::native::GrantVerification::TargetUnreadable => {
            Err(AccessibilityReadFailure::TargetNotInspectable.into())
        }
        super::native::GrantVerification::DifferentProcess => Err(DriverError::InvalidRequest(
            "cached accessibility root belongs to another process",
        )),
    }
}

impl MacOs26PlatformDriver {
    pub fn new(input: &StartupProbeInput) -> Self {
        Self {
            startup: StartupCapabilityProbe::run(input),
            accessibility_trees: BTreeMap::new(),
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
        // A suppression reason is an operator-facing diagnosis, so it must name
        // the layer that is actually absent. For the actuating rows the
        // MECHANISM exists -- a semantic action can be requested of an
        // application through the closed AxAction vocabulary -- and what is
        // missing is a wire serving handler, plus the review and activation
        // that would precede one. Saying "no dispatch path" sent the reader to
        // the platform layer to look for something already there.
        let mut suppression_reason = permission_lookup_failure.clone().or_else(|| {
            Some(
                "no wire serving handler: the semantic mechanism is built, and serving it \
                 awaits review and activation"
                    .to_string(),
            )
        });
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
        //
        // ITS ANSWER CURRENTLY CHANGES NOTHING: every actuating row is
        // suppressed by the unconditional default above, so binding all of the
        // release inputs would not advertise one. Whoever adds a serving
        // handler has to consult this deliberately, which is a thing to
        // remember rather than a thing enforced --
        // `dispatch_gate_tests::every_actuating_row_is_suppressed_unconditionally`
        // is the fence that asks the question at that moment.
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
        request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        request.target.validate()?;
        let timeout = accessibility_read_timeout(request.settle_interval_ms)?;

        #[cfg(target_os = "macos")]
        {
            let tree = cerebellum_macos::read_accessibility_tree(
                request.target.pid,
                cerebellum_macos::AxReadOptions {
                    timeout,
                    ..Default::default()
                },
            )
            .map_err(map_ax_read_error)?;
            let unreadable_subtrees = match tree.completeness {
                cerebellum_macos::AxTreeCompleteness::Complete => 0,
                cerebellum_macos::AxTreeCompleteness::Incomplete {
                    unreadable_subtrees,
                } => unreadable_subtrees,
            };
            let root_child_count = tree
                .root
                .children
                .len()
                .checked_add(tree.root.unreadable_children.len())
                .expect("the reader's element bound keeps child count within usize");
            let child_count = u32::try_from(root_child_count)
                .expect("the reader's element bound keeps child count within u32");
            let root_identifier = root_cache_key(&request.target);
            self.accessibility_trees.insert(
                root_identifier.clone(),
                CachedAccessibilityTree {
                    target: request.target,
                    tree: cache_ax_element(tree.root),
                    unreadable_subtrees,
                },
            );
            Ok(AccessibilityTreeResult {
                root_identifier: Some(root_identifier),
                child_count,
                handshake_attempted: true,
                degenerate_reason: root_degenerate_reason(child_count, unreadable_subtrees),
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = timeout;
            Err(DriverError::Unsupported("accessibility tree read"))
        }
    }
    fn resolve_element(
        &mut self,
        request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        #[cfg(target_os = "macos")]
        {
            let Some(cached) = self.accessibility_trees.get(&request.root_identifier) else {
                return Err(DriverError::ElementNotFound);
            };
            verify_cached_tree_owner(&cached.target)?;
            let element = resolve_cached_element(cached, &request)?;
            Ok(ElementResolutionResult {
                element_identifier: request.element_identifier,
                // Cloning occurs only after the kernel generation check above;
                // otherwise a reused PID could be reported as the old grant.
                owning_process: cached.target.clone(),
                semantic_actions: element.actions.clone(),
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("element resolution"))
        }
    }
    fn dispatch_semantic(
        &mut self,
        request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("semantic dispatch"))
        }
        #[cfg(target_os = "macos")]
        {
            // The grant is re-verified here rather than trusted from
            // resolution. Between resolving an element and acting on it the
            // process may have exited and its identifier been reused, and this
            // is the last moment before something changes.
            verify_cached_tree_owner(&request.element.owning_process)?;

            // Only the actions named in the closed AxAction vocabulary can be
            // requested. The wire carries a string, and passing it through
            // would let a caller ask an application for any action its
            // accessibility implementation happens to expose.
            let action = cerebellum_macos::AxAction::from_name(&request.action)
                .ok_or(DriverError::InvalidRequest("unknown accessibility action"))?;

            let element_name =
                cerebellum_macos::AxElementName::new(&request.element.element_identifier)
                    .map_err(|_| DriverError::InvalidRequest("unusable element identifier"))?;

            let outcome = cerebellum_macos::request_accessibility_action(
                request.element.owning_process.pid,
                &element_name,
                action,
                cerebellum_macos::AxActionOptions::default(),
            )
            .map_err(map_ax_action_error)?;

            Ok(dispatch_result_for_accepted_action(outcome))
        }
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
        request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("effect observation"))
        }
        #[cfg(target_os = "macos")]
        {
            use crate::dispatch::post_condition::{evaluate, ConditionOutcome, ObservedElement};
            use crate::dispatch::ExpectedPostCondition;

            // A condition this driver cannot decide is reported as
            // INDETERMINATE rather than refused. The action already happened;
            // the caller needs to know that its effect is unestablished, which
            // is a different fact from the observation machinery being broken.
            // Deserialized into the type that WROTE it, rather than a local copy
            // of its shape: a second definition of the same envelope drifts
            // silently, and the failure would be a condition that reads back
            // wrong rather than one that fails to read.
            let Ok(envelope) = serde_json::from_str::<ExpectedPostCondition>(&request.predicate)
            else {
                return Ok(EffectObservationResult {
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("post_condition_undeclarable".to_string()),
                });
            };

            // Read FRESH rather than consulting the cached tree. The cache was
            // populated before the action, so answering from it would report
            // the state the action was meant to change.
            let tree = match cerebellum_macos::read_accessibility_tree(
                request.target.pid,
                cerebellum_macos::AxReadOptions {
                    timeout: Duration::from_millis(u64::from(request.deadline_ms)),
                    ..Default::default()
                },
            ) {
                Ok(tree) => tree,
                Err(cerebellum_macos::AxReadError::DeadlineExceeded { .. }) => {
                    return Ok(EffectObservationResult {
                        status: EffectStatus::EffectIndeterminate,
                        failure_reason: Some("deadline_exceeded".to_string()),
                    })
                }
                Err(_) => {
                    return Ok(EffectObservationResult {
                        status: EffectStatus::EffectIndeterminate,
                        failure_reason: Some("observation_primitive_unavailable".to_string()),
                    })
                }
            };

            let Some(root) = observable_ax_root(&tree) else {
                return Ok(EffectObservationResult {
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("observation_tree_incomplete".to_string()),
                });
            };

            let identifier = envelope.condition.element_identifier();
            let mut found = None;
            let mut duplicate = false;
            observe_element(root, identifier, &mut found, &mut duplicate);
            if duplicate {
                return Ok(EffectObservationResult {
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("post_condition_undeclarable".to_string()),
                });
            }

            let observed = found.unwrap_or_else(ObservedElement::absent);
            let status = match evaluate(&envelope.condition, &observed) {
                ConditionOutcome::Satisfied => EffectStatus::EffectObserved,
                ConditionOutcome::Unsatisfied => EffectStatus::NoEffectObserved,
                ConditionOutcome::Indeterminate => EffectStatus::EffectIndeterminate,
            };
            let failure_reason = match status {
                // The application does not report the attribute the condition
                // is about, so nothing here can say whether the action worked.
                EffectStatus::EffectIndeterminate => {
                    Some("post_condition_undeclarable".to_string())
                }
                _ => None,
            };
            Ok(EffectObservationResult {
                status,
                failure_reason,
            })
        }
    }
    fn verify_attendance(
        &mut self,
        request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("attendance verification"))
        }
        #[cfg(target_os = "macos")]
        {
            // What this adds to the caller's own lease checks: whether the
            // TARGET is still the process the lease was granted for. The caller
            // can see that its lease has not expired and belongs to this
            // conversation, and cannot see that the process behind the
            // identifier was replaced in the meantime -- which is the failure a
            // lease alone cannot detect, because the replacement inherits the
            // identifier the lease names.
            let verification = super::native::verify_grant(request.target.pid, &request.target);
            Ok(AttendancePreconditionResult {
                valid: verification.is_current(),
                // Not reported: the lease's own generation and age are the
                // caller's, and echoing them back would present the caller's
                // input as an independent reading. This answers one question,
                // and says nothing about the rest.
                lease_generation: None,
                age_ms: None,
            })
        }
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

    /// Every actuating row is suppressed no matter what the release inputs say.
    ///
    /// A tripwire rather than a description of intent. `input_dispatch_ready()`
    /// is evaluated in the declaration path and its answer is DISCARDED, so
    /// binding every release input would still advertise nothing -- which is
    /// correct while no serving handler exists, and a trap on the day one does,
    /// because the gate would then be a memory rather than a check.
    ///
    /// Fully bound inputs are supplied here deliberately: a fixture leaving
    /// them absent would pass whether or not the gate were consulted, and could
    /// not tell the two apart.
    #[test]
    fn every_actuating_row_is_suppressed_unconditionally() {
        let driver = MacOs26PlatformDriver::default();
        let bound = ImmutableReleaseInputs {
            attendance_contract_owner: Some("fixture-owner".to_string()),
            attendance_contract_revision: Some("fixture-attendance-v1".to_string()),
            input_review_revision: Some("fixture-input-review-v1".to_string()),
            capture_review_revision: Some("fixture-capture-review-v1".to_string()),
            release_signing_topology_revision: Some("fixture-topology-v1".to_string()),
            ..Default::default()
        };
        assert!(
            bound.input_dispatch_ready(),
            "the fixture must satisfy the gate, or this test cannot tell a \
             consulted gate from an ignored one"
        );
        let context = CapabilityAdvertisementContext {
            inputs: bound,
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        for id in [
            "computer.click",
            "computer.type",
            "computer.keys",
            "computer.scroll",
            "computer.move",
            "computer.drag",
        ] {
            let declaration = driver.declaration(id, &context);
            assert!(
                !declaration.advertised,
                "{id} is advertised. If a wire serving handler now exists, this \
                 test is the question to answer: the declaration path evaluates \
                 input_dispatch_ready() and throws the answer away, so the gate \
                 must be consulted deliberately here rather than assumed."
            );
            let reason = declaration
                .suppression_reason
                .expect("a suppressed capability states why");
            assert!(
                reason.contains("no wire serving handler"),
                "{id} is suppressed for an unexpected reason: {reason}"
            );
        }
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

#[cfg(test)]
mod accessibility_tests {

    /// A replaced target fails attendance even when the lease is otherwise good.
    ///
    /// This is what the platform check adds. A lease can be unexpired and
    /// correctly bound to its conversation while the process behind the
    /// identifier has been replaced, because a replacement inherits the
    /// identifier the lease names. The caller cannot see that, and acting on it
    /// delivers to whatever holds the identifier now.
    ///
    /// Constructed against an identifier this process can read: a grant whose
    /// recorded generation cannot match the running process stands for the
    /// replacement case, since the two are the same observation.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_target_whose_generation_does_not_match_fails_attendance() {
        let mut driver = MacOs26PlatformDriver::new(&crate::platform::StartupProbeInput {
            os_major: 26,
            private_envelope_revision: None,
            resolved_private_symbols: Default::default(),
            permission_results: Vec::new(),
            responsible_process: None,
        });

        let stale = ProcessGrant {
            pid: std::process::id(),
            bundle_identity: "com.example.self".into(),
            process_generation_evidence: "generation-that-never-was".into(),
        };
        let result = driver
            .verify_attendance(AttendancePreconditionRequest {
                conversation_id: "conversation-1".into(),
                target: stale,
                maximum_lease_age_ms: 300_000,
            })
            .expect("the check answers rather than refusing");
        assert!(
            !result.valid,
            "a target whose generation does not match was reported as current"
        );

        // Nothing about the lease is echoed back: this check answers one
        // question, and reporting the caller's own values would present them as
        // an independent reading.
        assert_eq!(result.lease_generation, None);
        assert_eq!(result.age_ms, None);
    }

    /// A process that no longer exists fails attendance.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_target_that_is_gone_fails_attendance() {
        let mut driver = MacOs26PlatformDriver::new(&crate::platform::StartupProbeInput {
            os_major: 26,
            private_envelope_revision: None,
            resolved_private_symbols: Default::default(),
            permission_results: Vec::new(),
            responsible_process: None,
        });

        let result = driver
            .verify_attendance(AttendancePreconditionRequest {
                conversation_id: "conversation-1".into(),
                // A pid the kernel will not resolve to a running process.
                target: ProcessGrant {
                    pid: u32::MAX - 1,
                    bundle_identity: "com.example.gone".into(),
                    process_generation_evidence: "generation-1".into(),
                },
                maximum_lease_age_ms: 300_000,
            })
            .expect("the check answers rather than refusing");
        assert!(!result.valid);
    }

    /// An element is observed by exact identifier, with its attributes.
    #[cfg(target_os = "macos")]
    #[test]
    fn observing_an_element_reports_the_attributes_a_condition_reads() {
        let tree = cerebellum_macos::AxElement {
            role: None,
            subrole: None,
            title: None,
            value_description: Some("typed".to_string()),
            identifier: Some("field-1".to_string()),
            enabled: Some(true),
            focused: Some(true),
            frame: None,
            actions: Vec::new(),
            children: Vec::new(),
            unreadable_children: Vec::new(),
        };

        let mut found = None;
        let mut duplicate = false;
        observe_element(&tree, "field-1", &mut found, &mut duplicate);

        assert!(!duplicate);
        assert_eq!(
            found,
            Some(crate::dispatch::post_condition::ObservedElement {
                present: true,
                focused: Some(true),
                enabled: Some(true),
                value: Some("typed".to_string()),
            })
        );
    }

    /// Two elements answering to one identifier yield no observation.
    ///
    /// Picking the first would check the condition against whichever element
    /// the walk reached, and report an effect that may belong to the other. The
    /// caller receives INDETERMINATE, which is true: the condition was written
    /// about one element and the tree offers two.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_duplicate_identifier_yields_no_observation_rather_than_the_first_match() {
        fn node(identifier: &str, focused: bool) -> cerebellum_macos::AxElement {
            cerebellum_macos::AxElement {
                role: None,
                subrole: None,
                title: None,
                value_description: None,
                identifier: Some(identifier.to_string()),
                enabled: None,
                focused: Some(focused),
                frame: None,
                actions: Vec::new(),
                children: Vec::new(),
                unreadable_children: Vec::new(),
            }
        }
        let tree = cerebellum_macos::AxElement {
            role: None,
            subrole: None,
            title: None,
            value_description: None,
            identifier: None,
            enabled: None,
            focused: None,
            frame: None,
            actions: Vec::new(),
            // The two disagree, so picking either would give a different answer.
            children: vec![node("button-1", true), node("button-1", false)],
            unreadable_children: Vec::new(),
        };

        let mut found = None;
        let mut duplicate = false;
        observe_element(&tree, "button-1", &mut found, &mut duplicate);

        assert!(
            duplicate,
            "a duplicate identifier was resolved to a single element"
        );
    }

    /// An element that is not in the tree is absent rather than missing.
    ///
    /// Absence is a real observation: it satisfies a condition expecting the
    /// element to be gone and fails every other. Reporting it as a failed read
    /// would make a successful dismissal indistinguishable from a broken one.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_element_outside_the_tree_produces_no_observation() {
        let tree = cerebellum_macos::AxElement {
            role: None,
            subrole: None,
            title: None,
            value_description: None,
            identifier: Some("other".to_string()),
            enabled: None,
            focused: None,
            frame: None,
            actions: Vec::new(),
            children: Vec::new(),
            unreadable_children: Vec::new(),
        };

        let mut found = None;
        let mut duplicate = false;
        observe_element(&tree, "gone", &mut found, &mut duplicate);

        assert!(found.is_none());
        assert!(!duplicate);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_a_complete_tree_can_supply_an_observation_root() {
        fn tree(
            completeness: cerebellum_macos::AxTreeCompleteness,
        ) -> cerebellum_macos::AxAccessibilityTree {
            cerebellum_macos::AxAccessibilityTree {
                root: cerebellum_macos::AxElement {
                    role: None,
                    subrole: None,
                    title: None,
                    value_description: None,
                    identifier: Some("readable-root".to_string()),
                    enabled: None,
                    focused: None,
                    frame: None,
                    actions: Vec::new(),
                    children: Vec::new(),
                    unreadable_children: Vec::new(),
                },
                completeness,
            }
        }

        let complete = tree(cerebellum_macos::AxTreeCompleteness::Complete);
        assert_eq!(observable_ax_root(&complete), Some(&complete.root));

        let incomplete = tree(cerebellum_macos::AxTreeCompleteness::Incomplete {
            unreadable_subtrees: 1,
        });
        assert_eq!(observable_ax_root(&incomplete), None);
    }

    /// A platform acceptance does not claim an effect.
    ///
    /// The single most important property here: the accessibility API returns
    /// when the application's handler returns, so acceptance is evidence the
    /// request was delivered and nothing more. A caller told the effect was
    /// OBSERVED would skip the observation that establishes it, and would do so
    /// exactly against the applications whose handlers return without acting.
    #[test]
    fn platform_acceptance_leaves_the_effect_unclaimed() {
        let result = dispatch_result_for_accepted_action(
            cerebellum_macos::AxActionRequestOutcome::HandlerReturned,
        );
        assert!(result.accepted_by_platform);
        assert_eq!(result.effect_status, EffectStatus::EffectIndeterminate);
    }

    /// Every action failure keeps a distinct remedy.
    ///
    /// The failures differ in what a caller should do: grant a permission, stop
    /// entirely, name a different element, ask for an action the element offers,
    /// or retry. A mapping that collapsed any pair would send a caller down a
    /// path that cannot succeed, and the plausible guess after a failed action
    /// is to retry, which is wrong for most of these.
    #[test]
    fn every_action_failure_maps_to_a_distinct_remedy() {
        use cerebellum_macos::AxActionError;

        let cases = [
            (
                AxActionError::PermissionNotGranted,
                DriverError::AccessibilityUnreadable(AccessibilityReadFailure::PermissionRequired),
            ),
            (
                AxActionError::NoSuchProcess { pid: 7 },
                DriverError::AccessibilityUnreadable(AccessibilityReadFailure::TargetGone),
            ),
            (
                AxActionError::ElementNotFound {
                    identifier: "absent".to_string(),
                },
                DriverError::ElementNotFound,
            ),
            (
                AxActionError::ElementIdentifierAmbiguous {
                    identifier: "twice".to_string(),
                },
                DriverError::InvalidRequest("the element identifier names more than one element"),
            ),
            (
                AxActionError::ElementUniquenessUnestablished {
                    identifier: "partially-seen".to_string(),
                    unreadable_subtrees: 1,
                },
                DriverError::InvalidRequest(INCOMPLETE_TREE_UNIQUENESS),
            ),
            (
                AxActionError::DeadlineExceeded {
                    timeout: std::time::Duration::from_millis(1),
                },
                DriverError::AccessibilityUnreadable(
                    AccessibilityReadFailure::RetryableDeadlineExceeded,
                ),
            ),
        ];

        for (raw, expected) in cases {
            assert_eq!(map_ax_action_error(raw.clone()), expected, "{raw:?}");
        }
    }

    /// Absence, ambiguity, and an incomplete search require different remedies.
    ///
    /// An absent name can be corrected by naming an existing element, an
    /// ambiguous name by choosing one element, and an incomplete search only by
    /// obtaining a complete tree. Collapsing them would make at least one remedy
    /// unsafe or ineffective.
    #[test]
    fn incomplete_ambiguous_and_absent_action_targets_remain_distinct() {
        use cerebellum_macos::AxActionError;

        let absent = map_ax_action_error(AxActionError::ElementNotFound {
            identifier: "x".to_string(),
        });
        let ambiguous = map_ax_action_error(AxActionError::ElementIdentifierAmbiguous {
            identifier: "x".to_string(),
        });
        let incomplete = map_ax_action_error(AxActionError::ElementUniquenessUnestablished {
            identifier: "x".to_string(),
            unreadable_subtrees: 1,
        });

        assert_ne!(absent, ambiguous);
        assert_ne!(absent, incomplete);
        assert_ne!(ambiguous, incomplete);
    }
    use super::*;

    #[test]
    fn reader_failures_map_to_distinct_typed_driver_errors() {
        let cases = [
            (
                AccessibilityReaderFailure::PermissionDenied,
                AccessibilityReadFailure::PermissionRequired,
            ),
            (
                AccessibilityReaderFailure::ProcessGone,
                AccessibilityReadFailure::TargetGone,
            ),
            (
                AccessibilityReaderFailure::ProcessNotInspectable,
                AccessibilityReadFailure::TargetNotInspectable,
            ),
            (
                AccessibilityReaderFailure::DeadlineExceeded,
                AccessibilityReadFailure::RetryableDeadlineExceeded,
            ),
            (
                AccessibilityReaderFailure::BoundExceeded,
                AccessibilityReadFailure::TreeExceedsBound,
            ),
            (
                AccessibilityReaderFailure::IncompatibleValue,
                AccessibilityReadFailure::IncompatiblePlatformValue,
            ),
            (
                AccessibilityReaderFailure::SystemFailure,
                AccessibilityReadFailure::PlatformReadFailed,
            ),
        ];

        for (reader_failure, expected) in cases {
            assert_eq!(
                DriverError::from(AccessibilityReadFailure::from(reader_failure)),
                DriverError::AccessibilityUnreadable(expected),
                "the reader failure {reader_failure:?} did not retain its caller-visible remedy"
            );
        }
    }

    #[test]
    fn settle_interval_bounds_the_read_without_a_pre_read_wait() {
        assert_eq!(
            accessibility_read_timeout(500),
            Ok(Duration::from_millis(500))
        );
        assert_eq!(
            accessibility_read_timeout(300_001),
            Err(DriverError::InvalidRequest(
                "duration exceeds vocabulary bound"
            ))
        );
    }

    #[test]
    fn root_handle_binds_the_cache_to_the_granted_process_generation() {
        let first = ProcessGrant {
            pid: 41,
            bundle_identity: "com.example.reader".to_string(),
            process_generation_evidence: "generation-a".to_string(),
        };
        let replacement = ProcessGrant {
            process_generation_evidence: "generation-b".to_string(),
            ..first.clone()
        };

        assert_eq!(root_cache_key(&first), "accessibility-root:41:generation-a");
        assert_ne!(root_cache_key(&first), root_cache_key(&replacement));
    }

    #[test]
    fn an_empty_root_uses_the_closed_degeneracy_vocabulary() {
        assert_eq!(
            root_degenerate_reason(0, 0),
            Some("missing_children_for_nontrivial_window".to_string())
        );
        assert_eq!(root_degenerate_reason(1, 0), None);
        assert_eq!(
            root_degenerate_reason(2, 3),
            Some("incomplete_accessibility_tree:3_unreadable_subtrees".to_string())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn every_raw_read_error_preserves_its_typed_remedy() {
        let cases = [
            (
                cerebellum_macos::AxReadError::PermissionNotGranted,
                AccessibilityReadFailure::PermissionRequired,
            ),
            (
                cerebellum_macos::AxReadError::NoSuchProcess { pid: 41 },
                AccessibilityReadFailure::TargetGone,
            ),
            (
                cerebellum_macos::AxReadError::ProcessNotAccessible {
                    pid: 41,
                    ax_error: -25204,
                },
                AccessibilityReadFailure::TargetNotInspectable,
            ),
            (
                cerebellum_macos::AxReadError::DeadlineExceeded {
                    timeout: Duration::from_millis(500),
                },
                AccessibilityReadFailure::RetryableDeadlineExceeded,
            ),
            (
                cerebellum_macos::AxReadError::DepthLimitExceeded {
                    max_depth: 4,
                    attempted_depth: 5,
                },
                AccessibilityReadFailure::TreeExceedsBound,
            ),
            (
                cerebellum_macos::AxReadError::ElementLimitExceeded {
                    max_elements: 4,
                    attempted_elements: 5,
                },
                AccessibilityReadFailure::TreeExceedsBound,
            ),
            (
                cerebellum_macos::AxReadError::UnexpectedValueType {
                    attribute: "AXChildren",
                },
                AccessibilityReadFailure::IncompatiblePlatformValue,
            ),
            (
                cerebellum_macos::AxReadError::SystemCallFailed {
                    operation: "AXUIElementCopyAttributeValue",
                    ax_error: -25205,
                },
                AccessibilityReadFailure::PlatformReadFailed,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(
                map_ax_read_error(error),
                DriverError::AccessibilityUnreadable(expected)
            );
        }
    }
}

#[cfg(test)]
mod cached_element_tests {
    use super::*;

    fn cached_tree() -> CachedAccessibilityTree {
        CachedAccessibilityTree {
            target: ProcessGrant {
                pid: 41,
                bundle_identity: "com.example.reader".to_string(),
                process_generation_evidence: "generation-a".to_string(),
            },
            tree: CachedAccessibilityElement {
                identifier: Some("root-actual-id".to_string()),
                actions: Vec::new(),
                children: vec![CachedAccessibilityElement {
                    identifier: Some("child-actual-id".to_string()),
                    actions: vec!["AXPress".to_string()],
                    children: Vec::new(),
                }],
            },
            unreadable_subtrees: 0,
        }
    }

    #[test]
    fn missing_element_is_distinct_from_an_unreadable_tree() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_identifier: "missing".to_string(),
        };

        assert_eq!(
            resolve_cached_element(&cached_tree(), &request),
            Err(DriverError::ElementNotFound)
        );
    }

    #[test]
    fn an_incomplete_cached_tree_cannot_establish_element_uniqueness() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_identifier: "child-actual-id".to_string(),
        };
        let mut tree = cached_tree();
        tree.unreadable_subtrees = 1;

        assert_eq!(
            resolve_cached_element(&tree, &request),
            Err(DriverError::InvalidRequest(INCOMPLETE_TREE_UNIQUENESS))
        );
    }

    #[test]
    fn cached_element_preserves_advertised_action_names() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_identifier: "child-actual-id".to_string(),
        };

        let tree = cached_tree();
        let element = resolve_cached_element(&tree, &request)
            .expect("the constructed cache contains the named child");
        assert_eq!(element.actions, vec!["AXPress"]);
    }
}
