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
    role: Option<String>,
    title: Option<String>,
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
const AMBIGUOUS_ELEMENT_NAME: &str =
    "more than one element matches the supplied accessibility name";
const UNUSABLE_ELEMENT_NAME: &str = "unusable accessibility element name";

#[derive(Debug, Clone)]
pub struct MacOs26PlatformDriver {
    startup: StartupCapabilityProbe,
    accessibility_trees: BTreeMap<String, CachedAccessibilityTree>,
    expected_post_condition_available: bool,
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
fn dispatch_result_for_accepted_action(
    outcome: cerebellum_macos::AxActionRequestOutcome,
) -> DispatchResult {
    match outcome {
        cerebellum_macos::AxActionRequestOutcome::HandlerReturned { .. } => DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
        },
    }
}

#[cfg(target_os = "macos")]
impl From<cerebellum_macos::AxElementName> for AccessibilityElementName {
    fn from(name: cerebellum_macos::AxElementName) -> Self {
        match name {
            cerebellum_macos::AxElementName::Identifier(identifier) => Self::Identifier(identifier),
            cerebellum_macos::AxElementName::RoleAndTitle { role, title } => {
                Self::RoleAndTitle { role, title }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn ax_element_name(
    name: &AccessibilityElementName,
) -> Result<cerebellum_macos::AxElementName, DriverError> {
    match name {
        AccessibilityElementName::Identifier(identifier) => {
            cerebellum_macos::AxElementName::identifier(identifier)
        }
        AccessibilityElementName::RoleAndTitle { role, title } => {
            cerebellum_macos::AxElementName::role_and_title(role, title)
        }
    }
    .map_err(|_| DriverError::InvalidRequest(UNUSABLE_ELEMENT_NAME))
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

/// Map an action failure onto the driver's typed remedy vocabulary.
///
/// Every `AxActionError` is handled explicitly rather than through a catch-all,
/// so a variant added later stops the build here instead of silently inheriting
/// whichever case happened to be last.
#[cfg(target_os = "macos")]
fn map_ax_action_error(
    error: cerebellum_macos::AxActionError,
    requested_action: &str,
    deadline_ms: u64,
) -> DriverError {
    use cerebellum_macos::AxActionError;

    let semantic = match error {
        AxActionError::PermissionNotGranted => {
            SemanticDriverError::AccessibilityPermissionUnavailable
        }
        AxActionError::NoSuchProcess { .. } => SemanticDriverError::TargetNoLongerCurrent {
            disposition: TargetDisposition::Gone,
        },
        // No handler was reached, and no caller-controlled variation can make
        // an application that exposes no accessibility surface inspectable.
        AxActionError::ProcessNotAccessible { .. } => SemanticDriverError::PathUnavailable,
        AxActionError::ElementNotFound { element_name } => SemanticDriverError::ElementNotFound {
            key_form: AccessibilityElementName::from(element_name).key_form(),
        },
        AxActionError::ElementIdentifierAmbiguous {
            element_name,
            match_count,
        } => SemanticDriverError::ElementNameAmbiguous {
            key_form: AccessibilityElementName::from(element_name).key_form(),
            match_count: u64::try_from(match_count).unwrap_or(u64::MAX),
        },
        AxActionError::ActionNotAdvertised { advertised, .. } => {
            SemanticDriverError::ActionNotAdvertised {
                action: requested_action.to_owned(),
                advertised,
            }
        }
        AxActionError::ApplicationRefusedAction { ax_error, .. } => {
            SemanticDriverError::ApplicationRefused { ax_error }
        }
        AxActionError::DeadlineExceeded { timeout } => SemanticDriverError::Transient {
            deadline_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        },
        AxActionError::SystemCallFailed { .. } => SemanticDriverError::Transient { deadline_ms },
        // Incomplete uniqueness, traversal bounds, and unexpected framework
        // values are module-internal limits rather than caller remedies.
        AxActionError::ElementUniquenessUnestablished { .. }
        | AxActionError::DepthLimitExceeded { .. }
        | AxActionError::ElementLimitExceeded { .. }
        | AxActionError::UnexpectedValueType { .. } => SemanticDriverError::PathUnavailable,
    };
    DriverError::Semantic(semantic)
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
        role: element.role,
        title: element.title,
        actions: element.actions,
        children: element.children.into_iter().map(cache_ax_element).collect(),
    }
}

fn cached_element_matches(
    element: &CachedAccessibilityElement,
    name: &AccessibilityElementName,
) -> bool {
    match name {
        AccessibilityElementName::Identifier(identifier) => {
            element.identifier.as_deref() == Some(identifier.as_str())
        }
        AccessibilityElementName::RoleAndTitle { role, title } => {
            element.role.as_deref() == Some(role.as_str())
                && element.title.as_deref().unwrap_or_default() == title
        }
    }
}

fn find_cached_element<'a>(
    element: &'a CachedAccessibilityElement,
    name: &AccessibilityElementName,
    found: &mut Option<&'a CachedAccessibilityElement>,
    match_count: &mut usize,
) {
    if cached_element_matches(element, name) {
        *match_count += 1;
        if found.is_none() {
            *found = Some(element);
        }
    }
    for child in &element.children {
        find_cached_element(child, name, found, match_count);
    }
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
    if !request.element_name.is_usable() {
        return Err(DriverError::InvalidRequest(UNUSABLE_ELEMENT_NAME));
    }

    let mut found = None;
    let mut match_count = 0;
    find_cached_element(
        &tree.tree,
        &request.element_name,
        &mut found,
        &mut match_count,
    );
    match match_count {
        0 => Err(DriverError::ElementNotFound),
        1 => Ok(found.expect("one counted match stores one element")),
        _ => Err(DriverError::InvalidRequest(AMBIGUOUS_ELEMENT_NAME)),
    }
}

fn alternate_element_name(
    element: &CachedAccessibilityElement,
    matched_by: &AccessibilityElementName,
) -> Option<AccessibilityElementName> {
    match matched_by {
        AccessibilityElementName::Identifier(_) => Some(AccessibilityElementName::RoleAndTitle {
            role: element.role.clone()?,
            title: element.title.clone().unwrap_or_default(),
        }),
        AccessibilityElementName::RoleAndTitle { .. } => element
            .identifier
            .clone()
            .map(AccessibilityElementName::Identifier),
    }
}

fn resolution_from_cached_tree(
    tree: &CachedAccessibilityTree,
    request: &ElementResolutionRequest,
) -> Result<ElementResolutionResult, DriverError> {
    let element = resolve_cached_element(tree, request)?;
    Ok(ElementResolutionResult {
        element_name: request.element_name.clone(),
        alternate_name: alternate_element_name(element, &request.element_name),
        owning_process: tree.target.clone(),
        semantic_actions: element.actions.clone(),
    })
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
            expected_post_condition_available: true,
        }
    }

    /// Mark a request surface that cannot express an expected post-condition.
    ///
    /// The semantic action still runs and is journaled, but effect observation
    /// must not invent a predicate and then report that invented claim as the
    /// caller's. The existing vocabulary represents this as an indeterminate
    /// effect with an undeclarable post-condition.
    pub fn without_expected_post_condition(mut self) -> Self {
        self.expected_post_condition_available = false;
        self
    }

    pub fn startup_probe(&self) -> &StartupCapabilityProbe {
        &self.startup
    }

    /// Describe all eight actions, advertising only the ones that can be served.
    ///
    /// A declaration says what an action WOULD need; advertising says it can be
    /// used now. Semantic click has a reviewed serving path; the other actuating
    /// actions remain described but unavailable.
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
        } else if id == "computer.click" {
            suppression_reason = if !context.inputs.vocabulary_ready() {
                Some("computer action vocabulary input unresolved".to_string())
            } else if !context.inputs.semantic_actuation_ready() {
                if context.inputs.semantic_actuation_review_revision.is_none() {
                    Some("semantic actuation review revision is not bound".to_string())
                } else {
                    Some("release signing topology revision is not bound".to_string())
                }
            } else {
                None
            };
            advertised = suppression_reason.is_none();
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
        // The synthetic-input gate remains evaluated but does not admit any row.
        // Its review is separate from semantic actuation, and the five remaining
        // actuating rows keep the unconditional suppression set above.
        let _synthetic_inputs_resolved = context.inputs.input_dispatch_ready();
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
            // Resolution clones the owning grant only after the kernel
            // generation check above; otherwise a reused PID could be reported
            // as the old grant.
            resolution_from_cached_tree(cached, &request)
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

            let element_name = ax_element_name(&request.element.element_name)?;

            let options = cerebellum_macos::AxActionOptions::default();
            let deadline_ms = u64::try_from(options.timeout.as_millis()).unwrap_or(u64::MAX);
            let outcome = cerebellum_macos::request_accessibility_action(
                request.element.owning_process.pid,
                &element_name,
                action,
                options,
            )
            .map_err(|error| map_ax_action_error(error, &request.action, deadline_ms))?;

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

            if !self.expected_post_condition_available {
                return Ok(EffectObservationResult {
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("post_condition_undeclarable".to_string()),
                });
            }

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

    /// Semantic click is offered only under its own review binding.
    ///
    /// The synthetic-input review is deliberately present in the unbound case:
    /// substituting that unrelated gate for the semantic review must still leave
    /// the capability suppressed.
    #[test]
    fn computer_click_advertisement_requires_the_semantic_actuation_review() {
        let driver = MacOs26PlatformDriver::default();
        let mut bound = ImmutableReleaseInputs {
            attendance_contract_owner: Some("fixture-owner".to_string()),
            attendance_contract_revision: Some("fixture-attendance-v1".to_string()),
            input_review_revision: Some("fixture-input-review-v1".to_string()),
            capture_review_revision: Some("fixture-capture-review-v1".to_string()),
            semantic_actuation_review_revision: Some("fixture-semantic-review-v1".to_string()),
            release_signing_topology_revision: Some("fixture-topology-v1".to_string()),
            vocabulary_digests: VocabularyDigestInputs {
                manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
            },
        };
        assert!(
            bound.semantic_actuation_ready(),
            "the accepting fixture must satisfy the semantic actuation gate"
        );
        let context = |inputs| CapabilityAdvertisementContext {
            inputs,
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        let advertised = driver.declaration("computer.click", &context(bound.clone()));
        assert!(
            advertised.advertised,
            "reviewed semantic click was suppressed: {:?}",
            advertised.suppression_reason
        );

        bound.semantic_actuation_review_revision = None;
        assert!(
            bound.input_review_revision.is_some(),
            "the synthetic-input review must remain present for this tripwire"
        );
        let suppressed = driver.declaration("computer.click", &context(bound));
        assert!(
            !suppressed.advertised,
            "unreviewed semantic click was advertised"
        );
        assert_eq!(
            suppressed.suppression_reason.as_deref(),
            Some("semantic actuation review revision is not bound")
        );
    }

    /// Binding every release input does not activate another actuating row.
    #[test]
    fn other_actuating_rows_remain_suppressed_for_fully_bound_release_inputs() {
        let driver = MacOs26PlatformDriver::default();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs {
                attendance_contract_owner: Some("fixture-owner".to_string()),
                attendance_contract_revision: Some("fixture-attendance-v1".to_string()),
                input_review_revision: Some("fixture-input-review-v1".to_string()),
                capture_review_revision: Some("fixture-capture-review-v1".to_string()),
                semantic_actuation_review_revision: Some("fixture-semantic-review-v1".to_string()),
                release_signing_topology_revision: Some("fixture-topology-v1".to_string()),
                vocabulary_digests: VocabularyDigestInputs {
                    manifest_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                    source_lock_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                    computed_artifact_digest: Some(COMPUTER_ACTION_VOCABULARY_SHA256.to_string()),
                },
            },
            permissions: PermissionLivenessReport::default(),
            startup: driver.startup_probe().clone(),
        };

        for id in [
            "computer.type",
            "computer.keys",
            "computer.scroll",
            "computer.move",
            "computer.drag",
        ] {
            let declaration = driver.declaration(id, &context);
            assert!(!declaration.advertised, "{id} was advertised");
            let reason = declaration
                .suppression_reason
                .expect("a suppressed capability states why");
            assert!(
                reason.contains("no wire serving handler"),
                "{id} is suppressed for an unexpected reason: {reason}"
            );
        }
    }

    /// A wire surface with no expected post-condition makes no effect claim.
    #[test]
    fn absent_wire_post_condition_skips_observation_and_reports_the_frozen_coarser_status() {
        let mut driver = MacOs26PlatformDriver::default().without_expected_post_condition();
        let result = driver
            .observe_effect(EffectObservationRequest {
                target: ProcessGrant {
                    // No process can be inspected at pid zero. If the dedicated
                    // branch is removed, the attempted read reports the distinct
                    // observation-primitive-unavailable reason.
                    pid: 0,
                    bundle_identity: "com.example.target".to_string(),
                    process_generation_evidence: "generation-1".to_string(),
                },
                predicate: serde_json::to_string(&crate::dispatch::ExpectedPostCondition::new(
                    "fixture-effect-v1",
                    crate::dispatch::post_condition::PostCondition::ElementPresent {
                        element_identifier: "element-1".to_string(),
                    },
                ))
                .expect("the fixture post-condition serializes"),
                deadline_ms: 1,
            })
            .expect("absence of a claim is a result, not a platform failure");

        assert_eq!(result.status, EffectStatus::EffectIndeterminate);
        assert_eq!(
            result.failure_reason.as_deref(),
            Some("post_condition_undeclarable")
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
            cerebellum_macos::AxActionRequestOutcome::HandlerReturned {
                matched_by: cerebellum_macos::AxElementName::Identifier("button".to_owned()),
                alternate_name: Some(cerebellum_macos::AxElementName::RoleAndTitle {
                    role: "AXButton".to_owned(),
                    title: "Save".to_owned(),
                }),
            },
        );
        assert!(result.accepted_by_platform);
        assert_eq!(result.effect_status, EffectStatus::EffectIndeterminate);
    }

    /// Every framework action failure maps to its caller remedy.
    ///
    /// Internal traversal and value faults deliberately share `PathUnavailable`;
    /// the remaining cases stay distinct because their callers must take
    /// different actions.
    #[test]
    fn every_action_failure_maps_to_a_distinct_remedy() {
        use cerebellum_macos::{AxAction, AxActionError, AxElementName};

        let advertised = vec!["AXPress".to_string(), "AXConfirm".to_string()];
        let cases = [
            (
                AxActionError::PermissionNotGranted,
                DriverError::Semantic(SemanticDriverError::AccessibilityPermissionUnavailable),
            ),
            (
                AxActionError::NoSuchProcess { pid: 7 },
                DriverError::Semantic(SemanticDriverError::TargetNoLongerCurrent {
                    disposition: TargetDisposition::Gone,
                }),
            ),
            (
                AxActionError::ProcessNotAccessible {
                    pid: 7,
                    ax_error: -25204,
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::ElementNotFound {
                    element_name: AxElementName::Identifier("absent".to_string()),
                },
                DriverError::Semantic(SemanticDriverError::ElementNotFound {
                    key_form: AccessibilityKeyForm::Identifier,
                }),
            ),
            (
                AxActionError::ElementIdentifierAmbiguous {
                    element_name: AxElementName::RoleAndTitle {
                        role: "AXButton".to_string(),
                        title: "Save".to_string(),
                    },
                    match_count: 2,
                },
                DriverError::Semantic(SemanticDriverError::ElementNameAmbiguous {
                    key_form: AccessibilityKeyForm::RoleAndTitle,
                    match_count: 2,
                }),
            ),
            (
                AxActionError::ElementUniquenessUnestablished {
                    element_name: AxElementName::Identifier("partial".to_string()),
                    unreadable_subtrees: 1,
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::ActionNotAdvertised {
                    element_name: AxElementName::Identifier("save".to_string()),
                    action: AxAction::Press,
                    advertised: advertised.clone(),
                },
                DriverError::Semantic(SemanticDriverError::ActionNotAdvertised {
                    action: "press".to_string(),
                    advertised: advertised.clone(),
                }),
            ),
            (
                AxActionError::ApplicationRefusedAction {
                    element_name: AxElementName::Identifier("save".to_string()),
                    action: AxAction::Press,
                    ax_error: -25205,
                },
                DriverError::Semantic(SemanticDriverError::ApplicationRefused { ax_error: -25205 }),
            ),
            (
                AxActionError::DeadlineExceeded {
                    timeout: Duration::from_millis(1),
                },
                DriverError::Semantic(SemanticDriverError::Transient { deadline_ms: 1 }),
            ),
            (
                AxActionError::DepthLimitExceeded {
                    max_depth: 32,
                    attempted_depth: 33,
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::ElementLimitExceeded {
                    max_elements: 10_000,
                    attempted_elements: 10_001,
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::UnexpectedValueType {
                    attribute: "AXRole",
                },
                DriverError::Semantic(SemanticDriverError::PathUnavailable),
            ),
            (
                AxActionError::SystemCallFailed {
                    operation: "AXUIElementPerformAction",
                    ax_error: -25206,
                },
                DriverError::Semantic(SemanticDriverError::Transient { deadline_ms: 3_000 }),
            ),
        ];

        for (raw, expected) in cases {
            assert_eq!(
                map_ax_action_error(raw.clone(), "press", 3_000),
                expected,
                "{raw:?}"
            );
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

        let absent = map_ax_action_error(
            AxActionError::ElementNotFound {
                element_name: cerebellum_macos::AxElementName::Identifier("x".to_string()),
            },
            "press",
            3_000,
        );
        let ambiguous = map_ax_action_error(
            AxActionError::ElementIdentifierAmbiguous {
                element_name: cerebellum_macos::AxElementName::RoleAndTitle {
                    role: "AXButton".to_string(),
                    title: "Save".to_string(),
                },
                match_count: 2,
            },
            "press",
            3_000,
        );
        let incomplete = map_ax_action_error(
            AxActionError::ElementUniquenessUnestablished {
                element_name: cerebellum_macos::AxElementName::Identifier("x".to_string()),
                unreadable_subtrees: 1,
            },
            "press",
            3_000,
        );

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
                role: Some("AXApplication".to_string()),
                title: Some("Reader".to_string()),
                actions: Vec::new(),
                children: vec![
                    CachedAccessibilityElement {
                        identifier: Some("identifier-only".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("Shared".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: None,
                        role: Some("AXButton".to_string()),
                        title: Some("Save".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: Some("shared-title-peer".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("Shared".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: Some("duplicate-identifier".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("First Duplicate".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                    CachedAccessibilityElement {
                        identifier: Some("duplicate-identifier".to_string()),
                        role: Some("AXButton".to_string()),
                        title: Some("Second Duplicate".to_string()),
                        actions: vec!["AXPress".to_string()],
                        children: Vec::new(),
                    },
                ],
            },
            unreadable_subtrees: 0,
        }
    }

    #[test]
    fn missing_element_is_distinct_from_an_unreadable_tree() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::Identifier("missing".to_string()),
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
            element_name: AccessibilityElementName::Identifier("identifier-only".to_string()),
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
            element_name: AccessibilityElementName::Identifier("identifier-only".to_string()),
        };

        let tree = cached_tree();
        let element = resolve_cached_element(&tree, &request)
            .expect("the constructed cache contains the named child");
        assert_eq!(element.actions, vec!["AXPress"]);
    }

    #[test]
    fn resolution_reports_the_exact_key_that_established_uniqueness() {
        let cases = [
            (
                AccessibilityElementName::Identifier("identifier-only".to_string()),
                Some(AccessibilityElementName::RoleAndTitle {
                    role: "AXButton".to_string(),
                    title: "Shared".to_string(),
                }),
            ),
            (
                AccessibilityElementName::RoleAndTitle {
                    role: "AXButton".to_string(),
                    title: "Save".to_string(),
                },
                None,
            ),
        ];
        let tree = cached_tree();

        for (name, alternate_name) in cases {
            let request = ElementResolutionRequest {
                root_identifier: "accessibility-root:41:generation-a".to_string(),
                element_name: name.clone(),
            };
            let resolution = resolution_from_cached_tree(&tree, &request)
                .expect("the fixture makes each supplied key unique");
            assert_eq!(resolution.element_name, name);
            assert_eq!(resolution.alternate_name, alternate_name);
            assert_eq!(resolution.semantic_actions, vec!["AXPress"]);
        }
    }

    #[test]
    fn resolution_never_falls_back_between_key_forms() {
        let requests = [
            ElementResolutionRequest {
                root_identifier: "accessibility-root:41:generation-a".to_string(),
                element_name: AccessibilityElementName::Identifier("Save".to_string()),
            },
            ElementResolutionRequest {
                root_identifier: "accessibility-root:41:generation-a".to_string(),
                element_name: AccessibilityElementName::RoleAndTitle {
                    role: "AXButton".to_string(),
                    title: "identifier-only".to_string(),
                },
            },
        ];
        let tree = cached_tree();

        for request in requests {
            assert_eq!(
                resolution_from_cached_tree(&tree, &request),
                Err(DriverError::ElementNotFound)
            );
        }
    }

    #[test]
    fn a_shared_role_and_title_is_refused_instead_of_resolving_the_first_match() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::RoleAndTitle {
                role: "AXButton".to_string(),
                title: "Shared".to_string(),
            },
        };

        assert_eq!(
            resolution_from_cached_tree(&cached_tree(), &request),
            Err(DriverError::InvalidRequest(AMBIGUOUS_ELEMENT_NAME))
        );
    }

    #[test]
    fn a_shared_identifier_is_refused_instead_of_resolving_the_first_match() {
        let request = ElementResolutionRequest {
            root_identifier: "accessibility-root:41:generation-a".to_string(),
            element_name: AccessibilityElementName::Identifier("duplicate-identifier".to_string()),
        };

        assert_eq!(
            resolution_from_cached_tree(&cached_tree(), &request),
            Err(DriverError::InvalidRequest(AMBIGUOUS_ELEMENT_NAME))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dispatch_preserves_a_role_and_title_resolution_key() {
        let name = AccessibilityElementName::RoleAndTitle {
            role: "AXButton".to_string(),
            title: "Save".to_string(),
        };

        let ax_name = ax_element_name(&name).expect("the fixture name is usable");
        assert_eq!(
            ax_name,
            cerebellum_macos::AxElementName::RoleAndTitle {
                role: "AXButton".to_string(),
                title: "Save".to_string(),
            }
        );
        assert_eq!(AccessibilityElementName::from(ax_name), name);
    }
}
