//! Accessibility grounding and the deliberately narrow pixel fallback boundary.
//!
//! Grounding is a read-only phase.  It never posts an event.  The dispatch plane
//! consumes a [`GroundingDecision`] only after calling
//! [`GroundingResolver::revalidate_before_dispatch`].  Keeping the two phases
//! separate makes it impossible for an old screenshot, mark, window identifier,
//! or accessibility reference to silently become a dispatch authorization.

use crate::platform::ProcessGrant;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// The only AX degeneracy reasons accepted by the computer vocabulary.
pub const AX_DEGENERACY_REASON_NAMES: [&str; 5] = [
    "missing_children_for_nontrivial_window",
    "opaque_container_collapse",
    "no_actionable_actions",
    "degenerate_geometry",
    "implausibly_shallow_tree",
];

/// Closed AX degeneracy vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegeneracyReason {
    MissingChildrenForNontrivialWindow,
    OpaqueContainerCollapse,
    NoActionableActions,
    DegenerateGeometry,
    ImplausiblyShallowTree,
}

impl DegeneracyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingChildrenForNontrivialWindow => "missing_children_for_nontrivial_window",
            Self::OpaqueContainerCollapse => "opaque_container_collapse",
            Self::NoActionableActions => "no_actionable_actions",
            Self::DegenerateGeometry => "degenerate_geometry",
            Self::ImplausiblyShallowTree => "implausibly_shallow_tree",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "missing_children_for_nontrivial_window" => {
                Some(Self::MissingChildrenForNontrivialWindow)
            }
            "opaque_container_collapse" => Some(Self::OpaqueContainerCollapse),
            "no_actionable_actions" => Some(Self::NoActionableActions),
            "degenerate_geometry" => Some(Self::DegenerateGeometry),
            "implausibly_shallow_tree" => Some(Self::ImplausiblyShallowTree),
            _ => None,
        }
    }

    pub const fn all() -> [Self; 5] {
        [
            Self::MissingChildrenForNontrivialWindow,
            Self::OpaqueContainerCollapse,
            Self::NoActionableActions,
            Self::DegenerateGeometry,
            Self::ImplausiblyShallowTree,
        ]
    }
}

/// Grounding paths that a vocabulary row may explicitly authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingPath {
    AccessibilityElement,
    Pixel,
    SetOfMarks,
}

/// Containment is intentionally weaker for coordinate-addressed targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentRung {
    SemanticElement,
    PidStructural,
    GlobalNone,
}

/// A finite point in the screen coordinate space used by synthetic input.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Coordinate {
    pub x: f64,
    pub y: f64,
}

impl Coordinate {
    pub const fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    pub fn is_finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite()
    }
}

/// Axis-aligned element geometry reported by AX.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ElementRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl ElementRect {
    pub const fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn center(self) -> Coordinate {
        Coordinate::new(self.x + (self.width / 2.0), self.y + (self.height / 2.0))
    }

    pub fn is_valid(self) -> bool {
        self.x.is_finite()
            && self.y.is_finite()
            && self.width.is_finite()
            && self.height.is_finite()
            && self.width > 0.0
            && self.height > 0.0
    }
}

/// The manifest-declared Chromium/Electron accessibility handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityHandshakeDeclaration {
    pub client_identity: String,
    pub attribute: String,
    pub value: String,
    pub settle_interval_ms: u64,
}

impl AccessibilityHandshakeDeclaration {
    /// The declaration used by the v1 Chromium/Electron AX client.
    pub fn chromium_electron() -> Self {
        Self {
            client_identity: "cerebellum-computer".to_string(),
            attribute: "AXEnhancedUserInterface".to_string(),
            value: "true".to_string(),
            settle_interval_ms: 500,
        }
    }

    fn is_complete(&self) -> bool {
        !self.client_identity.is_empty()
            && !self.attribute.is_empty()
            && !self.value.is_empty()
            && self.settle_interval_ms > 0
    }
}

/// Return status from the handshake write.  The return status is recorded but is
/// deliberately not used to decide whether the post-handshake tree is usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeReturnCode {
    Accepted,
    Rejected,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeObservation {
    pub attempted: bool,
    pub return_code: HandshakeReturnCode,
    pub settle_interval_ms: u64,
    pub tree_population_observed: bool,
}

/// Accessibility-tree observations used for closed degeneracy classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityTreeSnapshot {
    pub root_identifier: Option<String>,
    pub target_process_generation: String,
    pub captured_at_ms: u64,
    pub visibly_nontrivial_window: bool,
    pub child_count: u32,
    pub opaque_container_collapse: bool,
    pub has_actionable_actions: bool,
    pub geometry_degenerate: bool,
    pub tree_depth: u16,
    pub minimum_plausible_depth: u16,
}

impl Default for AccessibilityTreeSnapshot {
    fn default() -> Self {
        Self {
            root_identifier: Some("root".to_string()),
            target_process_generation: "generation".to_string(),
            captured_at_ms: 0,
            visibly_nontrivial_window: false,
            child_count: 1,
            opaque_container_collapse: false,
            has_actionable_actions: true,
            geometry_degenerate: false,
            tree_depth: 3,
            minimum_plausible_depth: 2,
        }
    }
}

impl AccessibilityTreeSnapshot {
    pub fn absent(target_process_generation: impl Into<String>, captured_at_ms: u64) -> Self {
        Self {
            root_identifier: None,
            target_process_generation: target_process_generation.into(),
            captured_at_ms,
            ..Self::default()
        }
    }

    pub fn degeneracy_reasons(&self) -> Vec<DegeneracyReason> {
        let mut reasons = Vec::new();
        if self.visibly_nontrivial_window && self.child_count == 0 {
            reasons.push(DegeneracyReason::MissingChildrenForNontrivialWindow);
        }
        if self.opaque_container_collapse {
            reasons.push(DegeneracyReason::OpaqueContainerCollapse);
        }
        if !self.has_actionable_actions {
            reasons.push(DegeneracyReason::NoActionableActions);
        }
        if self.geometry_degenerate {
            reasons.push(DegeneracyReason::DegenerateGeometry);
        }
        if self.tree_depth > 0
            && self.minimum_plausible_depth > 0
            && self.tree_depth < self.minimum_plausible_depth
        {
            reasons.push(DegeneracyReason::ImplausiblyShallowTree);
        }
        reasons
    }

    pub fn is_absent(&self) -> bool {
        self.root_identifier.is_none()
    }
}

/// An AX element resolved from the application root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessibilityElement {
    pub root_identifier: String,
    pub element_identifier: String,
    pub target_process_generation: String,
    pub resolved_at_ms: u64,
    pub geometry: Option<ElementRect>,
    pub semantic_actions: Vec<String>,
    pub window_identifier: Option<String>,
}

impl AccessibilityElement {
    pub fn has_action(&self, action: &str) -> bool {
        self.semantic_actions
            .iter()
            .any(|candidate| candidate == action)
    }

    pub fn center(&self) -> Option<Coordinate> {
        self.geometry
            .filter(|geometry| geometry.is_valid())
            .map(ElementRect::center)
    }
}

/// Hit-test result for the reported center of an element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CenterHitTest {
    pub resolved_identifier: Option<String>,
    pub is_same_element_or_descendant: bool,
}

/// Pixel evidence is tied to every state that can make a coordinate stale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PixelEvidence {
    pub capture_generation: String,
    pub target_process_generation: String,
    pub window_identifier: String,
    pub coordinate: Coordinate,
    /// The size of the image the coordinate was read from.
    ///
    /// A pixel coordinate means nothing without the image it indexes, and this
    /// is not implied by `capture_generation`: a model shown a downscaled copy
    /// of a capture reports coordinates in the copy's space while the capture
    /// itself is unchanged, so the generation matches and the point is wrong.
    /// Nothing about the coordinate reveals which copy produced it, and a
    /// coordinate from a smaller copy still falls inside the capture, so no
    /// bounds check refuses it.
    ///
    /// Recording the frame is what makes the comparison expressible: a consumer
    /// holding the capture can require these to match its own dimensions, and
    /// refuse rather than actuate at a point the caller never chose.
    pub read_from_width_px: u32,
    pub read_from_height_px: u32,
    pub captured_at_ms: u64,
}

/// Set-of-Marks evidence carries the selected mark in addition to pixel state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetOfMarksEvidence {
    pub capture_generation: String,
    pub target_process_generation: String,
    pub window_identifier: String,
    pub mark_identifier: String,
    pub coordinate: Coordinate,
    /// The size of the image the coordinate was read from, for the same reason
    /// [`PixelEvidence`] carries it: a mark selected on a downscaled copy yields
    /// a coordinate in the copy's space, and the capture is unchanged.
    pub read_from_width_px: u32,
    pub read_from_height_px: u32,
    pub captured_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FallbackGrounding {
    Pixel(PixelEvidence),
    SetOfMarks(SetOfMarksEvidence),
}

impl FallbackGrounding {
    pub fn path(&self) -> GroundingPath {
        match self {
            Self::Pixel(_) => GroundingPath::Pixel,
            Self::SetOfMarks(_) => GroundingPath::SetOfMarks,
        }
    }

    pub fn captured_at_ms(&self) -> u64 {
        match self {
            Self::Pixel(evidence) => evidence.captured_at_ms,
            Self::SetOfMarks(evidence) => evidence.captured_at_ms,
        }
    }

    pub fn target_process_generation(&self) -> &str {
        match self {
            Self::Pixel(evidence) => &evidence.target_process_generation,
            Self::SetOfMarks(evidence) => &evidence.target_process_generation,
        }
    }

    pub fn coordinate(&self) -> Coordinate {
        match self {
            Self::Pixel(evidence) => evidence.coordinate,
            Self::SetOfMarks(evidence) => evidence.coordinate,
        }
    }
}

/// A target request may begin as an AX element lookup or as a coordinate that
/// can only be used after the AX tree proves itself absent or degenerate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GroundingLocator {
    AccessibilityElement {
        root_identifier: String,
        element_identifier: String,
        semantic_action: String,
    },
    Coordinate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroundingRequest {
    pub target: ProcessGrant,
    pub locator: GroundingLocator,
    pub fallback: Option<FallbackGrounding>,
}

impl GroundingRequest {
    pub fn accessibility_element(
        target: ProcessGrant,
        root_identifier: impl Into<String>,
        element_identifier: impl Into<String>,
        semantic_action: impl Into<String>,
    ) -> Self {
        Self {
            target,
            locator: GroundingLocator::AccessibilityElement {
                root_identifier: root_identifier.into(),
                element_identifier: element_identifier.into(),
                semantic_action: semantic_action.into(),
            },
            fallback: None,
        }
    }

    pub fn coordinate(target: ProcessGrant, fallback: FallbackGrounding) -> Self {
        Self {
            target,
            locator: GroundingLocator::Coordinate,
            fallback: Some(fallback),
        }
    }

    pub fn with_fallback(mut self, fallback: FallbackGrounding) -> Self {
        self.fallback = Some(fallback);
        self
    }
}

/// Numeric evidence-age bounds.  The two values are separate because an AX
/// reference and a rendered pixel frame decay at different rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundingAgeBounds {
    pub element_ms: u64,
    pub non_element_ms: u64,
}

impl Default for GroundingAgeBounds {
    fn default() -> Self {
        Self {
            element_ms: 2_000,
            non_element_ms: 1_000,
        }
    }
}

/// The row-authorized grounding configuration consumed by the resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundingPolicy {
    pub eligible_paths: BTreeSet<GroundingPath>,
    pub pixel_fallback_eligible: bool,
    pub age_bounds: GroundingAgeBounds,
    pub maximum_accessibility_tree_settle_interval_ms: Option<u64>,
    pub handshake: AccessibilityHandshakeDeclaration,
}

impl Default for GroundingPolicy {
    fn default() -> Self {
        Self {
            eligible_paths: [
                GroundingPath::AccessibilityElement,
                GroundingPath::Pixel,
                GroundingPath::SetOfMarks,
            ]
            .into_iter()
            .collect(),
            pixel_fallback_eligible: true,
            age_bounds: GroundingAgeBounds::default(),
            maximum_accessibility_tree_settle_interval_ms: Some(500),
            handshake: AccessibilityHandshakeDeclaration::chromium_electron(),
        }
    }
}

/// What grounding a capability requires.
///
/// A capability may require an element, address no element, or prefer an
/// element while retaining a coordinate-addressed path. Those outcomes are
/// distinct: treating the last case as a pixel fallback would let a coordinate
/// action claim the containment of an element it never resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundingRequirement {
    /// The capability addresses an element, resolved under this policy.
    Grounded(GroundingPolicy),
    /// The capability may resolve an element, or address a coordinate when no
    /// element is available.
    ElementOrCoordinateAddressed(GroundingPolicy),
    /// The capability addresses no element, so there is nothing to ground.
    /// Keyboard shortcuts, pointer movement, and observing actions may use their
    /// own non-element addressing modes without an element-resolution policy.
    NotGrounded,
    /// Not a capability this module serves.
    UnknownCapability,
}

/// The path a caller actually used after considering element availability.
///
/// Keeping the coordinate case separate makes its weakest containment rung
/// explicit. An element path can be revalidated and recorded by what moved;
/// a coordinate path can only be recorded by where it acted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundingResolutionPath {
    Element(GroundingPolicy),
    CoordinateAddressed { containment_rung: ContainmentRung },
}

impl GroundingRequirement {
    /// Select the actual path for a capability that can resolve an element.
    ///
    /// `None` means this requirement does not authorize element resolution for
    /// the supplied availability state. Callers retain the returned value with
    /// their result so later auditing can distinguish an element target from a
    /// coordinate-addressed target.
    pub fn resolution_path(&self, element_available: bool) -> Option<GroundingResolutionPath> {
        match self {
            Self::Grounded(policy) if element_available => {
                Some(GroundingResolutionPath::Element(policy.clone()))
            }
            Self::ElementOrCoordinateAddressed(policy) if element_available => {
                Some(GroundingResolutionPath::Element(policy.clone()))
            }
            Self::ElementOrCoordinateAddressed(_) => {
                Some(GroundingResolutionPath::CoordinateAddressed {
                    containment_rung: ContainmentRung::GlobalNone,
                })
            }
            Self::Grounded(_) | Self::NotGrounded | Self::UnknownCapability => None,
        }
    }
}

impl GroundingPolicy {
    pub fn for_capability(capability_id: &str) -> GroundingRequirement {
        let mut policy = Self::default();
        match capability_id {
            "computer.click" | "computer.scroll" => GroundingRequirement::Grounded(policy),
            "computer.type" => {
                // Typing resolves through the accessibility tree only. A pixel
                // fallback would let text reach a field identified by position
                // rather than by identity, which is how a credential field gets
                // typed into without ever being classified as one.
                policy.eligible_paths = [GroundingPath::AccessibilityElement].into_iter().collect();
                policy.pixel_fallback_eligible = false;
                GroundingRequirement::Grounded(policy)
            }
            "computer.drag" => {
                // Element aiming lets a drag be revalidated before dispatch and
                // recorded by what it moved. Without an element it remains
                // coordinate-addressed, so it can only be recorded by where it
                // acted at the weakest containment rung. Drag is the only action
                // in this vocabulary that makes durable changes, so it must not
                // let a pixel match pretend to be an element target.
                policy.eligible_paths = [GroundingPath::AccessibilityElement].into_iter().collect();
                policy.pixel_fallback_eligible = false;
                GroundingRequirement::ElementOrCoordinateAddressed(policy)
            }
            "computer.keys" | "computer.move" | "computer.screenshot" | "computer.wait" => {
                GroundingRequirement::NotGrounded
            }
            _ => GroundingRequirement::UnknownCapability,
        }
    }

    /// Whether a capability may name its target with a screen coordinate rather
    /// than resolving an element. This is separate from pixel fallback: pixels
    /// are weaker evidence for an element, while a coordinate names no element
    /// and therefore remains on the weakest containment rung.
    pub fn coordinate_addressable_for_capability(capability_id: &str) -> Option<bool> {
        match capability_id {
            "computer.move" | "computer.drag" => Some(true),
            "computer.click"
            | "computer.type"
            | "computer.keys"
            | "computer.scroll"
            | "computer.screenshot"
            | "computer.wait" => Some(false),
            _ => None,
        }
    }

    pub fn fallback_allowed(&self, path: GroundingPath) -> bool {
        self.pixel_fallback_eligible
            && matches!(path, GroundingPath::Pixel | GroundingPath::SetOfMarks)
            && self.eligible_paths.contains(&path)
    }

    fn usable(&self) -> bool {
        self.age_bounds.element_ms > 0
            && self.age_bounds.non_element_ms > 0
            && self
                .maximum_accessibility_tree_settle_interval_ms
                .is_some_and(|bound| bound > 0)
            && self.handshake.is_complete()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibilityTreeReadRequest {
    pub target: ProcessGrant,
    pub settle_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroundingDriverError {
    AccessibilityUnavailable,
    AccessibilityTreeUnavailable,
    ElementInvalid,
    ElementNotFound,
    HitTestUnavailable,
    RevalidationUnavailable,
}

impl fmt::Display for GroundingDriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AccessibilityUnavailable => "accessibility unavailable",
            Self::AccessibilityTreeUnavailable => "accessibility tree unavailable",
            Self::ElementInvalid => "accessibility element invalid",
            Self::ElementNotFound => "accessibility element not found",
            Self::HitTestUnavailable => "center hit-test unavailable",
            Self::RevalidationUnavailable => "grounding revalidation unavailable",
        })
    }
}

impl std::error::Error for GroundingDriverError {}

/// Revalidation facts returned immediately before a dispatch decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementRevalidation {
    pub element_valid: bool,
    pub target_generation_valid: bool,
    pub geometry_valid: bool,
    pub coordinate_valid: bool,
}

impl ElementRevalidation {
    pub const fn valid() -> Self {
        Self {
            element_valid: true,
            target_generation_valid: true,
            geometry_valid: true,
            coordinate_valid: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PixelRevalidation {
    pub pixel_valid: bool,
    pub capture_valid: bool,
    pub mark_valid: bool,
    pub target_generation_valid: bool,
    pub coordinate_valid: bool,
    pub window_valid: bool,
}

impl PixelRevalidation {
    pub const fn valid() -> Self {
        Self {
            pixel_valid: true,
            capture_valid: true,
            mark_valid: true,
            target_generation_valid: true,
            coordinate_valid: true,
            window_valid: true,
        }
    }
}

/// The platform seam used by grounding.  All methods are observations or
/// validation; no method is a dispatch primitive.
pub trait GroundingDriver {
    fn attempt_accessibility_handshake(
        &mut self,
        target: &ProcessGrant,
        declaration: &AccessibilityHandshakeDeclaration,
    ) -> Result<HandshakeObservation, GroundingDriverError>;

    fn read_accessibility_tree(
        &mut self,
        request: AccessibilityTreeReadRequest,
    ) -> Result<AccessibilityTreeSnapshot, GroundingDriverError>;

    fn resolve_accessibility_element(
        &mut self,
        target: &ProcessGrant,
        root_identifier: &str,
        element_identifier: &str,
    ) -> Result<AccessibilityElement, GroundingDriverError>;

    fn hit_test_center(
        &mut self,
        target: &ProcessGrant,
        element: &AccessibilityElement,
        center: Coordinate,
    ) -> Result<CenterHitTest, GroundingDriverError>;

    fn revalidate_element(&mut self, element: &AccessibilityElement) -> ElementRevalidation;

    fn revalidate_pixel(&mut self, evidence: &PixelEvidence) -> PixelRevalidation;

    fn revalidate_set_of_marks(&mut self, evidence: &SetOfMarksEvidence) -> PixelRevalidation;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoordinateAddress {
    FromAccessibilityElement {
        coordinate: Coordinate,
        element: AccessibilityElement,
    },
    Pixel(PixelEvidence),
    SetOfMarks(SetOfMarksEvidence),
}

impl PixelEvidence {
    /// Whether this records the image its coordinate indexes.
    pub const fn frame_is_present(&self) -> bool {
        self.read_from_width_px > 0 && self.read_from_height_px > 0
    }
}

impl SetOfMarksEvidence {
    /// Whether this records the image its coordinate indexes.
    pub const fn frame_is_present(&self) -> bool {
        self.read_from_width_px > 0 && self.read_from_height_px > 0
    }
}

impl CoordinateAddress {
    pub fn coordinate(&self) -> Coordinate {
        match self {
            Self::FromAccessibilityElement { coordinate, .. } => *coordinate,
            Self::Pixel(evidence) => evidence.coordinate,
            Self::SetOfMarks(evidence) => evidence.coordinate,
        }
    }

    pub fn source_path(&self) -> GroundingPath {
        match self {
            Self::FromAccessibilityElement { .. } => GroundingPath::AccessibilityElement,
            Self::Pixel(_) => GroundingPath::Pixel,
            Self::SetOfMarks(_) => GroundingPath::SetOfMarks,
        }
    }

    pub fn coordinate_addressed(&self) -> bool {
        matches!(self, Self::Pixel(_) | Self::SetOfMarks(_))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GroundingTarget {
    SemanticElement(AccessibilityElement),
    Coordinate(CoordinateAddress),
}

impl GroundingTarget {
    pub fn coordinate_addressed(&self) -> bool {
        match self {
            Self::SemanticElement(_) => false,
            Self::Coordinate(address) => address.coordinate_addressed(),
        }
    }
}

/// A grounding decision is evidence, not a dispatch authorization.  The
/// coordinate variants always carry `global_none`, even if a later backend
/// chooses a per-pid API to deliver the event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroundingDecision {
    pub target: GroundingTarget,
    pub containment_rung: ContainmentRung,
    pub coordinate_addressed: bool,
    pub tree_degeneracy: Vec<DegeneracyReason>,
    pub handshake: HandshakeObservation,
    pub tree_captured_at_ms: u64,
}

impl GroundingDecision {
    fn semantic(
        element: AccessibilityElement,
        handshake: HandshakeObservation,
        tree: &AccessibilityTreeSnapshot,
    ) -> Self {
        Self {
            target: GroundingTarget::SemanticElement(element),
            containment_rung: ContainmentRung::SemanticElement,
            coordinate_addressed: false,
            tree_degeneracy: tree.degeneracy_reasons(),
            handshake,
            tree_captured_at_ms: tree.captured_at_ms,
        }
    }

    fn coordinate(
        address: CoordinateAddress,
        handshake: HandshakeObservation,
        tree: &AccessibilityTreeSnapshot,
        degeneracy: Vec<DegeneracyReason>,
    ) -> Self {
        let coordinate_addressed = address.coordinate_addressed();
        Self {
            target: GroundingTarget::Coordinate(address),
            containment_rung: ContainmentRung::GlobalNone,
            coordinate_addressed,
            tree_degeneracy: degeneracy,
            handshake,
            tree_captured_at_ms: tree.captured_at_ms,
        }
    }
}

/// The only grounding refusals.  These names are shared with the computer-plane
/// result vocabulary; driver failures are intentionally collapsed into one of
/// these rather than leaking platform-specific error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingFailure {
    StaleElement,
    StaleGrounding,
    GroundingUntrusted,
}

impl GroundingFailure {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::StaleElement => "stale_element",
            Self::StaleGrounding => "stale_grounding",
            Self::GroundingUntrusted => "grounding_untrusted",
        }
    }
}

impl fmt::Display for GroundingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}

impl std::error::Error for GroundingFailure {}

pub type GroundingResult = Result<GroundingDecision, GroundingFailure>;

/// Resolves AX targets, classifies the tree, selects the explicitly authorized
/// fallback, and performs the final evidence-age/revalidation gate.
#[derive(Debug, Clone)]
pub struct GroundingResolver {
    policy: GroundingPolicy,
}

impl GroundingResolver {
    pub fn new(policy: GroundingPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &GroundingPolicy {
        &self.policy
    }

    pub fn ground<D: GroundingDriver>(
        &self,
        driver: &mut D,
        request: &GroundingRequest,
        now_ms: u64,
    ) -> GroundingResult {
        if !self.policy.usable() || request.target.validate().is_err() {
            return Err(GroundingFailure::GroundingUntrusted);
        }

        // This call is deliberately before the tree read and therefore before
        // any decision that the tree is absent or degenerate.  A rejected AX
        // attribute write is still useful if the resulting tree populates.
        let mut handshake = driver
            .attempt_accessibility_handshake(&request.target, &self.policy.handshake)
            .map_err(|_| GroundingFailure::GroundingUntrusted)?;
        if !handshake.attempted {
            return Err(GroundingFailure::GroundingUntrusted);
        }
        let settle_bound = self
            .policy
            .maximum_accessibility_tree_settle_interval_ms
            .expect("usable policy has a settle bound");
        // The wait is declared by the capability, not by the handshake return
        // code.  This preserves the tree-population case where the attribute
        // write reports an error but still starts asynchronous AX work.
        let settle_interval_ms = self.policy.handshake.settle_interval_ms.min(settle_bound);
        handshake.settle_interval_ms = settle_interval_ms;
        let tree = driver
            .read_accessibility_tree(AccessibilityTreeReadRequest {
                target: request.target.clone(),
                settle_interval_ms,
            })
            .map_err(|_| GroundingFailure::GroundingUntrusted)?;
        if tree.target_process_generation != request.target.process_generation_evidence {
            return Err(GroundingFailure::StaleGrounding);
        }

        let mut degeneracy = tree.degeneracy_reasons();
        if tree.is_absent() {
            return self
                .fallback_if_authorized(driver, request, now_ms, tree, handshake, degeneracy);
        }

        let GroundingLocator::AccessibilityElement {
            root_identifier,
            element_identifier,
            semantic_action,
        } = &request.locator
        else {
            if degeneracy.is_empty() {
                return Err(GroundingFailure::GroundingUntrusted);
            }
            return self
                .fallback_if_authorized(driver, request, now_ms, tree, handshake, degeneracy);
        };

        // A degenerate tree is never made trustworthy by resolving a child from
        // it.  Fallback is selected only after the handshake and closed reason
        // classification have succeeded.
        if !degeneracy.is_empty() {
            return self
                .fallback_if_authorized(driver, request, now_ms, tree, handshake, degeneracy);
        }

        if root_identifier.is_empty() || element_identifier.is_empty() {
            return Err(GroundingFailure::StaleElement);
        }
        let element = driver
            .resolve_accessibility_element(&request.target, root_identifier, element_identifier)
            .map_err(|_| GroundingFailure::StaleElement)?;
        if element.element_identifier != *element_identifier
            || element.root_identifier != *root_identifier
        {
            return Err(GroundingFailure::StaleElement);
        }
        if element.target_process_generation != request.target.process_generation_evidence {
            return Err(GroundingFailure::StaleGrounding);
        }
        if !within_age_bound(
            now_ms,
            element.resolved_at_ms,
            self.policy.age_bounds.element_ms,
        ) {
            return Err(GroundingFailure::StaleElement);
        }

        let center = match element.geometry {
            Some(geometry) if geometry.is_valid() => Some(geometry.center()),
            _ => None,
        };
        let hit_test_valid = match center {
            Some(center) => driver
                .hit_test_center(&request.target, &element, center)
                .map(|hit| hit.is_same_element_or_descendant)
                .unwrap_or(false),
            None => false,
        };
        if !hit_test_valid {
            degeneracy.push(DegeneracyReason::DegenerateGeometry);
        }

        if element.has_action(semantic_action) {
            // Semantic accessibility actions do not require a coordinate.  A
            // missing or falsified rectangle therefore does not invalidate a
            // semantic target; it only prohibits the coordinate path below.
            return Ok(GroundingDecision::semantic(element, handshake, &tree));
        }
        if let Some(geometry) = element.geometry.filter(|geometry| geometry.is_valid()) {
            if hit_test_valid {
                return Ok(GroundingDecision::coordinate(
                    CoordinateAddress::FromAccessibilityElement {
                        coordinate: geometry.center(),
                        element,
                    },
                    handshake,
                    &tree,
                    degeneracy,
                ));
            }
        }

        self.fallback_if_authorized(driver, request, now_ms, tree, handshake, degeneracy)
    }

    fn fallback_if_authorized<D: GroundingDriver>(
        &self,
        _driver: &mut D,
        request: &GroundingRequest,
        now_ms: u64,
        tree: AccessibilityTreeSnapshot,
        handshake: HandshakeObservation,
        degeneracy: Vec<DegeneracyReason>,
    ) -> GroundingResult {
        let Some(fallback) = request.fallback.as_ref() else {
            return Err(GroundingFailure::GroundingUntrusted);
        };
        let path = fallback.path();
        if !self.policy.fallback_allowed(path) {
            return Err(GroundingFailure::GroundingUntrusted);
        }
        // An absent tree is an eligible AX-absence signal.  A present tree must
        // carry at least one of the five closed reasons before pixel fallback is
        // permitted; a merely ineffective semantic action is not one of them.
        if !tree.is_absent() && degeneracy.is_empty() {
            return Err(GroundingFailure::GroundingUntrusted);
        }
        if !within_age_bound(
            now_ms,
            fallback.captured_at_ms(),
            self.policy.age_bounds.non_element_ms,
        ) {
            return Err(GroundingFailure::StaleGrounding);
        }
        // The frame is required alongside the identifiers, because a coordinate
        // whose image is unknown cannot be checked by anything downstream: the
        // driver's capture comparison has nothing to compare, and every bounds
        // check passes on a point from a smaller copy.
        let evidence_identifiers_present = match fallback {
            FallbackGrounding::Pixel(evidence) => {
                !evidence.capture_generation.is_empty()
                    && !evidence.window_identifier.is_empty()
                    && evidence.frame_is_present()
            }
            FallbackGrounding::SetOfMarks(evidence) => {
                !evidence.capture_generation.is_empty()
                    && !evidence.window_identifier.is_empty()
                    && evidence.frame_is_present()
            }
        };
        if !evidence_identifiers_present
            || fallback.target_process_generation() != request.target.process_generation_evidence
            || !fallback.coordinate().is_finite()
        {
            return Err(GroundingFailure::StaleGrounding);
        }
        let target = match fallback {
            FallbackGrounding::Pixel(evidence) => CoordinateAddress::Pixel(evidence.clone()),
            FallbackGrounding::SetOfMarks(evidence) => {
                if evidence.mark_identifier.is_empty() {
                    return Err(GroundingFailure::StaleGrounding);
                }
                CoordinateAddress::SetOfMarks(evidence.clone())
            }
        };
        Ok(GroundingDecision::coordinate(
            target, handshake, &tree, degeneracy,
        ))
    }

    /// Re-check every evidence component at the dispatch seam.  This method
    /// performs no dispatch and returns before a caller can invoke one.
    pub fn revalidate_before_dispatch<D: GroundingDriver>(
        &self,
        driver: &mut D,
        decision: &GroundingDecision,
        now_ms: u64,
        target_process_generation: &str,
    ) -> GroundingResult {
        match &decision.target {
            GroundingTarget::SemanticElement(element) => {
                if !within_age_bound(
                    now_ms,
                    element.resolved_at_ms,
                    self.policy.age_bounds.element_ms,
                ) {
                    return Err(GroundingFailure::StaleElement);
                }
                let evidence = driver.revalidate_element(element);
                if !evidence.element_valid {
                    return Err(GroundingFailure::StaleElement);
                }
                if !evidence.target_generation_valid
                    || element.target_process_generation != target_process_generation
                {
                    return Err(GroundingFailure::StaleGrounding);
                }
                Ok(decision.clone())
            }
            GroundingTarget::Coordinate(address) => {
                match address {
                    CoordinateAddress::FromAccessibilityElement {
                        element,
                        coordinate,
                    } => {
                        if !within_age_bound(
                            now_ms,
                            element.resolved_at_ms,
                            self.policy.age_bounds.element_ms,
                        ) {
                            return Err(GroundingFailure::StaleElement);
                        }
                        let evidence = driver.revalidate_element(element);
                        if !evidence.element_valid {
                            return Err(GroundingFailure::StaleElement);
                        }
                        if !evidence.target_generation_valid
                            || element.target_process_generation != target_process_generation
                        {
                            return Err(GroundingFailure::StaleGrounding);
                        }
                        if !evidence.geometry_valid
                            || !evidence.coordinate_valid
                            || !coordinate.is_finite()
                        {
                            return Err(GroundingFailure::StaleGrounding);
                        }
                    }
                    CoordinateAddress::Pixel(evidence) => {
                        self.revalidate_pixel(driver, evidence, now_ms, target_process_generation)?;
                    }
                    CoordinateAddress::SetOfMarks(evidence) => {
                        self.revalidate_marks(driver, evidence, now_ms, target_process_generation)?;
                    }
                }
                Ok(decision.clone())
            }
        }
    }

    fn revalidate_pixel<D: GroundingDriver>(
        &self,
        driver: &mut D,
        evidence: &PixelEvidence,
        now_ms: u64,
        target_process_generation: &str,
    ) -> Result<(), GroundingFailure> {
        if !within_age_bound(
            now_ms,
            evidence.captured_at_ms,
            self.policy.age_bounds.non_element_ms,
        ) {
            return Err(GroundingFailure::StaleGrounding);
        }
        if evidence.capture_generation.is_empty()
            || evidence.window_identifier.is_empty()
            || evidence.target_process_generation != target_process_generation
            || !evidence.coordinate.is_finite()
        {
            return Err(GroundingFailure::StaleGrounding);
        }
        let result = driver.revalidate_pixel(evidence);
        if result.pixel_valid
            && result.capture_valid
            && result.mark_valid
            && result.target_generation_valid
            && result.coordinate_valid
            && result.window_valid
        {
            Ok(())
        } else {
            Err(GroundingFailure::StaleGrounding)
        }
    }

    fn revalidate_marks<D: GroundingDriver>(
        &self,
        driver: &mut D,
        evidence: &SetOfMarksEvidence,
        now_ms: u64,
        target_process_generation: &str,
    ) -> Result<(), GroundingFailure> {
        if !within_age_bound(
            now_ms,
            evidence.captured_at_ms,
            self.policy.age_bounds.non_element_ms,
        ) {
            return Err(GroundingFailure::StaleGrounding);
        }
        if evidence.capture_generation.is_empty()
            || evidence.window_identifier.is_empty()
            || evidence.mark_identifier.is_empty()
            || evidence.target_process_generation != target_process_generation
            || !evidence.coordinate.is_finite()
        {
            return Err(GroundingFailure::StaleGrounding);
        }
        let result = driver.revalidate_set_of_marks(evidence);
        if result.pixel_valid
            && result.capture_valid
            && result.mark_valid
            && result.target_generation_valid
            && result.coordinate_valid
            && result.window_valid
        {
            Ok(())
        } else {
            Err(GroundingFailure::StaleGrounding)
        }
    }

    /// Run the full read-only grounding phase and its dispatch-seam check as
    /// one operation.  Callers must still perform the actual dispatch only
    /// after this method returns `Ok`.
    pub fn ground_and_revalidate<D: GroundingDriver>(
        &self,
        driver: &mut D,
        request: &GroundingRequest,
        now_ms: u64,
    ) -> GroundingResult {
        let decision = self.ground(driver, request, now_ms)?;
        self.revalidate_before_dispatch(
            driver,
            &decision,
            now_ms,
            &request.target.process_generation_evidence,
        )
    }

    /// Convenience form for dispatch code that already retains the complete
    /// target grant rather than only its generation field.
    pub fn revalidate_for_target<D: GroundingDriver>(
        &self,
        driver: &mut D,
        decision: &GroundingDecision,
        now_ms: u64,
        target: &ProcessGrant,
    ) -> GroundingResult {
        self.revalidate_before_dispatch(
            driver,
            decision,
            now_ms,
            &target.process_generation_evidence,
        )
    }

    /// Alias used by dispatch implementations that call the seam a final
    /// grounding check rather than a revalidation.
    pub fn final_grounding_check<D: GroundingDriver>(
        &self,
        driver: &mut D,
        decision: &GroundingDecision,
        now_ms: u64,
        target_process_generation: &str,
    ) -> GroundingResult {
        self.revalidate_before_dispatch(driver, decision, now_ms, target_process_generation)
    }
}

/// How old a piece of grounding evidence is, or `None` if it claims to have
/// been captured after the moment being checked.
///
/// Every caller compares this against a freshness bound, so saturating an
/// inverted subtraction to zero would report evidence from the future as the
/// freshest possible and pass every one of those bounds. The inversion means
/// the two readings do not share a clock, and a duration between readings on
/// different clocks measures nothing — including when it happens to look
/// plausible.
///
/// Absence rather than a large number, so a caller cannot compare its way past
/// the question: there is no age to test, and each caller refuses.
fn age_ms(now_ms: u64, captured_at_ms: u64) -> Option<u64> {
    now_ms.checked_sub(captured_at_ms)
}

/// Whether evidence captured at `captured_at_ms` is within `bound_ms` of now.
///
/// False when the age cannot be computed at all, which keeps the refusal at the
/// same call sites that already refuse stale evidence rather than adding a
/// second failure path for a condition with the same remedy: capture again.
fn within_age_bound(now_ms: u64, captured_at_ms: u64, bound_ms: u64) -> bool {
    age_ms(now_ms, captured_at_ms).is_some_and(|age| age <= bound_ms)
}

#[cfg(test)]
mod age_tests {
    use super::*;

    /// Evidence claiming to be from the future has no age, rather than the
    /// freshest possible one.
    ///
    /// Every caller compares an age against a freshness bound, so saturating the
    /// inverted subtraction to zero would pass all of them. An inversion means
    /// the two readings did not share a clock, and a duration measured across
    /// two clocks means nothing even when it looks plausible.
    #[test]
    fn evidence_from_the_future_has_no_age() {
        assert_eq!(age_ms(1_000, 2_000), None);
        assert_eq!(age_ms(1_000, 1_001), None);
    }

    /// An age that cannot be computed is not within any bound.
    ///
    /// Including a generous one: the check is not "is this recent enough" but
    /// "is this measurable at all", and no bound can rescue an unmeasurable age.
    #[test]
    fn an_unmeasurable_age_is_within_no_bound() {
        assert!(!within_age_bound(1_000, 2_000, 0));
        assert!(!within_age_bound(1_000, 2_000, u64::MAX));
    }

    /// Ordinary ages compare against the bound as expected.
    ///
    /// The accepting case, so the refusals above cannot be satisfied by a
    /// predicate that refuses everything.
    #[test]
    fn measurable_ages_compare_against_the_bound() {
        assert_eq!(age_ms(2_000, 1_000), Some(1_000));
        assert!(within_age_bound(2_000, 1_000, 1_000));
        assert!(within_age_bound(2_000, 1_000, 1_001));
        assert!(!within_age_bound(2_000, 1_000, 999));
        // Same instant is age zero, which is measurable and fresh.
        assert!(within_age_bound(1_000, 1_000, 0));
    }
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    fn evidence(width: u32, height: u32) -> PixelEvidence {
        PixelEvidence {
            capture_generation: "capture-1".to_string(),
            target_process_generation: "generation".to_string(),
            window_identifier: "window".to_string(),
            coordinate: Coordinate::new(30.0, 40.0),
            read_from_width_px: width,
            read_from_height_px: height,
            captured_at_ms: 0,
        }
    }

    /// Pixel evidence without the size of the image it was read from is refused.
    ///
    /// A coordinate is an index into an image, and every other field here
    /// describes the CAPTURE rather than the image a coordinate was read from.
    /// Those differ whenever the reader was shown a scaled copy: the capture is
    /// unchanged, so its generation still matches, while the coordinate belongs
    /// to a smaller picture and lands inside the capture's bounds anyway.
    ///
    /// Refused rather than defaulted, because there is no size that can stand in
    /// for an unknown one: assuming the capture's own dimensions is exactly the
    /// assumption that produces the wrong point.
    #[test]
    fn pixel_evidence_without_its_frame_is_refused() {
        assert!(!evidence(0, 1080).frame_is_present());
        assert!(!evidence(1920, 0).frame_is_present());
        assert!(!evidence(0, 0).frame_is_present());
    }

    /// Evidence carrying a frame is accepted, so the refusals above are not
    /// satisfied by a check that refuses everything.
    #[test]
    fn pixel_evidence_with_a_frame_is_accepted() {
        assert!(evidence(1920, 1080).frame_is_present());
        assert!(evidence(1, 1).frame_is_present());
    }
}

/// A deterministic driver useful for conformance fixtures and downstream slices.
/// It records the call sequence so tests can prove the handshake preceded tree
/// classification and that revalidation happened before dispatch.
#[derive(Debug, Clone)]
pub struct RecordingGroundingDriver {
    pub handshake: HandshakeObservation,
    pub tree: Result<AccessibilityTreeSnapshot, GroundingDriverError>,
    pub element: Result<AccessibilityElement, GroundingDriverError>,
    pub hit_test: Result<CenterHitTest, GroundingDriverError>,
    pub element_revalidation: ElementRevalidation,
    pub pixel_revalidation: PixelRevalidation,
    pub marks_revalidation: PixelRevalidation,
    pub calls: Vec<GroundingCall>,
}

impl Default for RecordingGroundingDriver {
    fn default() -> Self {
        Self {
            handshake: HandshakeObservation {
                attempted: true,
                return_code: HandshakeReturnCode::Accepted,
                settle_interval_ms: 500,
                tree_population_observed: true,
            },
            tree: Ok(AccessibilityTreeSnapshot::default()),
            element: Ok(AccessibilityElement {
                root_identifier: "root".to_string(),
                element_identifier: "element".to_string(),
                target_process_generation: "generation".to_string(),
                resolved_at_ms: 0,
                geometry: Some(ElementRect::new(10.0, 20.0, 20.0, 10.0)),
                semantic_actions: vec!["press".to_string()],
                window_identifier: Some("window".to_string()),
            }),
            hit_test: Ok(CenterHitTest {
                resolved_identifier: Some("element".to_string()),
                is_same_element_or_descendant: true,
            }),
            element_revalidation: ElementRevalidation::valid(),
            pixel_revalidation: PixelRevalidation::valid(),
            marks_revalidation: PixelRevalidation::valid(),
            calls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroundingCall {
    Handshake,
    ReadTree,
    ResolveElement,
    HitTestCenter,
    RevalidateElement,
    RevalidatePixel,
    RevalidateSetOfMarks,
}

impl GroundingDriver for RecordingGroundingDriver {
    fn attempt_accessibility_handshake(
        &mut self,
        _target: &ProcessGrant,
        declaration: &AccessibilityHandshakeDeclaration,
    ) -> Result<HandshakeObservation, GroundingDriverError> {
        self.calls.push(GroundingCall::Handshake);
        let mut observation = self.handshake.clone();
        observation.settle_interval_ms = observation
            .settle_interval_ms
            .min(declaration.settle_interval_ms);
        Ok(observation)
    }

    fn read_accessibility_tree(
        &mut self,
        _request: AccessibilityTreeReadRequest,
    ) -> Result<AccessibilityTreeSnapshot, GroundingDriverError> {
        self.calls.push(GroundingCall::ReadTree);
        self.tree.clone()
    }

    fn resolve_accessibility_element(
        &mut self,
        _target: &ProcessGrant,
        _root_identifier: &str,
        _element_identifier: &str,
    ) -> Result<AccessibilityElement, GroundingDriverError> {
        self.calls.push(GroundingCall::ResolveElement);
        self.element.clone()
    }

    fn hit_test_center(
        &mut self,
        _target: &ProcessGrant,
        _element: &AccessibilityElement,
        _center: Coordinate,
    ) -> Result<CenterHitTest, GroundingDriverError> {
        self.calls.push(GroundingCall::HitTestCenter);
        self.hit_test.clone()
    }

    fn revalidate_element(&mut self, _element: &AccessibilityElement) -> ElementRevalidation {
        self.calls.push(GroundingCall::RevalidateElement);
        self.element_revalidation
    }

    fn revalidate_pixel(&mut self, _evidence: &PixelEvidence) -> PixelRevalidation {
        self.calls.push(GroundingCall::RevalidatePixel);
        self.pixel_revalidation
    }

    fn revalidate_set_of_marks(&mut self, _evidence: &SetOfMarksEvidence) -> PixelRevalidation {
        self.calls.push(GroundingCall::RevalidateSetOfMarks);
        self.marks_revalidation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All four grounding outcomes are reachable, and they are different.
    ///
    /// The distinction exists so that a capability with nothing to ground and a
    /// capability this module does not serve are not answered alike. Asserting
    /// only the grounded case would leave that collapse indistinguishable from
    /// correct behaviour, since both of the others simply decline to ground.
    ///
    /// The capability names tested here are the module's whole action
    /// vocabulary. Moving one between the outcomes changes whether its target
    /// is resolved by identity or by position, so it should be a deliberate
    /// change rather than a consequence of another one.
    #[test]
    fn every_grounding_outcome_is_reachable_and_distinct() {
        assert!(matches!(
            GroundingPolicy::for_capability("computer.click"),
            GroundingRequirement::Grounded(_)
        ));

        // Typing resolves by identity only. A pixel fallback here would let
        // text reach a field picked out by position.
        let GroundingRequirement::Grounded(typing) =
            GroundingPolicy::for_capability("computer.type")
        else {
            panic!("typing is grounded");
        };
        assert!(!typing.pixel_fallback_eligible);
        assert_eq!(
            typing.eligible_paths,
            [GroundingPath::AccessibilityElement].into_iter().collect()
        );

        // Drag is the one durable action that can preserve an element target
        // when available but must remain coordinate-addressed otherwise.
        let GroundingRequirement::ElementOrCoordinateAddressed(drag) =
            GroundingPolicy::for_capability("computer.drag")
        else {
            panic!("drag resolves an element or addresses a coordinate");
        };
        assert_eq!(
            drag.eligible_paths,
            [GroundingPath::AccessibilityElement].into_iter().collect()
        );
        assert!(!drag.pixel_fallback_eligible);
        assert_eq!(
            GroundingPolicy::for_capability("computer.drag").resolution_path(false),
            Some(GroundingResolutionPath::CoordinateAddressed {
                containment_rung: ContainmentRung::GlobalNone,
            })
        );

        for capability in [
            "computer.keys",
            "computer.move",
            "computer.screenshot",
            "computer.wait",
        ] {
            assert_eq!(
                GroundingPolicy::for_capability(capability),
                GroundingRequirement::NotGrounded,
                "{capability} addresses no element, so it has nothing to ground"
            );
        }

        // A name outside the vocabulary is its own answer. Reported as
        // not-grounded, it would read as a normal capability that happens to
        // need no grounding, and the caller would proceed.
        assert_eq!(
            GroundingPolicy::for_capability("computer.launch_missiles"),
            GroundingRequirement::UnknownCapability
        );
        assert_eq!(
            GroundingPolicy::for_capability("browser.click"),
            GroundingRequirement::UnknownCapability
        );
    }

    fn grant() -> ProcessGrant {
        ProcessGrant {
            pid: 42,
            bundle_identity: "org.chromium.Chromium".to_string(),
            process_generation_evidence: "generation".to_string(),
        }
    }

    fn pixel() -> FallbackGrounding {
        FallbackGrounding::Pixel(PixelEvidence {
            capture_generation: "capture-1".to_string(),
            target_process_generation: "generation".to_string(),
            window_identifier: "window".to_string(),
            coordinate: Coordinate::new(30.0, 40.0),
            read_from_width_px: 1920,
            read_from_height_px: 1080,
            captured_at_ms: 0,
        })
    }

    #[test]
    fn closed_degeneracy_names_have_no_platform_escape_hatch() {
        assert_eq!(AX_DEGENERACY_REASON_NAMES.len(), 5);
        assert!(DegeneracyReason::all()
            .iter()
            .all(|reason| DegeneracyReason::parse(reason.as_str()).is_some()));
        assert!(DegeneracyReason::parse("tree_is_weird").is_none());
    }

    #[test]
    fn handshake_is_recorded_before_degeneracy_and_return_code_is_not_authoritative() {
        let mut driver = RecordingGroundingDriver {
            handshake: HandshakeObservation {
                attempted: true,
                return_code: HandshakeReturnCode::Rejected,
                settle_interval_ms: 500,
                tree_population_observed: true,
            },
            tree: Ok(AccessibilityTreeSnapshot {
                root_identifier: Some("root".to_string()),
                target_process_generation: "generation".to_string(),
                captured_at_ms: 0,
                visibly_nontrivial_window: false,
                child_count: 1,
                opaque_container_collapse: false,
                has_actionable_actions: true,
                geometry_degenerate: false,
                tree_depth: 3,
                minimum_plausible_depth: 2,
            }),
            ..RecordingGroundingDriver::default()
        };
        let resolver = GroundingResolver::new(GroundingPolicy::default());
        let request = GroundingRequest::accessibility_element(grant(), "root", "element", "press");
        let result = resolver.ground(&mut driver, &request, 1);
        assert!(result.is_ok());
        assert_eq!(driver.calls[0], GroundingCall::Handshake);
        assert_eq!(driver.calls[1], GroundingCall::ReadTree);
        assert_eq!(driver.calls[2], GroundingCall::ResolveElement);
        assert_eq!(driver.calls[3], GroundingCall::HitTestCenter);
        assert_eq!(
            result.unwrap().handshake.return_code,
            HandshakeReturnCode::Rejected
        );
    }

    #[test]
    fn degenerate_tree_allows_only_authorized_pixel_fallback_and_is_global() {
        let mut driver = RecordingGroundingDriver {
            tree: Ok(AccessibilityTreeSnapshot {
                visibly_nontrivial_window: true,
                child_count: 0,
                ..AccessibilityTreeSnapshot::default()
            }),
            ..RecordingGroundingDriver::default()
        };
        let resolver = GroundingResolver::new(GroundingPolicy::default());
        let request = GroundingRequest::coordinate(grant(), pixel());
        let decision = resolver.ground(&mut driver, &request, 1).unwrap();
        assert_eq!(decision.containment_rung, ContainmentRung::GlobalNone);
        assert!(decision.coordinate_addressed);
        assert_eq!(
            decision.tree_degeneracy[0],
            DegeneracyReason::MissingChildrenForNontrivialWindow
        );

        let mut refused_driver = RecordingGroundingDriver {
            tree: Ok(AccessibilityTreeSnapshot {
                visibly_nontrivial_window: true,
                child_count: 0,
                ..AccessibilityTreeSnapshot::default()
            }),
            ..RecordingGroundingDriver::default()
        };
        let policy = GroundingPolicy {
            pixel_fallback_eligible: false,
            ..GroundingPolicy::default()
        };
        let refused = GroundingResolver::new(policy).ground(&mut refused_driver, &request, 1);
        assert_eq!(refused, Err(GroundingFailure::GroundingUntrusted));
    }

    #[test]
    fn all_pixel_evidence_is_revalidated_before_dispatch() {
        let mut driver = RecordingGroundingDriver {
            tree: Ok(AccessibilityTreeSnapshot::absent("generation", 0)),
            pixel_revalidation: PixelRevalidation {
                capture_valid: false,
                ..PixelRevalidation::valid()
            },
            ..RecordingGroundingDriver::default()
        };
        let resolver = GroundingResolver::new(GroundingPolicy::default());
        let request = GroundingRequest::coordinate(grant(), pixel());
        let decision = resolver.ground(&mut driver, &request, 1).unwrap();
        assert_eq!(
            resolver.revalidate_before_dispatch(&mut driver, &decision, 1, "generation"),
            Err(GroundingFailure::StaleGrounding)
        );
        assert!(driver.calls.contains(&GroundingCall::RevalidatePixel));
    }

    #[test]
    fn age_boundaries_are_closed_and_element_and_pixel_use_different_bounds() {
        let mut driver = RecordingGroundingDriver::default();
        let resolver = GroundingResolver::new(GroundingPolicy::default());
        let element_request =
            GroundingRequest::accessibility_element(grant(), "root", "element", "press");
        assert!(resolver
            .ground(&mut driver, &element_request, 2_000)
            .is_ok());
        assert_eq!(
            resolver.ground(&mut driver, &element_request, 2_001),
            Err(GroundingFailure::StaleElement)
        );

        let mut absent_driver = RecordingGroundingDriver {
            tree: Ok(AccessibilityTreeSnapshot::absent("generation", 0)),
            ..RecordingGroundingDriver::default()
        };
        let pixel_request = GroundingRequest::coordinate(grant(), pixel());
        assert!(resolver
            .ground(&mut absent_driver, &pixel_request, 1_000)
            .is_ok());
        assert_eq!(
            resolver.ground(&mut absent_driver, &pixel_request, 1_001),
            Err(GroundingFailure::StaleGrounding)
        );
    }
}
