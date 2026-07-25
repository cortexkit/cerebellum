use cerebellum_computer::grounding::{
    AccessibilityTreeSnapshot, DegeneracyReason, FallbackGrounding, GroundingDecision,
    GroundingPath, GroundingRequest, GroundingResolver, GroundingTarget, PixelEvidence,
    RecordingGroundingDriver,
};
use cerebellum_computer::platform::ProcessGrant;

fn target() -> ProcessGrant {
    ProcessGrant {
        pid: 99,
        bundle_identity: "com.microsoft.edgemac".to_string(),
        process_generation_evidence: "gen-1".to_string(),
    }
}

fn pixel() -> FallbackGrounding {
    FallbackGrounding::Pixel(PixelEvidence {
        capture_generation: "capture-1".to_string(),
        target_process_generation: "gen-1".to_string(),
        window_identifier: "window-1".to_string(),
        coordinate: cerebellum_computer::grounding::Coordinate::new(12.0, 14.0),
        captured_at_ms: 0,
    })
}

fn request() -> GroundingRequest {
    GroundingRequest::accessibility_element(target(), "root", "element", "press")
        .with_fallback(pixel())
}

fn driver_with_tree(tree: AccessibilityTreeSnapshot) -> RecordingGroundingDriver {
    let mut driver = RecordingGroundingDriver::default();
    let mut tree = tree;
    tree.target_process_generation = "gen-1".to_string();
    driver.tree = Ok(tree);
    let mut element = driver
        .element
        .clone()
        .expect("the recording driver has a default element");
    element.target_process_generation = "gen-1".to_string();
    driver.element = Ok(element);
    driver
}

fn ground_with_tree(tree: AccessibilityTreeSnapshot) -> GroundingDecision {
    let mut driver = driver_with_tree(tree);
    GroundingResolver::new(Default::default())
        .ground(&mut driver, &request(), 1)
        .expect("an authorized pixel fallback should produce a grounding decision")
}

fn path(decision: &GroundingDecision) -> GroundingPath {
    match &decision.target {
        GroundingTarget::SemanticElement(_) => GroundingPath::AccessibilityElement,
        GroundingTarget::Coordinate(address) => address.source_path(),
    }
}

fn assert_pixel_fallback(decision: &GroundingDecision, reason: DegeneracyReason) {
    assert_eq!(path(decision), GroundingPath::Pixel);
    assert_eq!(decision.tree_degeneracy, vec![reason]);
}

#[test]
fn missing_children_for_nontrivial_window_forces_pixel_fallback() {
    let decision = ground_with_tree(AccessibilityTreeSnapshot {
        visibly_nontrivial_window: true,
        child_count: 0,
        ..AccessibilityTreeSnapshot::default()
    });

    assert_pixel_fallback(
        &decision,
        DegeneracyReason::MissingChildrenForNontrivialWindow,
    );
}

#[test]
fn opaque_container_collapse_forces_pixel_fallback() {
    let decision = ground_with_tree(AccessibilityTreeSnapshot {
        opaque_container_collapse: true,
        ..AccessibilityTreeSnapshot::default()
    });

    assert_pixel_fallback(&decision, DegeneracyReason::OpaqueContainerCollapse);
}

#[test]
fn no_actionable_actions_forces_pixel_fallback() {
    let decision = ground_with_tree(AccessibilityTreeSnapshot {
        has_actionable_actions: false,
        ..AccessibilityTreeSnapshot::default()
    });

    assert_pixel_fallback(&decision, DegeneracyReason::NoActionableActions);
}

#[test]
fn degenerate_geometry_forces_pixel_fallback() {
    let decision = ground_with_tree(AccessibilityTreeSnapshot {
        geometry_degenerate: true,
        ..AccessibilityTreeSnapshot::default()
    });

    assert_pixel_fallback(&decision, DegeneracyReason::DegenerateGeometry);
}

#[test]
fn implausibly_shallow_tree_forces_pixel_fallback() {
    let decision = ground_with_tree(AccessibilityTreeSnapshot {
        tree_depth: 1,
        minimum_plausible_depth: 2,
        ..AccessibilityTreeSnapshot::default()
    });

    assert_pixel_fallback(&decision, DegeneracyReason::ImplausiblyShallowTree);
}

#[test]
fn non_degenerate_tree_with_valid_locator_uses_semantic_path() {
    let decision = ground_with_tree(AccessibilityTreeSnapshot::default());

    assert_eq!(path(&decision), GroundingPath::AccessibilityElement);
    assert_eq!(decision.tree_degeneracy, Vec::<DegeneracyReason>::new());
}
