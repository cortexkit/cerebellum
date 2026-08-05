use cerebellum_computer::grounding::{
    AccessibilityElement, AccessibilityTreeSnapshot, CenterHitTest, Coordinate, ElementRect,
    FallbackGrounding, GroundingFailure, GroundingRequest, GroundingResolver, PixelEvidence,
    RecordingGroundingDriver,
};
use cerebellum_computer::platform::ProcessGrant;

fn target() -> ProcessGrant {
    ProcessGrant {
        pid: 100,
        bundle_identity: "org.chromium.Chromium".to_string(),
        process_generation_evidence: "gen-1".to_string(),
    }
}

fn pixel() -> FallbackGrounding {
    FallbackGrounding::Pixel(PixelEvidence {
        capture_generation: "capture-1".to_string(),
        target_process_generation: "gen-1".to_string(),
        window_identifier: "window-1".to_string(),
        coordinate: Coordinate::new(12.0, 14.0),
        captured_at_ms: 0,
    })
}

#[test]
fn failed_center_hit_test_blocks_ax_coordinate_and_uses_authorized_fallback() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot {
            target_process_generation: "gen-1".to_string(),
            ..AccessibilityTreeSnapshot::default()
        }),
        element: Ok(AccessibilityElement {
            root_identifier: "root".to_string(),
            element_identifier: "element".to_string(),
            target_process_generation: "gen-1".to_string(),
            resolved_at_ms: 0,
            geometry: Some(ElementRect::new(10.0, 10.0, 20.0, 20.0)),
            semantic_actions: Vec::new(),
            window_identifier: Some("window-1".to_string()),
        }),
        hit_test: Ok(CenterHitTest {
            resolved_identifier: Some("other".to_string()),
            is_same_element_or_descendant: false,
        }),
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::accessibility_element(target(), "root", "element", "press")
        .with_fallback(pixel());
    let decision = GroundingResolver::new(Default::default())
        .ground_and_revalidate(&mut driver, &request, 1)
        .expect("geometry degeneracy authorizes the row's pixel fallback");
    assert!(matches!(
        decision.target,
        cerebellum_computer::grounding::GroundingTarget::Coordinate(
            cerebellum_computer::grounding::CoordinateAddress::Pixel(_)
        )
    ));
    assert_eq!(
        decision.containment_rung,
        cerebellum_computer::grounding::ContainmentRung::GlobalNone
    );
}

#[test]
fn failed_center_hit_test_does_not_invalidate_semantic_ax_action() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot {
            target_process_generation: "gen-1".to_string(),
            ..AccessibilityTreeSnapshot::default()
        }),
        element: Ok(AccessibilityElement {
            root_identifier: "root".to_string(),
            element_identifier: "element".to_string(),
            target_process_generation: "gen-1".to_string(),
            resolved_at_ms: 0,
            geometry: Some(ElementRect::new(10.0, 10.0, 20.0, 20.0)),
            semantic_actions: vec!["press".to_string()],
            window_identifier: Some("window-1".to_string()),
        }),
        hit_test: Ok(CenterHitTest {
            resolved_identifier: Some("other".to_string()),
            is_same_element_or_descendant: false,
        }),
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::accessibility_element(target(), "root", "element", "press");
    let decision = GroundingResolver::new(Default::default())
        .ground_and_revalidate(&mut driver, &request, 1)
        .expect("semantic AX action does not derive a coordinate");
    assert!(matches!(
        decision.target,
        cerebellum_computer::grounding::GroundingTarget::SemanticElement(_)
    ));
    assert!(!decision.coordinate_addressed);
}

#[test]
fn invalidated_ax_coordinate_is_stale_grounding_not_a_fallback_authorization() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot {
            target_process_generation: "gen-1".to_string(),
            ..AccessibilityTreeSnapshot::default()
        }),
        element: Ok(AccessibilityElement {
            root_identifier: "root".to_string(),
            element_identifier: "element".to_string(),
            target_process_generation: "gen-1".to_string(),
            resolved_at_ms: 0,
            geometry: Some(ElementRect::new(10.0, 10.0, 20.0, 20.0)),
            semantic_actions: Vec::new(),
            window_identifier: Some("window-1".to_string()),
        }),
        element_revalidation: cerebellum_computer::grounding::ElementRevalidation {
            coordinate_valid: false,
            ..cerebellum_computer::grounding::ElementRevalidation::valid()
        },
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::accessibility_element(target(), "root", "element", "press");
    let decision = GroundingResolver::new(Default::default())
        .ground(&mut driver, &request, 1)
        .expect("center hit-test makes the AX coordinate candidate initially valid");
    assert_eq!(
        GroundingResolver::new(Default::default()).revalidate_before_dispatch(
            &mut driver,
            &decision,
            1,
            "gen-1"
        ),
        Err(GroundingFailure::StaleGrounding)
    );
}
