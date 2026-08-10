use cerebellum_computer::grounding::{
    AccessibilityTreeSnapshot, ContainmentRung, GroundingCall, GroundingFailure, GroundingPolicy,
    GroundingRequest, GroundingResolver, RecordingGroundingDriver,
};
use cerebellum_computer::platform::ProcessGrant;

fn target() -> ProcessGrant {
    ProcessGrant {
        pid: 99,
        bundle_identity: "com.microsoft.edgemac".to_string(),
        process_generation_evidence: "gen-1".to_string(),
    }
}

fn element_driver() -> RecordingGroundingDriver {
    let mut driver = RecordingGroundingDriver::default();
    let mut element = driver
        .element
        .clone()
        .expect("the recording driver has a default element");
    element.target_process_generation = "gen-1".to_string();
    driver.element = Ok(element);
    let mut tree = driver
        .tree
        .clone()
        .expect("the recording driver has a default tree");
    tree.target_process_generation = "gen-1".to_string();
    driver.tree = Ok(tree);
    driver
}

#[test]
fn coordinate_fallback_is_global_none_and_never_implies_pid_containment() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot::absent("gen-1", 0)),
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::coordinate(
        target(),
        cerebellum_computer::grounding::FallbackGrounding::Pixel(
            cerebellum_computer::grounding::PixelEvidence {
                capture_generation: "capture-1".to_string(),
                target_process_generation: "gen-1".to_string(),
                window_identifier: "window-1".to_string(),
                coordinate: cerebellum_computer::grounding::Coordinate::new(4.0, 5.0),
                read_from_width_px: 1920,
                read_from_height_px: 1080,
                captured_at_ms: 0,
            },
        ),
    );
    let decision = GroundingResolver::new(GroundingPolicy::default())
        .ground(&mut driver, &request, 1)
        .expect("absent AX is an eligible fallback condition");
    assert_eq!(decision.containment_rung, ContainmentRung::GlobalNone);
    assert!(decision.coordinate_addressed);
}

#[test]
fn stale_generation_refuses_before_any_dispatch_capable_operation() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot::absent("gen-1", 0)),
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::coordinate(
        target(),
        cerebellum_computer::grounding::FallbackGrounding::SetOfMarks(
            cerebellum_computer::grounding::SetOfMarksEvidence {
                capture_generation: "capture-1".to_string(),
                target_process_generation: "gen-2".to_string(),
                window_identifier: "window-1".to_string(),
                mark_identifier: "mark-1".to_string(),
                coordinate: cerebellum_computer::grounding::Coordinate::new(4.0, 5.0),
                read_from_width_px: 1920,
                read_from_height_px: 1080,
                captured_at_ms: 0,
            },
        ),
    );
    let result =
        GroundingResolver::new(GroundingPolicy::default()).ground(&mut driver, &request, 1);
    assert_eq!(result, Err(GroundingFailure::StaleGrounding));
}

#[test]
fn stale_element_revalidation_refuses_before_dispatch_and_names_failure() {
    let mut driver = element_driver();
    let resolver = GroundingResolver::new(GroundingPolicy::default());
    let request = GroundingRequest::accessibility_element(target(), "root", "element", "press");
    let decision = resolver
        .ground(&mut driver, &request, 0)
        .expect("fresh accessibility evidence should produce a decision");

    let result = resolver.revalidate_before_dispatch(&mut driver, &decision, 2_001, "gen-1");
    assert_eq!(result, Err(GroundingFailure::StaleElement));
    assert!(!driver.calls.contains(&GroundingCall::RevalidateElement));
}

#[test]
fn fresh_element_revalidation_reaches_dispatch_seam() {
    let mut driver = element_driver();
    let resolver = GroundingResolver::new(GroundingPolicy::default());
    let request = GroundingRequest::accessibility_element(target(), "root", "element", "press");
    let decision = resolver
        .ground(&mut driver, &request, 0)
        .expect("fresh accessibility evidence should produce a decision");

    let result = resolver.revalidate_before_dispatch(&mut driver, &decision, 2_000, "gen-1");
    assert!(result.is_ok());
    assert!(driver.calls.contains(&GroundingCall::RevalidateElement));
}

#[test]
fn grounding_untrusted_refuses_unauthorized_pixel_before_dispatch() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot::absent("gen-1", 0)),
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::coordinate(
        target(),
        cerebellum_computer::grounding::FallbackGrounding::Pixel(
            cerebellum_computer::grounding::PixelEvidence {
                capture_generation: "capture-1".to_string(),
                target_process_generation: "gen-1".to_string(),
                window_identifier: "window-1".to_string(),
                coordinate: cerebellum_computer::grounding::Coordinate::new(4.0, 5.0),
                read_from_width_px: 1920,
                read_from_height_px: 1080,
                captured_at_ms: 0,
            },
        ),
    );
    let policy = GroundingPolicy {
        pixel_fallback_eligible: false,
        ..GroundingPolicy::default()
    };
    let result = GroundingResolver::new(policy).ground_and_revalidate(&mut driver, &request, 1);

    assert_eq!(result, Err(GroundingFailure::GroundingUntrusted));
    assert!(!driver.calls.contains(&GroundingCall::RevalidatePixel));
}

#[test]
fn authorized_pixel_fallback_reaches_dispatch_seam() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot::absent("gen-1", 0)),
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::coordinate(
        target(),
        cerebellum_computer::grounding::FallbackGrounding::Pixel(
            cerebellum_computer::grounding::PixelEvidence {
                capture_generation: "capture-1".to_string(),
                target_process_generation: "gen-1".to_string(),
                window_identifier: "window-1".to_string(),
                coordinate: cerebellum_computer::grounding::Coordinate::new(4.0, 5.0),
                read_from_width_px: 1920,
                read_from_height_px: 1080,
                captured_at_ms: 0,
            },
        ),
    );
    let result = GroundingResolver::new(GroundingPolicy::default()).ground_and_revalidate(
        &mut driver,
        &request,
        1,
    );

    assert!(result.is_ok());
    assert!(driver.calls.contains(&GroundingCall::RevalidatePixel));
}
