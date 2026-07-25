extern crate cerebellum_computer;

mod platform {
    pub use cerebellum_computer::platform::*;
}

#[allow(dead_code)]
#[path = "../src/grounding/mod.rs"]
mod grounding;

use grounding::{
    AccessibilityTreeSnapshot, ContainmentRung, GroundingFailure, GroundingPolicy,
    GroundingRequest, GroundingResolver, RecordingGroundingDriver,
};
use platform::ProcessGrant;

fn target() -> ProcessGrant {
    ProcessGrant {
        pid: 99,
        bundle_identity: "com.microsoft.edgemac".to_string(),
        process_generation_evidence: "gen-1".to_string(),
    }
}

#[test]
fn coordinate_fallback_is_global_none_and_never_implies_pid_containment() {
    let mut driver = RecordingGroundingDriver {
        tree: Ok(AccessibilityTreeSnapshot::absent("gen-1", 0)),
        ..RecordingGroundingDriver::default()
    };
    let request = GroundingRequest::coordinate(
        target(),
        grounding::FallbackGrounding::Pixel(grounding::PixelEvidence {
            capture_generation: "capture-1".to_string(),
            target_process_generation: "gen-1".to_string(),
            window_identifier: "window-1".to_string(),
            coordinate: grounding::Coordinate::new(4.0, 5.0),
            captured_at_ms: 0,
        }),
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
        grounding::FallbackGrounding::SetOfMarks(grounding::SetOfMarksEvidence {
            capture_generation: "capture-1".to_string(),
            target_process_generation: "gen-2".to_string(),
            window_identifier: "window-1".to_string(),
            mark_identifier: "mark-1".to_string(),
            coordinate: grounding::Coordinate::new(4.0, 5.0),
            captured_at_ms: 0,
        }),
    );
    let result =
        GroundingResolver::new(GroundingPolicy::default()).ground(&mut driver, &request, 1);
    assert_eq!(result, Err(GroundingFailure::StaleGrounding));
}
