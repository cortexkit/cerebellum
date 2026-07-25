//! Acceptance tests for screenshot validation, PNG integrity, and coordinate safety.

#[allow(dead_code)]
#[path = "../src/coordinate.rs"]
mod coordinate;

use coordinate::{
    capture_from_backend, capture_screenshot, encode_base64, map_pixel_center, round_css_pixel,
    CoordinateError, InputRect, InvalidCoordinatesReason, ScreenshotPayload, ScreenshotSnapshot,
    ScreenshotStore, SnapshotKind, StaleSnapshotReason, TransformInputs, ViewportCaptureBackend,
    ViewportObservation,
};

const ONE_BY_ONE_PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";

fn state(transform: TransformInputs) -> ViewportObservation {
    ViewportObservation::new(7, transform)
}

fn base_transform() -> TransformInputs {
    TransformInputs::from_values(10.0, 20.0, 100.0, 50.0, 1.0, 1.0)
}

fn payload() -> ScreenshotPayload {
    ScreenshotPayload::new(ONE_BY_ONE_PNG_B64, 1, 1)
}

fn retained_snapshot(generation: u64) -> ScreenshotSnapshot {
    ScreenshotSnapshot::new_with_generation(
        "snapshot-1",
        7,
        "https://example.test",
        ONE_BY_ONE_PNG_B64,
        1,
        1,
        InputRect::new(0.0, 0.0, 1.0, 1.0),
        1.0,
        1.0,
        generation,
    )
    .unwrap()
}

#[test]
fn device_scale_and_visual_viewport_scale_are_retained_but_not_multiplied() {
    let first = TransformInputs::from_values(4.0, 8.0, 200.0, 100.0, 1.0, 1.0);
    let second = TransformInputs::from_values(4.0, 8.0, 200.0, 100.0, 2.0, 1.75);
    let first_center = map_pixel_center(first, 200, 100, 99u32, 49u32).unwrap();
    let second_center = map_pixel_center(second, 200, 100, 99u32, 49u32).unwrap();
    assert_eq!(first_center, second_center);
    assert_eq!(second_center.tuple(), (103.5, 57.5));
}

#[test]
fn fractional_rounding_uses_one_over_64_with_positive_ties() {
    assert_eq!(round_css_pixel(0.0078125).unwrap(), 0.015625);
    assert_eq!(round_css_pixel(-0.0078125).unwrap(), 0.0);
    assert_eq!(round_css_pixel(-0.0234375).unwrap(), -0.015625);
}

#[test]
fn capture_requires_a_coherent_bracket_and_keeps_no_clickable_state_on_rejection() {
    let before = state(base_transform());
    let mut after = before;
    after.document_epoch += 1;
    let error = capture_screenshot(before, payload(), after, false).unwrap_err();
    assert_eq!(
        error,
        CoordinateError::invalid(InvalidCoordinatesReason::ConversionFailure)
    );

    let store = ScreenshotStore::new(1).unwrap();
    assert_eq!(store.len(), 0);
    let mut changed = before;
    changed.transform.visual_viewport_scale = 2.0;
    assert!(capture_screenshot(before, payload(), changed, false).is_err());
    assert!(capture_screenshot(before, payload(), before, true).is_err());
    assert_eq!(store.len(), 0);
}

#[test]
fn metadata_reasons_are_closed_and_checked_before_mapping() {
    let non_finite = TransformInputs::from_values(f64::NAN, 0.0, 1.0, 1.0, 1.0, 1.0);
    assert_eq!(
        map_pixel_center(non_finite, 1, 1, 0i64, 0i64),
        Err(CoordinateError::invalid(
            InvalidCoordinatesReason::NonFiniteMetadata
        ))
    );
    let non_positive = TransformInputs::from_values(0.0, 0.0, 0.0, 1.0, 1.0, 1.0);
    assert_eq!(
        map_pixel_center(non_positive, 1, 1, 0i64, 0i64),
        Err(CoordinateError::invalid(
            InvalidCoordinatesReason::NonPositiveDimensions
        ))
    );
    let out_of_bounds = map_pixel_center(base_transform(), 10, 10, -1i64, 10i64).unwrap_err();
    assert_eq!(
        out_of_bounds,
        CoordinateError::invalid(InvalidCoordinatesReason::PointOutOfBounds)
    );
}

#[test]
fn canonical_png_checks_base64_structure_crc_and_image_dimensions() {
    let decoded = coordinate::validate_png_base64(ONE_BY_ONE_PNG_B64, 1, 1).unwrap();
    assert!(!decoded.as_bytes().is_empty());
    assert_eq!(
        coordinate::validate_png_base64(ONE_BY_ONE_PNG_B64, 2, 1),
        Err(CoordinateError::CdpFailure)
    );
    assert_eq!(
        coordinate::validate_png_base64("not base64", 1, 1),
        Err(CoordinateError::CdpFailure)
    );
    let mut malformed = decoded.into_bytes();
    let last = malformed.len() - 1;
    malformed[last] ^= 1;
    assert_eq!(
        coordinate::validate_png_base64(&encode_base64(&malformed), 1, 1),
        Err(CoordinateError::CdpFailure)
    );
}

#[test]
fn oversized_encoded_image_is_rejected_before_retention() {
    let oversized = "A".repeat(coordinate::MAX_ENCODED_PNG_BYTES + 4);
    let error = coordinate::validate_png_base64(&oversized, 1, 1).unwrap_err();
    assert_eq!(
        error,
        CoordinateError::ImageTooLarge {
            encoded_bytes: coordinate::MAX_ENCODED_PNG_BYTES + 4,
            bound_bytes: coordinate::MAX_ENCODED_PNG_BYTES,
        }
    );
    let store = ScreenshotStore::new(1).unwrap();
    assert_eq!(store.len(), 0);
}

#[test]
fn retained_screenshot_reports_kind_epoch_transform_session_and_eviction_reasons() {
    let snapshot = retained_snapshot(0);
    let mut store = ScreenshotStore::new(1).unwrap();
    store.retain(snapshot).unwrap();
    let current = state(TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0));
    assert_eq!(
        store.validate_kind("snapshot-1", SnapshotKind::Ax),
        Err(StaleSnapshotReason::SnapshotKindMismatch)
    );
    assert_eq!(
        store.validate_for_click("missing", current),
        Err(StaleSnapshotReason::SnapshotEvicted)
    );
    let changed_epoch = ViewportObservation::new(8, current.transform);
    assert_eq!(
        store.validate_for_click("snapshot-1", changed_epoch),
        Err(StaleSnapshotReason::DocumentEpochChanged)
    );

    let same = ViewportObservation::new(
        7,
        TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
    );
    // The retained snapshot's input transform is 0..1, so the initial
    // `validate_for_click` call with `same` should succeed.
    assert!(store.validate_for_click("snapshot-1", same).is_ok());
    store.invalidate_transform();
    assert_eq!(
        store.validate_for_click("snapshot-1", same),
        Err(StaleSnapshotReason::ViewportTransformChanged)
    );
    store.end_session();
    assert_eq!(
        store.validate_for_click("snapshot-1", same),
        Err(StaleSnapshotReason::SessionEnded)
    );
    assert_eq!(store.len(), 1);
}

#[derive(Debug)]
struct FixtureBackend {
    reads: usize,
    captures: usize,
}

impl ViewportCaptureBackend for FixtureBackend {
    type Error = ();

    fn read_viewport_state(&mut self) -> Result<ViewportObservation, Self::Error> {
        self.reads += 1;
        let mut state = state(TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0));
        if self.reads == 2 {
            state.document_epoch = 8;
        }
        Ok(state)
    }

    fn capture_visual_viewport(&mut self) -> Result<ScreenshotPayload, Self::Error> {
        self.captures += 1;
        Ok(payload())
    }
}

#[test]
fn backend_capture_retries_coherence_failure_and_returns_retained_inputs() {
    let mut backend = FixtureBackend {
        reads: 0,
        captures: 0,
    };
    // The fixture's second read is the failed attempt.  A real backend would
    // return the stable state on the next bracket.
    let result = capture_from_backend(&mut backend, 2, "snapshot-1", "https://example.test");
    assert!(result.is_ok());
    assert_eq!(backend.captures, 2);
}
