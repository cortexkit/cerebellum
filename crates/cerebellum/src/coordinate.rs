//! Screenshot coordinate safety primitives for the browser plane.
//!
//! This module deliberately contains no browser or CDP calls.  The browser adapter
//! supplies the two observations surrounding a viewport capture, and this module
//! accepts a capture only when the observations form one coherent bracket.  Keeping
//! validation and mapping here makes it possible for the adapter to reject bad
//! screenshot metadata before it retains clickable state or dispatches input.

use std::collections::BTreeMap;
use std::fmt;

/// The maximum UTF-8 byte length of a canonical base64 screenshot.
pub const MAX_ENCODED_PNG_BYTES: usize = 16 * 1024 * 1024;
/// Alias named after the wire field's bound.
pub const IMAGE_PNG_B64_BOUND_BYTES: usize = MAX_ENCODED_PNG_BYTES;
/// CSS coordinates are quantized to 1/64 CSS pixel before input dispatch.
pub const CSS_PIXEL_SUBDIVISIONS: f64 = 64.0;

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// Closed coordinate rejection reasons from the browser-plane wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCoordinatesReason {
    PointOutOfBounds,
    NonFiniteMetadata,
    NonPositiveDimensions,
    ConversionFailure,
    /// The caller addressed a differently-sized copy of the image.
    ///
    /// A pixel coordinate means nothing without the image it indexes, and the
    /// two sizes disagreeing is the only evidence available that the caller was
    /// looking at a different one. It is worth refusing rather than scaling,
    /// because a coordinate from a copy this module never produced cannot be
    /// mapped: nothing here knows how that copy was derived.
    ImageSizeMismatch,
}

impl InvalidCoordinatesReason {
    /// What the caller should do, rather than what went wrong.
    ///
    /// A caller told only the name of a rejection still has to work out the
    /// remedy, and the natural guess after a coordinate rejection is to try a
    /// different coordinate, which does not help for any of these.
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::PointOutOfBounds => {
                "address a pixel inside the declared image: 0 <= x < image_width_px and \
                 0 <= y < image_height_px"
            }
            Self::NonFiniteMetadata | Self::ConversionFailure => {
                "take a fresh screenshot: this one's retained geometry cannot be mapped"
            }
            Self::NonPositiveDimensions => {
                "take a fresh screenshot: this one reports no area to address"
            }
            Self::ImageSizeMismatch => {
                "send coordinates in the space of the image this module declared, and pass its \
                 image_width_px and image_height_px. If a model was shown a resized copy, \
                 multiply its coordinates by declared/shown before sending them."
            }
        }
    }

    /// The caller-visible wire spelling of this reason.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::PointOutOfBounds => "point_out_of_bounds",
            Self::NonFiniteMetadata => "non_finite_metadata",
            Self::NonPositiveDimensions => "non_positive_dimensions",
            Self::ConversionFailure => "conversion_failure",
            Self::ImageSizeMismatch => "image_size_mismatch",
        }
    }
}

impl fmt::Display for InvalidCoordinatesReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}

/// Errors selected while validating a screenshot or mapping a pixel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinateError {
    /// The metadata or point cannot be converted into a safe CSS coordinate.
    InvalidCoordinates { reason: InvalidCoordinatesReason },
    /// The canonical base64 field exceeded the wire bound.
    ImageTooLarge {
        encoded_bytes: usize,
        bound_bytes: usize,
    },
    /// Chromium supplied a malformed image or the PNG could not be decoded.
    CdpFailure,
}

impl CoordinateError {
    pub const fn invalid(reason: InvalidCoordinatesReason) -> Self {
        Self::InvalidCoordinates { reason }
    }

    /// Return the wire outcome for callers that serialize this error.
    pub const fn outcome(&self) -> &'static str {
        match self {
            Self::InvalidCoordinates { .. } => "invalid_coordinates",
            Self::ImageTooLarge { .. } => "image_too_large",
            Self::CdpFailure => "internal_error",
        }
    }

    /// Return the detail reason code when this error has one.
    pub const fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::InvalidCoordinates { reason } => Some(reason.reason_code()),
            Self::ImageTooLarge { .. } | Self::CdpFailure => None,
        }
    }
}

impl fmt::Display for CoordinateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCoordinates { reason } => write!(f, "invalid_coordinates: {reason}"),
            Self::ImageTooLarge {
                encoded_bytes,
                bound_bytes,
            } => write!(f, "image_too_large: {encoded_bytes} > {bound_bytes}"),
            Self::CdpFailure => f.write_str("internal_error: cdp_failure"),
        }
    }
}

impl std::error::Error for CoordinateError {}

/// A stale retained screenshot reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleSnapshotReason {
    DocumentEpochChanged,
    ViewportTransformChanged,
    SnapshotKindMismatch,
    SnapshotEvicted,
    SessionEnded,
}

impl StaleSnapshotReason {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::DocumentEpochChanged => "document_epoch_changed",
            Self::ViewportTransformChanged => "viewport_transform_changed",
            Self::SnapshotKindMismatch => "snapshot_kind_mismatch",
            Self::SnapshotEvicted => "snapshot_evicted",
            Self::SessionEnded => "session_ended",
        }
    }
}

impl fmt::Display for StaleSnapshotReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}

/// The axis-aligned rectangle accepted by CDP Input, in CSS coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InputRect {
    pub x_input_css: f64,
    pub y_input_css: f64,
    pub width_input_css: f64,
    pub height_input_css: f64,
}

impl InputRect {
    pub const fn new(
        x_input_css: f64,
        y_input_css: f64,
        width_input_css: f64,
        height_input_css: f64,
    ) -> Self {
        Self {
            x_input_css,
            y_input_css,
            width_input_css,
            height_input_css,
        }
    }

    fn right(self) -> Option<f64> {
        let right = self.x_input_css + self.width_input_css;
        right.is_finite().then_some(right)
    }

    fn bottom(self) -> Option<f64> {
        let bottom = self.y_input_css + self.height_input_css;
        bottom.is_finite().then_some(bottom)
    }
}

/// The six transform inputs retained by a screenshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TransformInputs {
    pub x_input_css: f64,
    pub y_input_css: f64,
    pub width_input_css: f64,
    pub height_input_css: f64,
    pub device_scale_factor: f64,
    pub visual_viewport_scale: f64,
}

impl TransformInputs {
    pub const fn new(
        input_rect: InputRect,
        device_scale_factor: f64,
        visual_viewport_scale: f64,
    ) -> Self {
        Self {
            x_input_css: input_rect.x_input_css,
            y_input_css: input_rect.y_input_css,
            width_input_css: input_rect.width_input_css,
            height_input_css: input_rect.height_input_css,
            device_scale_factor,
            visual_viewport_scale,
        }
    }

    pub const fn from_values(
        x_input_css: f64,
        y_input_css: f64,
        width_input_css: f64,
        height_input_css: f64,
        device_scale_factor: f64,
        visual_viewport_scale: f64,
    ) -> Self {
        Self {
            x_input_css,
            y_input_css,
            width_input_css,
            height_input_css,
            device_scale_factor,
            visual_viewport_scale,
        }
    }

    pub const fn input_rect(self) -> InputRect {
        InputRect::new(
            self.x_input_css,
            self.y_input_css,
            self.width_input_css,
            self.height_input_css,
        )
    }

    /// Compare every transform input by its binary64 bit pattern.
    pub fn bitwise_eq(self, other: Self) -> bool {
        self.x_input_css.to_bits() == other.x_input_css.to_bits()
            && self.y_input_css.to_bits() == other.y_input_css.to_bits()
            && self.width_input_css.to_bits() == other.width_input_css.to_bits()
            && self.height_input_css.to_bits() == other.height_input_css.to_bits()
            && self.device_scale_factor.to_bits() == other.device_scale_factor.to_bits()
            && self.visual_viewport_scale.to_bits() == other.visual_viewport_scale.to_bits()
    }

    /// Validate metadata that is required for every screenshot transform.
    pub fn validate(self) -> Result<(), CoordinateError> {
        let values = [
            self.x_input_css,
            self.y_input_css,
            self.width_input_css,
            self.height_input_css,
            self.device_scale_factor,
            self.visual_viewport_scale,
        ];
        if values.iter().any(|value| !value.is_finite()) {
            return Err(CoordinateError::invalid(
                InvalidCoordinatesReason::NonFiniteMetadata,
            ));
        }
        if self.width_input_css <= 0.0
            || self.height_input_css <= 0.0
            || self.device_scale_factor <= 0.0
            || self.visual_viewport_scale <= 0.0
        {
            return Err(CoordinateError::invalid(
                InvalidCoordinatesReason::NonPositiveDimensions,
            ));
        }
        // The half-open bounds are themselves part of the conversion.  An
        // overflowing right or bottom edge cannot be used safely even though
        // each individual metadata value is finite.
        if self.input_rect().right().is_none() || self.input_rect().bottom().is_none() {
            return Err(CoordinateError::invalid(
                InvalidCoordinatesReason::ConversionFailure,
            ));
        }
        Ok(())
    }

    /// Validate transform metadata and the four mapped corner pixel centers.
    pub fn validate_for_image(
        self,
        image_width_px: u32,
        image_height_px: u32,
    ) -> Result<(), CoordinateError> {
        self.validate()?;
        if image_width_px == 0 || image_height_px == 0 {
            return Err(CoordinateError::invalid(
                InvalidCoordinatesReason::NonPositiveDimensions,
            ));
        }
        let last_x = image_width_px - 1;
        let last_y = image_height_px - 1;
        for (x_px, y_px) in [(0, 0), (last_x, 0), (0, last_y), (last_x, last_y)] {
            map_pixel_center(self, image_width_px, image_height_px, x_px, y_px)?;
        }
        Ok(())
    }
}

/// A document identity/version and the transform-invalidation generation read together.
/// The document epoch changes when the page document is replaced; the generation
/// changes when viewport geometry changes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewportObservation {
    pub document_epoch: u64,
    pub transform: TransformInputs,
    /// A browser adapter increments this when a scroll, resize, zoom, or
    /// visual-viewport event changes the captured transform.  The generation
    /// closes the gap where an event is observed even if a later read happens
    /// to contain numerically equal values.
    pub transform_invalidation_generation: u64,
}

impl ViewportObservation {
    pub const fn new(document_epoch: u64, transform: TransformInputs) -> Self {
        Self {
            document_epoch,
            transform,
            transform_invalidation_generation: 0,
        }
    }

    pub const fn with_invalidation_generation(mut self, generation: u64) -> Self {
        self.transform_invalidation_generation = generation;
        self
    }

    pub fn coherent_with(self, other: Self, invalidation_observed: bool) -> bool {
        self.document_epoch == other.document_epoch
            && self.transform.bitwise_eq(other.transform)
            && self.transform_invalidation_generation == other.transform_invalidation_generation
            && !invalidation_observed
    }
}

/// A screenshot payload obtained from Chromium before validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenshotPayload {
    pub image_png_b64: String,
    pub image_width_px: u32,
    pub image_height_px: u32,
}

impl ScreenshotPayload {
    pub fn new(
        image_png_b64: impl Into<String>,
        image_width_px: u32,
        image_height_px: u32,
    ) -> Self {
        Self {
            image_png_b64: image_png_b64.into(),
            image_width_px,
            image_height_px,
        }
    }
}

/// The validated decoded PNG and dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPng {
    bytes: Vec<u8>,
    width_px: u32,
    height_px: u32,
}

impl ValidatedPng {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub const fn width_px(&self) -> u32 {
        self.width_px
    }

    pub const fn height_px(&self) -> u32 {
        self.height_px
    }
}

/// A coherent, validated capture that has not yet been retained.
#[derive(Debug, Clone, PartialEq)]
pub struct CoherentScreenshot {
    pub image_png_b64: String,
    pub image_width_px: u32,
    pub image_height_px: u32,
    pub png_bytes: Vec<u8>,
    pub document_epoch: u64,
    pub transform: TransformInputs,
    pub transform_invalidation_generation: u64,
}

impl CoherentScreenshot {
    pub fn into_snapshot(
        self,
        snapshot_id: impl Into<String>,
        source_origin: impl Into<String>,
    ) -> ScreenshotSnapshot {
        ScreenshotSnapshot {
            snapshot_id: snapshot_id.into(),
            document_epoch: self.document_epoch,
            source_origin: source_origin.into(),
            image_png_b64: self.image_png_b64,
            image_width_px: self.image_width_px,
            image_height_px: self.image_height_px,
            input_rect: self.transform.input_rect(),
            device_scale_factor: self.transform.device_scale_factor,
            visual_viewport_scale: self.transform.visual_viewport_scale,
            png_bytes: self.png_bytes,
            transform_invalidation_generation: self.transform_invalidation_generation,
        }
    }
}

/// A retained clickable screenshot and all inputs needed to reuse its mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct ScreenshotSnapshot {
    pub snapshot_id: String,
    pub document_epoch: u64,
    pub source_origin: String,
    pub image_png_b64: String,
    pub image_width_px: u32,
    pub image_height_px: u32,
    pub input_rect: InputRect,
    pub device_scale_factor: f64,
    pub visual_viewport_scale: f64,
    /// Exact decoded PNG bytes retained alongside the returned base64 field.
    pub png_bytes: Vec<u8>,
    pub transform_invalidation_generation: u64,
}

impl ScreenshotSnapshot {
    /// Construct and validate a retained screenshot from its wire fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: impl Into<String>,
        document_epoch: u64,
        source_origin: impl Into<String>,
        image_png_b64: impl Into<String>,
        image_width_px: u32,
        image_height_px: u32,
        input_rect: InputRect,
        device_scale_factor: f64,
        visual_viewport_scale: f64,
    ) -> Result<Self, CoordinateError> {
        Self::new_with_generation(
            snapshot_id,
            document_epoch,
            source_origin,
            image_png_b64,
            image_width_px,
            image_height_px,
            input_rect,
            device_scale_factor,
            visual_viewport_scale,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_generation(
        snapshot_id: impl Into<String>,
        document_epoch: u64,
        source_origin: impl Into<String>,
        image_png_b64: impl Into<String>,
        image_width_px: u32,
        image_height_px: u32,
        input_rect: InputRect,
        device_scale_factor: f64,
        visual_viewport_scale: f64,
        transform_invalidation_generation: u64,
    ) -> Result<Self, CoordinateError> {
        let image_png_b64 = image_png_b64.into();
        let png = validate_png_base64(&image_png_b64, image_width_px, image_height_px)?;
        let transform =
            TransformInputs::new(input_rect, device_scale_factor, visual_viewport_scale);
        transform.validate_for_image(image_width_px, image_height_px)?;
        Ok(Self {
            snapshot_id: snapshot_id.into(),
            document_epoch,
            source_origin: source_origin.into(),
            image_png_b64,
            image_width_px,
            image_height_px,
            input_rect,
            device_scale_factor,
            visual_viewport_scale,
            png_bytes: png.into_bytes(),
            transform_invalidation_generation,
        })
    }

    pub fn transform(&self) -> TransformInputs {
        TransformInputs::new(
            self.input_rect,
            self.device_scale_factor,
            self.visual_viewport_scale,
        )
    }

    /// Validate the snapshot immediately before a point click.
    pub fn validate_for_click(
        &self,
        current: ViewportObservation,
        session_ended: bool,
    ) -> Result<(), StaleSnapshotReason> {
        if session_ended {
            return Err(StaleSnapshotReason::SessionEnded);
        }
        if self.document_epoch != current.document_epoch {
            return Err(StaleSnapshotReason::DocumentEpochChanged);
        }
        if self.transform_invalidation_generation != current.transform_invalidation_generation
            || !self.transform().bitwise_eq(current.transform)
        {
            return Err(StaleSnapshotReason::ViewportTransformChanged);
        }
        Ok(())
    }

    pub fn map_pixel<X, Y>(&self, x_px: X, y_px: Y) -> Result<PixelCenter, CoordinateError>
    where
        X: TryInto<i128> + Copy,
        Y: TryInto<i128> + Copy,
    {
        map_pixel_center(
            self.transform(),
            self.image_width_px,
            self.image_height_px,
            x_px,
            y_px,
        )
    }
}

/// The CSS location of a mapped image-pixel center.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PixelCenter {
    pub x_css: f64,
    pub y_css: f64,
}

impl PixelCenter {
    pub const fn new(x_css: f64, y_css: f64) -> Self {
        Self { x_css, y_css }
    }

    pub const fn tuple(self) -> (f64, f64) {
        (self.x_css, self.y_css)
    }
}

/// Validate that two viewport reads bracket one unchanged capture, then validate
/// the canonical PNG.  No retained screenshot is produced on any rejection.
pub fn capture_screenshot(
    before: ViewportObservation,
    payload: ScreenshotPayload,
    after: ViewportObservation,
    invalidation_observed: bool,
) -> Result<CoherentScreenshot, CoordinateError> {
    before.transform.validate()?;
    after.transform.validate()?;

    if !before.coherent_with(after, invalidation_observed) {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::ConversionFailure,
        ));
    }

    let png = validate_png_base64(
        &payload.image_png_b64,
        payload.image_width_px,
        payload.image_height_px,
    )?;
    before
        .transform
        .validate_for_image(payload.image_width_px, payload.image_height_px)?;

    Ok(CoherentScreenshot {
        image_png_b64: payload.image_png_b64,
        image_width_px: payload.image_width_px,
        image_height_px: payload.image_height_px,
        png_bytes: png.into_bytes(),
        document_epoch: before.document_epoch,
        transform: before.transform,
        transform_invalidation_generation: before.transform_invalidation_generation,
    })
}

/// A source capable of providing the two reads and a visual-viewport capture.
///
/// The adapter's invalidation generation is sampled on both sides of the capture;
/// a generation change is therefore rejected even if the final numeric transform
/// happens to equal the initial one.
pub trait ViewportCaptureBackend {
    type Error;

    fn read_viewport_state(&mut self) -> Result<ViewportObservation, Self::Error>;
    fn capture_visual_viewport(&mut self) -> Result<ScreenshotPayload, Self::Error>;

    fn transform_invalidation_generation(&self) -> u64 {
        0
    }
}

/// Capture through a browser adapter, retrying only an incoherent bracket.
pub fn capture_from_backend<B>(
    backend: &mut B,
    max_attempts: usize,
    snapshot_id: impl Into<String>,
    source_origin: impl Into<String>,
) -> Result<ScreenshotSnapshot, CoordinateError>
where
    B: ViewportCaptureBackend,
    B::Error: fmt::Debug,
{
    let attempts = max_attempts.max(1);
    let snapshot_id = snapshot_id.into();
    let source_origin = source_origin.into();

    for attempt in 0..attempts {
        let mut before = backend
            .read_viewport_state()
            .map_err(|_| CoordinateError::CdpFailure)?;
        before.transform_invalidation_generation = backend.transform_invalidation_generation();
        before.transform.validate()?;

        let payload = backend
            .capture_visual_viewport()
            .map_err(|_| CoordinateError::CdpFailure)?;

        let mut after = backend
            .read_viewport_state()
            .map_err(|_| CoordinateError::CdpFailure)?;
        after.transform_invalidation_generation = backend.transform_invalidation_generation();

        match capture_screenshot(before, payload, after, false) {
            Ok(capture) => return Ok(capture.into_snapshot(&snapshot_id, &source_origin)),
            Err(CoordinateError::InvalidCoordinates {
                reason: InvalidCoordinatesReason::ConversionFailure,
            }) if attempt + 1 < attempts => continue,
            Err(error) => return Err(error),
        }
    }

    Err(CoordinateError::invalid(
        InvalidCoordinatesReason::ConversionFailure,
    ))
}

/// A small session-scoped store for retained clickable screenshots.
#[derive(Debug)]
pub struct ScreenshotStore {
    max_count: usize,
    snapshots: BTreeMap<String, ScreenshotSnapshot>,
    insertion_order: Vec<String>,
    transform_invalidation_generation: u64,
    session_ended: bool,
}

impl ScreenshotStore {
    pub fn new(max_count: usize) -> Result<Self, CoordinateError> {
        if max_count == 0 {
            return Err(CoordinateError::invalid(
                InvalidCoordinatesReason::NonPositiveDimensions,
            ));
        }
        Ok(Self {
            max_count,
            snapshots: BTreeMap::new(),
            insertion_order: Vec::new(),
            transform_invalidation_generation: 0,
            session_ended: false,
        })
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    pub fn transform_invalidation_generation(&self) -> u64 {
        self.transform_invalidation_generation
    }

    /// Retain only an already validated screenshot.  The store is not touched by
    /// validation failures, so rejected captures cannot leave clickable state.
    pub fn retain(&mut self, mut snapshot: ScreenshotSnapshot) -> Result<(), CoordinateError> {
        if self.session_ended {
            return Err(CoordinateError::invalid(
                InvalidCoordinatesReason::ConversionFailure,
            ));
        }
        let png = validate_png_base64(
            &snapshot.image_png_b64,
            snapshot.image_width_px,
            snapshot.image_height_px,
        )?;
        snapshot
            .transform()
            .validate_for_image(snapshot.image_width_px, snapshot.image_height_px)?;
        snapshot.png_bytes = png.into_bytes();
        snapshot.transform_invalidation_generation = self.transform_invalidation_generation;
        if self.snapshots.contains_key(&snapshot.snapshot_id) {
            self.snapshots
                .insert(snapshot.snapshot_id.clone(), snapshot);
            return Ok(());
        }
        if self.snapshots.len() >= self.max_count {
            let Some(oldest) = self.insertion_order.first().cloned() else {
                return Err(CoordinateError::invalid(
                    InvalidCoordinatesReason::ConversionFailure,
                ));
            };
            self.snapshots.remove(&oldest);
            self.insertion_order.remove(0);
        }
        self.insertion_order.push(snapshot.snapshot_id.clone());
        self.snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    pub fn get(&self, snapshot_id: &str) -> Option<&ScreenshotSnapshot> {
        self.snapshots.get(snapshot_id)
    }

    pub fn remove(&mut self, snapshot_id: &str) -> Option<ScreenshotSnapshot> {
        let removed = self.snapshots.remove(snapshot_id);
        if removed.is_some() {
            self.insertion_order.retain(|id| id != snapshot_id);
        }
        removed
    }

    /// Mark every retained screenshot stale after a transform-changing event.
    pub fn invalidate_transform(&mut self) {
        self.transform_invalidation_generation =
            self.transform_invalidation_generation.wrapping_add(1);
    }

    pub fn end_session(&mut self) {
        self.session_ended = true;
    }

    pub fn validate_for_click(
        &self,
        snapshot_id: &str,
        current: ViewportObservation,
    ) -> Result<&ScreenshotSnapshot, StaleSnapshotReason> {
        if self.session_ended {
            return Err(StaleSnapshotReason::SessionEnded);
        }
        let snapshot = self
            .snapshots
            .get(snapshot_id)
            .ok_or(StaleSnapshotReason::SnapshotEvicted)?;
        if snapshot.transform_invalidation_generation != self.transform_invalidation_generation {
            return Err(StaleSnapshotReason::ViewportTransformChanged);
        }
        snapshot
            .validate_for_click(current, self.session_ended)
            .map(|()| snapshot)
    }

    /// Validate the retained kind before looking at transform state.
    pub fn validate_kind(
        &self,
        snapshot_id: &str,
        kind: SnapshotKind,
    ) -> Result<(), StaleSnapshotReason> {
        if !self.snapshots.contains_key(snapshot_id) {
            return Err(StaleSnapshotReason::SnapshotEvicted);
        }
        if kind != SnapshotKind::Screenshot {
            return Err(StaleSnapshotReason::SnapshotKindMismatch);
        }
        Ok(())
    }
}

/// Snapshot kinds used by the shared retention layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    Ax,
    DomFull,
    Screenshot,
}

/// Strict RFC 4648 base64 plus PNG structure and dimension validation.
pub fn validate_png_base64(
    encoded: &str,
    expected_width_px: u32,
    expected_height_px: u32,
) -> Result<ValidatedPng, CoordinateError> {
    if encoded.len() > MAX_ENCODED_PNG_BYTES {
        return Err(CoordinateError::ImageTooLarge {
            encoded_bytes: encoded.len(),
            bound_bytes: MAX_ENCODED_PNG_BYTES,
        });
    }
    if expected_width_px == 0 || expected_height_px == 0 {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::NonPositiveDimensions,
        ));
    }

    let bytes = decode_canonical_base64(encoded).ok_or(CoordinateError::CdpFailure)?;
    validate_png_bytes(&bytes, expected_width_px, expected_height_px)
        .map_err(|_| CoordinateError::CdpFailure)?;
    Ok(ValidatedPng {
        bytes,
        width_px: expected_width_px,
        height_px: expected_height_px,
    })
}

/// Alias of [`validate_png_base64`] for callers that use the wire-level
/// operation name `validate_canonical_png`.
pub fn validate_canonical_png(
    encoded: &str,
    expected_width_px: u32,
    expected_height_px: u32,
) -> Result<ValidatedPng, CoordinateError> {
    validate_png_base64(encoded, expected_width_px, expected_height_px)
}

/// Encode bytes using the exact canonical base64 representation accepted above.
pub fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(a >> 2) as usize] as char);
        output.push(ALPHABET[((a & 0x03) << 4 | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((b & 0x0f) << 2 | (c >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(c & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn decode_canonical_base64(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let bytes = input.as_bytes();
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 || (padding > 0 && bytes.len() < 4) {
        return None;
    }
    if bytes[..bytes.len().saturating_sub(padding)]
        .iter()
        .any(|byte| decode_base64_char(*byte).is_none())
    {
        return None;
    }
    if bytes[bytes.len().saturating_sub(padding)..]
        .iter()
        .any(|byte| *byte != b'=')
    {
        return None;
    }

    let mut output = Vec::with_capacity(bytes.len() / 4 * 3 - padding);
    for (index, quartet) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let a = decode_base64_char(quartet[0])?;
        let b = decode_base64_char(quartet[1])?;
        let c = if quartet[2] == b'=' {
            if !last || quartet[3] != b'=' {
                return None;
            }
            0
        } else {
            decode_base64_char(quartet[2])?
        };
        let d = if quartet[3] == b'=' {
            if !last {
                return None;
            }
            0
        } else {
            decode_base64_char(quartet[3])?
        };
        output.push((a << 2) | (b >> 4));
        if quartet[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if quartet[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    // Re-encoding catches omitted padding and non-zero unused bits, both of
    // which otherwise decode to the same bytes but are not canonical RFC 4648.
    (encode_base64(&output) == input).then_some(output)
}

fn decode_base64_char(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn validate_png_bytes(
    bytes: &[u8],
    expected_width_px: u32,
    expected_height_px: u32,
) -> Result<(), ()> {
    if bytes.len() < PNG_SIGNATURE.len() || bytes[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
        return Err(());
    }
    let mut offset = PNG_SIGNATURE.len();
    let mut seen_ihdr = false;
    let mut seen_idat = false;
    let mut seen_iend = false;
    let mut width = None;
    let mut height = None;

    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(());
        }
        let length =
            u32::from_be_bytes(bytes[offset..offset + 4].try_into().map_err(|_| ())?) as usize;
        let chunk_end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
            .ok_or(())?;
        if chunk_end > bytes.len() {
            return Err(());
        }
        let chunk_type = &bytes[offset + 4..offset + 8];
        if !chunk_type.iter().all(|byte| byte.is_ascii_alphabetic())
            || chunk_type[2].is_ascii_lowercase()
        {
            return Err(());
        }
        let data_start = offset + 8;
        let data_end = data_start + length;
        let data = &bytes[data_start..data_end];
        let stored_crc = u32::from_be_bytes(bytes[data_end..chunk_end].try_into().map_err(|_| ())?);
        let mut crc_input = Vec::with_capacity(4 + data.len());
        crc_input.extend_from_slice(chunk_type);
        crc_input.extend_from_slice(data);
        if png_crc32(&crc_input) != stored_crc {
            return Err(());
        }

        match chunk_type {
            b"IHDR" => {
                if seen_ihdr || offset != PNG_SIGNATURE.len() || length != 13 {
                    return Err(());
                }
                let chunk_width = u32::from_be_bytes(data[0..4].try_into().map_err(|_| ())?);
                let chunk_height = u32::from_be_bytes(data[4..8].try_into().map_err(|_| ())?);
                if chunk_width == 0 || chunk_height == 0 || !valid_ihdr(data) {
                    return Err(());
                }
                width = Some(chunk_width);
                height = Some(chunk_height);
                seen_ihdr = true;
            }
            b"IDAT" => {
                if !seen_ihdr || seen_iend {
                    return Err(());
                }
                seen_idat = true;
            }
            b"IEND" => {
                if !seen_ihdr || !seen_idat || seen_iend || length != 0 {
                    return Err(());
                }
                seen_iend = true;
                if chunk_end != bytes.len() {
                    return Err(());
                }
            }
            _ => {
                if !seen_ihdr || seen_iend {
                    return Err(());
                }
            }
        }
        offset = chunk_end;
    }

    if !seen_ihdr || !seen_idat || !seen_iend {
        return Err(());
    }
    if width != Some(expected_width_px) || height != Some(expected_height_px) {
        return Err(());
    }
    Ok(())
}

fn valid_ihdr(data: &[u8]) -> bool {
    if data.len() != 13 {
        return false;
    }
    let bit_depth = data[8];
    let color_type = data[9];
    let compression = data[10];
    let filter = data[11];
    let interlace = data[12];
    if compression != 0 || filter != 0 || interlace > 1 {
        return false;
    }
    match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        2 => matches!(bit_depth, 8 | 16),
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),
        4 | 6 => matches!(bit_depth, 8 | 16),
        _ => false,
    }
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Round a finite CSS coordinate to the nearest 1/64 pixel, with ties toward
/// positive infinity (including negative values).
pub fn round_css_pixel(value: f64) -> Result<f64, CoordinateError> {
    if !value.is_finite() {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::ConversionFailure,
        ));
    }
    let scaled = value * CSS_PIXEL_SUBDIVISIONS;
    if !scaled.is_finite() {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::ConversionFailure,
        ));
    }
    let lower = scaled.floor();
    let fraction = scaled - lower;
    let units = if fraction >= 0.5 { lower + 1.0 } else { lower };
    let rounded = units / CSS_PIXEL_SUBDIVISIONS;
    rounded
        .is_finite()
        .then_some(rounded)
        .ok_or_else(|| CoordinateError::invalid(InvalidCoordinatesReason::ConversionFailure))
}

/// Map the addressed image-pixel center through the retained transform.
pub fn map_pixel_center<X, Y>(
    transform: TransformInputs,
    image_width_px: u32,
    image_height_px: u32,
    x_px: X,
    y_px: Y,
) -> Result<PixelCenter, CoordinateError>
where
    X: TryInto<i128> + Copy,
    Y: TryInto<i128> + Copy,
{
    transform.validate()?;
    if image_width_px == 0 || image_height_px == 0 {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::NonPositiveDimensions,
        ));
    }
    let x_px: i128 = x_px
        .try_into()
        .ok()
        .ok_or_else(|| CoordinateError::invalid(InvalidCoordinatesReason::PointOutOfBounds))?;
    let y_px: i128 = y_px
        .try_into()
        .ok()
        .ok_or_else(|| CoordinateError::invalid(InvalidCoordinatesReason::PointOutOfBounds))?;
    if x_px < 0
        || y_px < 0
        || x_px >= i128::from(image_width_px)
        || y_px >= i128::from(image_height_px)
    {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::PointOutOfBounds,
        ));
    }

    let x_ratio = (x_px as f64 + 0.5) * transform.width_input_css / f64::from(image_width_px);
    let y_ratio = (y_px as f64 + 0.5) * transform.height_input_css / f64::from(image_height_px);
    let x_unrounded = transform.x_input_css + x_ratio;
    let y_unrounded = transform.y_input_css + y_ratio;
    if !x_ratio.is_finite()
        || !y_ratio.is_finite()
        || !x_unrounded.is_finite()
        || !y_unrounded.is_finite()
    {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::ConversionFailure,
        ));
    }
    let x_css = round_css_pixel(x_unrounded)?;
    let y_css = round_css_pixel(y_unrounded)?;
    let rect = transform.input_rect();
    let right = rect
        .right()
        .ok_or_else(|| CoordinateError::invalid(InvalidCoordinatesReason::ConversionFailure))?;
    let bottom = rect
        .bottom()
        .ok_or_else(|| CoordinateError::invalid(InvalidCoordinatesReason::ConversionFailure))?;
    if x_css < rect.x_input_css || x_css >= right || y_css < rect.y_input_css || y_css >= bottom {
        return Err(CoordinateError::invalid(
            InvalidCoordinatesReason::ConversionFailure,
        ));
    }
    Ok(PixelCenter::new(x_css, y_css))
}

/// Explicit tuple-returning spelling useful to CDP adapters.
pub fn map_pixel_to_css<X, Y>(
    transform: TransformInputs,
    image_width_px: u32,
    image_height_px: u32,
    x_px: X,
    y_px: Y,
) -> Result<(f64, f64), CoordinateError>
where
    X: TryInto<i128> + Copy,
    Y: TryInto<i128> + Copy,
{
    map_pixel_center(transform, image_width_px, image_height_px, x_px, y_px).map(PixelCenter::tuple)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transform() -> TransformInputs {
        TransformInputs::from_values(10.0, 20.0, 100.0, 50.0, 2.0, 1.25)
    }

    fn png_1x1() -> Vec<u8> {
        // A valid RGBA 1x1 PNG.  The validator intentionally checks structure
        // and CRCs without decoding pixels, so this compact fixture is enough.
        const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";
        let mut bytes = Vec::new();
        let encoded = PNG.as_bytes();
        for quartet in encoded.chunks(4) {
            let values = quartet
                .iter()
                .map(|byte| decode_base64_char(*byte).unwrap_or(0))
                .collect::<Vec<_>>();
            bytes.push((values[0] << 2) | (values[1] >> 4));
            if quartet[2] != b'=' {
                bytes.push((values[1] << 4) | (values[2] >> 2));
            }
            if quartet[3] != b'=' {
                bytes.push((values[2] << 6) | values[3]);
            }
        }
        bytes
    }

    #[test]
    fn pixel_centers_use_input_rect_without_scale_multiplication() {
        let center = map_pixel_center(transform(), 100, 50, 0u32, 0u32).unwrap();
        assert_eq!(center, PixelCenter::new(10.5, 20.5));
        let center = map_pixel_center(transform(), 100, 50, 99u32, 49u32).unwrap();
        assert_eq!(center, PixelCenter::new(109.5, 69.5));
    }

    #[test]
    fn fractional_ties_round_toward_positive_infinity() {
        let t = TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0);
        let center = map_pixel_center(t, 128, 128, 63u32, 63u32).unwrap();
        assert_eq!(center.x_css, 0.5);
        assert_eq!(center.y_css, 0.5);
        assert_eq!(round_css_pixel(-0.0078125).unwrap(), 0.0);
        assert_eq!(round_css_pixel(-0.0234375).unwrap(), -0.015625);
    }

    #[test]
    fn malformed_or_mismatched_png_is_cdp_failure() {
        let encoded = encode_base64(&png_1x1());
        assert!(validate_png_base64(&encoded, 1, 1).is_ok());
        assert_eq!(
            validate_png_base64(&encoded, 2, 1),
            Err(CoordinateError::CdpFailure)
        );
        let mut bytes = png_1x1();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            validate_png_base64(&encode_base64(&bytes), 1, 1),
            Err(CoordinateError::CdpFailure)
        );
    }

    #[test]
    fn bracket_rejects_epoch_transform_and_event_changes() {
        let before = ViewportObservation::new(1, transform());
        let mut after = before;
        after.document_epoch = 2;
        assert_eq!(
            capture_screenshot(
                before,
                ScreenshotPayload::new(encode_base64(&png_1x1()), 1, 1),
                after,
                false
            ),
            Err(CoordinateError::invalid(
                InvalidCoordinatesReason::ConversionFailure
            ))
        );
        let after = before.with_invalidation_generation(1);
        assert!(capture_screenshot(
            before,
            ScreenshotPayload::new(encode_base64(&png_1x1()), 1, 1),
            after,
            false
        )
        .is_err());
    }

    #[test]
    fn store_invalidation_stales_without_removing_bytes() {
        let encoded = encode_base64(&png_1x1());
        let snapshot = ScreenshotSnapshot::new(
            "snap",
            1,
            "https://example.test",
            encoded,
            1,
            1,
            InputRect::new(0.0, 0.0, 1.0, 1.0),
            1.0,
            1.0,
        )
        .unwrap();
        let mut store = ScreenshotStore::new(1).unwrap();
        store.retain(snapshot).unwrap();
        store.invalidate_transform();
        let state = ViewportObservation::new(
            1,
            TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
        );
        assert_eq!(
            store.validate_for_click("snap", state),
            Err(StaleSnapshotReason::ViewportTransformChanged)
        );
        assert_eq!(store.len(), 1);
    }
}
