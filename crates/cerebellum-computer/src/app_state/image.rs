//! The one window image a state read may return: its size, how its pixels
//! map back to the screen, and the custody it passes through before any of
//! its bytes leave the module.

/// Why a requested image is missing from a reply that still carries its tree.
/// Every way the image can fail has its own word, so a custody or audit
/// failure is never reported as a capture or scaling failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageUnavailable {
    /// Screen Recording is not usable by this process right now.
    ScreenRecordingNotLive,
    /// The application has no on-screen window to capture.
    NoWindowCaptured,
    /// This host has no capture backend, or it could not be set up.
    CaptureUnavailable,
    /// The window server refused or failed the capture.
    CaptureFailed,
    /// Custody refused to prepare for the capture before it was taken.
    CaptureNotAdmitted,
    /// Custody refused to retain the captured image.
    CaptureNotRetained,
    /// Capture custody is unusable in this module process.
    CustodyUnavailable,
    /// The journal could not reserve, commit or finalize the capture's record.
    AuditUnavailable,
    /// The capture had no area, so there is no size to scale it to.
    ImageNotScalable,
    /// Chromium may have stopped painting while the window was covered.
    WindowCoveredMayBeStale,
    /// Fronting an image read requires the conversation's machine takeover grant.
    ImageNeedsTakeover,
    /// The capture front/restore interval exceeded the image read's own bound.
    FrontingBoundExceeded,
    /// The observed fronting bracket could not complete.
    FrontingUnavailable,
    /// The previous frontmost application could not be restored.
    RestoreFailed,
}

impl ImageUnavailable {
    pub const ALL: [Self; 14] = [
        Self::ScreenRecordingNotLive,
        Self::NoWindowCaptured,
        Self::CaptureUnavailable,
        Self::CaptureFailed,
        Self::CaptureNotAdmitted,
        Self::CaptureNotRetained,
        Self::CustodyUnavailable,
        Self::AuditUnavailable,
        Self::ImageNotScalable,
        Self::WindowCoveredMayBeStale,
        Self::ImageNeedsTakeover,
        Self::FrontingBoundExceeded,
        Self::FrontingUnavailable,
        Self::RestoreFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScreenRecordingNotLive => "screen_recording_not_live",
            Self::NoWindowCaptured => "no_window_captured",
            Self::CaptureUnavailable => "capture_unavailable",
            Self::CaptureFailed => "capture_failed",
            Self::CaptureNotAdmitted => "capture_not_admitted",
            Self::CaptureNotRetained => "capture_not_retained",
            Self::CustodyUnavailable => "custody_unavailable",
            Self::AuditUnavailable => "audit_unavailable",
            Self::ImageNotScalable => "image_not_scalable",
            Self::WindowCoveredMayBeStale => "window_covered_may_be_stale",
            Self::ImageNeedsTakeover => "image_needs_takeover",
            Self::FrontingBoundExceeded => "fronting_bound_exceeded",
            Self::FrontingUnavailable => "fronting_unavailable",
            Self::RestoreFailed => "restore_failed",
        }
    }
}

/// Text-free deciding visibility rule, not a guess derived from missing pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageDecision {
    Unknown,
    TargetAbsent,
    TargetTransparent,
    OutsideDisplays,
    CoveredByWindow,
    FullyOverlaid,
    FullyVisible,
    FrontedThenVisible,
}

/// Aggregate front/restore facts; never window or element text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImageFronting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_frontmost: Option<u32>,
    pub attempted: bool,
    pub restored: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_in_front: Option<u32>,
    pub longest_fronted_interval_ms: u64,
}

impl From<&crate::dispatch::BracketReport> for ImageFronting {
    fn from(report: &crate::dispatch::BracketReport) -> Self {
        use crate::dispatch::RestoreStatus;
        // Every variant is named, so a new one cannot compile into a silent
        // `left_in_front: None`. A restore skipped because the person
        // switched applications is not a restore, and what they switched to
        // is what was left in front.
        let (restored, left_in_front) = match report.restore {
            RestoreStatus::NotNeeded | RestoreStatus::Restored => (true, None),
            RestoreStatus::Failed { left_in_front } => (false, left_in_front),
            RestoreStatus::SkippedPerson { now_front } => (false, now_front),
        };
        Self {
            previous_frontmost: report.previous_frontmost,
            attempted: report.chunks > 0,
            restored,
            left_in_front,
            longest_fronted_interval_ms: report.longest_fronted_interval_ms,
        }
    }
}

/// The width and height a JPEG says it has, read from its frame header.
///
/// Read from the encoded bytes rather than carried from the encoder's
/// request, so the dimensions a reply states are the ones a reader of the
/// image will see even if an encoder chose differently.
pub fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..2)? != [0xFF, 0xD8] {
        return None;
    }
    let mut at = 2;
    loop {
        // Markers may be preceded by any number of fill bytes.
        while *bytes.get(at)? == 0xFF && *bytes.get(at + 1)? == 0xFF {
            at += 1;
        }
        if *bytes.get(at)? != 0xFF {
            return None;
        }
        let marker = *bytes.get(at + 1)?;
        at += 2;
        match marker {
            // Markers that stand alone, with no length.
            0x01 | 0xD0..=0xD7 => continue,
            // End of image, or start of scan data, before any frame header.
            0xD9 | 0xDA => return None,
            _ => {}
        }
        let length = usize::from(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]));
        if length < 2 {
            return None;
        }
        let is_frame_header =
            matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC);
        if is_frame_header {
            let height = u16::from_be_bytes([*bytes.get(at + 3)?, *bytes.get(at + 4)?]);
            let width = u16::from_be_bytes([*bytes.get(at + 5)?, *bytes.get(at + 6)?]);
            return Some((u32::from(width), u32::from(height)));
        }
        at += length;
    }
}

/// How a pixel of a returned image maps to a point on the desktop.
///
/// Recorded when the image is made, because a point an agent reads off the
/// image is in the image's own pixel space, and every step between that and
/// the screen is a fact of the capture:
///
/// `desktop = window_origin + (crop_origin + pixel / scale) / backing_scale`
///
/// where `scale` is the image's pixels per captured pixel (at most one, since
/// images are only ever scaled down), `crop_origin` is where in the captured
/// window the image begins (zero for a whole window), and `backing_scale` is
/// captured pixels per window point.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImageMapping {
    pub window_origin_x: f64,
    pub window_origin_y: f64,
    pub crop_origin_x: f64,
    pub crop_origin_y: f64,
    pub scale: f64,
    pub backing_scale: f64,
}

impl ImageMapping {
    /// The mapping for a whole-window capture of a window at `origin` whose
    /// size is `window_points`, captured at `captured_px` pixels and scaled to
    /// `image_px`. `None` when any dimension is zero, since no mapping exists.
    pub fn for_window(
        origin: (f64, f64),
        window_points: (f64, f64),
        captured_px: (u32, u32),
        image_px: (u32, u32),
    ) -> Option<Self> {
        if window_points.0 <= 0.0 || captured_px.0 == 0 || image_px.0 == 0 {
            return None;
        }
        Some(Self {
            window_origin_x: origin.0,
            window_origin_y: origin.1,
            crop_origin_x: 0.0,
            crop_origin_y: 0.0,
            scale: f64::from(image_px.0) / f64::from(captured_px.0),
            backing_scale: f64::from(captured_px.0) / window_points.0,
        })
    }

    /// The desktop point an image pixel shows.
    pub fn pixel_to_desktop(&self, x_px: f64, y_px: f64) -> (f64, f64) {
        (
            self.window_origin_x + (self.crop_origin_x + x_px / self.scale) / self.backing_scale,
            self.window_origin_y + (self.crop_origin_y + y_px / self.scale) / self.backing_scale,
        )
    }
}

/// One window's capture as the backend produced it, before custody.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowImageCapture {
    pub window_id: String,
    pub owning_pid: u32,
    /// The window's desktop origin and size, in points.
    pub window_origin: (f64, f64),
    pub window_points: (f64, f64),
    /// The size the window was captured at, before scaling.
    pub captured_px: (u32, u32),
    /// The scaled image, JPEG-encoded.
    pub jpeg: Vec<u8>,
}

/// An image cleared for release: custody holds it and its record is final.
#[derive(Debug, Clone, PartialEq)]
pub struct ReleasedImage {
    /// The captured window's identity as the capture backend named it; on
    /// macOS its window-server number.
    pub window_id: String,
    pub jpeg: Vec<u8>,
    pub width_px: u32,
    pub height_px: u32,
    pub mapping: ImageMapping,
}

/// Why custody would not retain an image. Kept apart from a custody fault,
/// which says the module itself cannot hold images at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainFailure {
    NotRetained,
    CustodyUnavailable,
}

/// A custody or journal step refused; which step says why the image is
/// missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyStepFailed;

/// The custody and journal steps an image passes through, in order.
///
/// A trait so every failure between capture and release can be driven by a
/// test: the real implementation is the computer audit, whose custody and
/// journal failures are hard to produce on demand.
pub trait ImageCustody {
    type Reservation;
    type Admission;

    /// Reserve the journal record the capture will be accounted to.
    fn reserve(&mut self) -> Result<Self::Reservation, CustodyStepFailed>;
    /// Ask custody to accept a capture for that record.
    fn prepare(
        &mut self,
        reservation: &Self::Reservation,
    ) -> Result<Self::Admission, CustodyStepFailed>;
    /// Hand the image to custody and confirm custody holds it.
    fn retain(
        &mut self,
        admission: Self::Admission,
        capture: &WindowImageCapture,
        width_px: u32,
        height_px: u32,
    ) -> Result<(), RetainFailure>;
    /// Commit and finalize the record.
    fn finalize(&mut self, reservation: Self::Reservation) -> Result<(), CustodyStepFailed>;
    /// Close the record as rejected, naming why.
    fn reject(&mut self, reservation: Self::Reservation, reason: ImageUnavailable);
}

/// Take one window image through custody, and release it only after custody
/// retains it and its journal record is final.
///
/// The capture runs after the record is reserved and custody has agreed to
/// accept it, so there are never pixels the journal has not made room for.
/// Every failure closes the record and returns the reason, with no bytes.
pub fn release_through_custody<C: ImageCustody>(
    custody: &mut C,
    capture: impl FnOnce() -> Result<WindowImageCapture, ImageUnavailable>,
) -> Result<ReleasedImage, ImageUnavailable> {
    let reservation = custody
        .reserve()
        .map_err(|CustodyStepFailed| ImageUnavailable::AuditUnavailable)?;
    let admission = match custody.prepare(&reservation) {
        Ok(admission) => admission,
        Err(CustodyStepFailed) => {
            custody.reject(reservation, ImageUnavailable::CaptureNotAdmitted);
            return Err(ImageUnavailable::CaptureNotAdmitted);
        }
    };
    let captured = match capture() {
        Ok(captured) => captured,
        Err(reason) => {
            custody.reject(reservation, reason);
            return Err(reason);
        }
    };
    if captured.captured_px.0 == 0 || captured.captured_px.1 == 0 {
        custody.reject(reservation, ImageUnavailable::ImageNotScalable);
        return Err(ImageUnavailable::ImageNotScalable);
    }
    let Some((width_px, height_px)) = jpeg_dimensions(&captured.jpeg) else {
        custody.reject(reservation, ImageUnavailable::CaptureFailed);
        return Err(ImageUnavailable::CaptureFailed);
    };
    let Some(mapping) = ImageMapping::for_window(
        captured.window_origin,
        captured.window_points,
        captured.captured_px,
        (width_px, height_px),
    ) else {
        custody.reject(reservation, ImageUnavailable::ImageNotScalable);
        return Err(ImageUnavailable::ImageNotScalable);
    };
    if let Err(failure) = custody.retain(admission, &captured, width_px, height_px) {
        let reason = match failure {
            RetainFailure::NotRetained => ImageUnavailable::CaptureNotRetained,
            RetainFailure::CustodyUnavailable => ImageUnavailable::CustodyUnavailable,
        };
        custody.reject(reservation, reason);
        return Err(reason);
    }
    custody
        .finalize(reservation)
        .map_err(|CustodyStepFailed| ImageUnavailable::AuditUnavailable)?;
    Ok(ReleasedImage {
        window_id: captured.window_id,
        jpeg: captured.jpeg,
        width_px,
        height_px,
        mapping,
    })
}

#[cfg(test)]
mod tests {
    use super::ImageFronting;
    use crate::dispatch::{BracketReport, RestoreStatus};

    fn report(restore: RestoreStatus) -> BracketReport {
        BracketReport {
            previous_frontmost: Some(100),
            chunks: 1,
            units_posted: 1,
            posts_returned: 0,
            generation_verifications: 0,
            longest_fronted_interval_ms: 40,
            slowest_unit_ms: 0,
            slowest_restore_ms: 0,
            restore,
            stop: None,
            waiting_out_slow_post: false,
            waiting_out_slow_restore: false,
            restore_calibrated: false,
        }
    }

    /// A restore skipped because the person switched to another application
    /// is reported as not restored, naming that application as the one left
    /// in front; the other outcomes keep their meaning.
    #[test]
    fn a_skipped_restore_is_not_restored_and_names_the_application_now_in_front() {
        let skipped = ImageFronting::from(&report(RestoreStatus::SkippedPerson {
            now_front: Some(300),
        }));
        assert!(!skipped.restored);
        assert_eq!(skipped.left_in_front, Some(300));
        assert!(skipped.attempted);

        let failed = ImageFronting::from(&report(RestoreStatus::Failed {
            left_in_front: Some(200),
        }));
        assert!(!failed.restored);
        assert_eq!(failed.left_in_front, Some(200));

        for restore in [RestoreStatus::Restored, RestoreStatus::NotNeeded] {
            let fronting = ImageFronting::from(&report(restore));
            assert!(fronting.restored);
            assert_eq!(fronting.left_in_front, None);
        }
    }
}
