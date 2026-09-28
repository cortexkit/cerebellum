//! An application's state as a compact text tree, with element ids that stay
//! attached to their elements across reads and a diff between reads.
//!
//! [`source`] is the seam a platform reads through, [`render`] turns elements
//! into lines, [`session`] numbers elements and diffs reads, and [`image`]
//! carries the optional window image through custody.

pub mod image;
#[cfg(target_os = "macos")]
pub mod native;
pub mod render;
pub mod session;
pub mod source;

use cerebellum_core::journal::{JournalIdentity, JournalStorage, Redactor, SeverityTaxonomy};

use crate::audit::{
    ComputerAudit, ComputerCapability, ComputerPlaneDescriptor, ObservationState,
    TypedCaptureDispatch,
};
use crate::capture_custody::{CaptureScope, CustodyUnavailable, PixelArtifact};
use crate::grounding::ContainmentRung;
use image::{ImageCustody, ImageUnavailable, RetainFailure, WindowImageCapture};

/// The computer audit as the custody a state read's image passes through.
///
/// The image is recorded as a `computer.read_state` capture: reading pixels
/// reaches no element and moves nothing, so it claims only process-level
/// containment, and nobody is assumed to be watching.
pub struct AuditImageCustody<'a, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    pub audit: &'a mut ComputerAudit<R, T, S>,
    pub identity: JournalIdentity,
    pub now_ms: u64,
    /// The application the image is of, recorded as the capture's final
    /// context. A bundle identity, never application text.
    pub bundle_identity: String,
}

fn descriptor() -> ComputerPlaneDescriptor {
    ComputerPlaneDescriptor::new(
        ComputerCapability::ReadState,
        ContainmentRung::PidStructural,
        ObservationState::HumanUnobserved,
    )
}

impl<R, T, S> ImageCustody for AuditImageCustody<'_, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    type Reservation = cerebellum_core::journal::ReservationHandle;
    type Admission = crate::capture_custody::CaptureAdmissionToken;

    fn reserve(&mut self) -> Result<Self::Reservation, ()> {
        self.audit
            .reserve(self.identity.clone(), descriptor())
            .map_err(|_| ())
    }

    fn prepare(&mut self, reservation: &Self::Reservation) -> Result<Self::Admission, ()> {
        self.audit
            .prepare_capture(*reservation, CaptureScope::PerWindow, None, self.now_ms)
            .map_err(|_| ())
    }

    fn retain(
        &mut self,
        admission: Self::Admission,
        capture: &WindowImageCapture,
        width_px: u32,
        height_px: u32,
    ) -> Result<(), RetainFailure> {
        let artifact = PixelArtifact::per_window(
            capture.jpeg.clone(),
            self.now_ms,
            capture.window_id.clone(),
            capture.owning_pid,
            width_px,
            height_px,
        );
        let artifact_id = self
            .audit
            .admit_capture(admission, artifact, self.now_ms)
            .map_err(|_| RetainFailure::NotRetained)?;
        // Custody must hold what is about to be returned. Checked rather than
        // assumed, because a reply carrying an image custody never took looks
        // exactly like a correct one at the wire.
        match self.audit.custody().artifact_readable(&artifact_id) {
            Ok(true) => Ok(()),
            Ok(false) => Err(RetainFailure::NotRetained),
            Err(CustodyUnavailable) => Err(RetainFailure::CustodyUnavailable),
        }
    }

    fn finalize(&mut self, reservation: Self::Reservation) -> Result<(), ()> {
        let dispatch = TypedCaptureDispatch::new(
            ComputerCapability::ReadState,
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        )
        .dispatch_material(b"computer.read_state".to_vec());
        let token = self
            .audit
            .commit_dispatched(reservation, &dispatch, b"app_grant".to_vec(), None)
            .map_err(|_| ())?;
        self.audit
            .finalize_dispatched(
                token,
                b"captured".to_vec(),
                self.bundle_identity.clone().into_bytes(),
            )
            .map(|_| ())
            .map_err(|_| ())
    }

    fn reject(&mut self, reservation: Self::Reservation, reason: ImageUnavailable) {
        let _ = self
            .audit
            .finalize_rejected(reservation, reason.as_str().as_bytes().to_vec());
    }
}

#[cfg(test)]
mod tests;
