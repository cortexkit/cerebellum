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
use image::{CustodyStepFailed, ImageCustody, ImageUnavailable, RetainFailure, WindowImageCapture};

/// One successful state read's journal row, with optional image custody.
/// Tree-only reads use the same finalization path without preparing a capture.
pub struct AuditImageCustody<'a, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    pub audit: &'a mut ComputerAudit<R, T, S>,
    pub identity: JournalIdentity,
    pub now_ms: u64,
    pub summary: ReadStateSummary,
    pub finalized: bool,
}

/// Only counts and process identity cross the journal boundary; tree strings
/// are deliberately absent so labels and values cannot become durable text.
pub struct ReadStateSummary {
    pub grant_identity: crate::platform::ProcessGrant,
    pub element_count: usize,
    pub unreadable_count: usize,
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

    fn reserve(&mut self) -> Result<Self::Reservation, CustodyStepFailed> {
        self.audit
            .reserve(self.identity.clone(), descriptor())
            .map_err(|_| CustodyStepFailed)
    }

    fn prepare(
        &mut self,
        reservation: &Self::Reservation,
    ) -> Result<Self::Admission, CustodyStepFailed> {
        self.audit
            .prepare_capture(*reservation, CaptureScope::PerWindow, None, self.now_ms)
            .map_err(|_| CustodyStepFailed)
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

    fn finalize(&mut self, reservation: Self::Reservation) -> Result<(), CustodyStepFailed> {
        self.finalize_read(reservation, true)
    }

    fn reject(&mut self, reservation: Self::Reservation, _reason: ImageUnavailable) {
        // The image failed, not the tree read. Its successful tree still needs
        // the same completed row, explicitly saying that no image was released.
        let _ = self.finalize_read(reservation, false);
    }
}

impl<R: Redactor, T: SeverityTaxonomy, S: JournalStorage> AuditImageCustody<'_, R, T, S> {
    pub fn finalize_read(
        &mut self,
        reservation: cerebellum_core::journal::ReservationHandle,
        image_returned: bool,
    ) -> Result<(), CustodyStepFailed> {
        let dispatch = TypedCaptureDispatch::new(
            ComputerCapability::ReadState,
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        )
        .dispatch_material(
            serde_json::to_vec(&self.summary.grant_identity).map_err(|_| CustodyStepFailed)?,
        );
        let token = self
            .audit
            .commit_dispatched(reservation, &dispatch, b"app_grant".to_vec(), None)
            .map_err(|_| CustodyStepFailed)?;
        let result = serde_json::json!({
            "element_count": self.summary.element_count,
            "unreadable_count": self.summary.unreadable_count,
            "image_returned": image_returned,
        });
        self.audit
            .finalize_dispatched(
                token,
                serde_json::to_vec(&result).map_err(|_| CustodyStepFailed)?,
                self.summary
                    .grant_identity
                    .bundle_identity
                    .clone()
                    .into_bytes(),
            )
            .map_err(|_| CustodyStepFailed)?;
        self.finalized = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
