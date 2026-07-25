//! Computer-plane crate. Platform-specific code is kept behind the bounded
//! [`platform`] seam so the shared cerebellum substrate remains plane-agnostic.

#![forbid(unsafe_code)]

pub mod audit;
pub mod capture;
pub mod capture_custody;
pub mod dispatch;
pub mod grounding;
pub mod platform;

pub use audit::{ComputerJournalCodec, ComputerPlaneDescriptor, TypedCaptureDispatch};
pub use capture_custody::{
    CaptureAdmissionToken, CaptureCustody, CaptureDescriptor, CaptureScope, PixelArtifact,
};
