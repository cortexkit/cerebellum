//! Computer-plane crate. Platform-specific code is kept behind the bounded
//! [`platform`] seam so the shared cerebellum substrate remains plane-agnostic.

#![forbid(unsafe_code)]

pub mod platform;
