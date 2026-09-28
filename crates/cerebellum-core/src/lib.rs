//! Plane-agnostic substrate for the ck-cerebellum organ.
//!
//! ck-cerebellum serves multiple execution planes that share one
//! motor-execution substrate. Every plane uses the SAME foundations — three-fact
//! bind identity, insulated health-v2, dispatch timing atomics and a monotonic
//! clock, principal default-deny, and configuration parsing — and none of those
//! foundations depends on a plane's technology.
//!
//! This crate is that shared substrate. Each plane's module crate vendors it
//! one-way: a plane depends on `cerebellum-core`, never the reverse. Keeping the
//! substrate in one place means the bind-identity policy, the health semantics,
//! the default-deny backstop, and the config surface are defined once and cannot
//! drift between the planes.
//!
//! # Why the plane-agnostic boundary is enforced mechanically
//!
//! The whole value of this crate is that it is provably plane-agnostic: no
//! execution-framework dependency and no plane-specific type may appear here.
//! If a plane's technology leaks in, the boundary is drawn wrong — the substrate
//! would quietly couple to one plane and could no longer be shared by the other.
//! Rather than assert this in a comment,
//! the crate carries tests (see `tests/plane_agnostic.rs`) that read this
//! crate's own manifest and source and fail if a forbidden plane dependency or
//! type appears. Extending those explicit forbidden lists is the intended way to
//! cover a new plane.

#![forbid(unsafe_code)]

pub mod ask;
pub mod clock;
pub mod config;
pub mod consent;
pub mod dispatch;
pub mod health;
pub mod identity;
pub mod journal;
pub mod platform_dirs;
pub mod principal;
pub mod serde_base64;
pub mod vision;
