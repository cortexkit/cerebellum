//! Plane-agnostic substrate for the ck-cerebellum organ.
//!
//! ck-cerebellum serves two execution planes that share one motor-execution
//! substrate: a browser plane (CDP automation) and a computer plane (macOS
//! desktop automation). Both planes need the SAME foundations — three-fact bind
//! identity, insulated health-v2, the dispatch timing atomics and monotonic
//! clock, principal default-deny, and configuration parsing — and none of those
//! foundations depends on either plane's technology.
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
//! browser/CDP dependency, no macOS/GUI-framework dependency, and no
//! plane-specific type may appear here. If a plane's technology leaks in, the
//! boundary is drawn wrong — the substrate would quietly couple to one plane and
//! could no longer be shared by the other. Rather than assert this in a comment,
//! the crate carries tests (see `tests/plane_agnostic.rs`) that read this
//! crate's own manifest and source and fail if a forbidden plane dependency or
//! type appears. Extending those explicit forbidden lists is the intended way to
//! cover a new plane.

#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod dispatch;
pub mod health;
pub mod identity;
pub mod principal;
