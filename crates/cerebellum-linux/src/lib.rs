//! Narrow seams over Linux process primitives and the read-only EDS transport.
//!
//! This crate exists so the platform-neutral crates can keep their exact
//! `#![forbid(unsafe_code)]` boundary. It returns raw process readings and
//! performs the small ptrace barrier that requires syscalls. Its EDS transport
//! exposes raw source objects without depending on cerebellum's ability policy.
//! Callers decide what a path, digest, build ID, or missing reading means.
//!
//! Keep additions here small and mechanical. This crate is the auditable place
//! for platform calls, not a place to move browser policy.

#[cfg(target_os = "linux")]
pub mod eds;
// The exec-stop state machine has no syscalls, so its loop and bounds remain
// testable where launching a Linux tracee is impossible.
#[cfg(any(target_os = "linux", test))]
mod exec_stop;
#[cfg(target_os = "linux")]
mod launch;
#[cfg(target_os = "linux")]
pub mod session;
// Parsing procfs stays compiled under tests off Linux so the field-boundary
// checks remain exercised where launching a Linux tracee is impossible.
#[cfg(any(target_os = "linux", test))]
mod linux;

// The export gate matches the module gate. A platform-neutral parser compiled
// only for tests must keep its public surface there or deny-warnings reads it
// as unused code.
#[cfg(target_os = "linux")]
pub use launch::{
    executed_image_identity, process_descriptors, spawn_barred, terminate_exact_generation,
    BarredChild, ExecutedImageIdentity, GenerationMatch, ImageIdentityError, ProcessControlError,
    ProcessGeneration, ReleasedChild, SpawnError, TerminationOutcome,
};
#[cfg(any(target_os = "linux", all(test, unix)))]
pub use linux::process_start_time;
#[cfg(any(target_os = "linux", test))]
pub use linux::{process_generation, ProcessGenerationReading, ProcessStartTime};
