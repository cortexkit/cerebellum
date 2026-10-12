//! The per-call permission to start an external mutation.
//!
//! A call's terminal decision (its own result, its work-budget expiry, a
//! cancel, a closed route or a drain) can be taken while a blocking worker is
//! still running platform work. From that moment the worker must not start any
//! further mutation: no accessibility action or value write, no synthetic post,
//! no launch, no menu press and no fronting bracket. Only the bounded release
//! of input this call may have left held is exempt.
//!
//! The gate is asked immediately before each such mutation. It answers true
//! only while the call has not been stopped, and a true answer records that a
//! mutation may have begun, so the terminal decision can tell "nothing was
//! sent" from "something may have been sent".

/// The gate a blocking worker asks before each external mutation.
///
/// Implementations must make `begin_mutation` a single atomic step that both
/// checks for a stop and records the dispatch, so a stop and a mutation can
/// never both believe they came first.
pub trait MutationGate: Send + Sync {
    /// Ask to start one external mutation. Returns false once the call has
    /// been stopped; the caller must then not perform the mutation.
    fn begin_mutation(&self) -> bool;

    /// Whether the call has been stopped. Used between the posts of one
    /// sequence, where the sequence's own release recovery must still run.
    fn stopped(&self) -> bool;
}

/// A gate that is never stopped: for callers with no terminal decision of
/// their own, such as direct unit tests of the dispatcher.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenGate;

impl MutationGate for OpenGate {
    fn begin_mutation(&self) -> bool {
        true
    }

    fn stopped(&self) -> bool {
        false
    }
}
