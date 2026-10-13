//! What the inbound call being served right now is, for code deep inside it.
//!
//! The frame loop runs each request under two task-local values: the in-flight
//! guard that counts it as busy, and the validated key of the tool call. Code
//! that raises a consent card reads them here, so a card can pause the busy
//! accounting while a person decides and can name the call that raised it.
//!
//! Tokio task-local values are not inherited by spawned tasks: a task spawned
//! from a call sees neither, and has to be handed what it needs before it is
//! spawned.

use std::sync::Arc;

tokio::task_local! {
    /// The in-flight guard of the inbound call this task serves. Absent on
    /// tasks that serve no inbound call, such as a pending reply written
    /// after its call returned.
    pub(crate) static ROUTE_GUARD: Arc<cerebellum_core::dispatch::InFlightGuard>;
    /// The validated key identifying the tool call that initiated this request.
    pub(crate) static CALL_KEY: String;
}

/// The key of the tool call this task serves, when it serves one.
pub(crate) fn current_call_key() -> Option<String> {
    CALL_KEY.try_with(Clone::clone).ok()
}
