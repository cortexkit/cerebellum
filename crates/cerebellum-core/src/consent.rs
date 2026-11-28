//! The proof a global pointer dispatch carries that someone admitted it.
//!
//! Consent itself is no longer held here. Permission to act in an application
//! is an app grant, and permission to drive the one real system pointer is a
//! takeover grant; both live in the serving crate, which asks the person and
//! remembers the answer. What stays in this plane-agnostic crate is the one
//! value the global dispatch path demands before it will post: a token minted
//! for exactly one dispatch.

/// The kind of global pointer action admitted by the takeover grant check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeoverAction {
    Move,
    Click,
    Drag,
    Scroll,
}

/// Proof that one global pointer dispatch was admitted.
///
/// The global pointer stream reaches every application on the screen, so the
/// dispatch path refuses to post without one of these. It is minted by the
/// serving layer at the moment it admits one dispatch under the conversation's
/// takeover grant (plus the app grant for the application under the pointer,
/// where the action names one), and handed to that dispatch alone.
///
/// No `Default` and no `Clone`: one admission yields one token, and a token
/// cannot be duplicated to cover a second dispatch nobody admitted.
///
/// ```compile_fail
/// use cerebellum_core::consent::{OnceDispatchToken, TakeoverAction};
/// fn dispatch(_token: OnceDispatchToken) {}
/// let token = OnceDispatchToken::admitted_by_takeover_grant(TakeoverAction::Move);
/// dispatch(token);
/// dispatch(token); // A consumed token cannot authorize a second call.
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct OnceDispatchToken {
    action: TakeoverAction,
}

impl OnceDispatchToken {
    /// Mint the token for one dispatch the takeover grant has just admitted.
    ///
    /// WHY THIS IS PUBLIC, AND WHAT KEEPS IT SEALED. The token is the proof
    /// that a person agreed to hand over their pointer, so it may be made in
    /// exactly one place: the takeover grant check in the serving crate
    /// (`ComputerGrants::require_takeover_dispatch`), which returns it only
    /// after the grant is held. The type has to live here, below both the
    /// dispatch crate that demands it and the serving crate that checks the
    /// grant, and Rust has no visibility that admits one named downstream
    /// crate and no other. So the seal is split in two:
    ///
    /// * the grant check wraps the token in a value only that check can
    ///   build, so nothing else in the serving crate can obtain one; and
    /// * a structural test (`once_dispatch_token_site.rs` in the serving
    ///   crate) scans every production source of the workspace and fails if
    ///   this constructor is called anywhere but in that check.
    ///
    /// Tests build tokens of their own; that is outside the production paths
    /// the scan covers. Call this only at the point of admission, immediately
    /// before building the dispatch it is for: a token minted earlier and held
    /// is a standing permission, which is what the type exists to prevent.
    #[doc(hidden)]
    pub fn admitted_by_takeover_grant(action: TakeoverAction) -> Self {
        Self { action }
    }

    pub fn admits(&self, action: TakeoverAction) -> bool {
        self.action == action
    }
}
