//! The proof a global pointer dispatch carries that someone admitted it.
//!
//! Consent itself is no longer held here. Permission to act in an application
//! is an app grant, and permission to drive the one real system pointer is a
//! takeover grant; both live in the serving crate, which asks the person and
//! remembers the answer. What stays in this plane-agnostic crate is the one
//! value the global dispatch path demands before it will post: a token minted
//! for exactly one dispatch.

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
#[derive(Debug, PartialEq, Eq)]
pub struct OnceDispatchToken {
    _private: (),
}

impl OnceDispatchToken {
    /// Mint the token for one dispatch the takeover grant has just admitted.
    ///
    /// Call this only at the point of admission, immediately before building
    /// the dispatch it is for: a token minted earlier and held is a standing
    /// permission, which is what the type exists to prevent.
    pub fn admitted_by_takeover_grant() -> Self {
        Self { _private: () }
    }
}
