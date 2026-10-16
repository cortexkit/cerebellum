//! Cerebellum's client for Cingulate, the consent module.
//!
//! Cerebellum raises its permission cards (browser site access, app control,
//! takeover, login import and capture, profile re-identification and stuck
//! profile clearance) as Cingulate `consent` cards, over a route it opens
//! itself under the calling agent's session scope while it holds that agent's
//! call. The contract is Cingulate's `consent-requester-v2`; its served
//! vectors are copied under `tests/vectors/consent-requester-v2/`.
//!
//! - [`wire`]: request bodies, refusal codes and requester records.
//! - [`route`]: the route opener ([`route::DaemonCingulate`]) on
//!   `subc-transport`.
//! - [`live_call`]: the proof that a live inbound call is held, without which
//!   no route is opened.
//! - [`card`]: the card bodies cerebellum's builders render, as
//!   `consent.request` params.
//!
//! Before this client, cards were sent on the "reverse elicitation lane": as
//! `elicitation/create` requests back along the route of core's inbound call,
//! answered by whoever held that route. Several comments and tests here
//! compare against what that path sent, because the phone must keep seeing
//! the same cards.
//! - [`desk`]: raising, waiting in the call, detaching, withdrawing, and
//!   applying late answers from the answers feed.
//! - [`subject`]: the one subject string per card kind that a card is filed
//!   under, so a second call asking the same thing joins the open card.

pub mod card;
pub mod desk;
pub mod features;
pub mod live_call;
pub mod route;
pub mod subject;
pub mod wire;

#[doc(hidden)]
pub mod double;
#[doc(hidden)]
pub use double::{vector, Reply, ScriptedAnswer, ScriptedCingulate};
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;

#[cfg(test)]
pub(crate) mod worker_vectors;
