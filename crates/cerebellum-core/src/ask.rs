//! Asking a question back down a route and waiting for the answer.
//!
//! Requests normally arrive and responses leave. This is the other direction: a
//! module sends a request on its own route channel, the daemon rewrites the
//! channel toward the consumer and preserves the correlation, and the consumer
//! answers with a response the daemon routes back. When the consumer is a
//! gateway with a human behind it, that is how a question reaches a person.
//!
//! Plane-agnostic because both planes ask the same kind of question: whether the
//! user permits reaching something.
//!
//! WHY AN INBOUND RESPONSE IS UNAMBIGUOUSLY OURS. Correlations are chosen by
//! whoever opens an exchange, so a consumer's own numbering can collide with
//! ours on the same channel. The frame type separates them regardless: we ANSWER
//! requests and we RECEIVE answers, so an inbound response can only belong to a
//! question we asked. Nothing here needs a distinct correlation space, and
//! reserving one would imply a protection it does not provide.
//!
//! WHAT AN UNANSWERED QUESTION MEANS. Not-granted, always. The declaration that
//! a consumer can relay a question is unverified, so a consumer that
//! over-declares produces a question nobody receives, and a module that treated
//! silence as anything but refusal would be permissive exactly when the path is
//! broken. The deadline therefore belongs to the ask rather than to the caller's
//! patience: its expiry is a definite answer, not an unfinished wait.
//!
//! WHY THE WAITING IS NOT HERE. This crate is synchronous throughout and holds no
//! async runtime, which is what lets it be tested without one and used from any
//! executor. So it keeps the bookkeeping — allocating a correlation, matching an
//! answer to its question, forgetting one that ended — and is generic over
//! whatever the caller parks to be woken. The waiting itself belongs beside the
//! wire, which is the only place a runtime already exists. Pulling a runtime in
//! here to hold a map would trade a property of the substrate for the
//! convenience of one caller.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::Value;

/// How a question ended.
///
/// The two unanswered outcomes are kept apart even though both mean not-granted,
/// because only one of them is a fault. A consumer that declined has made a
/// decision, and repeating the question would be pestering someone who already
/// answered; a question that could not be delivered, or that nobody answered, is
/// a broken path and worth retrying and recording. Collapsing them would leave a
/// caller unable to tell "the user said no" from "the user was never asked",
/// which are the same only in their effect and opposite in their remedy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskOutcome {
    /// The consumer answered. The body is theirs, unexamined here.
    Answered(Value),
    /// The question was delivered and the deadline passed with no answer.
    NoAnswer,
    /// The question could never be delivered, so nobody had the chance to
    /// answer. Distinct from silence: this is our side failing, not theirs.
    Undeliverable,
}

impl AskOutcome {
    /// Whether an answer came back at all.
    ///
    /// Deliberately not named `is_granted`: this reports that someone replied,
    /// and what the reply permits is for the caller that understands the
    /// question to decide.
    pub const fn is_answered(&self) -> bool {
        matches!(self, Self::Answered(_))
    }
}

/// Where a question was sent, and therefore where its answer will arrive.
type Correlation = (u16, u64);

/// Questions sent and not yet answered.
///
/// Registration happens before the question is sent. The opposite order has a
/// window in which the answer arrives before anything is waiting for it, and an
/// answer with no waiter is indistinguishable from an answer to a question
/// nobody asked, so it would be dropped as noise.
#[derive(Debug)]
pub struct AskLane<W> {
    waiting: Mutex<HashMap<Correlation, W>>,
    next_correlation: AtomicU64,
}

impl<W> Default for AskLane<W> {
    fn default() -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            next_correlation: AtomicU64::new(0),
        }
    }
}

impl<W> AskLane<W> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a correlation for a question about to be sent.
    pub fn next_correlation(&self) -> u64 {
        self.next_correlation.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Register a question, parking `waiter` to be handed back with its answer.
    ///
    /// Separate from sending so the caller can register, send, and then wait: the
    /// registration must be in place before the frame leaves, or a fast answer
    /// arrives with nothing recorded to receive it.
    pub fn register(&self, channel: u16, correlation: u64, waiter: W) {
        self.waiting
            .lock()
            .expect("ask registry lock")
            .insert((channel, correlation), waiter);
    }

    /// Stop waiting for an answer, so a question that ended does not leave an
    /// entry behind.
    ///
    /// Every path that stops waiting must call this, including the ones that
    /// give up: a registry that only forgets on success grows one entry per
    /// unanswered question for the life of the process.
    pub fn forget(&self, channel: u16, correlation: u64) {
        self.waiting
            .lock()
            .expect("ask registry lock")
            .remove(&(channel, correlation));
    }

    /// Claim the waiter for an arriving answer.
    ///
    /// `None` means the answer belongs to no outstanding question — a late reply
    /// to one that already gave up, or a correlation never sent — and the caller
    /// must treat it as unsolicited rather than assuming it was consumed. Waking
    /// the waiter is the caller's act, because only the caller knows what a
    /// waiter is.
    pub fn claim(&self, channel: u16, correlation: u64) -> Option<W> {
        self.waiting
            .lock()
            .expect("ask registry lock")
            .remove(&(channel, correlation))
    }

    /// How many questions are outstanding.
    pub fn outstanding(&self) -> usize {
        self.waiting.lock().expect("ask registry lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A waiter is whatever the caller parks; a string stands in for one here.
    fn lane() -> AskLane<String> {
        AskLane::new()
    }

    /// An arriving answer claims the waiter that was registered for it.
    #[test]
    fn an_answer_claims_its_waiter() {
        let lane = lane();
        let correlation = lane.next_correlation();
        lane.register(7, correlation, "asker".to_string());

        assert_eq!(lane.claim(7, correlation).as_deref(), Some("asker"));
        assert_eq!(lane.outstanding(), 0, "an answered question was retained");
    }

    /// An answer with no outstanding question is not claimed.
    ///
    /// It must not be reported as delivered: an answer nobody was waiting for and
    /// an answer handed to its asker are different facts, and only the second
    /// means the exchange completed. Claiming twice is the same case, since the
    /// first claim consumed the question.
    #[test]
    fn an_answer_with_no_waiter_is_not_claimed() {
        let lane = lane();
        let correlation = lane.next_correlation();
        lane.register(7, correlation, "asker".to_string());

        assert!(lane.claim(7, correlation).is_some());
        assert!(
            lane.claim(7, correlation).is_none(),
            "a second answer to one question was claimed"
        );
        assert!(
            lane.claim(7, lane.next_correlation()).is_none(),
            "an answer to a question never asked was claimed"
        );
    }

    /// Forgetting a question that ended leaves nothing behind.
    ///
    /// Every path that stops waiting has to reach this, including the ones that
    /// give up: a registry that only forgot on success would grow one entry per
    /// unanswered question for the life of the process.
    #[test]
    fn forgetting_a_question_releases_its_entry() {
        let lane = lane();
        let correlation = lane.next_correlation();
        lane.register(7, correlation, "asker".to_string());
        assert_eq!(lane.outstanding(), 1);

        lane.forget(7, correlation);
        assert_eq!(lane.outstanding(), 0);
        assert!(
            lane.claim(7, correlation).is_none(),
            "a forgotten question still claimed an answer"
        );
    }

    /// Answers are matched per channel, not by correlation alone.
    ///
    /// Two routes number their questions independently, so one correlation can be
    /// outstanding on both at once. Matching on the correlation alone would hand
    /// one route's answer to the other route's asker.
    #[test]
    fn the_same_correlation_on_two_channels_stays_separate() {
        let lane = lane();
        lane.register(7, 1, "seven".to_string());
        lane.register(9, 1, "nine".to_string());

        assert_eq!(lane.claim(9, 1).as_deref(), Some("nine"));
        assert_eq!(
            lane.outstanding(),
            1,
            "claiming one channel's answer consumed another's question"
        );
        assert_eq!(lane.claim(7, 1).as_deref(), Some("seven"));
    }

    /// Correlations are not reused while questions are outstanding.
    #[test]
    fn correlations_do_not_repeat() {
        let lane = lane();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            assert!(
                seen.insert(lane.next_correlation()),
                "a correlation was issued twice"
            );
        }
    }
}
