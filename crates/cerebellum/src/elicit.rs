//! Putting a question to whoever is on the other end of a route.
//!
//! The bookkeeping lives in the substrate; this is the half that needs a
//! runtime. It builds the request frame, registers the question before sending
//! it, waits for the answer under a deadline, and reports what happened.
//!
//! A question travels as a request in the module-to-client direction on the
//! module's own route channel. The daemon rewrites the channel toward the
//! consumer, preserves the correlation, and forwards the body without reading
//! it; a consumer that fronts a person relays it onward as a request of its own.
//! So the body here is the consumer's contract rather than the daemon's, and
//! nothing in this file inspects it.

use std::sync::Arc;
use std::time::Duration;

use cerebellum_core::ask::AskLane;
use serde_json::Value;
use subc_protocol::{Flags, Frame, FrameType, Priority};
use tokio::sync::{mpsc, oneshot};

/// How a question ended.
///
/// The two unanswered outcomes are separate because only one is a fault. A
/// consumer that declined has made a decision, and asking again would pester
/// someone who already answered; a question that could not be sent, or that
/// nobody answered, is a broken path worth retrying and recording. Both mean
/// not-granted to a caller deciding whether to act, and they differ entirely in
/// what should happen next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskOutcome {
    /// The consumer answered. The body is theirs, unexamined here.
    Answered(Value),
    /// The question was sent and the deadline passed with no answer.
    ///
    /// NOT a distinguished failure to a caller: silence is not-granted. Named so
    /// the journal can record that nobody replied, which is a different fact
    /// from a reply that said no, and a reply that says no is inside
    /// [`Self::Answered`] because reading it is the asker's job.
    NoAnswer,
    /// The question never left, so nobody had the chance to answer.
    ///
    /// Distinct from silence because this is our side failing rather than
    /// theirs, and it is the one worth alerting on.
    Undeliverable,
}

impl AskOutcome {
    /// Whether someone replied at all.
    ///
    /// Deliberately not `is_granted`: this says a reply arrived, and what the
    /// reply permits is for the caller that understands the question.
    pub const fn is_answered(&self) -> bool {
        matches!(self, Self::Answered(_))
    }
}

/// The questions this module has outstanding.
pub struct Elicitor {
    lane: AskLane<oneshot::Sender<Value>>,
}

impl Default for Elicitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Elicitor {
    pub fn new() -> Self {
        Self {
            lane: AskLane::new(),
        }
    }

    /// Ask a question on `channel` and wait for the answer.
    ///
    /// The deadline is a parameter rather than a constant because what counts as
    /// too long depends on who is being asked: a person reading a prompt on a
    /// phone is not a program computing a reply. It is required rather than
    /// optional so that no question can be asked without one.
    pub async fn ask(
        &self,
        writer: &mpsc::Sender<Frame>,
        channel: u16,
        epoch: u32,
        body: Value,
        deadline: Duration,
    ) -> AskOutcome {
        let correlation = self.lane.next_correlation();
        let (tx, rx) = oneshot::channel();

        // Registered BEFORE the frame is sent. The opposite order leaves a
        // window in which the answer arrives with nothing recorded to receive
        // it, and an answer with no waiter is indistinguishable from one nobody
        // asked for, so it would be discarded as noise.
        self.lane.register(channel, correlation, tx);

        let Ok(payload) = serde_json::to_vec(&body) else {
            self.lane.forget(channel, correlation);
            return AskOutcome::Undeliverable;
        };
        // Interactive priority: a person is waiting at the other end, so this
        // frame should not queue behind bulk traffic. Not marked last, because
        // the answer continues the exchange.
        let Ok(frame) = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            correlation,
            payload,
        ) else {
            self.lane.forget(channel, correlation);
            return AskOutcome::Undeliverable;
        };
        if writer.send(frame).await.is_err() {
            self.lane.forget(channel, correlation);
            return AskOutcome::Undeliverable;
        }

        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(answer)) => AskOutcome::Answered(answer),
            // The sender was dropped, which happens when the question is
            // forgotten without an answer. Nobody replied.
            Ok(Err(_)) => {
                self.lane.forget(channel, correlation);
                AskOutcome::NoAnswer
            }
            Err(_) => {
                self.lane.forget(channel, correlation);
                AskOutcome::NoAnswer
            }
        }
    }

    /// Hand an arriving answer to the question that asked for it.
    ///
    /// Returns whether anyone was waiting. False means the answer belongs to no
    /// outstanding question — a reply that arrived after its deadline, or a
    /// correlation this module never sent — and the caller should treat it as
    /// unsolicited rather than assume it was consumed.
    pub fn deliver(&self, channel: u16, correlation: u64, body: Value) -> bool {
        let Some(waiter) = self.lane.claim(channel, correlation) else {
            return false;
        };
        // A closed receiver means the asker stopped waiting between the claim
        // and now, which is the same as nobody waiting.
        waiter.send(body).is_ok()
    }

    /// How many questions are outstanding.
    pub fn outstanding(&self) -> usize {
        self.lane.outstanding()
    }
}

/// A shared handle, since the loop delivering answers and the code asking
/// questions are different tasks.
pub type SharedElicitor = Arc<Elicitor>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn writer() -> (mpsc::Sender<Frame>, mpsc::Receiver<Frame>) {
        mpsc::channel(8)
    }

    /// A question is sent as a request on the module's own channel, and its
    /// answer reaches the asker.
    #[tokio::test]
    async fn an_answer_reaches_the_question_that_asked_it() {
        let elicitor = Arc::new(Elicitor::new());
        let (tx, mut rx) = writer();

        let asking = {
            let elicitor = Arc::clone(&elicitor);
            tokio::spawn(async move {
                elicitor
                    .ask(
                        &tx,
                        7,
                        1,
                        json!({"method": "elicitation/create"}),
                        Duration::from_secs(5),
                    )
                    .await
            })
        };

        let frame = rx.recv().await.expect("the question is sent");
        assert_eq!(frame.header.ty, FrameType::Request);
        assert_eq!(frame.header.channel, 7);

        assert!(elicitor.deliver(7, frame.header.corr, json!({"decision": "allow"})));

        assert_eq!(
            asking.await.unwrap(),
            AskOutcome::Answered(json!({"decision": "allow"}))
        );
        assert_eq!(elicitor.outstanding(), 0, "an answered question was kept");
    }

    /// A question nobody answers ends at its deadline as not-answered.
    ///
    /// The elapsed time is not asserted. That would be a claim about the machine
    /// rather than the code, and it fails under load for reasons unrelated to the
    /// property; the outcome and the empty registry are the property.
    #[tokio::test]
    async fn an_unanswered_question_ends_at_its_deadline() {
        let elicitor = Elicitor::new();
        let (tx, _rx) = writer();

        let outcome = elicitor
            .ask(&tx, 7, 1, json!({}), Duration::from_millis(10))
            .await;

        assert_eq!(outcome, AskOutcome::NoAnswer);
        assert_eq!(
            elicitor.outstanding(),
            0,
            "an abandoned question left an entry behind"
        );
    }

    /// A question that cannot be sent is reported as undeliverable, not as
    /// silence.
    ///
    /// Waiting out a deadline for a frame that never left would report the
    /// consumer as unresponsive for our own failure, and it would take the whole
    /// deadline to say so.
    #[tokio::test]
    async fn a_browser_grant_question_that_times_out_mints_nothing() {
        let management = crate::management::ManagementPlane::new(Arc::new(
            crate::management::PlatformResolver::new(),
        ));
        let question = management
            .browser_grant_question_for_test(
                "conversation",
                vec!["https://example.test".to_string()],
                vec![crate::authorization::HazardClass::CredentialFormSubmit],
            )
            .await;
        let elicitor = Elicitor::new();
        let (tx, _rx) = writer();

        let outcome = elicitor
            .ask(&tx, 7, 1, question.body, Duration::from_millis(10))
            .await;
        assert_eq!(outcome, AskOutcome::NoAnswer);
        management
            .settle_browser_grant(&question.ask_id, None)
            .await;
        assert_eq!(management.browser_grant_count().await, 0);
    }

    #[tokio::test]
    async fn a_browser_grant_question_that_is_undeliverable_mints_nothing() {
        let management = crate::management::ManagementPlane::new(Arc::new(
            crate::management::PlatformResolver::new(),
        ));
        let question = management
            .browser_grant_question_for_test(
                "conversation",
                vec!["https://example.test".to_string()],
                vec![crate::authorization::HazardClass::UnverifiedFormContents],
            )
            .await;
        let elicitor = Elicitor::new();
        let (tx, rx) = writer();
        drop(rx);

        let outcome = elicitor
            .ask(&tx, 7, 1, question.body, Duration::from_secs(1))
            .await;
        assert_eq!(outcome, AskOutcome::Undeliverable);
        management
            .settle_browser_grant(&question.ask_id, None)
            .await;
        assert_eq!(management.browser_grant_count().await, 0);
    }

    #[tokio::test]
    async fn a_question_that_cannot_be_sent_is_not_reported_as_silence() {
        let elicitor = Elicitor::new();
        let (tx, rx) = writer();
        drop(rx);

        let outcome = elicitor
            .ask(&tx, 7, 1, json!({}), Duration::from_secs(30))
            .await;

        assert_eq!(outcome, AskOutcome::Undeliverable);
        assert_eq!(
            elicitor.outstanding(),
            0,
            "a question that never left was left outstanding"
        );
    }

    /// An answer arriving after its deadline is not claimed.
    #[tokio::test]
    async fn a_late_answer_is_not_claimed() {
        let elicitor = Elicitor::new();
        let (tx, mut rx) = writer();

        let outcome = elicitor
            .ask(&tx, 7, 1, json!({}), Duration::from_millis(10))
            .await;
        assert_eq!(outcome, AskOutcome::NoAnswer);

        let frame = rx.recv().await.expect("the question was sent");
        assert!(
            !elicitor.deliver(7, frame.header.corr, json!({"decision": "allow"})),
            "a late answer was reported as delivered"
        );
    }
}
