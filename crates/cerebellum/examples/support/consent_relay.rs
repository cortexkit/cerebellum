//! The consent relay every live probe needs to answer its own elicitation.
//!
//! A probe that drives a capability requiring user consent has to play both
//! parts: it sends the request, catches the reverse-request question the module
//! emits on the same route, answers it, and reads the reply. That is scaffolding
//! rather than measurement, and it was copied byte-for-byte into four probes --
//! where a change to the consent path had four places to be missed and a probe
//! carrying a stale relay MIS-MEASURES rather than failing.
//!
//! Included with `#[path = "support/consent_relay.rs"] mod consent_relay;`
//! inside each probe's target-gated module. Cargo mints example targets from
//! `examples/*.rs` and `examples/*/main.rs` only, so a file here is not built as
//! an example of its own, and `scripts/module-wiring-gate.sh` scans the same
//! shape and will not ask for it to be declared.

use std::time::Duration;

use cerebellum::Planes;
use serde_json::Value;
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

/// Drive one request that may open an elicitation, answer it, return the reply.
///
/// Reads frames until the reply is in hand, answering any question that
/// arrives on the way. Both orders happen on one route: a computer grant is
/// asked while the request waits, so its question comes BEFORE the reply,
/// while a browser grant replies `consent_pending` first and asks after. So a
/// `consent_pending` reply is final only once its question has been answered.
pub async fn elicit_and_answer(
    planes: &Planes,
    opening: Frame,
    answer_body: Value,
    label: &str,
) -> Result<Value, String> {
    elicit_and_answer_observing(planes, opening, answer_body, label, |_| {}).await
}

/// Drive a consent-capable request, observing each question before answering it.
/// The observer lets probes verify the choices the production relay offered.
pub async fn elicit_and_answer_observing(
    planes: &Planes,
    opening: Frame,
    answer_body: Value,
    label: &str,
    mut observe: impl FnMut(&Value),
) -> Result<Value, String> {
    let (writer, mut frames) = mpsc::channel(8);
    // Returns once the request is spawned, so a request that waits for its
    // answer is still running when the question is read below.
    cerebellum::handle_frame_for_test(opening, &writer, planes)
        .await
        .map_err(|error| format!("{label} request failed: {error}"))?;

    let mut reply = None;
    let mut answered = false;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(10), frames.recv())
            .await
            .map_err(|_| format!("{label} reply or question timed out"))?
            .ok_or_else(|| format!("{label} relay closed"))?;
        let body: Value = serde_json::from_slice(&frame.body)
            .map_err(|error| format!("{label} frame was not JSON: {error}"))?;
        if frame.header.ty == FrameType::Request {
            observe(&body);
            println!("{label} question: {body}");
            println!("{label} answer: {answer_body}");
            // Addressed to the QUESTION's channel, epoch and corr rather than
            // the request's: the answer is correlated to the ask, and a reply
            // built from the opening frame's header is silently never matched.
            let answer = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
                serde_json::to_vec(&answer_body).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            cerebellum::handle_frame_for_test(answer, &writer, planes)
                .await
                .map_err(|error| format!("{label} answer failed: {error}"))?;
            answered = true;
        } else {
            reply = Some(body);
        }
        if let Some(reply) = reply.as_ref() {
            if reply["outcome"] != "consent_pending" || answered {
                break;
            }
        }
    }
    let reply = reply.ok_or_else(|| format!("{label} returned no reply"))?;
    println!("{label} reply: {reply}");
    Ok(reply)
}
