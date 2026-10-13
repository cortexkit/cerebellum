//! Drive probe requests over a fixture for Cingulate, the consent service.
//! Permission questions are inspected at that service; the agent route's writer
//! carries only the probe's reply, never a question sent back to the agent.

#[allow(dead_code)]
pub mod cingulate {
    include!("../../tests/support/cingulate.rs");
}
use std::time::Duration;

use cerebellum::Planes;
use serde_json::Value;
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

/// Drive a request that may ask a permission question, answer it, and return
/// the reply. When the request replies before the answer, make another request
/// to apply that answer so the probe can inspect the resulting permission.
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
    observe: impl FnMut(&Value),
) -> Result<Value, String> {
    elicit_and_answer_waiting(
        planes,
        opening,
        answer_body,
        label,
        observe,
        Duration::from_secs(10),
    )
    .await
}

/// As [`elicit_and_answer_observing`], waiting up to `frame_wait` for each
/// frame. For a request that holds its reply open on purpose after the answer,
/// such as a login capture waiting out its handoff.
#[allow(dead_code)]
pub async fn elicit_and_answer_waiting(
    planes: &Planes,
    opening: Frame,
    answer_body: Value,
    label: &str,
    mut observe: impl FnMut(&Value),
    frame_wait: Duration,
) -> Result<Value, String> {
    let service = cingulate::ScriptedCarrier::default();
    let configured = service.install(planes.clone());
    let channel = opening.header.channel;
    let epoch = opening.header.epoch;
    let (writer, mut frames) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(opening, &writer, &configured)
        .await
        .map_err(|error| format!("{label} request failed: {error}"))?;
    let deadline = tokio::time::Instant::now() + frame_wait;
    let mut observed = 0;
    loop {
        for question in service.questions().iter().skip(observed) {
            observe(question);
            let id = question["id"].as_str().unwrap();
            service.answer_id(
                id,
                cerebellum::elicit::AskOutcome::Answered(answer_body.clone()),
            );
            observed += 1;
        }
        match frames.try_recv() {
            Ok(frame) => {
                if frame.header.ty == FrameType::Request {
                    return Err(format!("{label} emitted a reverse request"));
                }
                let reply: Value =
                    serde_json::from_slice(&frame.body).map_err(|error| error.to_string())?;
                let structured = reply.get("structuredContent").unwrap_or(&reply);
                if structured["outcome"] == "consent_pending" {
                    // The original request returned before the person answered.
                    // A new request applies the answer; no background task does it.
                    for question in service.questions().iter().skip(observed) {
                        observe(question);
                        service.answer_id(
                            question["id"].as_str().unwrap(),
                            cerebellum::elicit::AskOutcome::Answered(answer_body.clone()),
                        );
                    }
                    let frame = Frame::build_with_version(
                        PROTOCOL_VERSION,
                        FrameType::Request,
                        Flags::new(false, Priority::Interactive, false),
                        channel,
                        epoch,
                        99001,
                        serde_json::to_vec(&serde_json::json!({"method":"test.drain","params":{}}))
                            .unwrap(),
                    )
                    .unwrap();
                    cerebellum::handle_frame_for_test(frame, &writer, &configured)
                        .await
                        .map_err(|error| error.to_string())?;
                    tokio::time::timeout_at(deadline, frames.recv())
                        .await
                        .map_err(|_| format!("{label} drain timed out"))?;
                }
                return Ok(reply);
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Err(format!("{label} writer closed"))
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("{label} reply timed out"));
        }
        tokio::task::yield_now().await;
    }
}
