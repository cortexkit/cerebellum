//! The probes' consent relay, driven on the wire with no desk.
//!
//! `elicit_and_answer` is scaffolding four live probes depend on, and until
//! this file nothing exercised it: the probes are the only callers and they
//! need a window, a browser or an application to run. So the one piece of code
//! standing between every probe and the module's consent path was reachable
//! only on a machine somebody was sitting at.
//!
//! Nothing here needs any of that. The relay pumps frames against
//! `handle_frame_for_test`, and `browser.open_grant` opens a real elicitation
//! without launching anything, so the whole contract is testable in-process.
//!
//! Three properties, each of which a copy of this relay got wrong:
//!
//!   * the reply and the question arrive in EITHER order on one route
//!   * a reply that is not `consent_pending` returns without waiting for a
//!     question that is never owed -- the fixed two-iteration pump in the
//!     `live_login` and `live_launch` copies waited out its own timeout here
//!     and then blamed a question nobody asked for
//!   * the answer is addressed to the QUESTION's channel, epoch and corr, not
//!     the request's, or it correlates to nothing and the consent never settles

use std::sync::Arc;

use cerebellum::{JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

#[path = "../examples/support/consent_relay.rs"]
mod consent_relay;

const MANAGEMENT_CHANNEL: u16 = 4;
const MANAGEMENT_EPOCH: u32 = 1;

fn identity() -> BindIdentity {
    BindIdentity::new(
        std::env::temp_dir().join("ck-consent-relay-test"),
        "test",
        "consent-relay-test",
    )
}

fn route_request(corr: u64, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

/// A module with one management route that declares it can be asked questions.
///
/// `consumer_capabilities: ["elicitation"]` is what makes the module willing to
/// send a reverse request at all; without it `open_grant` answers rather than
/// asking, which is a different path and would test nothing here.
async fn management_planes() -> Planes {
    // Isolated, not because this test journals anything -- `open_grant` does
    // not -- but because the constructor decides where the journal WOULD go,
    // and a test that writes into the operator's backed-up tree does so
    // whether or not the author meant to journal. The gate refuses the durable
    // constructor in tests for exactly that reason, and refused this file.
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    );
    let request = ModuleControlRequest::RouteBind {
        route_channel: MANAGEMENT_CHANNEL,
        epoch: MANAGEMENT_EPOCH,
        target: RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
        identity: identity(),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: Some(vec!["elicitation".to_string()]),
        admission_facts: Some(json!({
            "agentProjectId": "pj-consent-relay-test",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.open_grant"]
        })),
        scope: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        u64::from(MANAGEMENT_CHANNEL),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    cerebellum::handle_control_request_for_test_with_bindings(
        frame,
        &writer,
        &planes.health,
        &planes.routes,
    )
    .await
    .expect("the management route binds");
    let reply = replies.recv().await.expect("route.bind receives a reply");
    assert_eq!(reply.header.ty, FrameType::Response);
    planes
}

fn open_grant(corr: u64) -> Frame {
    route_request(
        corr,
        json!({
            "method": cerebellum::management::OPEN_GRANT,
            "params": {
                "origins": ["https://example.com"],
                "hazards": ["unverified_form_contents"]
            }
        }),
    )
}

/// The relay carries an answer to the question and the grant settles.
#[tokio::test]
async fn the_relay_answers_the_question_and_the_consent_settles() {
    let planes = management_planes().await;
    let before = planes.management.browser_grant_count().await;

    let reply = consent_relay::elicit_and_answer(
        &planes,
        open_grant(10),
        json!({"decision": "allow"}),
        "browser.open_grant",
    )
    .await
    .expect("the relay completes the request and its question");

    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while planes.management.browser_grant_count().await <= before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the affirmative answer mints a grant");
}

/// A refusal is returned promptly rather than waited on for a question.
///
/// This is the arm the replaced copies failed. Their pump read exactly two
/// frames, so a reply with no question behind it spent the full two-second
/// receive timeout and then reported that "the consent question was not
/// prompt" -- naming a question that was never owed. The deadline here is the
/// assertion: a relay that waits for a second frame cannot meet it.
#[tokio::test]
async fn a_reply_that_opens_no_question_returns_without_waiting_for_one() {
    let planes = management_planes().await;
    let unknown = route_request(
        11,
        json!({ "method": "browser.not_a_method", "params": {} }),
    );

    let started = std::time::Instant::now();
    let reply = consent_relay::elicit_and_answer(
        &planes,
        unknown,
        json!({"decision": "allow"}),
        "an unknown method",
    )
    .await
    .expect("a refusal is a completed relay, not a failed one");

    assert_ne!(reply["outcome"], "consent_pending", "{reply}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "the relay waited {:?} for a question that was never owed",
        started.elapsed()
    );
}

/// An answer correlated to the REQUEST rather than the question settles nothing.
///
/// Built by hand rather than through the relay, because this is the mistake the
/// relay exists to prevent: the reply frame and the question frame carry
/// different corrs, and answering on the wrong one is silently ignored. Without
/// this arm, a relay that used the request's header would pass every other test
/// here by returning the same `consent_pending` body.
#[tokio::test]
async fn an_answer_on_the_requests_correlation_settles_nothing() {
    let planes = management_planes().await;
    let before = planes.management.browser_grant_count().await;
    let (writer, mut frames) = mpsc::channel(8);

    cerebellum::handle_frame_for_test(open_grant(12), &writer, &planes)
        .await
        .expect("the grant request is served");

    let mut saw_question = false;
    while let Ok(Some(frame)) =
        tokio::time::timeout(std::time::Duration::from_millis(500), frames.recv()).await
    {
        saw_question |= frame.header.ty == FrameType::Request;
    }
    assert!(
        saw_question,
        "the module asked a question to answer wrongly"
    );

    // corr 12 is the REQUEST's; the question carries its own.
    let misaddressed = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        12,
        serde_json::to_vec(&json!({"decision": "allow"})).unwrap(),
    )
    .unwrap();
    let _ = cerebellum::handle_frame_for_test(misaddressed, &writer, &planes).await;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        planes.management.browser_grant_count().await,
        before,
        "an answer on the request's correlation must mint nothing"
    );
}
