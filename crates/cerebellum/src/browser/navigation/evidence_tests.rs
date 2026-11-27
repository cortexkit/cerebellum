use std::sync::Arc;
use std::time::Duration;

use cerebellum_core::clock::SystemClock;
use cerebellum_core::dispatch_witness::DispatchWitness;
use serde_json::{json, Value};

use super::test_support::FakeClock;
use super::tests::{driver_with_download_denial, FakePipe};
use super::CdpNavigationDriver;
use crate::authorization::{ActionGrant, GrantStore, HazardClass, Severity};
use crate::browser::{BrowserCapability, BrowserPlane, Tracker};
use crate::browser_session::{
    BrowserSessions, CleanupStage, LaunchSlot, NavigationDriveError, NavigationWait,
    OwnedBrowserProcess, ProcessControlFailure, SessionCleanup, SessionCleanupOutcome,
};
use crate::snapshot_store::CommittedDocument;
use crate::{BrowserConfig, RouteIdentity};

struct NavigationProcess(CdpNavigationDriver<FakePipe>);

impl OwnedBrowserProcess for NavigationProcess {
    fn committed_document(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        Ok(CommittedDocument::new(
            "https://requested.example.com/page",
            1,
            "loader-page",
        ))
    }

    fn navigate(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        // CDP replies are scripted. Only the driver's polling sleeps should
        // consume the navigation budget, not time spent waiting to be scheduled.
        self.0.navigate_for_test(
            context_key,
            url,
            wait,
            deadline_ms,
            tracker,
            &mut FakeClock::new(),
        )
    }

    fn generation_matches(&self) -> bool {
        true
    }

    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }

    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(true)
    }

    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }

    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
}

struct NoopCleanup;

impl SessionCleanup for NoopCleanup {
    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        Ok(SessionCleanupOutcome::Complete)
    }
}

async fn dispatch_navigation(
    events: impl IntoIterator<Item = Value>,
    navigate_result: Value,
    wait: &str,
    intent: &str,
    navigation_settle_deadline_ms: u64,
) -> Value {
    let mut route = RouteIdentity::from_accepted_bind(
        &subc_protocol::BindIdentity::new("test", "b1-s3-session"),
        &Some(subc_protocol::Principal::Direct),
        Some(&json!({"agentProjectId": "b1-s3-agent", "sessionKind": "primary"})),
    );
    route.witness = DispatchWitness::armed();

    let frames = [
        json!({"id":1,"result":{"targetId":"target-own"}}),
        json!({"id":2,"result":{"sessionId":"session-own"}}),
        json!({"id":3,"sessionId":"session-own","result":{}}),
        json!({"id":4,"sessionId":"session-own","result":{}}),
        json!({"id":5,"sessionId":"session-own","result":{}}),
    ]
    .into_iter()
    .chain(events)
    .chain(std::iter::once(
        json!({"id":6,"sessionId":"session-own","result":navigate_result}),
    ));
    let process = Box::new(NavigationProcess(driver_with_download_denial(frames)));

    let sessions = BrowserSessions::default();
    let LaunchSlot::Acquired {
        browser_session_id: acquired_id,
    } = sessions.acquire_launch_slot(&route.conversation_key)
    else {
        panic!("expected to acquire the launch slot");
    };
    let clock = Arc::new(SystemClock::new());
    clock.pause_for_test();
    let config = BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 30_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms,
    };
    let (browser_session_id, _, cancelled) = sessions
        .establish_ready(
            &route.conversation_key,
            route.profile_disposition,
            &config,
            clock.as_ref(),
            process,
            Box::new(NoopCleanup),
        )
        .expect("the acquired launch slot accepts a ready process");
    assert_eq!(browser_session_id, acquired_id);
    assert!(!cancelled);

    let grant = ActionGrant::new(
        "b1-s3-navigation-grant",
        1,
        route.conversation_key.clone(),
        Severity {
            tier: 4,
            credential: true,
            financial: true,
        },
        ["https://requested.example.com"],
    )
    .with_disclosed_hazards([HazardClass::UnverifiedFormContents]);
    let plane = BrowserPlane::with_session_gate(sessions, clock, navigation_settle_deadline_ms)
        .with_grants_installed(GrantStore::new([grant]));
    plane.open_context(route.clone()).await.unwrap();
    plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example.com/",
                "intent": intent,
                "wait": wait,
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await
}

#[tokio::test]
async fn page_navigate_error_text_is_a_named_refusal_not_an_ok_reply() {
    let result = dispatch_navigation(
        [],
        json!({
            "frameId": "main",
            "errorText": "net::ERR_NAME_NOT_RESOLVED"
        }),
        "none",
        "open a resolvable host",
        100,
    )
    .await;

    assert_eq!(
        result,
        json!({
            "outcome": "navigation_failed",
            "remedy": "inspect detail.error_text and choose a reachable destination or retry when that browser error is transient",
            "detail": {"error_text": "net::ERR_NAME_NOT_RESOLVED"},
            "context": {
                "profile_uuid": null,
                "profile_name": "default",
                "session_kind_effective": "primary",
                "profile_disposition": "durable"
            }
        })
    );
    assert_ne!(result["outcome"], "ok", "{result}");
}

#[tokio::test]
async fn main_frame_cloudflare_challenge_header_is_reported_as_evidence() {
    let result = dispatch_navigation(
        [
            json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"main","response":{"status":403,"statusText":"Forbidden","headers":{"cf-mitigated":"challenge"}}}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example.com/"}}}),
        ],
        json!({"frameId":"main"}),
        "none",
        "observe a documented challenge response",
        100,
    )
    .await;

    assert_eq!(
        result,
        json!({
            "outcome": "ok",
            "url_final": "https://requested.example.com/",
            "lifecycle": {"events": ["navigation_started"], "loaded": false, "settled": false},
            "http_status": 403,
            "challenge": {"vendor": "cloudflare", "evidence": "cf-mitigated: challenge"},
            "context": {
                "profile_uuid": null,
                "profile_name": "default",
                "session_kind_effective": "primary",
                "profile_disposition": "durable"
            }
        })
    );
}

#[tokio::test]
async fn subframe_document_response_cannot_replace_main_frame_status_or_claim_a_challenge() {
    let result = dispatch_navigation(
        [
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example.com/"}}}),
            json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"main","response":{"status":403,"statusText":"Forbidden","headers":{"server":"cloudflare"}}}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"subframe","parentId":"main","url":"https://embed.example/"}}}),
            json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"subframe","response":{"status":200,"statusText":"OK","headers":{"cf-mitigated":"challenge"}}}}),
        ],
        json!({"frameId":"main"}),
        "none",
        "observe the main document response only",
        100,
    )
    .await;

    assert_eq!(
        result,
        json!({
            "outcome": "ok",
            "url_final": "https://requested.example.com/",
            "lifecycle": {"events": ["navigation_started"], "loaded": false, "settled": false},
            "http_status": 403,
            "context": {
                "profile_uuid": null,
                "profile_name": "default",
                "session_kind_effective": "primary",
                "profile_disposition": "durable"
            }
        })
    );
    assert!(result.get("challenge").is_none(), "{result}");
}

#[tokio::test]
async fn unsettled_navigation_keeps_its_observed_main_frame_status() {
    let result = dispatch_navigation(
        [
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example.com/"}}}),
            json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"main","response":{"status":503,"statusText":"Service Unavailable","headers":{}}}}),
        ],
        json!({"frameId":"main"}),
        "settle",
        "observe an unsettled service response",
        300,
    )
    .await;

    assert_eq!(result["outcome"], "not_settled", "{result}");
    assert_eq!(result["http_status"], 503, "{result}");
}
