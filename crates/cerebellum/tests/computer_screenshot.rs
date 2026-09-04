//! Serving `computer.screenshot` over the wire.
//!
//! The interesting properties here are about ORDER and about what happens when
//! a step fails, neither of which an assertion on the returned outcome can see.

mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cerebellum::computer_capability::{
    servable, ComputerPlane, ComputerPlaneUnavailable, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::management::ManagementPlane;
use cerebellum_computer::audit::ComputerCapability;
use cerebellum_computer::capture::{EnumeratedWindow, InMemoryCaptureBackend, WindowFrame};
use cerebellum_computer::platform::{TargetResolution, UnreadableReason};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{IoDiagnostic, StorageError};
use serde_json::{json, Value};
use support::computer::{
    audit, failing_audit, grant, identity, leased_management, management, request,
    CapturingBackend, Fixed, RefusingBackend,
};

#[test]
fn journal_boot_failure_message_names_its_path_and_typed_cause() {
    let path = PathBuf::from("/unwritable/cortexkit/cerebellum/journal/computer.json");
    let reason = ComputerPlaneUnavailable::JournalStorage {
        path: path.clone(),
        error: StorageError::CreateDirectory {
            path: path.parent().expect("journal directory").to_path_buf(),
            source: IoDiagnostic {
                kind: std::io::ErrorKind::PermissionDenied,
                message: "permission denied".to_string(),
            },
        },
    };

    let message = reason.to_string();

    assert!(message.contains(path.to_str().expect("UTF-8 fixture path")));
    assert!(message.contains("CreateDirectory"));
    assert!(message.contains("PermissionDenied"));
}

/// Every capability the vocabulary freezes is servable over the wire.
///
/// Listed by name rather than matched by a wildcard, so a capability added to
/// the vocabulary cannot become servable by default: the match in `servable`
/// stops compiling until the new row is admitted or refused by name, and this
/// list forces the same decision in the test.
#[test]
fn every_frozen_capability_is_servable() {
    for (name, capability) in [
        ("computer.click", ComputerCapability::Click),
        ("computer.type", ComputerCapability::Type),
        ("computer.keys", ComputerCapability::Keys),
        ("computer.scroll", ComputerCapability::Scroll),
        ("computer.move", ComputerCapability::Move),
        ("computer.drag", ComputerCapability::Drag),
        ("computer.screenshot", ComputerCapability::Screenshot),
        ("computer.wait", ComputerCapability::Wait),
    ] {
        assert_eq!(
            servable(name).map(|s| s.capability()),
            Some(capability),
            "{name} has a reviewed wire path and must be servable"
        );
    }
    assert!(servable("computer.not-a-capability").is_none());
}

/// Without a lease, a screenshot is refused and names how to get one.
///
/// The refusal is the whole gate: no pixels are read and no journal entry is
/// created, so nothing has to be undone. Asserted by its exact outcome rather
/// than by failure, because a request rejected for a malformed field would also
/// "fail" and would prove nothing about authority.
#[tokio::test]
async fn a_screenshot_without_a_lease_is_refused_with_the_recipe() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &request(),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the no-lease reply");

    assert_eq!(reply["outcome"], "no_lease");
    let remedy = reply["remedy"]
        .as_str()
        .expect("a refusal states its remedy");
    assert!(remedy.contains("computer.open_target"), "{remedy}");
}

/// Whole-display capture is refused for want of a broad grant.
///
/// Refused before any lease is consulted or any pixel read: the scope names a
/// blast radius this conversation does not hold, and attempting it first would
/// mean deciding on pixels already taken.
#[tokio::test]
async fn whole_display_capture_is_refused() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "display", "include_cursor": false }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the broad-grant refusal");

    assert_eq!(reply["outcome"], "broad_grant_required");
}

/// A request asking for the cursor is refused rather than quietly served without it.
///
/// The request schema pins this field to false, so a caller setting it is asking
/// for something the action does not offer. Ignoring it would return a picture
/// that differs from the one requested, with nothing saying so.
#[tokio::test]
async fn asking_for_the_cursor_is_an_invalid_request() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": true }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the invalid request reply");

    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["field"], "include_cursor");
}

/// Predicate waiting resolves the authorized target before attempting readback.
#[tokio::test]
async fn waiting_reports_an_unreadable_authorized_target_as_indeterminate() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.wait").expect("wait is servable"),
            &json!({
                "predicate": {
                    "kind": "element_present",
                    "element": {"Identifier": "ready"},
                },
                "timeout_ms": 250,
            }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("the schema-conformant indeterminate reply is returned");

    assert_eq!(reply["outcome"], "indeterminate");
    assert_eq!(reply["settle_path"], "poll_with_deadline");
    let evidence: Value = serde_json::from_str(
        reply["evidence"]
            .as_str()
            .expect("wait evidence is a JSON string"),
    )
    .expect("wait evidence contains a typed value");
    assert_eq!(evidence["status"], "indeterminate");
    assert_eq!(evidence["predicate"]["kind"], "element_present");
}

/// A declared refusal passes the serving boundary without a schema finding.
#[tokio::test]
async fn declared_screenshot_refusal_leaves_no_result_schema_finding() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": true }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("the declared refusal conforms to the frozen result schema");

    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["field"], "include_cursor");
    assert!(plane.result_schema_findings().is_empty());
}

/// Withholding mode must permit an actionable refusal declared by vocabulary v8.
#[tokio::test]
async fn withholding_mode_permits_a_declared_refusal() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> =
        ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold);
    let clock = FakeClock::new();

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": true }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &management(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("withholding mode must permit the declared refusal");

    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["reason"], "unknown_value");
    assert!(plane.result_schema_findings().is_empty());
}

/// A capture that fails still leaves an audit record behind.
///
/// The journal must reserve the action BEFORE any pixel is read, so an action
/// that went wrong is still accounted for. If capture ran first, a failing
/// capture would return the same refusal to the caller while leaving NOTHING
/// recorded — indistinguishable from outside, and an unrecorded observation is
/// what the journal exists to prevent.
///
/// Proved by making capture fail and asserting the journal grew. Asserting the
/// returned outcome alone would pass whichever order the code used.
#[tokio::test]
async fn a_failed_capture_is_still_recorded() {
    let plane: ComputerPlane<RefusingBackend, _, _, _> = ComputerPlane::new(audit());
    let clock = FakeClock::new();
    let before = plane.journal_entry_count().await;

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &request(),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| RefusingBackend {
                windows: vec![EnumeratedWindow {
                    window_id: "window-1".to_string(),
                    owner_identity: grant(),
                    owner_identity_verified: true,
                    frame: WindowFrame {
                        x: 0,
                        y: 0,
                        width: 800,
                        height: 600,
                    },
                    accessibility_root: None,
                }],
            },
        )
        .await
        .expect("detect-only validation preserves the capture failure");

    assert_eq!(reply["outcome"], "capture_failed");
    assert!(
        plane.journal_entry_count().await > before,
        "a capture that failed left no record, so the journal was reserved after the pixels \
         rather than before them"
    );
}

/// A runtime journal write failure refuses before the capture backend is built.
#[tokio::test]
async fn runtime_journal_save_failure_prevents_capture() {
    let clock = FakeClock::new();
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(failing_audit());
    let backend_built = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&backend_built);

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &request(),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            move |_| {
                observed.store(true, Ordering::SeqCst);
                InMemoryCaptureBackend::default()
            },
        )
        .await
        .expect("detect-only validation preserves the audit refusal");

    assert_eq!(reply["outcome"], "audit_unavailable");
    assert_eq!(
        reply["remedy"],
        "the action was not performed; retry once the journal is available"
    );
    assert!(
        reply.get("detail").is_none(),
        "journal diagnostics are not a public refusal field"
    );
    assert!(!backend_built.load(Ordering::SeqCst));
}

/// A request without `region` still captures the whole window and is returned.
///
/// The artifact handed to custody carries the encoded bytes and the dimensions
/// they describe. An artifact built with no bytes and zero dimensions passes
/// every check in this handler and is refused by custody at the moment of
/// retention, which returns a capture the caller never receives -- so the
/// assertion is on the RESULT reaching the caller, not merely on custody
/// having been called.
#[tokio::test]
async fn a_request_without_region_captures_the_whole_window() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let png = vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4, 5, 6, 7, 8];

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: vec![EnumeratedWindow {
                    window_id: "window-1".to_string(),
                    owner_identity: grant(),
                    owner_identity_verified: true,
                    frame: WindowFrame {
                        x: 0,
                        y: 0,
                        width: 800,
                        height: 600,
                    },
                    accessibility_root: None,
                }],
                png: png.clone(),
            },
        )
        .await
        .expect("the conforming capture reply passes result-schema validation");

    assert_eq!(
        reply["outcome"], "captured",
        "capture was not retained: {reply}"
    );

    let windows = reply["windows"].as_array().expect("windows are returned");
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0]["width_px"], 800);
    assert_eq!(windows[0]["height_px"], 600);
    assert!(
        !windows[0]["image_png_b64"]
            .as_str()
            .expect("an encoded image")
            .is_empty(),
        "the reply carried no image"
    );
}

fn patterned_bgra(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(width as usize * height as usize * 4);
    for y in 0..height {
        for x in 0..width {
            bytes.extend_from_slice(&[(x % 256) as u8, (y % 256) as u8, 0, 255]);
        }
    }
    bytes
}

fn decode_base64(encoded: &str) -> Vec<u8> {
    const TABLE: [i8; 256] = {
        let mut table = [-1i8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < alphabet.len() {
            table[alphabet[i] as usize] = i as i8;
            i += 1;
        }
        table
    };
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in encoded.bytes() {
        if byte == b'=' {
            break;
        }
        let value = TABLE[byte as usize];
        assert!(value >= 0, "invalid base64");
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

/// A region request returns pixels from that window-local rectangle.
///
/// Dimensions alone cannot distinguish a crop from a scaled or clamped window.
/// The final output row must carry row 35's marker: y=20 plus height=16 ends
/// there. The whole window or a rect shifted by its screen position cannot
/// produce that marker.
#[tokio::test]
async fn a_region_request_returns_the_named_window_rows() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let pixels = patterned_bgra(80, 60);
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({
                "scope": "target_windows",
                "include_cursor": false,
                "region": { "x_px": 10, "y_px": 20, "width_px": 30, "height_px": 16 }
            }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: vec![EnumeratedWindow {
                    window_id: "window-1".to_string(),
                    owner_identity: grant(),
                    owner_identity_verified: true,
                    frame: WindowFrame {
                        x: 500,
                        y: 300,
                        width: 80,
                        height: 60,
                    },
                    accessibility_root: None,
                }],
                png: pixels,
            },
        )
        .await
        .expect("the region capture conforms to the result schema");

    assert_eq!(
        reply["outcome"], "captured",
        "region capture failed: {reply}"
    );
    let window = &reply["windows"][0];
    let captured = decode_base64(
        window["image_png_b64"]
            .as_str()
            .expect("the captured bytes are encoded"),
    );
    let row_bytes = 30 * 4;
    let final_row = &captured[captured.len() - row_bytes..];
    let source_rows: Vec<u8> = (0_u8..60)
        .filter(|source_row| {
            final_row
                .as_chunks::<4>()
                .0
                .iter()
                .all(|pixel| pixel[1] == *source_row)
        })
        .collect();
    assert_eq!(
        source_rows,
        vec![35],
        "the requested region must end on source row 35"
    );
    assert_ne!(
        source_rows,
        vec![59],
        "the whole window was scaled or clamped"
    );
}

/// A present region must have the object shape declared by vocabulary v8.
#[tokio::test]
async fn a_null_region_request_is_rejected_as_the_wrong_type() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({
                "scope": "target_windows",
                "include_cursor": false,
                "region": null
            }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: Vec::new(),
                png: Vec::new(),
            },
        )
        .await
        .expect("detect-only validation preserves actionable request fields");

    assert_eq!(
        reply,
        json!({
            "outcome": "invalid_request",
            "windows": [],
            "field": "region",
            "reason": "wrong_type"
        })
    );
}

/// A target whose windows carry no pixels is reported as such.
///
/// Distinct from a capture that failed: there was nothing to capture rather
/// than an attempt that went wrong, and the remedies differ -- open a window,
/// versus retry or check permissions.
#[tokio::test]
async fn a_target_with_no_capturable_window_says_so() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());

    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: Vec::new(),
                png: Vec::new(),
            },
        )
        .await
        .expect("detect-only validation preserves the no-window reply");

    assert_eq!(
        reply["outcome"], "no_window_captured",
        "unexpected: {reply}"
    );
    assert!(
        reply["remedy"]
            .as_str()
            .is_some_and(|remedy| !remedy.is_empty()),
        "the refusal named no way forward"
    );
}

/// An unreadable window list is never reported as the application being absent.
///
/// The two answers send a person in opposite directions: `not_running` says to
/// start the application, while an unreadable list says nothing about whether it
/// is running at all.
///
/// Not hypothetical. Under concurrent load on a real machine the permission
/// query reported capture as permitted while enumeration failed in the same
/// instant with a declined-permission error, so a transient window-server
/// failure arrives wearing a denial's clothes. Reporting that as "not running"
/// tells someone to start a second copy of an application already in front of
/// them, and the second copy then makes the target ambiguous.
#[tokio::test]
async fn an_unreadable_window_list_is_not_reported_as_the_application_being_absent() {
    let plane = Arc::new(ManagementPlane::new(Arc::new(Fixed(
        TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable),
    ))));
    let clock = FakeClock::new();

    let (body, question) = plane
        .open_target(
            "agent-under-test",
            "com.example.App",
            cerebellum_core::consent::ActionKind::Observe,
            true,
            &clock,
        )
        .await;

    assert_eq!(
        body["outcome"], "targets_unreadable",
        "an unreadable window list produced: {body}"
    );
    assert!(
        question.is_none(),
        "a person was asked to approve a target nothing could see: {body}"
    );
}

/// The REASON a target was unreadable reaches the wire, and the remedy is
/// that reason's remedy.
///
/// One word used to carry every cause, and the remedy attached to it named a
/// macOS screen-recording grant -- so a Windows caller running in a service
/// session was told to check a permission on the wrong operating system for
/// a problem that was the session it ran in. Asserted at the reply, because
/// the reason travelled correctly inside the resolver for a day while the
/// wire kept saying the same thing.
#[tokio::test]
async fn an_unreadable_reason_reaches_the_wire_with_its_own_remedy() {
    let clock = FakeClock::new();
    let mut seen = std::collections::BTreeSet::new();

    for (reason, remedy_names) in [
        (
            UnreadableReason::SessionNotInteractive {
                session_id: 0,
                console_session_id: 1,
            },
            "console session",
        ),
        (
            UnreadableReason::NoConsoleSession { session_id: 0 },
            "log a user in",
        ),
        (
            UnreadableReason::PartialWindowList {
                unreadable_owners: 2,
            },
            "could not be attributed",
        ),
        (
            UnreadableReason::GenerationUnreadable { pid: 4242 },
            "do NOT start another instance",
        ),
        (
            UnreadableReason::WindowListUnavailable,
            "window-reading permission",
        ),
    ] {
        let plane = Arc::new(ManagementPlane::new(Arc::new(Fixed(
            TargetResolution::Unreadable(reason.clone()),
        ))));
        let (body, _) = plane
            .open_target(
                "agent-under-test",
                "com.example.App",
                cerebellum_core::consent::ActionKind::Observe,
                true,
                &clock,
            )
            .await;

        assert_eq!(body["outcome"], "targets_unreadable", "{body}");
        // The reason itself, serialized, not merely a prose hint about it.
        assert_eq!(
            body["unreadable"],
            serde_json::to_value(&reason).expect("reason serializes"),
            "the wire did not carry the reason: {body}"
        );
        let remedy = body["remedy"].as_str().expect("a remedy string");
        assert!(
            remedy.contains(remedy_names),
            "the remedy for {reason:?} does not name its own fix: {remedy}"
        );
        // Five reasons, five distinct remedies. A shared remedy would mean a
        // reason with nothing to say for itself, which is the collapse again.
        assert!(
            seen.insert(remedy.to_string()),
            "two reasons share one remedy: {remedy}"
        );
    }
}

/// A region outside any target window is refused before capture.
#[tokio::test]
async fn a_region_outside_the_window_is_refused() {
    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({
                "scope": "target_windows",
                "include_cursor": false,
                "region": { "x_px": 70, "y_px": 20, "width_px": 30, "height_px": 16 }
            }),
            ServeContext {
                grantee: "pj-example",
                identity: identity(),
                management: &leased_management(&clock).await,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: vec![EnumeratedWindow {
                    window_id: "window-1".to_string(),
                    owner_identity: grant(),
                    owner_identity_verified: true,
                    frame: WindowFrame {
                        x: 500,
                        y: 300,
                        width: 80,
                        height: 60,
                    },
                    accessibility_root: None,
                }],
                png: patterned_bgra(80, 60),
            },
        )
        .await
        .expect("detect-only validation preserves actionable request fields");

    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["field"], "region");
    assert_eq!(reply["reason"], "region_outside_window");
    assert_eq!(reply["windows"], json!([]));
}
