//! A capture_login cancelled before its window is handed over ends without
//! presenting a handed-over window, storing a login, or leaving its
//! throwaway profile, whichever step the Cancel interrupts. Only fakes are
//! used: the fake launcher and vault, never a real credential or profile.

use super::HANG_GUARD;
use super::*;
use journal::call_records::{
    CallRecordError, CallRecordStorage, CallRecords, InMemoryCallRecordStorage,
};
use login_capture::test_support::{fixture, BlockingGate, Fixture};
use std::sync::atomic::Ordering;

const CREDENTIAL: &str = "cookie:ollama.com:work";

fn cancel_frame(corr: u64) -> Frame {
    Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Cancel,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        corr,
        Vec::new(),
    )
    .unwrap()
}

/// The outcome of this credential's capture audit row, once it is written.
/// The row is written when the capture has ended, however it ended.
async fn capture_audit_outcome(planes: &Planes) -> String {
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let export = planes.browser.journal_export_for_test().await;
            let outcome = export.lines().find_map(|line| {
                let entry: journal::JournalEntry = serde_json::from_str(line).ok()?;
                match entry.payload {
                    Some(journal::JournalPayload::LoginCapture(payload))
                        if payload.credential_id == CREDENTIAL =>
                    {
                        Some(payload.outcome)
                    }
                    _ => None,
                }
            });
            if let Some(outcome) = outcome {
                return outcome;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the capture ends and records itself")
}

async fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(HANG_GUARD, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn assert_nothing_stored_and_profile_gone(fixture: &Fixture) {
    assert_eq!(
        fixture.vault.calls(),
        0,
        "a cancelled capture stored a login"
    );
    let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
    assert!(
        !fixture.fs.exists(placement.profile_directory()),
        "the cancelled capture left its throwaway profile"
    );
    let events = fixture.events.snapshot();
    assert!(
        events.contains(&"profile_deleted".to_string()),
        "{events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event.starts_with("cookie_header:")),
        "a cancelled capture read the login: {events:?}"
    );
}

/// The browser launch runs on the blocking pool. A Cancel that chooses the
/// reply while it runs must stop the capture once the launch returns: the
/// window is never shown, nothing is handed over or stored, and the profile
/// is deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_during_the_browser_launch_ends_the_capture_before_presenting() {
    let fixture = fixture();
    let gate = Arc::new(BlockingGate::default());
    *fixture.launcher.launch_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_cap_launch")
        .answered_in_call("el_cap_launch", "allow");
    let planes = cingulate.planes(&fixture);
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame_for_test(
        capture_request_frame(361, ollama_capture_params()),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    wait_until("the launch to start", || gate.entered()).await;

    handle_frame_for_test(cancel_frame(361), &tx, &planes)
        .await
        .unwrap();
    let reply: Value = serde_json::from_slice(&next_frame(&mut rx).await.body).unwrap();
    assert_eq!(reply, json!({"context":null,"outcome":"cancelled"}));

    gate.open();
    assert_eq!(capture_audit_outcome(&planes).await, "cancelled");
    let events = fixture.events.snapshot();
    assert!(
        !events
            .iter()
            .any(|event| event == "present" || event.starts_with("navigate:")),
        "the window was shown after the Cancel: {events:?}"
    );
    assert!(events.contains(&"browser_closed".to_string()), "{events:?}");
    assert_nothing_stored_and_profile_gone(&fixture);
    assert!(!planes.capture.is_detached());
    assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 1);
}

/// Call records that hold the first write saving a capture's hold until the
/// test releases it.
struct HoldCaptureSave {
    memory: InMemoryCallRecordStorage,
    held: std::sync::atomic::AtomicBool,
    gate: Arc<BlockingGate>,
}

impl HoldCaptureSave {
    fn before_write(&self, bytes: &[u8]) {
        if login_capture::test_support::contains_bytes(bytes, "\"capture\":true")
            && !self.held.swap(true, Ordering::SeqCst)
        {
            self.gate.pass();
        }
    }
}

impl CallRecordStorage for HoldCaptureSave {
    fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError> {
        self.memory.load()
    }
    fn append(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
        self.before_write(bytes);
        self.memory.append(bytes, version)
    }
    fn replace(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
        self.before_write(bytes);
        self.memory.replace(bytes, version)
    }
}

/// A Cancel that chooses the reply while the capture's hold is being saved
/// wins over the handover: the saved hold is settled as interrupted, and the
/// window that was already shown is closed with nothing stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_while_the_hold_is_saved_settles_it_interrupted_and_stores_nothing() {
    let fixture = fixture();
    let cingulate = ScriptedConsent::new();
    cingulate
        .raises("el_cap_hold")
        .answered_in_call("el_cap_hold", "allow");
    let mut planes = cingulate.planes(&fixture);
    let gate = Arc::new(BlockingGate::default());
    planes.calls = Arc::new(CallRecords::open(
        Box::new(HoldCaptureSave {
            memory: InMemoryCallRecordStorage::new(),
            held: std::sync::atomic::AtomicBool::new(false),
            gate: Arc::clone(&gate),
        }),
        wall_clock_ms(),
    ));
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame_for_test(
        capture_request_frame(362, ollama_capture_params()),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    wait_until("the hold to be saving", || gate.entered()).await;

    // The wire Cancel's own step: its handle chooses the reply. The frame's
    // other steps wait on the call records this test is holding.
    planes
        .cancellations
        .get((4, 1, 362))
        .expect("the capture is in flight")
        .cancel();
    gate.open();
    let reply: Value = serde_json::from_slice(&next_frame(&mut rx).await.body).unwrap();
    assert_eq!(reply, json!({"context":null,"outcome":"cancelled"}));

    assert_eq!(capture_audit_outcome(&planes).await, "cancelled");
    let late = capture_stored_late(&planes, 362).await;
    assert_eq!(late["result"]["outcome"], "handoff_interrupted", "{late}");
    let events = fixture.events.snapshot();
    assert!(events.contains(&"present".to_string()), "{events:?}");
    assert!(events.contains(&"browser_closed".to_string()), "{events:?}");
    assert!(
        !events.iter().any(|event| event.starts_with("verify:")),
        "the cancelled capture kept observing sign-in: {events:?}"
    );
    assert_nothing_stored_and_profile_gone(&fixture);
    assert!(!planes.capture.is_detached());
}
