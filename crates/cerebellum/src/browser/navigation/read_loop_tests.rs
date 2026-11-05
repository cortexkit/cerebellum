use super::tests::{FakeClock, FakePipe};
use super::*;
use serde_json::json;

#[test]
fn an_event_backlog_does_not_add_polling_sleeps_before_the_reply() {
    const CHUNKS: u64 = 128;
    let events = (0..CHUNKS).map(|_| {
        json!({"method":"Page.navigatedWithinDocument","sessionId":"session",
            "params":{"frameId":"frame","url":"https://example.test/", "padding":"x".repeat(32 * 1024)}})
    });
    let pipe = FakePipe::with_frames(events.chain([
        json!({"id":1,"result":{"sentinel":"earlier"}}),
        json!({"id":2,"result":{"sentinel":"expected"}}),
    ]));
    let mut driver =
        CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());
    driver
        .frame_sessions
        .insert("frame".into(), "session".into());
    let mut clock = FakeClock::new();
    let start = clock.now();
    driver
        .transport
        .issue_command("Page.getFrameTree", None, None, start)
        .unwrap();
    let response = driver
        .command_response(
            "Page.getFrameTree",
            None,
            None,
            start + Duration::from_secs(2),
            None,
            None,
            &mut clock,
        )
        .unwrap();

    assert_eq!(response.result.unwrap()["sentinel"], "expected");
    assert_eq!(
        driver.pending_responses[&1].result.as_ref().unwrap()["sentinel"],
        "earlier"
    );
    assert_eq!(
        driver.frame_revisions["frame"], CHUNKS,
        "every event must update driver state"
    );
    assert_eq!(
        clock.now().duration_since(start),
        Duration::ZERO,
        "readable events and unrelated replies must not incur the 5 ms polling sleep"
    );
}

use crate::browser_session::{DriveScope, DriverWatch};
use std::io;
use std::sync::{Arc, Mutex};

struct Clock {
    now: Arc<Mutex<Instant>>,
    sleeps: usize,
}

impl NavigationClock for Clock {
    fn now(&mut self) -> Instant {
        *self.now.lock().unwrap()
    }
    fn sleep(&mut self, duration: Duration) {
        *self.now.lock().unwrap() += duration;
        self.sleeps += 1;
    }
}

struct Firehose {
    frame: Vec<u8>,
    reads: usize,
    now: Arc<Mutex<Instant>>,
    per_read: Duration,
    cancel: Option<(usize, Arc<crate::TerminalArbiter>)>,
    respond: bool,
    replies: VecDeque<Vec<u8>>,
}

impl CdpPipeIo for Firehose {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.respond {
            let request: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
            let mut response = json!({"id":request["id"],"result":{}});
            if request["method"] == "Target.attachToTarget" {
                response["result"] = json!({"sessionId":"session"});
            }
            if let Some(session) = request.get("sessionId") {
                response["sessionId"] = session.clone();
            }
            let mut frame = serde_json::to_vec(&response).unwrap();
            frame.push(0);
            self.replies.push_back(frame);
        }
        Ok(())
    }
    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        self.reads += 1;
        *self.now.lock().unwrap() += self.per_read;
        if let Some((after, terminal)) = &self.cancel {
            if self.reads == *after {
                terminal.stop(crate::TerminalCause::Cancelled);
            }
        }
        let frame = self
            .replies
            .pop_front()
            .unwrap_or_else(|| self.frame.clone());
        destination[..frame.len()].copy_from_slice(&frame);
        Ok(PipeRead::Bytes(frame.len()))
    }
}

fn firehose(per_read: Duration) -> (CdpNavigationDriver<Firehose>, Clock) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let mut frame = serde_json::to_vec(&json!({"method":"Page.navigatedWithinDocument",
        "sessionId":"session", "params":{"frameId":"frame","url":"https://example.test/",
        "padding":"x".repeat(32 * 1024)}}))
    .unwrap();
    frame.push(0);
    let pipe = Firehose {
        frame,
        reads: 0,
        now: now.clone(),
        per_read,
        cancel: None,
        respond: false,
        replies: VecDeque::new(),
    };
    let mut driver =
        CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());
    driver
        .frame_sessions
        .insert("frame".into(), "session".into());
    (driver, Clock { now, sleeps: 0 })
}

#[test]
fn a_continuously_readable_pipe_checks_the_command_deadline_each_turn() {
    let (mut driver, mut clock) = firehose(Duration::from_millis(2));
    let start = clock.now();
    let error = driver
        .command_response(
            "Page.getFrameTree",
            None,
            None,
            start + Duration::from_millis(9),
            None,
            None,
            &mut clock,
        )
        .unwrap_err();
    assert_eq!(
        error,
        NavigationDriveError::CommandDeadline {
            method: "Page.getFrameTree".into(),
            command_sent: true
        }
    );
    assert_eq!(driver.pipe.reads, 5);
    assert_eq!(driver.frame_revisions["frame"], 5);
    assert_eq!(clock.now().duration_since(start), Duration::from_millis(10));
    assert_eq!(clock.sleeps, 0);
    assert_eq!(driver.transport.pending_len(), 0);
    assert!(!driver.transport.is_closed());
}

#[test]
fn a_continuously_readable_pipe_checks_settlement_and_click_deadlines_each_turn() {
    let (mut driver, mut clock) = firehose(Duration::from_millis(2));
    let deadline = clock.now() + Duration::from_millis(9);
    driver
        .settle_navigation(
            "context",
            &mut Tracker::default(),
            deadline,
            |_| false,
            &mut clock,
        )
        .unwrap();
    assert_eq!(driver.pipe.reads, 5);
    assert_eq!(clock.sleeps, 0);

    let (mut driver, mut clock) = firehose(Duration::from_millis(2));
    let result = driver
        .observe_click_navigation("context", Tracker::default(), 20_000, &mut clock)
        .unwrap();
    assert!(matches!(
        result,
        ClickNavigation::NoneObserved { window_ms: 100 }
    ));
    assert_eq!(driver.pipe.reads, 50);
    assert_eq!(driver.frame_revisions["frame"], 50);
    assert_eq!(clock.sleeps, 0);
}

#[test]
fn cancellation_stops_a_continuously_readable_command_and_retires_its_reply() {
    let request = subc_protocol::Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        subc_protocol::FrameType::Request,
        crate::wire::control_flags(),
        9,
        3,
        1,
        serde_json::to_vec(&json!({"name":crate::browser::TYPE})).unwrap(),
    )
    .unwrap();
    let terminal = Arc::new(crate::TerminalArbiter::new(request));
    let watch = Arc::new(DriverWatch::default());
    let _scope = DriveScope::enter(Some(terminal.clone()), &watch);
    let (mut driver, mut clock) = firehose(Duration::ZERO);
    driver.pipe.cancel = Some((7, terminal));
    let deadline = clock.now() + Duration::from_secs(20);
    let error = driver
        .command_response(
            "Page.getFrameTree",
            None,
            None,
            deadline,
            None,
            None,
            &mut clock,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        NavigationDriveError::CommandDeadline {
            command_sent: true,
            ..
        }
    ));
    assert_eq!(driver.pipe.reads, 7);
    assert_eq!(driver.frame_revisions["frame"], 7);
    assert_eq!(clock.sleeps, 0);
    assert_eq!(driver.transport.pending_len(), 0);
    let late = serde_json::to_vec(&json!({"id":1,"result":{}})).unwrap();
    assert!(driver.transport.take_response(&late).unwrap().abandoned);
}

#[test]
fn a_would_block_pipe_still_sleeps_and_obeys_the_absolute_deadline() {
    let mut driver = CdpNavigationDriver::new(
        FakePipe::default(),
        CdpTransport::new(),
        CdpFrameDecoder::default(),
    );
    let mut clock = FakeClock::new();
    let start = clock.now();
    let result = driver.command_response(
        "Page.getFrameTree",
        None,
        None,
        start + Duration::from_millis(12),
        None,
        None,
        &mut clock,
    );
    assert!(matches!(
        result,
        Err(NavigationDriveError::CommandDeadline {
            command_sent: true,
            ..
        })
    ));
    assert_eq!(clock.now().duration_since(start), Duration::from_millis(12));
}

#[test]
fn a_continuously_readable_verification_loop_checks_its_absolute_deadline() {
    let (mut driver, mut clock) = firehose(Duration::from_millis(2));
    driver.pipe.respond = true;
    let start = clock.now();
    let result = driver.load_in_verification_target(
        "target",
        "https://example.test/",
        start + Duration::from_millis(29),
        &mut clock,
    );
    assert!(matches!(result, Err(NavigationDriveError::CdpFailure)));
    assert_eq!(driver.pipe.reads, 15);
    assert_eq!(driver.frame_revisions["frame"], 11);
    assert_eq!(clock.now().duration_since(start), Duration::from_millis(30));
    assert_eq!(clock.sleeps, 0);
}
