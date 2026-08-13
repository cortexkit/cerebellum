use std::cmp;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::browser::Tracker;
use crate::browser_launch_readiness::{CdpPipeIo, PipeRead};
use crate::browser_session::{NavigationDriveError, NavigationWait};
use crate::cdp::{Attachment, CdpEvent, CdpFrameDecoder, CdpResponse, CdpTransport, IdentityMap};

const READ_CHUNK_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachedTarget {
    target_id: String,
    session_id: String,
    context_key: String,
}

/// Owns every CDP write, frame decoder, and request correlator for one browser.
/// Keeping these together prevents a lifecycle command and a navigation command
/// from assigning competing request ids or interleaving frames on the pipe.
pub(crate) struct CdpNavigationDriver<IO> {
    pipe: IO,
    transport: CdpTransport,
    decoder: CdpFrameDecoder,
    identities: IdentityMap,
    attachment: Option<AttachedTarget>,
    read_buffer: Vec<u8>,
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(crate) fn new(pipe: IO, mut transport: CdpTransport, decoder: CdpFrameDecoder) -> Self {
        // Readiness can observe browser-wide startup events before this route has
        // attached a target. They have no route identity and must not remain in
        // the established session's bounded event queue.
        while transport.pop_event().is_some() {}
        Self {
            pipe,
            transport,
            decoder,
            identities: IdentityMap::new(),
            attachment: None,
            read_buffer: vec![0; READ_CHUNK_BYTES],
        }
    }

    pub(crate) fn navigate(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        self.navigate_with_clock(context_key, url, wait, deadline_ms, tracker, &mut clock)
    }

    #[cfg(test)]
    pub(crate) fn navigate_for_test<C: NavigationClock>(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        self.navigate_with_clock(context_key, url, wait, deadline_ms, tracker, clock)
    }

    fn navigate_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::CdpFailure)?;

        self.command(
            "Page.enable",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            clock,
        )?;
        self.command(
            "Network.enable",
            None,
            Some(attachment.session_id.clone()),
            deadline,
            None,
            clock,
        )?;

        let mut params = Map::new();
        params.insert("url".into(), Value::String(url.to_string()));
        self.command(
            "Page.navigate",
            Some(params),
            Some(attachment.session_id.clone()),
            deadline,
            Some((context_key, tracker)),
            clock,
        )?;

        if wait == NavigationWait::None {
            return Ok(());
        }

        while clock.now() < deadline {
            self.read_turn(None, Some((context_key, tracker)), clock.now())?;
            if tracker.poll_settlement(clock.now()) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }
        tracker.poll_settlement(clock.now());
        Ok(())
    }

    pub(crate) fn request_browser_close(&mut self) -> Result<(), NavigationDriveError> {
        // Teardown uses the same correlator as navigation so request ids remain
        // unique until the descriptor closes; a fixed close id could alias a
        // completed navigation response on a long-lived session.
        let command = self
            .transport
            .issue_command("Browser.close", None, None, Instant::now())
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        let mut bytes = command
            .json_bytes()
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        bytes.push(0);
        self.pipe
            .write_frame(&bytes)
            .map_err(|_| NavigationDriveError::ConnectorFailure)
    }

    fn ensure_attached<C: NavigationClock>(
        &mut self,
        context_key: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        if let Some(attachment) = &self.attachment {
            return if attachment.context_key == context_key {
                Ok(())
            } else {
                Err(NavigationDriveError::CdpFailure)
            };
        }

        // A dedicated target makes ownership explicit. Selecting an arbitrary
        // pre-existing tab would let one route drive a page whose custody was
        // never established for that route.
        let mut create_params = Map::new();
        create_params.insert("url".into(), Value::String("about:blank".into()));
        let created = self.command(
            "Target.createTarget",
            Some(create_params),
            None,
            deadline,
            None,
            clock,
        )?;
        let target_id = required_result_string(&created, "targetId")?;

        let mut attach_params = Map::new();
        attach_params.insert("targetId".into(), Value::String(target_id.clone()));
        attach_params.insert("flatten".into(), Value::Bool(true));
        let attached = self.command(
            "Target.attachToTarget",
            Some(attach_params),
            None,
            deadline,
            None,
            clock,
        )?;
        let session_id = required_result_string(&attached, "sessionId")?;

        self.identities
            .attach(Attachment {
                target_id: target_id.clone(),
                session_id: session_id.clone(),
                frame_ids: Vec::new(),
                context_key: context_key.to_string(),
            })
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        self.attachment = Some(AttachedTarget {
            target_id,
            session_id,
            context_key: context_key.to_string(),
        });
        Ok(())
    }

    fn command<C: NavigationClock>(
        &mut self,
        method: &str,
        params: Option<Map<String, Value>>,
        session_id: Option<String>,
        deadline: Instant,
        mut tracking: Option<(&str, &mut Tracker)>,
        clock: &mut C,
    ) -> Result<Map<String, Value>, NavigationDriveError> {
        let command = self
            .transport
            .issue_command(method, params, session_id, clock.now())
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        let command_id = command.id;
        let mut bytes = command
            .json_bytes()
            .map_err(|_| NavigationDriveError::CdpFailure)?;
        bytes.push(0);
        self.pipe
            .write_frame(&bytes)
            .map_err(|_| NavigationDriveError::ConnectorFailure)?;

        loop {
            if clock.now() >= deadline {
                return Err(NavigationDriveError::CdpFailure);
            }
            let response = match tracking.as_mut() {
                Some((context_key, tracker)) => self.read_turn(
                    Some(command_id),
                    Some((*context_key, *tracker)),
                    clock.now(),
                )?,
                None => self.read_turn(Some(command_id), None, clock.now())?,
            };
            if let Some(response) = response {
                if response.error.is_some() {
                    return Err(NavigationDriveError::CdpFailure);
                }
                return response.result.ok_or(NavigationDriveError::CdpFailure);
            }
            let remaining = deadline.saturating_duration_since(clock.now());
            clock.sleep(cmp::min(POLL_INTERVAL, remaining));
        }
    }

    fn read_turn(
        &mut self,
        expected_response_id: Option<u64>,
        mut tracking: Option<(&str, &mut Tracker)>,
        observed_at: Instant,
    ) -> Result<Option<CdpResponse>, NavigationDriveError> {
        let bytes = match self.pipe.read(&mut self.read_buffer) {
            Ok(PipeRead::Bytes(bytes)) if bytes <= self.read_buffer.len() => bytes,
            Ok(PipeRead::Bytes(_)) | Ok(PipeRead::Closed) => {
                return Err(NavigationDriveError::ConnectorFailure)
            }
            Ok(PipeRead::WouldBlock) => return Ok(None),
            Err(_) => return Err(NavigationDriveError::ConnectorFailure),
        };

        let mut matched = None;
        for frame in self.decoder.push(&self.read_buffer[..bytes]) {
            let value: Value =
                serde_json::from_slice(&frame).map_err(|_| NavigationDriveError::CdpFailure)?;
            if value.get("id").is_some() {
                let response = self
                    .transport
                    .take_response(&frame)
                    .map_err(|_| NavigationDriveError::CdpFailure)?;
                if Some(response.id) == expected_response_id {
                    matched = Some(response);
                }
                continue;
            }

            let event = self
                .transport
                .accept_event(&frame)
                .map_err(|_| NavigationDriveError::CdpFailure)?;
            let _ = self.transport.pop_event();
            if let Some((context_key, tracker)) = tracking.as_mut() {
                self.apply_event(context_key, tracker, &event, observed_at);
            }
        }
        Ok(matched)
    }

    fn apply_event(
        &self,
        context_key: &str,
        tracker: &mut Tracker,
        event: &CdpEvent,
        observed_at: Instant,
    ) {
        let Some(attachment) = self.attachment.as_ref() else {
            return;
        };
        let Some(session_id) = event.session_id.as_deref() else {
            return;
        };
        let event_target = event
            .raw
            .get("targetId")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("targetId"))
                    .and_then(Value::as_str)
            })
            .unwrap_or(&attachment.target_id);
        if self
            .identities
            .context_for(event_target, session_id, None)
            .ok()
            != Some(context_key)
        {
            return;
        }

        match event.method.as_str() {
            "Page.loadEventFired" => tracker.load(observed_at),
            "Network.requestWillBeSent" => tracker.request_started(),
            "Network.loadingFinished" | "Network.loadingFailed" => {
                tracker.request_finished(observed_at)
            }
            "Page.frameNavigated" => {
                let frame = event
                    .params
                    .as_ref()
                    .and_then(|params| params.get("frame"))
                    .and_then(Value::as_object);
                if let Some(frame) = frame.filter(|frame| !frame.contains_key("parentId")) {
                    if let Some(url) = frame.get("url").and_then(Value::as_str) {
                        tracker.url_final = Some(url.to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

fn required_result_string(
    result: &Map<String, Value>,
    field: &str,
) -> Result<String, NavigationDriveError> {
    result
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or(NavigationDriveError::CdpFailure)
}

pub(crate) trait NavigationClock {
    fn now(&mut self) -> Instant;
    fn sleep(&mut self, duration: Duration);
}

struct SystemNavigationClock;

impl NavigationClock for SystemNavigationClock {
    fn now(&mut self) -> Instant {
        Instant::now()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use serde_json::json;

    use super::*;
    use crate::browser::QUIET_MS;

    #[derive(Default)]
    struct FakePipe {
        writes: Vec<Value>,
        reads: VecDeque<Vec<u8>>,
    }

    impl FakePipe {
        fn with_frames(frames: impl IntoIterator<Item = Value>) -> Self {
            let reads = frames
                .into_iter()
                .map(|frame| {
                    let mut bytes = serde_json::to_vec(&frame).unwrap();
                    bytes.push(0);
                    bytes
                })
                .collect();
            Self {
                writes: Vec::new(),
                reads,
            }
        }
    }

    impl CdpPipeIo for FakePipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.writes
                .push(serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap());
            Ok(())
        }

        fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
            let Some(bytes) = self.reads.pop_front() else {
                return Ok(PipeRead::WouldBlock);
            };
            destination[..bytes.len()].copy_from_slice(&bytes);
            Ok(PipeRead::Bytes(bytes.len()))
        }
    }

    struct FakeClock {
        now: Instant,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Instant::now(),
            }
        }
    }

    impl NavigationClock for FakeClock {
        fn now(&mut self) -> Instant {
            self.now
        }

        fn sleep(&mut self, duration: Duration) {
            self.now += duration;
        }
    }

    fn driver(frames: impl IntoIterator<Item = Value>) -> CdpNavigationDriver<FakePipe> {
        CdpNavigationDriver::new(
            FakePipe::with_frames(frames),
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        )
    }

    fn attached_driver(frames: impl IntoIterator<Item = Value>) -> CdpNavigationDriver<FakePipe> {
        let mut driver = driver(frames);
        driver
            .identities
            .attach(Attachment {
                target_id: "target-own".into(),
                session_id: "session-own".into(),
                frame_ids: Vec::new(),
                context_key: "route-own".into(),
            })
            .unwrap();
        driver.attachment = Some(AttachedTarget {
            target_id: "target-own".into(),
            session_id: "session-own".into(),
            context_key: "route-own".into(),
        });
        driver
    }

    fn event(method: &str, params: Value) -> CdpEvent {
        let raw = json!({
            "method": method,
            "sessionId": "session-own",
            "params": params,
        });
        CdpEvent {
            method: method.into(),
            params: raw["params"].as_object().cloned(),
            session_id: Some("session-own".into()),
            raw,
        }
    }

    #[test]
    fn main_frame_sets_the_browser_reported_url_and_subframe_cannot_replace_it() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let now = Instant::now();
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event(
                "Page.frameNavigated",
                json!({"frame":{"id":"main","url":"https://landed.example/final"}}),
            ),
            now,
        );
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event(
                "Page.frameNavigated",
                json!({"frame":{"id":"ad","parentId":"main","url":"https://ads.example/"}}),
            ),
            now,
        );

        assert_eq!(
            tracker.url_final.as_deref(),
            Some("https://landed.example/final")
        );
    }

    #[test]
    fn another_targets_event_cannot_drive_this_tracker() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        let mut foreign = event("Page.loadEventFired", json!({}));
        foreign.raw["targetId"] = Value::String("target-foreign".into());
        driver.apply_event("route-own", &mut tracker, &foreign, Instant::now());

        assert!(!tracker.load_observed);
        assert!(tracker.lifecycle.is_empty());
    }

    #[test]
    fn request_will_be_sent_starts_the_attributed_request() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.requestWillBeSent", json!({})),
            Instant::now(),
        );

        assert_eq!(tracker.inflight_count, 1);
    }

    #[test]
    fn loading_failure_finishes_the_attributed_request() {
        let driver = attached_driver([]);
        let mut tracker = Tracker::default();
        tracker.request_started();
        driver.apply_event(
            "route-own",
            &mut tracker,
            &event("Network.loadingFailed", json!({})),
            Instant::now(),
        );

        assert_eq!(tracker.inflight_count, 0);
    }

    #[test]
    fn every_settlement_condition_is_required() {
        let now = Instant::now();

        let mut no_load = Tracker::default();
        no_load.request_started();
        no_load.request_finished(now);
        assert!(!no_load.poll_settlement(now + Duration::from_millis(QUIET_MS)));

        let mut in_flight = Tracker::default();
        in_flight.load(now);
        // Assign the public count directly so the quiet timestamp remains
        // satisfied and this assertion isolates the in-flight predicate.
        in_flight.inflight_count = 1;
        assert!(!in_flight.poll_settlement(now + Duration::from_millis(QUIET_MS)));

        let mut not_quiet = Tracker::default();
        not_quiet.load(now);
        assert!(!not_quiet.poll_settlement(now + Duration::from_millis(QUIET_MS - 1)));

        let mut complete = Tracker::default();
        complete.load(now);
        assert!(complete.poll_settlement(now + Duration::from_millis(QUIET_MS)));
        assert_eq!(complete.lifecycle, ["load", "network_quiet"]);
    }

    #[test]
    fn enables_page_and_network_before_navigation() {
        let frames = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
        ];
        let mut driver = driver(frames);
        let mut tracker = Tracker::default();
        driver
            .navigate_for_test(
                "route-own",
                "https://requested.example/",
                NavigationWait::None,
                100,
                &mut tracker,
                &mut FakeClock::new(),
            )
            .unwrap();

        let methods = driver
            .pipe
            .writes
            .iter()
            .map(|write| write["method"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            [
                "Target.createTarget",
                "Target.attachToTarget",
                "Page.enable",
                "Network.enable",
                "Page.navigate",
            ]
        );
    }

    #[test]
    fn redirected_main_frame_is_the_final_url_and_subframe_is_ignored() {
        let frames = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
            json!({"method":"Network.requestWillBeSent","sessionId":"session-own","params":{}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example/"}}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://landed.example/final"}}}),
            json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"ad","parentId":"main","url":"https://ads.example/"}}}),
            json!({"method":"Network.loadingFinished","sessionId":"session-own","params":{}}),
            json!({"method":"Page.loadEventFired","sessionId":"session-own","params":{}}),
        ];
        let mut driver = driver(frames);
        let mut tracker = Tracker::default();
        tracker.token("navigation_started");
        driver
            .navigate_for_test(
                "route-own",
                "https://requested.example/",
                NavigationWait::Settle,
                1_000,
                &mut tracker,
                &mut FakeClock::new(),
            )
            .unwrap();

        assert!(tracker.settled);
        assert_eq!(
            tracker.url_final.as_deref(),
            Some("https://landed.example/final")
        );
        assert_eq!(
            tracker.lifecycle,
            ["navigation_started", "load", "network_quiet"]
        );
    }

    #[test]
    fn deadline_returns_observed_tokens_without_hanging() {
        let frames = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{}}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
            json!({"method":"Page.loadEventFired","sessionId":"session-own","params":{}}),
        ];
        let mut driver = driver(frames);
        let mut tracker = Tracker::default();
        tracker.token("navigation_started");
        let mut clock = FakeClock::new();
        driver
            .navigate_for_test(
                "route-own",
                "https://requested.example/",
                NavigationWait::Settle,
                10,
                &mut tracker,
                &mut clock,
            )
            .unwrap();

        assert!(!tracker.settled);
        assert_eq!(tracker.lifecycle, ["navigation_started", "load"]);
    }
}
