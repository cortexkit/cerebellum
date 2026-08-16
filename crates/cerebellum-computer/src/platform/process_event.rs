//! Platform-neutral routing for one synthesized event to one process.
//!
//! This module decides whether the public per-process transport may be called.
//! It does not expose a global transport, and the event is moved into the
//! selected transport even when that transport reports failure. That ownership
//! boundary makes retrying the same event through another transport impossible.

#[cfg(target_os = "macos")]
use std::time::Duration;

/// The process generation an event was authorized for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessEventTarget {
    pub pid: u32,
    pub start_time_micros: u64,
}

/// A fresh kernel reading of the process currently holding a pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGenerationReading {
    Started(u64),
    Gone,
    NotInspectable,
}

/// Whether the window server currently describes the target process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowServerVisibility {
    Visible,
    NotVisible,
    Unreadable(String),
}

/// The one per-process transport this routing slice selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerProcessTransport {
    PublicCoreGraphics,
}

/// Evidence that the selected transport's post call returned.
///
/// This is deliberately not named `Delivered`: CoreGraphics does not report
/// whether the target received the event or acted on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a returned post call is not evidence that the event was delivered"]
pub struct PostCallMade {
    pub transport: PerProcessTransport,
}

impl PostCallMade {
    pub fn public_core_graphics() -> Self {
        Self {
            transport: PerProcessTransport::PublicCoreGraphics,
        }
    }
}

/// Why the selected transport could not complete its post call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostCallFailure {
    pub reason: String,
}

impl PostCallFailure {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// A refusal to call, or a failure reported by, the per-process transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessEventRefusal {
    ProcessGone,
    ProcessReplaced {
        expected_start_time_micros: u64,
        observed_start_time_micros: u64,
    },
    ProcessNotInspectable,
    NotVisibleToWindowServer,
    WindowServerUnreadable {
        reason: String,
    },
    PostCallFailed(PostCallFailure),
}

/// Raw readings and the single effectful call needed by the routing decision.
///
/// `event` is consumed by `post_to_pid`, including on failure. An uncertain
/// failed call therefore cannot return the event for a second transport to post.
pub trait PerProcessEventTransport {
    type Event;

    fn process_generation(&mut self, pid: u32) -> ProcessGenerationReading;
    fn window_server_visibility(&mut self, pid: u32) -> WindowServerVisibility;
    fn post_to_pid(
        &mut self,
        pid: u32,
        event: Self::Event,
    ) -> Result<PostCallMade, PostCallFailure>;
}

/// Route one event to the exact process generation named by `target`.
///
/// Generation is checked once before the window-server read so a departed
/// process is not mistaken for an invisible one, then checked again immediately
/// before posting to close pid reuse during that read.
pub fn route_event_to_process<T: PerProcessEventTransport>(
    target: ProcessEventTarget,
    event: T::Event,
    transport: &mut T,
) -> Result<PostCallMade, ProcessEventRefusal> {
    require_exact_generation(target, transport.process_generation(target.pid))?;

    match transport.window_server_visibility(target.pid) {
        WindowServerVisibility::Visible => {}
        WindowServerVisibility::NotVisible => {
            return Err(ProcessEventRefusal::NotVisibleToWindowServer)
        }
        WindowServerVisibility::Unreadable(reason) => {
            return Err(ProcessEventRefusal::WindowServerUnreadable { reason })
        }
    }

    // This is the post-time identity check. Nothing that can block or inspect
    // another subsystem occurs between this reading and the selected post call.
    require_exact_generation(target, transport.process_generation(target.pid))?;

    transport
        .post_to_pid(target.pid, event)
        .map_err(ProcessEventRefusal::PostCallFailed)
}

fn require_exact_generation(
    target: ProcessEventTarget,
    reading: ProcessGenerationReading,
) -> Result<(), ProcessEventRefusal> {
    match reading {
        ProcessGenerationReading::Started(observed) if observed == target.start_time_micros => {
            Ok(())
        }
        ProcessGenerationReading::Started(observed) => Err(ProcessEventRefusal::ProcessReplaced {
            expected_start_time_micros: target.start_time_micros,
            observed_start_time_micros: observed,
        }),
        ProcessGenerationReading::Gone => Err(ProcessEventRefusal::ProcessGone),
        ProcessGenerationReading::NotInspectable => Err(ProcessEventRefusal::ProcessNotInspectable),
    }
}

/// Public CoreGraphics transport readings for production macOS callers.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
pub struct MacOsPerProcessEventTransport {
    window_list_timeout: Duration,
}

#[cfg(target_os = "macos")]
impl MacOsPerProcessEventTransport {
    pub fn new(window_list_timeout: Duration) -> Self {
        Self {
            window_list_timeout,
        }
    }
}

#[cfg(target_os = "macos")]
impl PerProcessEventTransport for MacOsPerProcessEventTransport {
    type Event = cerebellum_macos::OwnedCgEvent;

    fn process_generation(&mut self, pid: u32) -> ProcessGenerationReading {
        match cerebellum_macos::process_start_time(pid) {
            cerebellum_macos::ProcessStartTime::Started(micros) => {
                ProcessGenerationReading::Started(micros)
            }
            cerebellum_macos::ProcessStartTime::NoSuchProcess => ProcessGenerationReading::Gone,
            cerebellum_macos::ProcessStartTime::NotPermitted
            | cerebellum_macos::ProcessStartTime::LayoutMismatch
            | cerebellum_macos::ProcessStartTime::NoStartTime => {
                ProcessGenerationReading::NotInspectable
            }
        }
    }

    fn window_server_visibility(&mut self, pid: u32) -> WindowServerVisibility {
        match cerebellum_macos::enumerate_windows(self.window_list_timeout) {
            Ok(windows) if windows.iter().any(|window| window.owner_pid == pid) => {
                WindowServerVisibility::Visible
            }
            Ok(_) => WindowServerVisibility::NotVisible,
            Err(reason) => WindowServerVisibility::Unreadable(reason),
        }
    }

    fn post_to_pid(
        &mut self,
        pid: u32,
        event: Self::Event,
    ) -> Result<PostCallMade, PostCallFailure> {
        let pid = i32::try_from(pid)
            .map_err(|_| PostCallFailure::new("process id does not fit macOS pid_t"))?;
        let _call_made_not_delivery = cerebellum_macos::post_event_to_pid(pid, &event);
        Ok(PostCallMade::public_core_graphics())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const PID: u32 = 41;
    const START_TIME: u64 = 8_000_123;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FakeEvent(u8);

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        ReadGeneration,
        ReadVisibility,
        Post { pid: u32, event: FakeEvent },
    }

    struct FakeTransport {
        generations: VecDeque<ProcessGenerationReading>,
        visibility: WindowServerVisibility,
        post_results: VecDeque<Result<PostCallMade, PostCallFailure>>,
        calls: Vec<Call>,
    }

    impl FakeTransport {
        fn new(
            generations: impl IntoIterator<Item = ProcessGenerationReading>,
            visibility: WindowServerVisibility,
            post_results: impl IntoIterator<Item = Result<PostCallMade, PostCallFailure>>,
        ) -> Self {
            Self {
                generations: generations.into_iter().collect(),
                visibility,
                post_results: post_results.into_iter().collect(),
                calls: Vec::new(),
            }
        }

        fn posting(
            generations: impl IntoIterator<Item = ProcessGenerationReading>,
            visibility: WindowServerVisibility,
        ) -> Self {
            Self::new(
                generations,
                visibility,
                [Ok(PostCallMade::public_core_graphics())],
            )
        }

        fn post_count(&self) -> usize {
            self.calls
                .iter()
                .filter(|call| matches!(call, Call::Post { .. }))
                .count()
        }
    }

    impl PerProcessEventTransport for FakeTransport {
        type Event = FakeEvent;

        fn process_generation(&mut self, _pid: u32) -> ProcessGenerationReading {
            self.calls.push(Call::ReadGeneration);
            self.generations
                .pop_front()
                .expect("the test supplied every expected generation reading")
        }

        fn window_server_visibility(&mut self, _pid: u32) -> WindowServerVisibility {
            self.calls.push(Call::ReadVisibility);
            self.visibility.clone()
        }

        fn post_to_pid(
            &mut self,
            pid: u32,
            event: Self::Event,
        ) -> Result<PostCallMade, PostCallFailure> {
            self.calls.push(Call::Post { pid, event });
            self.post_results
                .pop_front()
                .unwrap_or_else(|| Err(PostCallFailure::new("unexpected second transport")))
        }
    }

    fn target() -> ProcessEventTarget {
        ProcessEventTarget {
            pid: PID,
            start_time_micros: START_TIME,
        }
    }

    fn current() -> ProcessGenerationReading {
        ProcessGenerationReading::Started(START_TIME)
    }

    fn route(transport: &mut FakeTransport) -> Result<PostCallMade, ProcessEventRefusal> {
        route_event_to_process(target(), FakeEvent(7), transport)
    }

    #[test]
    fn one_synthesized_event_reaches_exactly_one_transport() {
        let mut transport =
            FakeTransport::posting([current(), current()], WindowServerVisibility::Visible);

        let result = route(&mut transport).expect("the selected post call should be made");

        assert_eq!(result.transport, PerProcessTransport::PublicCoreGraphics);
        assert_eq!(transport.post_count(), 1);
        assert_eq!(
            transport.calls,
            vec![
                Call::ReadGeneration,
                Call::ReadVisibility,
                Call::ReadGeneration,
                Call::Post {
                    pid: PID,
                    event: FakeEvent(7),
                },
            ]
        );
    }

    #[test]
    fn a_failed_post_is_not_retried_through_another_transport() {
        let failure = PostCallFailure::new("framework call failed");
        let mut transport = FakeTransport::new(
            [current(), current()],
            WindowServerVisibility::Visible,
            [Err(failure.clone())],
        );

        assert_eq!(
            route(&mut transport),
            Err(ProcessEventRefusal::PostCallFailed(failure))
        );
        assert_eq!(transport.post_count(), 1);
    }

    #[test]
    fn an_undeliverable_target_is_a_named_refusal_not_silent_success() {
        let mut transport = FakeTransport::posting([current()], WindowServerVisibility::NotVisible);

        assert_eq!(
            route(&mut transport),
            Err(ProcessEventRefusal::NotVisibleToWindowServer)
        );
        assert_eq!(transport.post_count(), 0);
    }

    #[test]
    fn a_recycled_pid_is_refused_by_the_final_generation_read() {
        let mut transport = FakeTransport::posting(
            [current(), ProcessGenerationReading::Started(START_TIME + 1)],
            WindowServerVisibility::Visible,
        );

        assert_eq!(
            route(&mut transport),
            Err(ProcessEventRefusal::ProcessReplaced {
                expected_start_time_micros: START_TIME,
                observed_start_time_micros: START_TIME + 1,
            })
        );
        assert_eq!(transport.post_count(), 0);
        assert_eq!(
            transport.calls,
            vec![
                Call::ReadGeneration,
                Call::ReadVisibility,
                Call::ReadGeneration,
            ]
        );
    }

    #[test]
    fn every_typed_refusal_is_preserved_for_the_caller() {
        let unreadable_window_list = "window list timed out".to_string();
        let post_failure = PostCallFailure::new("framework call failed");
        let cases = [
            (
                FakeTransport::posting(
                    [ProcessGenerationReading::Gone],
                    WindowServerVisibility::Visible,
                ),
                ProcessEventRefusal::ProcessGone,
            ),
            (
                FakeTransport::posting(
                    [ProcessGenerationReading::Started(START_TIME + 1)],
                    WindowServerVisibility::Visible,
                ),
                ProcessEventRefusal::ProcessReplaced {
                    expected_start_time_micros: START_TIME,
                    observed_start_time_micros: START_TIME + 1,
                },
            ),
            (
                FakeTransport::posting(
                    [ProcessGenerationReading::NotInspectable],
                    WindowServerVisibility::Visible,
                ),
                ProcessEventRefusal::ProcessNotInspectable,
            ),
            (
                FakeTransport::posting([current()], WindowServerVisibility::NotVisible),
                ProcessEventRefusal::NotVisibleToWindowServer,
            ),
            (
                FakeTransport::posting(
                    [current()],
                    WindowServerVisibility::Unreadable(unreadable_window_list.clone()),
                ),
                ProcessEventRefusal::WindowServerUnreadable {
                    reason: unreadable_window_list,
                },
            ),
            (
                FakeTransport::new(
                    [current(), current()],
                    WindowServerVisibility::Visible,
                    [Err(post_failure.clone())],
                ),
                ProcessEventRefusal::PostCallFailed(post_failure),
            ),
        ];

        for (mut transport, expected) in cases {
            assert_eq!(route(&mut transport), Err(expected));
        }
    }
}
