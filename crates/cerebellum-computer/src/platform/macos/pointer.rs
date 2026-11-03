//! The native pointer sequence, with platform operations injectable without a desk.

use super::*;

pub(super) fn request_verified_front(
    target: Option<ProcessEventTarget>,
    pid: u32,
    generation: impl FnOnce() -> super::super::process_event::ProcessGenerationReading,
    front: impl FnOnce() -> bool,
) -> bool {
    if let Some(target) = target.filter(|target| target.pid == pid) {
        if super::super::process_event::require_exact_generation(target, generation()).is_err() {
            return false;
        }
    }
    front()
}

pub(super) trait PointerOperations {
    type Event;
    fn prepare(&mut self, index: usize) -> Result<(), DriverError>;
    fn refresh_observer(&mut self, index: usize) -> Result<(), DriverError>;
    fn contained(&mut self) -> bool;
    fn generation(&mut self) -> super::super::process_event::ProcessGenerationReading;
    fn frontmost_pid(&mut self) -> Option<u32>;
    fn final_observation(&mut self, index: usize) -> Result<(), DriverError>;
    fn post(&mut self, index: usize, event: Self::Event);
}

pub(super) fn post_pointer_unit<O: PointerOperations>(
    target: ProcessEventTarget,
    steps: Vec<SyntheticStep<O::Event>>,
    cancelled: &dyn Fn() -> bool,
    operations: &mut O,
) -> Result<
    super::super::process_event::SequencePostReport,
    super::super::process_event::GuardedSequenceFailure<DriverError>,
> {
    let releases: Vec<_> = steps
        .iter()
        .map(|step| step.role == super::super::process_event::SyntheticStepRole::Release)
        .collect();
    super::super::process_event::post_guarded_event_sequence(
        steps,
        cancelled,
        |index, event, recovery| {
            let Some(event) = event else {
                return operations.prepare(index).map(|()| 0);
            };
            let live = operations.refresh_observer(index);
            // Every post, including recovery, re-reads exact window and sensitivity.
            // Accessibility (AX), generation and focus reads can block; the last drain and deadline
            // check follow them. No blocking work separates that check from the post.
            // These are best-effort snapshots, not atomic WindowServer containment:
            // physical input, a Space change or a window reorder can still race us.
            let contained = operations.contained();
            super::super::process_event::require_exact_generation(target, operations.generation())
                .map_err(|_| DriverError::Unsupported("global target generation changed"))?;
            let focused = operations.frontmost_pid() == Some(target.pid);
            let final_observation = operations.final_observation(index);
            let stopped = cancelled() || live.is_err() || final_observation.is_err();
            if !contained || !focused {
                return Err(DriverError::Unsupported(
                    "global pointer target containment changed",
                ));
            }
            // Do not discard an already-selected up when cancellation or observer
            // loss happened during an AX read. Recovery still requires containment;
            // an unchecked up awaits disposable-VM routing measurements.
            if !recovery && !(releases[index] && stopped) {
                live?;
                final_observation?;
                if cancelled() {
                    return Err(DriverError::Unsupported("pointer dispatch cancelled"));
                }
            }
            operations.post(index, event);
            Ok(1)
        },
    )
}

pub(super) struct NativePointerOperations<'a, 'b> {
    pub(super) started: Instant,
    pub(super) target: ProcessEventTarget,
    pub(super) transport: &'a mut MacOsPerProcessEventTransport,
    pub(super) heartbeat: &'a mut HeartbeatPoster,
    pub(super) pointer: &'a mut MacPointerUnit,
    pub(super) observation: crate::dispatch::ObservedUnit<'b, cerebellum_macos::SessionEventTap>,
    pub(super) last_post_at: Instant,
    pub(super) live_at: Option<Instant>,
    pub(super) event_count: usize,
}

impl PointerOperations for NativePointerOperations<'_, '_> {
    type Event = cerebellum_macos::OwnedCgEvent;

    fn prepare(&mut self, index: usize) -> Result<(), DriverError> {
        // The inter-post wait deliberately outlives a heartbeat. A new echo
        // will be required after preparation, never reuse the preceding one.
        self.live_at = None;
        if index > 0 {
            let next =
                self.last_post_at + Duration::from_millis(u64::from(self.pointer.interval_ms));
            while Instant::now() < next {
                if (self.observation.cancelled)() {
                    break;
                }
                match self.observation.tap.events().recv_timeout(
                    next.saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(2)),
                ) {
                    Ok(event) => observe_session_event(
                        self.observation.watcher,
                        event,
                        self.heartbeat.our_pid,
                        index,
                    ),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => self.observation.watcher.abort(
                        crate::dispatch::AbortReason::ObserverUnavailable,
                        index,
                        None,
                    ),
                }
                if self.observation.watcher.abort_decision().is_some() {
                    return Err(observed_abort_error(self.observation.watcher));
                }
            }
        }
        self.final_observation(index)
    }

    fn refresh_observer(&mut self, index: usize) -> Result<(), DriverError> {
        let probe = self.heartbeat.post().0;
        let observation = heartbeat_observation(
            self.observation.tap,
            self.observation.watcher,
            probe,
            self.started,
        );
        let liveness = crate::dispatch::heartbeat_liveness(probe, observation);
        self.observation.watcher.observe_heartbeat(liveness, index);
        if self.observation.watcher.abort_decision().is_some() {
            return Err(observed_abort_error(self.observation.watcher));
        }
        self.live_at = Some(Instant::now());
        Ok(())
    }

    fn contained(&mut self) -> bool {
        (self.pointer.guard.0)()
    }

    fn generation(&mut self) -> super::super::process_event::ProcessGenerationReading {
        self.transport.process_generation(self.target.pid)
    }

    fn frontmost_pid(&mut self) -> Option<u32> {
        cerebellum_macos::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok())
    }

    fn final_observation(&mut self, index: usize) -> Result<(), DriverError> {
        drain_session_events(
            self.observation.tap,
            self.observation.watcher,
            self.heartbeat.our_pid,
            index,
        );
        if self.observation.watcher.abort_decision().is_some() {
            return Err(observed_abort_error(self.observation.watcher));
        }
        if elapsed_millis(self.started) >= self.observation.deadline_ms {
            return Err(DriverError::Unsupported(
                "pointer fronting interval exceeded",
            ));
        }
        if self
            .live_at
            .is_some_and(|at| at.elapsed() > Duration::from_millis(OBSERVER_HEARTBEAT_BOUND_MS))
        {
            return Err(DriverError::Unsupported(
                "pointer observer evidence expired during containment reads",
            ));
        }
        Ok(())
    }

    fn post(&mut self, index: usize, event: Self::Event) {
        let _ = cerebellum_macos::post_event_globally(event);
        self.last_post_at = Instant::now();
        self.pointer.last_post_at = Some(self.last_post_at);
        // This counter update is in-memory only; it cannot wait for the OS.
        if index + 1 < self.event_count {
            self.observation.watcher.take_post_slot();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::process_event::SyntheticStepRole;
    use super::*;
    use crate::app_state::pointer_sensitivity::pointer_target_safe;
    use crate::app_state::source::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Default)]
    enum Surface {
        #[default]
        Canvas,
        SecureTarget,
        SecureAncestor,
        SecureFocus,
        Unreadable,
    }

    struct Ax(Mutex<Surface>, std::sync::atomic::AtomicU32);

    impl Default for Ax {
        fn default() -> Self {
            Self(
                Mutex::new(Surface::Canvas),
                std::sync::atomic::AtomicU32::new(7),
            )
        }
    }

    impl AppStateSource for Ax {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            unreachable!()
        }
        fn element_at(
            &self,
            _: HitScope,
            _: (f64, f64),
        ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
            if matches!(*self.0.lock().unwrap(), Surface::Unreadable) {
                return Err(ElementActionError::Failed);
            }
            Ok(Some((Arc::new(FixtureElementToken(1)), Some(41))))
        }
        fn element_facts(
            &self,
            element: &ElementHandle,
        ) -> Result<ElementFacts, ElementActionError> {
            let token = element
                .as_any()
                .downcast_ref::<FixtureElementToken>()
                .unwrap()
                .0;
            let surface = *self.0.lock().unwrap();
            Ok(ElementFacts {
                pid: Some(41),
                role: Some(if token == 3 { "AXWindow" } else { "AXGroup" }.into()),
                subrole: (matches!(
                    (surface, token),
                    (Surface::SecureTarget, 1)
                        | (Surface::SecureAncestor, 2)
                        | (Surface::SecureFocus, 4)
                ))
                .then(|| "AXSecureTextField".into()),
                ..ElementFacts::default()
            })
        }
        fn element_parent(
            &self,
            element: &ElementHandle,
        ) -> Result<Option<ElementHandle>, ElementActionError> {
            let token = element
                .as_any()
                .downcast_ref::<FixtureElementToken>()
                .unwrap()
                .0;
            Ok(Some(Arc::new(FixtureElementToken(if token == 1 {
                2
            } else {
                3
            }))))
        }
        fn pointer_window_at(&self, _: (f64, f64)) -> Option<u32> {
            Some(self.1.load(std::sync::atomic::Ordering::Relaxed))
        }
        fn element_window_number(&self, _: &ElementHandle) -> Option<u32> {
            Some(7)
        }
        fn focused_element(
            &self,
            _: &ProcessGrant,
        ) -> Result<Option<ElementHandle>, ElementActionError> {
            Ok(matches!(*self.0.lock().unwrap(), Surface::SecureFocus)
                .then(|| Arc::new(FixtureElementToken(4)) as ElementHandle))
        }
    }

    struct Ops {
        index: usize,
        generation_lost_at: usize,
        window_lost_at: usize,
        focus_lost_at: usize,
        live_lost_at: usize,
        deadline_at: usize,
        stop_in_containment: bool,
        calls: Vec<(&'static str, usize)>,
        posts: Vec<u8>,
        ax: Ax,
        replace_at_seam: Surface,
    }

    impl Default for Ops {
        fn default() -> Self {
            Self {
                index: 0,
                generation_lost_at: usize::MAX,
                window_lost_at: usize::MAX,
                focus_lost_at: usize::MAX,
                live_lost_at: usize::MAX,
                deadline_at: usize::MAX,
                stop_in_containment: false,
                calls: Vec::new(),
                posts: Vec::new(),
                ax: Ax::default(),
                replace_at_seam: Surface::Canvas,
            }
        }
    }

    fn target() -> ProcessEventTarget {
        ProcessEventTarget {
            pid: 41,
            start_time_micros: 123,
        }
    }

    fn grant() -> ProcessGrant {
        ProcessGrant {
            bundle_identity: "test.app".into(),
            pid: 41,
            process_generation_evidence: "123".into(),
        }
    }

    fn denied() -> DriverError {
        DriverError::Unsupported("injected native refusal")
    }

    impl PointerOperations for Ops {
        type Event = u8;
        fn prepare(&mut self, _: usize) -> Result<(), DriverError> {
            Ok(())
        }
        fn refresh_observer(&mut self, index: usize) -> Result<(), DriverError> {
            self.index = index;
            self.calls.push(("live", index));
            if index >= self.live_lost_at {
                Err(denied())
            } else {
                Ok(())
            }
        }
        fn contained(&mut self) -> bool {
            self.calls.push(("containment", self.index));
            *self.ax.0.lock().unwrap() = self.replace_at_seam;
            if self.stop_in_containment && self.index > 0 {
                self.deadline_at = self.index;
            }
            self.ax.1.store(
                if self.index < self.window_lost_at {
                    7
                } else {
                    8
                },
                std::sync::atomic::Ordering::Relaxed,
            );
            crate::app_state::pointer_sensitivity::pointer_target_contained(
                &self.ax,
                &grant(),
                (10.0, 20.0),
                7,
            )
        }
        fn generation(&mut self) -> super::super::super::process_event::ProcessGenerationReading {
            self.calls.push(("generation", self.index));
            super::super::super::process_event::ProcessGenerationReading::Started(
                if self.index >= self.generation_lost_at {
                    456
                } else {
                    123
                },
            )
        }
        fn frontmost_pid(&mut self) -> Option<u32> {
            self.calls.push(("focus", self.index));
            if self.index < self.focus_lost_at {
                Some(41)
            } else {
                Some(42)
            }
        }
        fn final_observation(&mut self, index: usize) -> Result<(), DriverError> {
            self.calls.push(("drain", index));
            if index >= self.deadline_at {
                Err(denied())
            } else {
                Ok(())
            }
        }
        fn post(&mut self, index: usize, event: u8) {
            self.calls.push(("post", index));
            self.posts.push(event);
        }
    }

    fn drag() -> Vec<SyntheticStep<u8>> {
        vec![
            SyntheticStep {
                event: 0,
                role: SyntheticStepRole::Press,
            },
            SyntheticStep {
                event: 1,
                role: SyntheticStepRole::SelfContained,
            },
            SyntheticStep {
                event: 2,
                role: SyntheticStepRole::Release,
            },
        ]
    }

    #[test]
    fn native_pointer_generation_is_checked_at_every_ordinary_and_recovery_post() {
        for lost_at in 0..3 {
            let mut ops = Ops {
                generation_lost_at: lost_at,
                ..Ops::default()
            };
            assert!(post_pointer_unit(target(), drag(), &|| false, &mut ops).is_err());
            assert_eq!(ops.posts, (0..lost_at as u8).collect::<Vec<_>>());
            assert!(ops.calls.contains(&("generation", lost_at)));
            if lost_at == 1 {
                assert!(ops.calls.contains(&("generation", 2)));
            }
        }
    }

    #[test]
    fn native_pointer_exact_window_rejects_a_same_app_sheet_at_every_post() {
        for lost_at in 0..3 {
            let mut ops = Ops {
                window_lost_at: lost_at,
                ..Ops::default()
            };
            assert!(post_pointer_unit(target(), drag(), &|| false, &mut ops).is_err());
            assert_eq!(ops.posts, (0..lost_at as u8).collect::<Vec<_>>());
        }
    }

    #[test]
    fn native_pointer_focus_is_checked_at_every_ordinary_and_recovery_post() {
        for lost_at in 0..3 {
            let mut ops = Ops {
                focus_lost_at: lost_at,
                ..Ops::default()
            };
            assert!(post_pointer_unit(target(), drag(), &|| false, &mut ops).is_err());
            assert_eq!(ops.posts, (0..lost_at as u8).collect::<Vec<_>>());
        }
    }

    #[test]
    fn native_pointer_liveness_lost_after_down_stops_work_and_selects_only_paired_up() {
        let mut ops = Ops {
            live_lost_at: 1,
            ..Ops::default()
        };
        assert!(post_pointer_unit(target(), drag(), &|| false, &mut ops).is_err());
        assert_eq!(ops.posts, [0, 2]);
    }

    #[test]
    fn native_pointer_mid_gesture_deadline_stops_work_and_selects_only_paired_up() {
        let mut ops = Ops {
            deadline_at: 1,
            ..Ops::default()
        };
        assert!(post_pointer_unit(target(), drag(), &|| false, &mut ops).is_err());
        assert_eq!(ops.posts, [0, 2]);
    }

    #[test]
    fn native_pointer_selected_up_survives_a_stop_during_containment() {
        let mut ops = Ops {
            stop_in_containment: true,
            ..Ops::default()
        };
        let click = vec![
            SyntheticStep {
                event: 0,
                role: SyntheticStepRole::Press,
            },
            SyntheticStep {
                event: 2,
                role: SyntheticStepRole::Release,
            },
        ];
        assert!(post_pointer_unit(target(), click, &|| false, &mut ops).is_ok());
        assert_eq!(ops.posts, [0, 2]);
    }

    #[test]
    fn native_pointer_secure_target_at_seam_refuses() {
        sensitive(Surface::SecureTarget);
    }
    #[test]
    fn native_pointer_secure_ancestor_at_seam_refuses() {
        sensitive(Surface::SecureAncestor);
    }
    #[test]
    fn native_pointer_secure_focus_in_same_window_at_seam_refuses() {
        sensitive(Surface::SecureFocus);
    }
    #[test]
    fn native_pointer_unreadable_ax_at_seam_refuses() {
        sensitive(Surface::Unreadable);
    }

    fn sensitive(surface: Surface) {
        let mut ops = Ops::default();
        // Placement sees ordinary content. The same window replaces it with
        // an inline secure form before the native post adapter checks AX.
        assert!(pointer_target_safe(&ops.ax, &grant(), (10.0, 20.0), 7));
        ops.replace_at_seam = surface;
        assert!(post_pointer_unit(target(), drag(), &|| false, &mut ops).is_err());
        assert!(ops.posts.is_empty());
    }

    #[test]
    fn native_pointer_readable_canvas_without_semantics_is_allowed() {
        let mut ops = Ops::default();
        assert!(post_pointer_unit(target(), drag(), &|| false, &mut ops).is_ok());
        assert_eq!(ops.posts, [0, 1, 2]);
        for post in 0..3 {
            let at = ops
                .calls
                .iter()
                .position(|call| *call == ("post", post))
                .unwrap();
            assert_eq!(ops.calls[at - 1], ("drain", post));
        }
    }
}

#[cfg(test)]
#[test]
fn native_pointer_replaced_generation_never_requests_front() {
    let mut requested = false;
    assert!(!request_verified_front(
        Some(ProcessEventTarget {
            pid: 41,
            start_time_micros: 123
        }),
        41,
        || super::super::process_event::ProcessGenerationReading::Started(456),
        || {
            requested = true;
            true
        },
    ));
    assert!(!requested);
}

#[cfg(test)]
#[test]
fn native_pointer_disabled_or_disconnected_observer_is_explicit_without_event_pid() {
    for enabled in [false, true] {
        let (sender, receiver) = std::sync::mpsc::channel();
        if enabled {
            drop(sender);
        }
        let mut watcher = SeizeWatcher::new(50);
        drain_observer_events(&receiver, enabled, &mut watcher, 7, 0);
        assert_eq!(
            watcher.abort_decision().unwrap().reason,
            crate::dispatch::AbortReason::ObserverUnavailable
        );
    }
}

#[cfg(test)]
#[test]
fn native_pointer_tap_disabled_notification_refuses_even_with_our_pid() {
    let mut watcher = SeizeWatcher::new(50);
    observe_session_event(
        &mut watcher,
        cerebellum_macos::SessionEvent {
            source_unix_process_id: 7,
            event_type: u32::MAX - 1,
            marker_nonce: 0,
            timestamp_ns: 0,
            observed_at_ns: 0,
        },
        7,
        0,
    );
    assert_eq!(
        watcher.abort_decision().unwrap().reason,
        crate::dispatch::AbortReason::ObserverUnavailable
    );
}
