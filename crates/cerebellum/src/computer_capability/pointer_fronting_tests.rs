//! Pointer dispatch through the production image admission, shared bracket,
//! restore obligation and held-input quarantine, without native input posts.

use super::*;
use cerebellum_computer::dispatch::{AbortDecision, AbortReason, ObservedUnit};
use cerebellum_computer::platform::process_event::{
    post_guarded_event_sequence, SyntheticStep, SyntheticStepRole,
};
use cerebellum_computer::platform::GlobalPointerGuard;

const WINDOW: u32 = 77;
const COVER: u32 = 88;

#[cfg(target_os = "macos")]
#[path = "pointer_fronting_native_tests.rs"]
mod native_composed;

#[derive(Default)]
pub(super) struct Script {
    #[cfg(target_os = "macos")]
    pub native_post: Option<support::DeskHook>,
    #[cfg(target_os = "macos")]
    pub native: bool,
    pub before_post: Option<support::DeskHook>,
    pub action: Option<SyntheticAction>,
    pub held: Option<Arc<super::super::held_input::HeldInput>>,
    pub input_on_front: bool,
    pub input_before: Option<usize>,
    pub cancel_before: Option<(usize, crate::CancelHandle)>,
    pub wrong_window_before: Option<usize>,
    pub switch_after: bool,
    pub checks: usize,
    pub roles: Vec<SyntheticStepRole>,
    pub reject_pointer: bool,
    pub reject_hooks: bool,
}

struct PointerHost {
    base: FakeBracket,
    guard: GlobalPointerGuard,
    roles: Vec<SyntheticStepRole>,
    abort: Option<AbortDecision>,
}

impl RestoreHostSource for PointerHost {
    fn restore_host(&self) -> Box<dyn FrontingRestoreHost> {
        self.base.restore_host()
    }
}

impl FrontingBracketHost for PointerHost {
    type Tap = ();
    fn now_ms(&mut self) -> u64 {
        self.base.now_ms()
    }
    fn pause_ms(&mut self, ms: u64) {
        self.base.pause_ms(ms);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.base.frontmost_pid()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        let result = self.base.request_front(pid);
        if self.base.0.frontmost() == Some(TARGET) {
            self.base.0.desk.state().topmost_window = Some(WINDOW);
            if self.base.0.state().pointer.input_on_front {
                self.base.0.state().person_key_pending = true;
            }
        }
        result
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn create_tap(&mut self) -> Option<()> {
        self.base.create_tap()
    }
    fn read_idle(&mut self) -> IdleReading {
        self.base.read_idle()
    }
    fn drain(&mut self, _tap: &()) -> Vec<SourcedInputEvent> {
        let mut state = self.base.0.state();
        if !std::mem::take(&mut state.person_key_pending) {
            return Vec::new();
        }
        state.last_input_ms = Some(state.now);
        vec![SourcedInputEvent {
            source_unix_process_id: 0,
            detection_latency_ms: 0,
            platform_delivery_latency_ms: Some(0),
        }]
    }
    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        self.base.post_heartbeat()
    }
    fn observe_heartbeat(
        &mut self,
        tap: &(),
        probe: HeartbeatProbe,
        watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        self.base.observe_heartbeat(tap, probe, watcher)
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.base.hardware_input_snapshot()
    }
    fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
        unreachable!("pointer units need the live observation")
    }
    fn post_observed_unit(
        &mut self,
        _index: usize,
        observation: ObservedUnit<'_, ()>,
    ) -> Result<UnitPosted, SequencePostFailure> {
        #[cfg(target_os = "macos")]
        if self.base.0.state().pointer.native {
            return self.post_native(observation);
        }
        let screen = self.base.0.clone();
        let hook = screen.state().pointer.before_post.take();
        if let Some(hook) = hook {
            (hook.0)();
        }
        assert!(
            screen
                .state()
                .pointer
                .held
                .as_ref()
                .unwrap()
                .global_send_outstanding(),
            "even a self-contained global post must finish before terminal cleanup restores"
        );
        let steps = self
            .roles
            .iter()
            .copied()
            .enumerate()
            .map(|(index, role)| SyntheticStep { role, event: index })
            .collect();
        let result =
            post_guarded_event_sequence(steps, observation.cancelled, |index, event, recovery| {
                if event.is_none() {
                    let mut state = screen.state();
                    if state.pointer.input_before == Some(index) {
                        state.last_input_ms = Some(state.now);
                        observation
                            .watcher
                            .abort(AbortReason::UserSeizedControl, index, Some(0));
                    }
                    if let Some((at, cancel)) = &state.pointer.cancel_before {
                        if *at == index {
                            cancel.cancel();
                        }
                    }
                    if state.pointer.wrong_window_before == Some(index) {
                        screen.desk.state().topmost_window = Some(COVER);
                    }
                    if observation.watcher.abort_decision().is_some() {
                        return Err(ProcessEventRefusal::Cancelled);
                    }
                    return Ok(0);
                }
                screen.state().pointer.checks += 1;
                if (self.guard.0)(std::time::Instant::now() + std::time::Duration::from_millis(300))
                    .is_err()
                    || screen.frontmost() != Some(TARGET)
                {
                    observation
                        .watcher
                        .abort(AbortReason::FocusMismatch, index, None);
                    return Err(ProcessEventRefusal::Cancelled);
                }
                if recovery && !screen.state().release_ok {
                    return Err(ProcessEventRefusal::Cancelled);
                }
                let role = self.roles[index];
                screen.state().log.push(
                    match role {
                        SyntheticStepRole::Press => "down",
                        SyntheticStepRole::Release => "up",
                        SyntheticStepRole::SelfContained => "move",
                    }
                    .into(),
                );
                Ok(1)
            });
        self.abort = observation.watcher.abort_decision();
        match result {
            Ok(report) => {
                if screen.state().pointer.switch_after {
                    screen.desk.state().frontmost = Some(THIRD);
                    let mut state = screen.state();
                    state.now += 1;
                    state.last_input_ms = Some(state.now);
                }
                Ok(UnitPosted {
                    posts_returned: report.posts_returned,
                    generation_verifications: report.generation_verifications,
                })
            }
            Err(failure) => Err(SequencePostFailure {
                posts_returned: failure.posts_returned,
                held_state: failure.held_state,
                refusal: ProcessEventRefusal::Cancelled,
            }),
        }
    }
}

pub(super) fn dispatch(
    driver: &mut FakeDriver,
    request: GlobalDispatchRequest,
    cancelled: &dyn Fn() -> bool,
) -> Result<DispatchResult, DriverError> {
    let Some(guard) = driver.pointer_guard.take() else {
        return Err(DriverError::Unsupported(
            "the fake posts nothing globally without fronting admission",
        ));
    };
    let mut hooks = driver
        .hooks
        .take()
        .expect("a front has a restore obligation");
    let roles = request.synthetic.action.step_roles();
    driver.screen.state().pointer.action = Some(request.synthetic.action.clone());
    driver.screen.state().pointer.roles = roles.clone();
    let mut host = PointerHost {
        base: FakeBracket(driver.screen.clone()),
        guard,
        roles,
        abort: None,
    };
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut host,
        &mut UserIdleEstimator::new(),
        cerebellum_computer::dispatch::BracketPlan {
            target_pid: request.synthetic.target.pid,
            units: 1,
            maximum_interval_ms: 300,
            maximum_seize_detection_latency_ms: 50,
        },
        cancelled,
        hooks.as_mut(),
        None,
    );
    if let Some(cerebellum_computer::dispatch::BracketStop::PostFailed(failure)) =
        &outcome.report.stop
    {
        if failure.held_state == HeldStateDisposition::Unknown {
            if let Some(abort) = host.abort {
                return Err(DriverError::ObservedSequenceFailed {
                    abort,
                    failure: Box::new(failure.clone()),
                });
            }
            return Err(DriverError::SyntheticDispatchFailed(failure.clone()));
        }
    }
    if let Some(abort) = host.abort.or(match outcome.report.stop {
        Some(cerebellum_computer::dispatch::BracketStop::Aborted(abort)) => Some(abort),
        _ => None,
    }) {
        return Err(DriverError::ObservedDispatchAborted(abort));
    }
    if outcome.report.stop.is_some() {
        return Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: outcome.report.posts_returned,
            held_state: HeldStateDisposition::NoneHeld,
            refusal: ProcessEventRefusal::Cancelled,
        }));
    }
    Ok(DispatchResult {
        accepted_by_platform: true,
        effect_status: EffectStatus::EffectIndeterminate,
        unreadable_subtrees: 0,
        delivery_posts_returned: outcome.report.posts_returned,
        delivery_generation_verifications: outcome.report.generation_verifications,
    })
}

async fn fixture() -> (Rig, String) {
    fixture_with_grants(true, true).await
}

async fn fixture_with_grants(takeover: bool, app: bool) -> (Rig, String) {
    use cerebellum_computer::app_state::image::ImageMapping;
    use cerebellum_computer::app_state::session::RegisteredImage;
    let management = if app {
        support::granted_management().await
    } else {
        support::management()
    };
    let mut rig = rig_with(AppUse::Background, mail_desk(), management);
    let mut plane = Arc::try_unwrap(rig.plane)
        .ok()
        .unwrap()
        .with_takeover_pointer_fronting_admitted(true)
        .with_app_use_fronting_admitted(false)
        .with_fronting_bracket_admitted(false);
    // Exercise the dormant down/up orchestration without enabling production.
    plane.down_gesture_recovery_measured = true;
    rig.plane = Arc::new(plane);
    rig.screen.state().pointer.held = Some(Arc::clone(&rig.plane.held_input));
    rig.desk.state().topmost_window = Some(COVER);
    rig.desk.state().application_hit = Some((1, Some(TARGET)));
    rig.desk.state().system_wide_hit = Some((1, Some(TARGET)));
    rig.desk.state().elements.insert(
        1,
        support::DeskElement {
            facts: support::facts("AXWindow", &[]),
            ..support::DeskElement::default()
        },
    );
    rig.desk.state().element_windows.insert(1, WINDOW);
    rig.desk.state().real_cursor = Some((110.0, 70.0));
    rig.desk.state().window = Some((1, None));
    rig.desk.state().focus = support::DeskFocus::Nothing;
    let image_id = rig.management.app_state_sessions().register_window_image(
        &support::identity().conversation_key,
        RegisteredImage {
            bundle_identity: support::TARGET_BUNDLE_ID.to_owned(),
            pid: TARGET,
            process_generation: support::grant().process_generation_evidence,
            width_px: 1000,
            height_px: 600,
            mapping: ImageMapping::for_window(
                (100.0, 50.0),
                (1000.0, 600.0),
                (1000, 600),
                (1000, 600),
            )
            .unwrap(),
        },
        WINDOW,
    );
    if takeover {
        let carrier = support::ScriptedCarrier::answering(&["computer_30m"]);
        rig.management
            .computer_grants()
            .require(
                &crate::computer_grants::GrantNeed::Takeover,
                &support::relayed(&carrier),
                &crate::CancelHandle::pending(),
            )
            .await
            .unwrap();
    }
    (rig, image_id)
}

#[tokio::test]
async fn a_covered_granted_image_click_fronts_posts_down_up_and_restores() {
    let (rig, image_id) = fixture().await;
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "down", "up", "restore:100"]
    );
    assert_eq!(
        rig.screen.state().pointer.roles,
        [SyntheticStepRole::Press, SyntheticStepRole::Release]
    );
    assert_eq!(
        rig.screen.state().pointer.checks,
        2,
        "every fake sequence post invokes the production window guard"
    );
    assert_eq!(
        rig.screen.state().pointer.action,
        Some(SyntheticAction::ClickPointer {
            point: cerebellum_computer::platform::SyntheticPoint { x: 110.0, y: 70.0 },
        })
    );
    assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
    assert!(!rig.lock.held());
    let rows = journal_results(&rig);
    let actuation = rows
        .iter()
        .find(|row| row["outcome"] == "handler_returned")
        .expect("the pointer post has an actuation row");
    assert_eq!(actuation["fronting"]["fronted"], true, "{actuation}");
    assert_eq!(actuation["fronting"]["restore"], "restored", "{actuation}");
}

#[tokio::test]
async fn bound_down_gestures_refuse_without_the_routing_measurement() {
    for action in ["takeover_click", "takeover_drag"] {
        let (mut rig, image_id) = fixture().await;
        let mut plane = Arc::try_unwrap(rig.plane).ok().unwrap();
        plane.down_gesture_recovery_measured = false;
        rig.plane = Arc::new(plane);
        let args = if action == "takeover_click" {
            json!({"image_id":image_id,"x":10,"y":20})
        } else {
            json!({"image_id":image_id,"from":{"x":10,"y":20},"to":{"x":20,"y":30}})
        };
        let reply = rig
            .call_under(&under_terminal(), &format!("computer.{action}"), args)
            .await;
        assert_eq!(reply["outcome"], "invalid_request", "{reply}");
        assert!(rig.screen.log().is_empty());
    }
}

#[tokio::test]
async fn scroll_requires_real_cursor_recipient_and_safe_ax_at_placement() {
    for failure in ["cursor", "window", "secure", "unreadable"] {
        let (rig, _) = fixture().await;
        rig.desk.state().topmost_window = Some(WINDOW);
        match failure {
            "cursor" => rig.desk.state().real_cursor = None,
            "window" => rig.desk.state().topmost_window = Some(COVER),
            "secure" => {
                rig.desk.state().elements.get_mut(&1).unwrap().facts =
                    support::facts("AXSecureTextField", &[])
            }
            _ => {
                let mut desk = rig.desk.state();
                desk.elements.clear();
                desk.facts_from_roots = false;
            }
        }
        let reply = rig
            .call_under(
                &under_terminal(),
                "computer.takeover_scroll",
                json!({"target":support::TARGET_BUNDLE_ID,"axis":"vertical","amount_lines":-3}),
            )
            .await;
        assert_ne!(reply["outcome"], "completed", "{failure}: {reply}");
        assert!(
            rig.screen.log().is_empty(),
            "{failure}: {:?}",
            rig.screen.log()
        );
    }
}

#[tokio::test]
async fn scroll_rechecks_the_current_cursor_and_sensitivity_at_the_post() {
    for failure in ["cursor", "window", "secure", "unreadable"] {
        let (rig, _) = fixture().await;
        rig.desk.state().topmost_window = Some(WINDOW);
        let desk = rig.desk.clone();
        rig.screen.state().pointer.before_post =
            Some(support::DeskHook(Arc::new(move || match failure {
                "cursor" => {
                    desk.state().real_cursor = Some((500.0, 500.0));
                    desk.state().topmost_windows_at = vec![((500.0, 500.0), COVER)];
                }
                "window" => desk.state().topmost_window = Some(COVER),
                "secure" => {
                    desk.state().elements.get_mut(&1).unwrap().facts =
                        support::facts("AXSecureTextField", &[])
                }
                _ => {
                    let mut desk = desk.state();
                    desk.elements.clear();
                    desk.facts_from_roots = false;
                }
            })));
        let reply = rig
            .call_under(
                &under_terminal(),
                "computer.takeover_scroll",
                json!({"target":support::TARGET_BUNDLE_ID,"axis":"vertical","amount_lines":-3}),
            )
            .await;
        assert_ne!(reply["outcome"], "completed", "{failure}: {reply}");
        assert!(
            !rig.screen.log().iter().any(|post| post == "move"),
            "{failure}: {:?}",
            rig.screen.log()
        );
        assert!(rig
            .screen
            .log()
            .iter()
            .any(|post| post.starts_with("front:")));
    }
}

#[tokio::test]
async fn helper_query_failures_name_the_step_in_the_takeover_refusal() {
    for step in [
        "mouse-down recipient helper unavailable",
        "mouse-down recipient helper reply timed out",
        "mouse-down recipient helper disconnected",
        "mouse-down recipient helper reply malformed",
    ] {
        let (rig, image_id) = fixture().await;
        rig.desk.state().pointer_query_error = Some(step);
        rig.desk.state().pointer_prewarm_error = Some(step);
        let reply = rig
            .call_under(
                &under_terminal(),
                "computer.takeover_move",
                json!({"image_id":image_id,"to":{"x":10,"y":20}}),
            )
            .await;
        assert_ne!(reply["outcome"], "completed", "{reply}");
        assert!(
            reply["remedy"]
                .as_str()
                .is_some_and(|remedy| remedy.contains(step)),
            "{reply}"
        );
        assert!(!rig.screen.log().iter().any(|post| post == "move"));
        assert_eq!(rig.desk.state().pointer_prewarm_deadlines.len(), 1);
        assert!(rig.plane.result_schema_findings().is_empty());
    }
}

#[tokio::test]
async fn move_and_scroll_prewarm_before_placement_with_only_the_existing_call_budget() {
    for admitted in [false, true] {
        for action in ["takeover_move", "takeover_scroll"] {
            let (mut rig, image_id) = fixture().await;
            rig.plane = Arc::new(
                Arc::try_unwrap(rig.plane)
                    .ok()
                    .unwrap()
                    .with_takeover_pointer_fronting_admitted(admitted),
            );
            // Force placement to refuse. Preparation must precede even this
            // first placement, not just dispatch after a successful placement.
            rig.desk.state().real_cursor = None;
            let arguments = if action == "takeover_move" {
                json!({"image_id":format!("missing-{image_id}"),"to":{"x":10,"y":20}})
            } else {
                json!({"target":support::TARGET_BUNDLE_ID,"axis":"vertical","amount_lines":2})
            };
            let end = tokio::time::Instant::now() + Duration::from_millis(100);
            let _ = crate::call_context::CALL_DEADLINE
                .scope(
                    end,
                    rig.call_under(&under_terminal(), &format!("computer.{action}"), arguments),
                )
                .await;
            let deadlines = rig.desk.state().pointer_prewarm_deadlines.clone();
            if admitted {
                assert_eq!(deadlines, [end.into_std()], "{action}");
            } else {
                assert!(
                    deadlines.is_empty(),
                    "unbound {action} must not prepare a helper"
                );
            }
            assert!(rig.screen.log().is_empty());
        }
    }
    for action in ["takeover_move", "takeover_scroll"] {
        stalled_prewarm_reaches_placement(action).await;
    }
}

async fn stalled_prewarm_reaches_placement(action: &'static str) {
    use cerebellum_computer::pointer_query::PREPARE_TIMEOUT;
    let (rig, image_id) = fixture().await;
    rig.desk.state().real_cursor = None;
    let started = Arc::new(tokio::sync::Notify::new());
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = StdMutex::new(released);
    let entered = Arc::clone(&started);
    rig.desk.state().on_pointer_prewarm = Some(support::DeskHook(Arc::new(move || {
        entered.notify_one();
        // The sender is dropped on assertion failure too, so a broken timeout
        // cannot leave a blocking worker alive after the test ends.
        let _ = released.lock().unwrap().recv();
    })));
    let arguments = if action == "takeover_move" {
        json!({"image_id":format!("missing-{image_id}"),"to":{"x":10,"y":20}})
    } else {
        json!({"target":support::TARGET_BUNDLE_ID,"axis":"vertical","amount_lines":2})
    };
    let end = tokio::time::Instant::now() + Duration::from_secs(60);
    let before = std::time::Instant::now();
    let worker_rig = rig.clone();
    let mut call = tokio::spawn(async move {
        crate::call_context::CALL_DEADLINE
            .scope(
                end,
                worker_rig.call_under(&under_terminal(), &format!("computer.{action}"), arguments),
            )
            .await
    });
    tokio::time::timeout(crate::test_support::HANG_GUARD, started.notified())
        .await
        .expect("preparation never started");
    let deadline = rig.desk.state().pointer_prewarm_deadlines[0];
    assert!(deadline >= before + PREPARE_TIMEOUT);
    assert!(
        deadline <= std::time::Instant::now() + PREPARE_TIMEOUT,
        "preparation must not inherit the much longer call deadline"
    );
    let observed = tokio::time::timeout(PREPARE_TIMEOUT + Duration::from_secs(1), &mut call).await;
    drop(release);
    let reply = match observed {
        Ok(reply) => reply.unwrap(),
        Err(_) => {
            let _ = call.await;
            panic!("placement must proceed while readiness remains unanswered");
        }
    };
    assert!(
        tokio::time::Instant::now() < end,
        "preparation must leave call time for placement"
    );
    let expected = if action == "takeover_move" {
        "image_reference_unknown"
    } else {
        "target_not_frontmost"
    };
    assert_eq!(
        reply["outcome"], expected,
        "placement must produce its ordinary refusal: {reply}"
    );
    assert!(rig.screen.log().is_empty());
}

#[tokio::test]
async fn input_during_the_pointer_front_posts_nothing_and_restores() {
    let (rig, image_id) = fixture().await;
    rig.screen.state().pointer.input_on_front = true;
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(reply["outcome"], "user_seized_control", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
    assert_eq!(rig.screen.state().pointer.checks, 0);
}

#[tokio::test]
async fn pointer_cancel_and_seize_release_the_button_before_restoring() {
    for seized in [false, true] {
        let (rig, image_id) = fixture().await;
        let cancel = crate::CancelHandle::pending();
        if seized {
            rig.screen.state().pointer.input_before = Some(1);
        } else {
            rig.screen.state().pointer.cancel_before = Some((1, cancel.clone()));
        }
        let terminal = under_terminal();
        let reply = crate::CALL_TERMINAL
            .scope(
                terminal,
                rig.serve(
                    "computer.takeover_drag",
                    json!({"image_id":image_id,"from":{"x":10,"y":20},"to":{"x":20,"y":30}}),
                    cancel,
                ),
            )
            .await;
        assert_eq!(
            reply["outcome"],
            if seized {
                "user_seized_control"
            } else {
                "cancelled"
            },
            "{reply}"
        );
        assert_eq!(
            rig.screen.log(),
            ["front:4242", "down", "up", "restore:100"]
        );
        assert!(!rig.lock.held());
    }
}

#[tokio::test]
async fn a_pointer_release_that_is_unknown_never_restores_or_allows_another_front() {
    let (rig, image_id) = fixture().await;
    let cancel = crate::CancelHandle::pending();
    rig.screen.state().pointer.cancel_before = Some((1, cancel.clone()));
    rig.screen.state().release_ok = false;
    let reply = crate::CALL_TERMINAL
        .scope(
            under_terminal(),
            rig.serve(
                "computer.takeover_click",
                json!({"image_id":image_id,"x":10,"y":20}),
                cancel,
            ),
        )
        .await;
    assert_eq!(reply["outcome"], "restore_failed", "{reply}");
    assert_eq!(reply["fronting"]["restore"], "failed", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242", "down"]);
    assert!(rig.lock.held(), "quarantine retains the global exclusion");
    let later = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_move",
            json!({"image_id":image_id,"to":{"x":10,"y":20}}),
        )
        .await;
    assert_eq!(later["outcome"], "target_busy", "{later}");
    assert_eq!(
        later["detail"]["reason"], "held_input_unconfirmed",
        "{later}"
    );
    assert_eq!(rig.screen.log(), ["front:4242", "down"]);
}

#[tokio::test]
async fn a_person_switch_after_pointer_release_is_not_restored_over() {
    let (rig, image_id) = fixture().await;
    rig.screen.state().pointer.switch_after = true;
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"]["restore"], "skipped_person", "{reply}");
    assert_eq!(rig.screen.frontmost(), Some(THIRD));
    assert_eq!(rig.screen.log(), ["front:4242", "down", "up"]);
    assert!(!rig.lock.held());
}

#[tokio::test]
async fn a_different_window_before_the_up_prevents_that_post_and_the_restore() {
    let (rig, image_id) = fixture().await;
    rig.screen.state().pointer.wrong_window_before = Some(1);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(reply["outcome"], "restore_failed", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242", "down"]);
    assert!(rig.screen.state().pointer.checks >= 2);
    assert!(rig.lock.held());
    let rows = journal_results(&rig);
    let row = rows
        .iter()
        .find(|row| row["outcome"] == "refused")
        .expect("the partial sequence is audited");
    let recorded: cerebellum_computer::audit::RecordedActuationOutcome =
        serde_json::from_value(row.clone()).unwrap();
    let cerebellum_computer::audit::ActuationOutcome::Refused { refusal, abort } = recorded.outcome
    else {
        panic!("the stop must remain a refusal");
    };
    assert_eq!(abort.unwrap().reason, AbortReason::FocusMismatch);
    assert!(matches!(
        refusal,
        cerebellum_computer::dispatch::DispatchError::SyntheticSequenceFailed {
            held_state: HeldStateDisposition::Unknown,
            ..
        }
    ));
}

#[tokio::test]
async fn missing_takeover_or_app_grant_fronts_and_posts_nothing() {
    // Whole-computer authority also covers an App need. Test absent app
    // admission before obtaining that broader authority, as the serving path does.
    for (takeover, app, outcome) in [
        (false, true, "consent_unavailable"),
        (false, false, "app_grant_required"),
    ] {
        let (rig, image_id) = fixture_with_grants(takeover, app).await;
        let reply = rig
            .call_under(
                &under_terminal(),
                "computer.takeover_click",
                json!({"image_id":image_id,"x":10,"y":20}),
            )
            .await;
        assert_eq!(reply["outcome"], outcome, "{reply}");
        assert!(rig.screen.log().is_empty());
        assert!(!rig.lock.held());
    }
}

#[tokio::test]
async fn a_failed_pointer_front_is_bounded_and_posts_nothing() {
    let (rig, image_id) = fixture().await;
    rig.screen.state().comes_forward = false;
    let terminal = under_terminal();
    let reply = rig
        .call_under(
            &terminal,
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(reply["outcome"], "restore_failed", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "front_failed",
        "{reply}"
    );
    assert_eq!(reply["fronting"]["fronted"], false);
    assert_eq!(reply["fronting"]["restore"], "failed");
    assert_eq!(rig.screen.state().now, 600);
    assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
    assert!(rig
        .screen
        .log()
        .iter()
        .all(|line| line.starts_with("front:") || line.starts_with("restore:")));
    assert!(
        rig.lock.held(),
        "the unresolved activation still owns cleanup"
    );
}

#[tokio::test]
async fn move_drag_and_location_free_scroll_share_the_temporary_front() {
    for action in ["takeover_move", "takeover_drag", "takeover_scroll"] {
        let (rig, image_id) = fixture_with_grants(true, action != "takeover_scroll").await;
        if action == "takeover_scroll" {
            rig.desk.state().topmost_window = Some(WINDOW);
        }
        let arguments = match action {
            "takeover_move" => json!({"image_id":image_id,"to":{"x":10,"y":20}}),
            "takeover_drag" => {
                json!({"image_id":image_id,"from":{"x":10,"y":20},"to":{"x":20,"y":30}})
            }
            _ => json!({"target":support::TARGET_BUNDLE_ID,"axis":"vertical","amount_lines":2}),
        };
        let reply = rig
            .call_under(&under_terminal(), &format!("computer.{action}"), arguments)
            .await;
        assert_eq!(reply["outcome"], "completed", "{action}: {reply}");
        assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
        assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
        assert_eq!(rig.screen.log().first().unwrap(), "front:4242");
        assert_eq!(rig.screen.log().last().unwrap(), "restore:100");
        assert!(!rig.lock.held());
    }
}

#[tokio::test]
async fn another_point_owner_is_refused_even_when_the_window_number_matches() {
    let (rig, image_id) = fixture().await;
    rig.desk.state().application_hit = Some((1, Some(THIRD)));
    rig.desk.state().system_wide_hit = Some((1, Some(THIRD)));
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(reply["outcome"], "target_not_frontmost", "{reply}");
    // The fresh accessibility placement check refuses a foreign owner before any front, rather
    // than waiting for the posting guard to reject it after activation.
    assert_eq!(reply["reason"], "no_application_at_point", "{reply}");
    assert!(rig.screen.log().is_empty());
    assert!(!rig.lock.held());
}

fn assert_no_action_reservation(rig: &Rig) {
    let audit = cerebellum_computer::audit::lock_audit(&rig.plane.audit);
    assert_eq!(audit.journal().active_pre_dispatch_count(), 0);
    assert_eq!(audit.journal().unfinalized_dispatch_count(), 0);
    drop(audit);
    let rows = journal_results(rig);
    let row = rows
        .iter()
        .find(|row| row["outcome"] == "no_action")
        .expect("refusal finalized as no action");
    assert!(row["refusal"].is_object(), "{row}");
    assert!(rig.screen.log().is_empty());
}

#[tokio::test]
async fn pointer_audit_missing_terminal_closes_reservation_without_posts() {
    let (rig, image_id) = fixture().await;
    let reply = rig
        .call(
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "fronting_unavailable",
        "{reply}"
    );
    assert_no_action_reservation(&rig);
}

#[tokio::test(start_paused = true)]
async fn pointer_audit_lock_timeout_closes_reservation_without_posts() {
    let (rig, image_id) = fixture().await;
    let lock = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "fronting_busy",
        "{reply}"
    );
    assert_no_action_reservation(&rig);
    drop(lock);
}

#[tokio::test]
async fn pointer_audit_driver_hook_refusals_close_reservation_without_posts() {
    for pointer in [true, false] {
        let (rig, image_id) = fixture().await;
        rig.screen.state().pointer.reject_pointer = pointer;
        rig.screen.state().pointer.reject_hooks = !pointer;
        let reply = rig
            .call_under(
                &under_terminal(),
                "computer.takeover_click",
                json!({"image_id":image_id,"x":10,"y":20}),
            )
            .await;
        assert_eq!(reply["outcome"], "dispatch_failed", "{reply}");
        assert_no_action_reservation(&rig);
    }
}

#[tokio::test]
async fn pointer_audit_cancelled_lock_wait_closes_reservation_without_posts() {
    let (rig, image_id) = fixture().await;
    let lock = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let cancel = crate::CancelHandle::pending();
    let worker_rig = rig.clone();
    let signal = cancel.clone();
    let worker = tokio::spawn(async move {
        crate::CALL_TERMINAL
            .scope(
                under_terminal(),
                worker_rig.serve(
                    "computer.takeover_click",
                    json!({"image_id":image_id,"x":10,"y":20}),
                    signal,
                ),
            )
            .await
    });
    wait_for_one_pre_dispatch_reservation(&rig).await;
    cancel.cancel();
    let reply = worker.await.unwrap();
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "cancelled",
        "{reply}"
    );
    assert_no_action_reservation(&rig);
    drop(lock);
}

/// Waits until the call has reserved its audit entry and is parked on the
/// fronting lock. Bounded by the shared hang guard rather than a yield count:
/// under a loaded test run the worker can need more than any fixed number of
/// yields to reach the lock.
async fn wait_for_one_pre_dispatch_reservation(rig: &Rig) {
    let count = || {
        cerebellum_computer::audit::lock_audit(&rig.plane.audit)
            .journal()
            .active_pre_dispatch_count()
    };
    tokio::time::timeout(crate::test_support::HANG_GUARD, async {
        while count() != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no audit reservation; count is {}", count()));
}

#[tokio::test]
async fn pointer_audit_abandoned_predispatch_token_is_closed_by_raii() {
    use cerebellum_computer::audit::{AuditToken, ComputerPlaneDescriptor, ObservationState};
    let (rig, _) = fixture().await;
    let mut token = AuditToken::new(
        rig.plane.audit.clone(),
        Arc::new(cerebellum_computer::dispatch::OpenGate),
    );
    token
        .reserve_ahead(
            support::identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::TakeoverClick,
                cerebellum_computer::grounding::ContainmentRung::GlobalNone,
                ObservationState::HumanObserved,
            ),
        )
        .unwrap();
    assert!(token.has_unused_reservation());
    drop(token);
    assert_no_action_reservation(&rig);
}

#[tokio::test]
async fn pointer_audit_held_input_after_lock_wait_closes_reservation_without_posts() {
    let (rig, image_id) = fixture().await;
    let lock = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let worker_rig = rig.clone();
    let worker = tokio::spawn(async move {
        worker_rig
            .call_under(
                &under_terminal(),
                "computer.takeover_click",
                json!({"image_id":image_id,"x":10,"y":20}),
            )
            .await
    });
    wait_for_one_pre_dispatch_reservation(&rig).await;
    let press = super::super::held_input::HeldPress::global_send(
        &support::grant(),
        &SyntheticAction::ClickPointer {
            point: cerebellum_computer::platform::SyntheticPoint { x: 10.0, y: 20.0 },
        },
    );
    let ticket = rig.plane.held_input.begin_send(press, None);
    drop(ticket);
    drop(lock);
    let reply = worker.await.unwrap();
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "held_input_unconfirmed",
        "{reply}"
    );
    assert_no_action_reservation(&rig);
}
