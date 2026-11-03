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

#[derive(Default)]
pub(super) struct Script {
    pub action: Option<SyntheticAction>,
    pub held: Option<Arc<super::super::held_input::HeldInput>>,
    pub input_on_front: bool,
    pub input_before: Option<usize>,
    pub cancel_before: Option<(usize, crate::CancelHandle)>,
    pub wrong_window_before: Option<usize>,
    pub switch_after: bool,
    pub checks: usize,
    pub roles: Vec<SyntheticStepRole>,
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
        let screen = self.base.0.clone();
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
                if !(self.guard.0)() || screen.frontmost() != Some(TARGET) {
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
    let plane = Arc::try_unwrap(rig.plane)
        .ok()
        .unwrap()
        .with_takeover_pointer_fronting_admitted(true)
        .with_app_use_fronting_admitted(false)
        .with_fronting_bracket_admitted(false);
    rig.plane = Arc::new(plane);
    rig.screen.state().pointer.held = Some(Arc::clone(&rig.plane.held_input));
    rig.desk.state().topmost_window = Some(COVER);
    rig.desk.state().application_hit = Some((1, Some(TARGET)));
    rig.desk.state().system_wide_hit = Some((1, Some(TARGET)));
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
        "every native post has a window check"
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
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.takeover_click",
            json!({"image_id":image_id,"x":10,"y":20}),
        )
        .await;
    assert_eq!(reply["outcome"], "not_fronted", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "front_failed",
        "{reply}"
    );
    assert_eq!(rig.screen.state().now, 300);
    assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
    assert!(rig
        .screen
        .log()
        .iter()
        .all(|line| line.starts_with("front:") || line.starts_with("restore:")));
    assert!(!rig.lock.held());
}

#[tokio::test]
async fn move_drag_and_location_free_scroll_share_the_temporary_front() {
    for action in ["takeover_move", "takeover_drag", "takeover_scroll"] {
        let (rig, image_id) = fixture_with_grants(true, action != "takeover_scroll").await;
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
    assert_eq!(reply["reason"], "target_focus_mismatch", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
    assert!(!rig.lock.held());
}
