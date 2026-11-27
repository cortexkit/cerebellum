use super::*;
use crate::browser::keys::KeyTarget;

pub(super) enum Input {
    Mouse(BrowserClickPosition),
    Key(crate::browser::keys::Key),
}

impl Input {
    fn event(&self, down: bool) -> (&'static str, Map<String, Value>, BrowserInputEvent) {
        match *self {
            Self::Mouse(position) => {
                let (kind, event) = if down {
                    ("mousePressed", BrowserInputEvent::Press(position))
                } else {
                    ("mouseReleased", BrowserInputEvent::Release(position))
                };
                let mut params = mouse_event_params(kind, position);
                params.insert("button".into(), Value::String("left".into()));
                params.insert("clickCount".into(), Value::Number(1.into()));
                (MOUSE_EVENT, params, event)
            }
            Self::Key(key) => (
                KEY_EVENT,
                key.event(down)
                    .as_object()
                    .expect("CDP command parameters")
                    .clone(),
                if down {
                    BrowserInputEvent::KeyPress
                } else {
                    BrowserInputEvent::KeyRelease
                },
            ),
        }
    }
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub fn press_key_classified(
        &mut self,
        context: &str,
        target: &KeyTarget,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(ClickDriveError::Navigation(
                NavigationDriveError::CdpFailure,
            ))?;
        self.ensure_attached(context, deadline, &mut clock)
            .map_err(ClickDriveError::Navigation)?;
        let attachment = self
            .frame_attachment(&target.node)
            .map_err(ClickDriveError::Navigation)?;
        for focused in [false, true] {
            if let Some(frame) = self.active_frame.clone() {
                if !self
                    .prepare_frame(context, &frame, deadline_ms)
                    .map_err(ClickDriveError::Navigation)?
                {
                    return Err(ClickDriveError::ClassificationChanged);
                }
            }
            let live = self
                .classify_click_before(
                    context,
                    &target.node,
                    target.expected.document_epoch,
                    &target.origin,
                    deadline,
                    &mut clock,
                )
                .map_err(ClickDriveError::Navigation)?;
            if !live
                .is_ok_and(|record| target.key.matches_classification(&target.expected, &record))
            {
                return Err(ClickDriveError::ClassificationChanged);
            }
            if !focused {
                let mut command = |method, params: Value| {
                    self.command(
                        method,
                        params.as_object().cloned(),
                        Some(attachment.session_id.clone()),
                        deadline,
                        None,
                        &mut clock,
                    )
                    .map_err(ClickDriveError::Navigation)
                };
                command(
                    "Emulation.setFocusEmulationEnabled",
                    serde_json::json!({"enabled":true}),
                )?;
                command(
                    "DOM.focus",
                    serde_json::json!({"backendNodeId":target.node.backend_node_id}),
                )?;
            }
        }
        let mut command = |method, params: Value| {
            self.command(
                method,
                params.as_object().cloned(),
                Some(attachment.session_id.clone()),
                deadline,
                None,
                &mut clock,
            )
            .map_err(ClickDriveError::Navigation)
        };
        command("Runtime.enable", Value::Null)?;
        let node = command(
            "DOM.resolveNode",
            serde_json::json!({"backendNodeId":target.node.backend_node_id}),
        )?;
        let Some(object_id) = node
            .get("object")
            .and_then(|node| node["objectId"].as_str())
        else {
            return Err(ClickDriveError::ClassificationChanged);
        };
        let focused = command(
            "Runtime.callFunctionOn",
            serde_json::json!({
                "objectId":object_id,"functionDeclaration":crate::user_browser::functions::HAS_FOCUS,"returnByValue":true,
            }),
        )?;
        if focused
            .get("result")
            .and_then(|value| value["value"].as_bool())
            != Some(true)
        {
            return Err(ClickDriveError::Intercepted(
                serde_json::json!({"reason_code":"type_focus_not_ready"}),
            ));
        }
        self.actuate_input(
            context,
            &attachment.session_id,
            Input::Key(target.key),
            deadline,
            deadline_ms,
            input_dispatched,
            &mut clock,
        )
        .map_err(ClickDriveError::Navigation)
    }

    /// Dispatch a press and release, then report what happened to the main
    /// frame. `settle_deadline_ms` bounds the wait for a navigation the input
    /// started, measured from when it was seen to start,
    /// as `browser.navigate` bounds its own.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn actuate_input<C: NavigationClock>(
        &mut self,
        context_key: &str,
        session_id: &str,
        input: Input,
        deadline: Instant,
        settle_deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
        clock: &mut C,
    ) -> Result<BrowserClickOutcome, NavigationDriveError> {
        // Page events must be enabled before either input dispatch. Arming after a
        // blocked release would leave the first dialog waiting for an answer,
        // and the events that show the click starting a navigation arrive
        // while the input commands are still in flight.
        self.command(
            "Page.enable",
            None,
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;
        // Network events are what a navigation settles on (in-flight requests
        // reaching quiet) and where the landing document's status comes from.
        self.command(
            "Network.enable",
            None,
            Some(session_id.to_string()),
            deadline,
            None,
            clock,
        )?;

        // Tracked from the press onward: Chrome reports a link click's
        // navigation request before it acknowledges the release.
        let mut tracker = Tracker::default();
        if self.continuously_serviced {
            self.enable_lifecycle_events(deadline, clock)?;
            tracker.begin_loader_fence(self.frame_generation);
        }
        let mut dialogs = Vec::new();
        for down in [true, false] {
            let (method, params, event) = input.event(down);
            let mut dispatched = || input_dispatched(event);
            let reply = self.command_response_handling_javascript_dialogs(
                method,
                Some(params),
                Some(session_id.to_string()),
                deadline,
                Some(&mut dispatched),
                &mut dialogs,
                (context_key, &mut tracker),
                clock,
            )?;
            if reply.error.is_some() {
                return Err(NavigationDriveError::CdpFailure);
            }
        }

        let navigation =
            self.observe_click_navigation(context_key, tracker, settle_deadline_ms, clock)?;
        Ok(match input {
            Input::Key(_) => BrowserClickOutcome::KeyPressed {
                navigation,
                dialogs,
            },
            Input::Mouse(position) if dialogs.is_empty() => BrowserClickOutcome::Clicked {
                position,
                navigation,
            },
            Input::Mouse(position) => BrowserClickOutcome::JavaScriptDialogDismissed {
                position,
                dialogs,
                navigation,
            },
        })
    }

    /// Wait up to [`CLICK_NAVIGATION_WINDOW`] for the main frame to start
    /// navigating, and if it does, settle that navigation exactly as
    /// `browser.navigate` settles its own.
    pub(super) fn observe_click_navigation<C: NavigationClock>(
        &mut self,
        context_key: &str,
        mut tracker: Tracker,
        settle_deadline_ms: u64,
        clock: &mut C,
    ) -> Result<ClickNavigation, NavigationDriveError> {
        let window_end = clock
            .now()
            .checked_add(CLICK_NAVIGATION_WINDOW)
            .ok_or(NavigationDriveError::CdpFailure)?;
        while !tracker.main_frame_navigation_observed()
            && tracker.same_document_url().is_none()
            && clock.now() < window_end
            && !read_cancelled()
        {
            let turn = self.read_turn(None, Some((context_key, &mut tracker)), clock.now())?;
            if tracker.main_frame_navigation_observed() || tracker.same_document_url().is_some() {
                break;
            }
            if matches!(turn, ReadTurn::WouldBlock) {
                let remaining = window_end.saturating_duration_since(clock.now());
                clock.sleep(cmp::min(POLL_INTERVAL, remaining));
            }
        }

        if tracker.main_frame_navigation_observed() {
            // Prepend the same first lifecycle entry as `browser.navigate`.
            // The landing page may have fired `load` during input dispatch.
            tracker.lifecycle.insert(0, "navigation_started".into());
            let settle_deadline = clock
                .now()
                .checked_add(Duration::from_millis(settle_deadline_ms))
                .ok_or(NavigationDriveError::CdpFailure)?;
            self.settle_navigation(
                context_key,
                &mut tracker,
                settle_deadline,
                Tracker::navigation_ended_without_commit,
                clock,
            )?;
            return Ok(ClickNavigation::MainFrame(Box::new(tracker)));
        }
        if let Some(url) = tracker.same_document_url() {
            return Ok(ClickNavigation::SameDocument {
                url: url.to_string(),
            });
        }
        Ok(ClickNavigation::NoneObserved {
            window_ms: CLICK_NAVIGATION_WINDOW.as_millis() as u64,
        })
    }
}
