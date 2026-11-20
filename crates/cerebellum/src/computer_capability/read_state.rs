use super::*;

impl<B, R, T, S, D> ComputerPlane<B, R, T, S, D>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    /// Read the named application's state as a text tree, numbering its
    /// elements for this conversation, with one image of its frontmost window
    /// when asked for.
    ///
    /// The read resets the diff baseline that later actions report against.
    /// Filters narrow what is shown, never what is read, so the baseline
    /// always covers everything the read reached.
    pub(super) async fn serve_read_state<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
        make_backend: impl FnOnce(&cerebellum_computer::platform::ProcessGrant) -> B,
    ) -> Value {
        let mut parsed = match parse_read_state_request(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };
        parsed.target = match self.resolve_target_name(&parsed.target).await {
            Ok(bundle_identity) => bundle_identity,
            Err(refusal) => return refusal,
        };
        let ServeContext {
            cancel,
            grantee: _,
            identity,
            management,
            consent,
            clock: _,
            now_ms,
        } = context;
        let (grant, admission) = match self
            .admit_app(management, &parsed.target, &consent, &cancel)
            .await
        {
            Ok(admitted) => admitted,
            Err(AppRefusal::Consent(ConsentRefusal::Cancelled)) => {
                return json!({"outcome": "cancelled"})
            }
            Err(refusal) => return refusal.reply(&parsed.target),
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return locked;
        }
        let work = quarantine::CallWork::current();
        if let Some(mut busy) = work.bind(&self.serializer.quarantine, &grant).await {
            admission.decorate(&mut busy);
            return busy;
        }
        // Foreground mode brings the application to the front before it is
        // read. A front that stops for a reason the person or the platform
        // caused falls back to an unfronted read; one that stops because the
        // call is ending reads nothing at all.
        let foreground = self
            .front_for_foreground(fronting::FrontCall {
                grant: &grant,
                consent: &consent,
                cancel: &cancel,
                management,
                conversation_key: &identity.conversation_key,
                input_follows: false,
            })
            .await;
        if let Some(stop) = foreground.and_then(|front| front.stop) {
            if fronting::stop_ends_call(stop) {
                let mut reply = if stop == cerebellum_computer::dispatch::FrontingStop::Cancelled {
                    json!({"outcome": "cancelled"})
                } else {
                    quarantine::stopped_before_dispatch_reply()
                };
                if let Some(front) = foreground {
                    front.fronting.apply(&mut reply);
                }
                admission.decorate(&mut reply);
                return reply;
            }
        }
        let fronting_admission = self.fronting_admission(&consent, false);
        let bring_to_front = parsed.include_image
            && parsed.bring_to_front
            && fronting_admission.mode == cerebellum_core::config::AppUse::Background;
        if bring_to_front && fronting_admission.may_front_image().is_ok() {
            if let Some(mut refusal) = self
                .refuse_if_person_changed(management, &identity.conversation_key, &grant)
                .await
            {
                admission.decorate(&mut refusal);
                return refusal;
            }
        }
        let sessions = management.app_state_sessions().clone();
        let conversation_key = identity.conversation_key.clone();

        // An id from another application, another process generation or
        // another conversation names nothing here; refused before reading so
        // the caller learns it at once.
        let zoom = parsed.zoom.as_deref().map(Zoom::parse);
        let zoom_element = if let Some(Zoom::Element(zoomed)) = zoom {
            match sessions.resolve(&conversation_key, zoomed) {
                ElementResolution::Live {
                    handle,
                    bundle_identity,
                    pid,
                    process_generation,
                } if bundle_identity == grant.bundle_identity
                    && pid == grant.pid
                    && process_generation == grant.process_generation_evidence =>
                {
                    Some((zoomed.to_owned(), handle))
                }
                ElementResolution::PreviousRun => {
                    let mut reply = element_actions::previous_run_reply();
                    admission.decorate(&mut reply);
                    return reply;
                }
                _ => {
                    let mut reply = stale_zoom_reply();
                    admission.decorate(&mut reply);
                    return reply;
                }
            }
        } else {
            None
        };

        let source = self.app_state_source.clone();
        let read_grant = grant.clone();
        let expand_menus =
            sessions.zoom_expands_menus(&conversation_key, &grant, parsed.zoom.as_deref());
        let read_zoom_element = zoom_element.clone();
        let read_work = work.clone();
        let read = tokio::task::spawn_blocking(move || {
            let _ax = read_work.bound_ax();
            // Expanding menus presses them, so it is a mutation: a call stopped
            // while it waited for this worker reads nothing further.
            if expand_menus && !read_work.begin_mutation() {
                return None;
            }
            let _scope =
                cerebellum_computer::audit::AccessibilityReadScope::new(read_grant.pid, None);
            // Read before the tree, so a change the person makes while the
            // tree is read shows up at the next action rather than passing
            // as something this read showed.
            let seen = SeenMarks::read(source.as_ref(), &read_grant);
            // A window that shows only its own buttons is usually a WebKit
            // page still being built: wait once and read that window again.
            // The wait is skipped when it would run past the call's work
            // deadline; the re-reads together are held to the tree read's
            // allowance and to that deadline. Runs on the tree as read: the
            // full tree for a full read, the zoomed subtree for a zoomed
            // read, in both cases before any filter narrows what is shown,
            // so a narrowed read gets the same recovery as a full one.
            let reread_shell = |raw: &mut RawAppState| {
                raw.reread_shell_windows(
                    source.as_ref(),
                    &read_grant,
                    RereadTiming {
                        phase: std::time::Duration::from_millis(crate::budgets::AX_TREE_PHASE_MS),
                        now: &std::time::Instant::now,
                        call_end: read_work.deadline(),
                    },
                    |delay| {
                        if read_work.stopped()
                            || std::time::Instant::now() + delay >= read_work.deadline()
                        {
                            return false;
                        }
                        std::thread::sleep(delay);
                        !read_work.stopped()
                    },
                );
            };
            let raw = if let Some((_, element)) = read_zoom_element {
                match source.element_facts(&element) {
                    Ok(facts) if facts.pid.is_none_or(|pid| pid == read_grant.pid) => source
                        .read_element_state(
                            &read_grant,
                            &element,
                            ReadBounds::default(),
                            expand_menus,
                        )
                        .map(|mut zoomed| {
                            // A zoom into a window whose page is still building
                            // re-reads like a full read; any other zoomed
                            // subtree is no shell window, so this is free.
                            reread_shell(&mut zoomed);
                            zoomed
                        })
                        .map_err(|error| match error {
                            ElementReadError::Gone => StateReadFailure::ZoomGone,
                            ElementReadError::Unreadable => StateReadFailure::ZoomUnreadable,
                        }),
                    Ok(_) | Err(ElementActionError::Gone) => Err(StateReadFailure::ZoomGone),
                    Err(_) => Err(StateReadFailure::ZoomUnreadable),
                }
            } else {
                let raw = if expand_menus {
                    source.read_app_state_expanding_menus(&read_grant, ReadBounds::default())
                } else {
                    source.read_app_state(&read_grant, ReadBounds::default())
                };
                raw.map(|mut raw| {
                    reread_shell(&mut raw);
                    raw
                })
                .map_err(StateReadFailure::Application)
            };
            Some((
                raw,
                cerebellum_computer::audit::AccessibilityReadScope::current(),
                Some(seen),
            ))
        })
        .await
        .unwrap_or(Some((
            Err(StateReadFailure::Application(AppStateReadError::Unreadable)),
            None,
            None,
        )));
        let Some((raw, manual_accessibility, seen)) = read else {
            return quarantine::stopped_before_dispatch_reply();
        };
        let mut raw = match raw {
            Ok(raw) => raw,
            Err(StateReadFailure::Application(AppStateReadError::TargetGone)) => {
                let mut reply = json!({
                    "outcome": "not_running",
                    "bundle_identity": parsed.target,
                    "remedy": "the application quit while it was being read; start it and read again",
                });
                admission.decorate(&mut reply);
                return reply;
            }
            Err(StateReadFailure::Application(error)) => {
                let summary = cerebellum_computer::app_state::ReadStateSummary {
                    grant_identity: grant.clone(),
                    element_count: 0,
                    unreadable_subtrees: 1,
                };
                let mut reply = if self
                    .journal_state_read(
                        identity,
                        summary,
                        manual_accessibility,
                        now_ms,
                        None,
                        ImageReadPlan {
                            requested: parsed.include_image,
                            fronting: Some(foreground.map_or_else(
                                || {
                                    fronting::Fronting::untouched(
                                        app_use::call_mode()
                                            .unwrap_or(cerebellum_core::config::AppUse::Background),
                                    )
                                },
                                |front| front.fronting,
                            )),
                            ..Default::default()
                        },
                    )
                    .await
                    .is_ok()
                {
                    unreadable_application_reply(error)
                } else {
                    read_audit_unavailable_reply()
                };
                admission.decorate(&mut reply);
                return reply;
            }
            Err(StateReadFailure::ZoomGone) => {
                let mut reply = stale_zoom_reply();
                admission.decorate(&mut reply);
                return reply;
            }
            Err(StateReadFailure::ZoomUnreadable) => RawAppState {
                roots: Vec::new(),
                focused: None,
                unreadable_subtrees: 1,
                read_bound_reached: true,
            },
        };
        if let Some((_, element)) = &zoom_element {
            match raw.roots.first() {
                Some(root)
                    if raw.roots.len() == 1 && root.handle.same_element(element.as_ref()) => {}
                Some(_) => {
                    let mut reply = stale_zoom_reply();
                    admission.decorate(&mut reply);
                    return reply;
                }
                None if raw.is_complete() => {
                    let mut reply = stale_zoom_reply();
                    admission.decorate(&mut reply);
                    return reply;
                }
                None => raw.unreadable_subtrees = raw.unreadable_subtrees.max(1),
            }
        }
        // The picture is scheduled after the read. A zoom or one unambiguous
        // filter match names the element being read; otherwise focus remains
        // the best available target. Geometry and window-follow work stays off
        // the read's reply path.
        let unpopulated = raw.mark_unpopulated_content();
        let observed = if let Some((element_id, _)) = &zoom_element {
            sessions.observe_zoomed_subtree(&conversation_key, &grant, element_id, &raw)
        } else {
            sessions.observe(&conversation_key, &grant, &raw)
        };
        let focused = raw.focused.clone();
        let zoomed = zoom_element.as_ref().map(|(_, element)| element.clone());
        let filtered = if zoomed.is_none()
            && (!parsed.role_filter.is_empty() || parsed.text_filter.is_some())
        {
            single_filter_match(
                &observed.roots,
                &StateRequest {
                    zoom,
                    roles: &parsed.role_filter,
                    text: parsed.text_filter.as_deref(),
                },
            )
            .and_then(|node| node.element_id.as_deref())
            .and_then(|element_id| {
                match sessions.resolve(&conversation_key, element_id) {
                    ElementResolution::Live {
                        handle,
                        bundle_identity,
                        pid,
                        process_generation,
                    } if bundle_identity == grant.bundle_identity
                        && pid == grant.pid
                        && process_generation == grant.process_generation_evidence =>
                    {
                        Some(handle)
                    }
                    _ => None,
                }
            })
        } else {
            None
        };
        let app_name = management.application_name(&grant);
        // A read of one element (a zoom or a single filter match) previews
        // that element's window; any other read previews the application's
        // frontmost window.
        let window = if zoomed.is_some() || filtered.is_some() {
            cursor::WindowChoice::Element
        } else {
            cursor::WindowChoice::Frontmost
        };
        self.badges(app_name.clone()).schedule(
            cursor::Identity::current(identity.agent_project_id.clone()),
            cerebellum_computer::cursor::CursorKind::Reading,
            grant.clone(),
            cursor::ReadAim {
                preferred: read_cursor_target(zoomed, filtered, focused.clone()),
                focused,
            },
            None,
            window,
        );
        let mut rendered = render_state(
            &StateHeader {
                app_name: &app_name,
                focused_element_id: observed.focused_element_id.as_deref(),
            },
            &observed.roots,
            &StateRequest {
                zoom,
                roles: &parsed.role_filter,
                text: parsed.text_filter.as_deref(),
            },
        );
        // An application that is not the active one has no key window and no
        // main window, so controls that act on a window find no target and
        // read as disabled. Said once, and only when this reply shows a
        // disabled element, since otherwise the sentence explains nothing
        // the caller sees. It uses the same frontmost reading the keystroke
        // rows use; when that reading fails, nothing is said.
        if rendered.shows_disabled {
            if let Some(sentence) =
                background_app_sentence(&app_name, self.app_state_source.frontmost_pid(), &grant)
            {
                rendered.text.push_str(&sentence);
            }
        }
        if unpopulated > 0 {
            rendered.text.push_str("Accessibility content incomplete: a window or web area exposes only an empty shell; it may still be loading. Read again.\n");
        }
        // A filtered read that matched nothing on an incomplete read says
        // so: matching content may sit behind the part that could not be
        // read, so the empty result must not certify that nothing matches.
        // Appended after the render, like the note above, so no filter can
        // remove either line.
        if !rendered.filter_matched
            && (!parsed.role_filter.is_empty() || parsed.text_filter.is_some())
            && !observed.complete
        {
            rendered
                .text
                .push_str("no matches; the page content isn't readable yet.\n");
        }
        if !rendered.zoom_found {
            if !observed.complete && matches!(zoom, Some(Zoom::Element(_))) {
                // An incomplete read cannot prove that a previously live element is gone.
                rendered.text.push_str(
                    "That part couldn't be read this time; read the state again without zoom, then try again.\n",
                );
            } else {
                let mut reply = stale_zoom_reply();
                admission.decorate(&mut reply);
                return reply;
            }
        }

        let mut reply = json!({
            "outcome": "completed",
            STATE_TEXT_FIELD: rendered.text,
            "unreadable_subtrees": observed.unreadable_subtrees,
        });
        fn has_window(nodes: &[cerebellum_computer::app_state::source::RawElement]) -> bool {
            nodes
                .iter()
                .any(|node| node.role.as_deref() == Some("AXWindow") || has_window(&node.children))
        }
        if raw.is_complete() && !has_window(&raw.roots) && parsed.zoom.is_none() {
            if let Some(text) = reply[STATE_TEXT_FIELD].as_str() {
                reply[STATE_TEXT_FIELD] =
                    json!(format!("{text}\nThis application has no open window.\n"));
            }
        }
        if let Some(focused) = observed.focused_element_id {
            reply["focused_element_id"] = json!(focused);
        }
        if let Some(truncation) = rendered.truncation {
            reply["truncation"] = json!({
                "reason": truncation.reason.as_str(),
                "omitted_elements": truncation.omitted_elements,
            });
        }
        fn count_elements(nodes: &[cerebellum_computer::app_state::source::RawElement]) -> usize {
            nodes
                .iter()
                .map(|node| 1 + count_elements(&node.children))
                .sum()
        }
        let summary = cerebellum_computer::app_state::ReadStateSummary {
            grant_identity: grant.clone(),
            element_count: count_elements(&raw.roots),
            unreadable_subtrees: raw.unreadable_subtrees,
        };
        // Screen Recording serves only the optional image, never the tree.
        // Do not construct a capture backend when the startup reading was not
        // live: a later grant still requires restarting cerebellum.
        let image_permission_live = self
            .permissions
            .state(cerebellum_computer::platform::PermissionService::ScreenRecording)
            == PermissionLiveness::Live;
        // Foreground mode uses its ordinary one-way front. Only background
        // mode temporarily brings an app forward for its picture and restores.
        let mut image_hooks = None;
        let mut image_fronting = None;
        if bring_to_front && image_permission_live && fronting_admission.may_front_image().is_ok() {
            let call = fronting::FrontCall {
                grant: &grant,
                consent: &consent,
                cancel: &cancel,
                management,
                conversation_key: &conversation_key,
                input_follows: false,
            };
            match self.prepare_image_front(call, &admission).await {
                Ok(parts) => image_hooks = Some(fronting::CellHooks::new(parts)),
                Err(prepared) => {
                    if let Some(change) = prepared.change {
                        let mut refusal =
                            element_actions::state_changed_by_person_reply(&app_name, change);
                        admission.decorate(&mut refusal);
                        return refusal;
                    }
                    image_fronting = Some(fronting::Fronting::stopped(
                        fronting_admission.mode,
                        fronting::Purpose::NeedsFront,
                        prepared.stop,
                    ));
                }
            }
        }
        // What the read's row records of the front, as far as it is known
        // before the image: a bring_to_front bracket run through the hooks
        // replaces it with its own outcome once the bracket returns.
        let planned_fronting = match (&image_hooks, image_fronting) {
            (Some(_), _) => fronting::Fronting {
                purpose: fronting::Purpose::NeedsFront,
                ..fronting::Fronting::untouched(fronting_admission.mode)
            },
            (None, Some(stopped)) => stopped,
            (None, None) => foreground.map_or_else(
                || fronting::Fronting::untouched(fronting_admission.mode),
                |front| front.fronting,
            ),
        };
        match self
            .journal_state_read(
                identity,
                summary,
                manual_accessibility,
                now_ms,
                (parsed.include_image && image_permission_live).then(|| make_backend(&grant)),
                ImageReadPlan {
                    requested: parsed.include_image,
                    bring_to_front,
                    cancel: Some(cancel),
                    now_ms,
                    gate: None,
                    hooks: image_hooks.clone(),
                    fronting: Some(planned_fronting),
                },
            )
            .await
        {
            Ok((Some(image), _, fronting)) => {
                if let Some(fronting) = fronting {
                    reply["image_fronting"] = json!(fronting);
                }
                let registered = RegisteredImage {
                    bundle_identity: grant.bundle_identity.clone(),
                    pid: grant.pid,
                    process_generation: grant.process_generation_evidence.clone(),
                    width_px: image.width_px,
                    height_px: image.height_px,
                    mapping: image.mapping,
                };
                // The captured window is remembered with the image, so a
                // coordinate action can refuse a point that lands in another
                // window. A window id that is not a window-server number is
                // not remembered, and such an image refuses every coordinate
                // action rather than acting on an unconfirmed window.
                let image_id = match image.window_id.parse::<u32>() {
                    Ok(window_number) if window_number != 0 => sessions
                        .register_framed_window_image(
                            &conversation_key,
                            registered,
                            window_number,
                            image.window_frame,
                        ),
                    _ => sessions.register_image(&conversation_key, registered),
                };
                reply["image"] = json!({
                    "image_id": image_id,
                    "mime": "image/jpeg",
                    "data_b64": cerebellum_core::serde_base64::encode(&image.jpeg),
                    "width_px": image.width_px,
                    "height_px": image.height_px,
                });
            }
            Ok((None, Some(reason), fronting)) => {
                reply["image_unavailable"] = json!({"reason": reason.as_str()});
                if let Some(fronting) = fronting {
                    reply["image_fronting"] = json!(fronting);
                }
            }
            Ok((None, None, _)) => {
                if parsed.include_image && !image_permission_live {
                    reply["image_unavailable"] = json!({
                        "reason": ImageUnavailable::ScreenRecordingNotLive.as_str(),
                    });
                }
            }
            Err(_) => {
                let mut refusal = read_audit_unavailable_reply();
                admission.decorate(&mut refusal);
                return refusal;
            }
        }
        if let Some(hooks) = &image_hooks {
            let end = hooks.end();
            image_fronting = Some(fronting::hooked_fronting(
                fronting_admission.mode,
                fronting::Purpose::NeedsFront,
                &end,
            ));
        }
        let fronting = image_fronting.or(foreground.map(|front| front.fronting));
        if let Some(fronting) = fronting {
            fronting.apply(&mut reply);
        }
        // The bracket can confirm an app switch, not which accessibility focus
        // or window changes it caused. Keep the marks from before the tree:
        // newer marks could hide changes or input the reply never showed.
        if let Some(seen) = seen {
            sessions.remember_seen(&conversation_key, &grant, seen);
        }
        admission.decorate(&mut reply);
        reply
    }

    /// Finalize one text-free state-read row, with or without an image.
    /// Pixels are released only through custody, after this same row is final.
    async fn journal_state_read(
        &self,
        identity: JournalIdentity,
        summary: cerebellum_computer::app_state::ReadStateSummary,
        manual_accessibility: Option<&'static str>,
        now_ms: u64,
        backend: Option<B>,
        image_plan: ImageReadPlan,
    ) -> Result<
        (
            Option<ReleasedImage>,
            Option<ImageUnavailable>,
            Option<ImageFronting>,
        ),
        ImageUnavailable,
    > {
        use cerebellum_computer::app_state::image::ImageCustody;
        let audit = self.audit.clone();
        let grant = summary.grant_identity.clone();
        let freshness = self.image_freshness_source.clone();
        let make_driver = self.make_synthetic_driver.clone();
        let own_input = self.own_input.clone();
        let input_source = self.app_state_source.clone();
        let work = quarantine::CallWork::current();
        let mut image_plan = image_plan;
        image_plan.gate = Some(work.gate());
        // The read's own row records any front this call made.
        fronting::action_row_started();
        tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(
                grant.pid,
                manual_accessibility,
            );
            let evidence =
                std::cell::RefCell::new(cerebellum_computer::app_state::ImageReadEvidence {
                    decision: image_plan
                        .requested
                        .then_some(cerebellum_computer::app_state::image::ImageDecision::Unknown),
                    fronting: None,
                    fronting_record: image_plan.fronting.and_then(fronting::Fronting::row_record),
                });
            let mut custody = AuditImageCustody {
                audit: &audit,
                identity,
                now_ms,
                summary,
                finalized: false,
                image_evidence: &evidence,
            };
            let Some(backend) = backend else {
                let reservation = custody
                    .reserve()
                    .map_err(|_| ImageUnavailable::AuditUnavailable)?;
                custody
                    .finalize_read(reservation, false)
                    .map_err(|_| ImageUnavailable::AuditUnavailable)?;
                return Ok((None, None, None));
            };
            let image = release_through_custody(&mut custody, || {
                // The observed bracket posts a heartbeat, just as keys does;
                // do not mistake that input for the person's next action.
                let mut posting = image_plan.hooks.as_ref().map(|_| {
                    let posting =
                        own_input.begin_posting(person::last_input_instant(input_source.as_ref()));
                    work.publish_posting(&own_input, &posting);
                    posting
                });
                let captured = read_image::capture(
                    backend,
                    &mut make_driver(),
                    freshness.as_ref(),
                    &grant,
                    &image_plan,
                    &evidence,
                    &mut || {
                        if let Some(posting) = posting.take() {
                            own_input.end_posting(posting);
                        }
                    },
                );
                if let Some(posting) = posting {
                    own_input.end_posting(posting);
                }
                captured
            });
            if !custody.finalized {
                return Err(ImageUnavailable::AuditUnavailable);
            }
            let fronting = evidence.into_inner().fronting;
            Ok(match image {
                Ok(image) => (Some(image), None, fronting),
                Err(reason) => (None, Some(reason), fronting),
            })
        })
        .await
        .unwrap_or(Err(ImageUnavailable::CaptureFailed))
    }
}
