use super::*;

impl Coordinator {
    /// Show an agent's preview, or point it at another window. It may start
    /// the cursor-overlay process.
    pub(crate) fn send_preview(&self, preview: CursorPreview) -> bool {
        self.send_line(CursorLine::Preview(preview))
    }

    /// Queue a frame for an agent's preview. It never waits and never starts
    /// the helper, and it is not an action: the badge's idle clock is not
    /// restarted by it. At most one frame per agent waits for the pipe; a
    /// newer one replaces it. A frame over `MAX_FRAME_BYTES` is dropped.
    pub(crate) fn send_frame(&self, frame: CursorFrame) -> bool {
        if self.0.stopped.load(std::sync::atomic::Ordering::Acquire) || !frame.valid() {
            return false;
        }
        let Some(sender) = self.0.sender.get() else {
            return false;
        };
        if !self
            .0
            .writes_confirmed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            // Without a confirmed pipe writer, send the frame directly to
            // the channel reader instead of storing it for a later write.
            return sender.try_send(CursorLine::Frame(frame)).is_ok();
        }
        let mut frames = self.frames();
        if let Some(waiting) = frames
            .iter_mut()
            .find(|waiting| waiting.frame_agent == frame.frame_agent)
        {
            // Latest wins; the writer was already woken for the older one.
            *waiting = frame;
            return true;
        }
        if frames.len() >= PENDING_FRAME_CAP {
            return false;
        }
        // Only a wake: the writer takes frames from the record, never from
        // the channel. If the channel is full the writer is busy and finds
        // the frame once it has written the lines ahead of it.
        let wake = CursorFrame {
            frame_agent: frame.frame_agent.clone(),
            frame_generation: frame.frame_generation,
            frame_window: frame.frame_window,
            frame_w: frame.frame_w,
            frame_h: frame.frame_h,
            frame_jpeg: String::new(),
        };
        frames.push_back(frame);
        let _ = sender.try_send(CursorLine::Frame(wake));
        true
    }

    /// Move an agent's badge inside its preview of `motion.pmotion_window`,
    /// and answer when its tip lands. The serial and the motion on the line
    /// are chosen here: the motion from where the badge last was in that
    /// preview, measured in the thumbnail's points (`thumbnail` is its width
    /// and height). A badge last drawn on the screen or in another window's
    /// preview appears with its entry.
    #[cfg(test)]
    pub(crate) fn schedule_preview_motion(
        &self,
        motion: CursorPreviewMotion,
        thumbnail: [f64; 2],
    ) -> Arrival {
        if !self.enabled() || !thumbnail.iter().all(|v| v.is_finite() && *v > 0.0) {
            return Arrival::none();
        }
        let serial = self
            .0
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.refresh_reduce_motion();
        let scheduled = tokio::time::Instant::now();
        let agent = motion.pmotion_agent.clone();
        let queued = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sent =
            self.send_preview_motion(&mut self.drawn(), motion, thumbnail, serial, scheduled);
        let (decided, decision) = oneshot::channel();
        tokio::spawn(
            self.clone()
                .decide(decided, sent, queued.clone(), scheduled + ARRIVAL_CAP),
        );
        Arrival {
            decision: Some(decision),
            scheduled,
            queued,
            watch: Some(BadgeWatch {
                cursor: self.clone(),
                agent,
                serial,
            }),
            preview_call: None,
            screen_window: Arc::default(),
        }
    }

    /// Choose the motion for `motion` from where its badge last was, put
    /// the line on the pipe and record where the badge now is. Answers how
    /// an action waits for it, or `None` when nothing will be drawn.
    fn send_preview_motion(
        &self,
        drawn: &mut Drawn,
        mut motion: CursorPreviewMotion,
        thumbnail: [f64; 2],
        serial: u64,
        now: tokio::time::Instant,
    ) -> Option<Sent> {
        let agent = motion.pmotion_agent.clone();
        let (chosen, tip) = drawn.aim(
            &Aim {
                agent: &agent,
                serial,
                space: Space::Preview {
                    window: motion.pmotion_window,
                },
                to: motion.pmotion_to,
                resting: false,
                scale: thumbnail,
            },
            now,
            self.reduce_motion(),
        );
        motion.pmotion_serial = serial;
        motion.pmotion_motion = chosen;
        let waits = !self
            .0
            .helper_down
            .load(std::sync::atomic::Ordering::Acquire);
        let sent = self.send_awaited(CursorLine::PreviewMotion(motion), &agent, serial, waits);
        if sent.is_some() {
            drawn.keep(&agent, tip);
            #[cfg(any(target_os = "macos", test))]
            self.note_queued_badge(&agent);
        }
        sent.flatten().map(|written| Sent {
            duration: Duration::from_secs_f64(chosen.duration_ms / 1000.0),
            written,
        })
    }

    /// Schedule a background-mode action's badge inside its agent's preview.
    ///
    /// The agent's preview slot is taken first, so a fourth agent learns at
    /// once that it gets no preview: it then gets no badge and no arrival
    /// wait, and its call's reply says `preview: "not_shown_capacity"`.
    /// Otherwise, within the same read budget as an on-screen picture, the
    /// window the action addresses is read (`preview_window`, one read for
    /// its id and bounds), the preview is shown or retargeted to it, and the
    /// badge moves inside it to the addressed element's visible centre (or
    /// the exact point) as a `PreviewMotion` line, which the action waits
    /// for as it would for a picture. A preview showing the application's
    /// icon, an element with no geometry in that window, or a read that
    /// finds nothing makes no motion and no wait.
    ///
    /// Nothing is ever drawn on the screen from here: a window that cannot
    /// be read means no badge and no wait for this action, because an
    /// on-screen badge would point at whatever covers the application.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn schedule_in_preview(
        &self,
        identity: Identity,
        kind: CursorKind,
        grant: ProcessGrant,
        source: Arc<dyn AppStateSource>,
        aim: ReadAim,
        point: Option<[f64; 2]>,
        preview: PreviewAim,
    ) -> Arrival {
        if !self.enabled() {
            return Arrival::none();
        }
        let agent = identity.badge.clone();
        if preview.worker.reserve(&agent).is_none() {
            if let Some(call) = &preview.call {
                call.note_not_shown_capacity();
            }
            return Arrival::none();
        }
        // Numbered before it is recorded: an end that lands in between then
        // counts this badge as scheduled before it, and drops it.
        let serial = self
            .0
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.record(&identity);
        self.refresh_reduce_motion();
        let (decided, decision) = oneshot::channel();
        let arrival = Arrival {
            decision: Some(decision),
            scheduled: tokio::time::Instant::now(),
            queued: Arc::default(),
            watch: Some(BadgeWatch {
                cursor: self.clone(),
                agent: agent.clone(),
                serial,
            }),
            preview_call: preview.call.clone(),
            screen_window: Arc::default(),
        };
        let decision = (
            decided,
            arrival.queued.clone(),
            arrival.scheduled + ARRIVAL_CAP,
        );
        let cursor = self.clone();
        tokio::spawn(async move {
            let avatar_agent = identity.avatar_agent;
            let (read_source, read_grant) = (source.clone(), grant.clone());
            let (frontmost, bundle) = (preview.frontmost.clone(), preview.bundle.clone());
            let choice = preview.window;
            let read = tokio::task::spawn_blocking(move || {
                background_read(
                    read_source.as_ref(),
                    &read_grant,
                    kind,
                    aim,
                    point,
                    choice,
                    frontmost.as_ref(),
                    bundle.as_ref(),
                )
            });
            match tokio::time::timeout(READ_BUDGET, read).await {
                Ok(Ok(Some(aimed))) => {
                    cursor
                        .draw_in_preview(
                            aimed,
                            PreviewDraw {
                                agent,
                                serial,
                                kind,
                                grant,
                                app: preview.app,
                                worker: preview.worker,
                                call: preview.call,
                            },
                            avatar_agent,
                            decision,
                        )
                        .await;
                }
                // No window could be read, or the read failed or ran out of
                // time: `decided` is dropped, so nothing is drawn and
                // nothing is waited for.
                _ => preview.worker.release_unshown(&agent),
            }
        });
        arrival
    }

    /// Show the agent's preview of the window read for its action and move
    /// its badge there, then answer the action waiting for it.
    async fn draw_in_preview(
        &self,
        aimed: PreviewAimed,
        draw: PreviewDraw,
        avatar_agent: Option<String>,
        (decided, queued, cap): Decision,
    ) {
        let PreviewDraw {
            agent,
            serial,
            kind,
            grant,
            app,
            worker,
            call,
        } = draw;
        #[cfg(target_os = "macos")]
        let heading = agent_names::heading(
            avatar_agent
                .as_deref()
                .and_then(|agent| self.0.avatars.get()?.known_name(agent))
                .as_deref(),
            &app,
        );
        #[cfg(not(target_os = "macos"))]
        let heading = app.clone();
        let mut preview_generation = None;
        let now = tokio::time::Instant::now();
        let sent = {
            // Held across the show, the same record `end` hides previews
            // under: an end either comes first and is seen here, or comes
            // after and hides the preview shown here.
            let mut drawn = self.drawn();
            if drawn
                .ended_at
                .get(&agent)
                .is_some_and(|ended| serial < *ended)
            {
                drop(drawn);
                worker.release_unshown(&agent);
                return;
            }
            let to = aimed.placement(&drawn, &agent, now);
            let outcome = worker.show(PreviewRequest {
                agent: agent.clone(),
                target: grant,
                window: aimed.window,
                app: heading,
                icon_path: aimed.icon_path,
                label: aimed.label,
                backing_scale: PREVIEW_BACKING_SCALE,
            });
            match outcome {
                ShowOutcome::NotShownCapacity => {
                    if let Some(call) = &call {
                        call.note_not_shown_capacity();
                    }
                    None
                }
                ShowOutcome::Shown {
                    generation,
                    thumbnail,
                    icon,
                    ..
                } => {
                    preview_generation = Some(generation);
                    if let Some(call) = &call {
                        call.showing(&worker, &agent);
                    }
                    match to.filter(|_| !icon) {
                        Some((to, target)) => self.send_preview_motion(
                            &mut drawn,
                            CursorPreviewMotion {
                                pmotion_agent: agent.clone(),
                                pmotion_serial: serial,
                                pmotion_generation: generation,
                                pmotion_window: aimed.window.id,
                                pmotion_kind: kind,
                                pmotion_to: to,
                                pmotion_target: target,
                                // Chosen as the line is sent.
                                pmotion_motion: PictureMotion::still(),
                            },
                            thumbnail,
                            serial,
                            now,
                        ),
                        None => None,
                    }
                }
            }
        };
        let drew = sent.is_some();
        tokio::spawn(self.clone().decide(decided, sent, queued, cap));
        #[cfg(target_os = "macos")]
        if preview_generation.is_some() {
            if drew {
                self.send_avatar(
                    avatar_agent.clone(),
                    CursorEvent {
                        initial: agent.chars().next().unwrap_or('A').to_ascii_uppercase(),
                        agent: agent.clone(),
                        // Ignored for a badge inside a preview.
                        to: [0.0, 0.0],
                        target: None,
                        window: None,
                        resting: true,
                        label: None,
                        kind,
                        serial,
                        avatar_rgba: None,
                        avatar_update: false,
                        avatar_tint: None,
                        motion: PictureMotion::still(),
                    },
                )
                .await;
            } else if let (Some(agent_id), Some(avatars)) =
                (avatar_agent.as_deref(), self.0.avatars.get())
            {
                let _ = avatars.fetch_and_render(agent_id).await;
            }
            if let (Some(generation), Some(agent_id), Some(avatars)) = (
                preview_generation,
                avatar_agent.as_deref(),
                self.0.avatars.get(),
            ) {
                worker.update_heading(
                    &agent,
                    generation,
                    agent_names::heading(avatars.known_name(agent_id).as_deref(), &app),
                );
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (drew, avatar_agent, preview_generation);
    }
}
