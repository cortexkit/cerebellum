use super::*;

type ScopedReadResult = Result<Map<String, Value>, ClassificationUnavailable>;

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    /// Pipeline only identity/description reads. A ref's context needs several
    /// replies; dividing its budget by the ref count can make even the first
    /// reply impossible. Bounded windows amortize pipe polling without extending
    /// the snapshot deadline or bypassing command admission.
    pub(super) fn scoped_reads<C: NavigationClock>(
        &mut self,
        method: &str,
        params: Vec<Value>,
        session: &str,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<Vec<ScopedReadResult>, NavigationDriveError> {
        assert!(matches!(method, "DOM.resolveNode" | "DOM.describeNode"));
        let mut results = Vec::with_capacity(params.len());
        for window in params.chunks(64) {
            if deadline.saturating_duration_since(clock.now()) < POLL_INTERVAL {
                return Err(NavigationDriveError::CommandDeadline {
                    method: method.into(),
                    command_sent: false,
                });
            }
            let step = snapshot_step_deadline(deadline, true, clock.now());
            let context = crate::browser_session::drive_context();
            let _watch = context.as_ref().map(|c| {
                c.watch
                    .begin_command(method, step.saturating_duration_since(clock.now()))
            });
            let mut ids = Vec::new();
            let run = (|| {
                for params in window {
                    if step.saturating_duration_since(clock.now()) < POLL_INTERVAL {
                        return Err(NavigationDriveError::CommandDeadline {
                            method: method.into(),
                            command_sent: !ids.is_empty(),
                        });
                    }
                    let params = params.as_object().cloned();
                    let effect = command_effect(method, params.as_ref(), Some(session));
                    if let Some(context) = &context {
                        admit_command(context, method, &effect)?;
                    }
                    let command = self
                        .transport
                        .issue_command(method, params, Some(session.into()), clock.now())
                        .map_err(|_| NavigationDriveError::CdpFailure)?;
                    ids.push(command.id);
                    let mut bytes = command
                        .json_bytes()
                        .map_err(|_| NavigationDriveError::CdpFailure)?;
                    bytes.push(0);
                    self.pipe
                        .write_frame(&bytes)
                        .map_err(|_| NavigationDriveError::ConnectorFailure)?;
                }
                for id in &ids {
                    let response = loop {
                        if let Some(response) = self.pending_responses.remove(id) {
                            break response;
                        }
                        if clock.now() >= step || read_cancelled() {
                            return Err(NavigationDriveError::CommandDeadline {
                                method: method.into(),
                                command_sent: true,
                            });
                        }
                        // Sleep only when the pipe is empty: a read that made
                        // progress may have more frames already waiting.
                        match self.read_turn(Some(*id), None, clock.now())? {
                            ReadTurn::Progress(Some(response)) => break response,
                            ReadTurn::Progress(None) => {}
                            ReadTurn::WouldBlock => {
                                let remaining = step.saturating_duration_since(clock.now());
                                clock.sleep(cmp::min(POLL_INTERVAL, remaining));
                            }
                        }
                    };
                    if let Some(context) = &context {
                        settle_command(
                            context,
                            &command_effect(method, None, Some(session)),
                            response.error.is_none(),
                        );
                    }
                    results.push(if response.error.is_none() {
                        response
                            .result
                            .ok_or(ClassificationUnavailable::DomReadFailed)
                    } else {
                        Err(ClassificationUnavailable::DomReadFailed)
                    });
                }
                Ok(())
            })();
            if let Err(error) = run {
                for id in ids {
                    self.pending_responses.remove(&id);
                    self.transport.abandon_command(id);
                }
                return Err(error.at_step(method));
            }
        }
        Ok(results)
    }
}
