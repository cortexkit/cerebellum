use super::*;

/// Wait for consent and window handover, not the person's sign-in. The durable
/// obligation is saved before replying so a restart can settle it, and only
/// closed outcome codes, never the captured header, enter the late entry.
pub(super) async fn capture_browser_login(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    address: (u16, u32, u64),
    request: &login_capture::CaptureRequest,
    call_key: &str,
) -> Value {
    let (channel, epoch, corr) = address;
    if !computer_grants::admits_consent(facts) {
        let why = if facts.flow_id.is_some() {
            return flow_consent_refusal("unattended_flow");
        } else {
            cingulate_client::desk::NoCard::NoAgentSession
        };
        return json!({"outcome":"consent_unavailable","detail":{"reason":why.reason(),"remedy":why.remedy()}});
    }
    // Before the sign-in window is handed to the person, cancellation of the
    // request also cancels consent. Once the caller has been told the window
    // was handed over, its result is owed to the caller as a late result, so
    // closing the request must not stop sign-in. Module shutdown still
    // interrupts the capture and disposes its throwaway profile.
    let cancel = planes.cancellations.get((channel, epoch, corr));
    let draining = Arc::clone(&planes.draining);
    let cancel_for_capture = cancel.clone();
    let cancel_for_handover = cancel.clone();
    let held_calls = Arc::clone(&planes.calls);
    let held_scope = facts
        .scope
        .as_ref()
        .map(journal::call_records::ScopeIdentity::from_stamp);
    let detached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let detached_for_capture = Arc::clone(&detached);
    // The card is raised through the module's computer grants, which hold
    // the call for a bounded wait, leave the card open past it, and answer a
    // retry from a late approval; the capture reports to Cingulate what
    // became of an approval it used that way.
    let capture = Arc::clone(&planes.capture);
    let request = request.clone();
    let accepted = facts.clone();
    let grants = Arc::clone(planes.management.computer_grants());
    let consent = login_consent_request(
        planes,
        facts,
        writer,
        (channel, epoch),
        computer_grants::LoginCapability::CaptureLogin,
        request.consent_parameters(),
        cancel,
    );
    let (ready, handed_over) = tokio::sync::oneshot::channel();
    let mut handed_over = handed_over;
    let deposit_calls = Arc::clone(&planes.calls);
    let deposit_principal = journal::call_records::principal_label(facts.principal.as_ref());
    let deposit_key = call_key.to_owned();
    let mut running = Box::pin(async move {
        capture
            .run_notifying(
                &request,
                login_capture::CaptureCall {
                    accepted: &accepted,
                    grants: &grants,
                    consent,
                    cancelled: move || {
                        (!detached_for_capture.load(std::sync::atomic::Ordering::Acquire)
                            && cancel_for_capture
                                .as_ref()
                                .is_some_and(CancelHandle::is_cancelled))
                            || draining.load(std::sync::atomic::Ordering::Acquire)
                            || held_scope
                                .as_ref()
                                .is_some_and(|scope| held_calls.held_scope_ended(scope))
                    },
                },
                Some(ready),
                Some(Box::new(move || {
                    deposit_calls.begin_capture_deposit(&deposit_principal, &deposit_key)
                })),
            )
            .await
    });
    let handoff = tokio::select! {
        biased;
        ready = &mut handed_over => ready.ok(),
        outcome = &mut running => {
            return journal_capture_outcome(&planes.browser, &facts.identity, outcome).await;
        }
    };
    let Some(handoff) = handoff else {
        return journal_capture_outcome(&planes.browser, &facts.identity, running.await).await;
    };
    // A Cancel that came in while the window was being shown is honoured
    // before any settlement obligation is saved.
    if cancel_for_handover
        .as_ref()
        .is_some_and(CancelHandle::is_cancelled)
    {
        let _ = handoff.proceed.send(false);
        return journal_capture_outcome(&planes.browser, &facts.identity, running.await).await;
    }
    let principal = journal::call_records::principal_label(facts.principal.as_ref());
    let scope = facts
        .scope
        .as_ref()
        .map(journal::call_records::ScopeIdentity::from_stamp)
        .unwrap_or_else(|| journal::call_records::ScopeIdentity {
            owner: principal.clone(),
            reference: facts.identity.conversation_key.clone(),
            scope_epoch: 0,
        });
    let calls = Arc::clone(&planes.calls);
    let key = call_key.to_owned();
    let (save_principal, save_key, origin) =
        (principal.clone(), key.clone(), handoff.origin.clone());
    let saved = tokio::task::spawn_blocking(move || {
        calls.hold_capture(&save_principal, &save_key, scope, &origin, wall_clock_ms())
    })
    .await;
    if !matches!(saved, Ok(Ok(()))) {
        let _ = handoff.proceed.send(false);
        let _ = journal_capture_outcome(&planes.browser, &facts.identity, running.await).await;
        return json!({"outcome":"internal_failure","reason":"call_record_unavailable"});
    }
    // The capture is handed over only once `capture_pending` is this call's
    // reply. Until then a Cancel (or another stop) can still choose the
    // reply, and the capture must then end even though its hold is saved.
    let reply_chosen = capture_pending_chosen(TerminalArbiter::current(), cancel_for_handover);
    let browser = Arc::clone(&planes.browser);
    let identity = facts.identity.clone();
    let calls = Arc::clone(&planes.calls);
    #[cfg(test)]
    let journal_finalization = planes.capture.take_journal_finalization();
    #[cfg(test)]
    let module = Arc::clone(&planes.capture);
    tokio::spawn(async move {
        let handed_over = reply_chosen.await;
        // Set before the capture may proceed, so a Cancel arriving after the
        // pending reply was chosen can no longer stop the sign-in.
        detached.store(handed_over, std::sync::atomic::Ordering::Release);
        let _ = handoff.proceed.send(handed_over);
        #[cfg(test)]
        if handed_over {
            module.note_detached();
        }
        // A capture stopped here ends as cancelled, which settles the saved
        // hold as interrupted.
        let outcome = running.await;
        let ending = if outcome.deposit_unknown {
            journal::call_records::HandoffEnding::Unknown
        } else {
            capture_ending(&outcome.reply)
        };
        let _ = tokio::task::spawn_blocking(move || {
            calls.finish_handoff(&principal, &key, ending, wall_clock_ms())
        })
        .await;
        // Audit congestion must not hold back the capture's already-known result.
        let _ = journal_capture_outcome(&browser, &identity, outcome).await;
        #[cfg(test)]
        if let Some(finalized) = journal_finalization {
            let _ = finalized.send(());
        }
    });
    json!({
        "outcome":"capture_pending", "origin":handoff.origin,
        "expires_in_ms":handoff.expires_in_ms,
        "message":"The capture result will arrive later as a notice; do not poll for it."
    })
}

/// Resolves to whether this call's reply is the `capture_pending` the caller
/// is about to send, rather than a reply a stop chose first.
///
/// Watched before that reply is sent: the call's terminal arbiter decides
/// under its lock which reply wins, so a Cancel is ordered either before the
/// handover (and stops the capture) or after it (and is ignored). Without an
/// arbiter only the cancel flag can say.
fn capture_pending_chosen(
    terminal: Option<Arc<TerminalArbiter>>,
    cancel: Option<CancelHandle>,
) -> impl std::future::Future<Output = bool> + Send + 'static {
    let watched = terminal.map(|terminal| terminal.watch_reply());
    async move {
        match watched {
            // A call that ends with no reply chosen never handed it over.
            Some(watched) => watched.await == Ok(false),
            None => !cancel.as_ref().is_some_and(CancelHandle::is_cancelled),
        }
    }
}

fn capture_ending(reply: &Value) -> journal::call_records::HandoffEnding {
    use journal::call_records::HandoffEnding;
    match reply["outcome"].as_str() {
        Some("captured") => HandoffEnding::Captured,
        Some("expired") if reply["reason"] != login_capture::LOGIN_NOT_VERIFIED => {
            HandoffEnding::Expired
        }
        Some(
            "expired"
            | "no_login_observed"
            | "capture_no_cookies_for_url"
            | "capture_header_unusable",
        ) => HandoffEnding::SessionInvalid,
        _ => HandoffEnding::HandoffInterrupted,
    }
}

async fn journal_capture_outcome(
    browser: &BrowserPlane,
    identity: &RouteIdentity,
    outcome: login_capture::CaptureOutcome,
) -> Value {
    // A deposit already made stays in the vault when this record cannot be
    // written: the vault cannot be asked to withdraw it, and its own audit
    // row, bound to the consent card's id, still describes it.
    if browser
        .journal_login_capture(identity, outcome.journal)
        .await
        .is_err()
    {
        return json!({"outcome":"internal_failure","reason":"journal_unavailable"});
    }
    outcome.reply
}

/// A tool-route request, with its optional `call_key` handled before the call
/// itself is.
///
/// A call carrying a key is recorded under `(route principal, call_key)`
/// before it can do anything, and a resend of the same key is answered from
/// that record instead of running again. A call without a key runs exactly as
/// it always has. `tool.withdraw` also arrives here: it is a tool-provider
/// operation on the same route, so it takes the tool envelope, never the
/// management one.
pub(super) async fn handle_keyed_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let object = serde_json::from_slice::<Value>(&frame.body).ok();
    let name = object.as_ref().and_then(|value| value["name"].as_str());
    let bind = planes.routes.get(frame.header.channel, frame.header.epoch);
    if let (Some(name), Some(facts)) = (name, bind.as_ref()) {
        if let Err(error) = tool_provider::check_call_mode(name, &facts.call_mode, planes) {
            return tool_provider::send_error(
                error,
                (
                    frame.header.ver,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                ),
                writer,
            )
            .await;
        }
    }
    // Result-reader support is a route declaration, never a call argument.
    // Older cores retain their exact legacy body until they declare the reader.
    let result_bind = name.zip(bind).map(|(name, bind)| (name.to_owned(), bind));
    let operator_call = computer_capability::operator_confirm::Call {
        wire: Arc::clone(&planes.operator_confirm),
        writer: writer.clone(),
        route: (frame.header.channel, frame.header.epoch),
    };
    tool_result::RESULT_BIND
        .scope(
            result_bind,
            tool_result::SETTLEMENT_NOTE_OMITTED.scope(
                std::cell::Cell::new(false),
                tool_result::IMAGE_HANDLE_NOTE.scope(
                    std::cell::RefCell::new(None),
                    tool_result::APP_USE_NOTE.scope(
                        std::cell::RefCell::new(None),
                        codemode::CALL_RECORDS.scope(
                            Arc::clone(&planes.calls),
                            computer_capability::operator_confirm::CALL.scope(
                                operator_call,
                                handle_keyed_tool_request_inner(frame, writer, planes),
                            ),
                        ),
                    ),
                ),
            ),
        )
        .await
}

pub(super) async fn handle_keyed_tool_request_inner(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    use journal::call_records::{self, Begin};

    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    // A body that does not decode, or is not an object, is left to the call's
    // own envelope check, which already refuses it by name.
    let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(&frame.body) else {
        return Box::pin(handle_tool_request(
            frame,
            writer,
            planes,
            &CallObservation::new(),
        ))
        .await;
    };
    if object.contains_key("schema_pin") {
        if let Err(error) = tool_provider::check_tool_call(&object, planes) {
            return tool_provider::send_error(error, (ver, channel, epoch, corr), writer).await;
        }
    }
    let call_key = match object.remove("call_key") {
        None => None,
        Some(Value::String(key)) if call_records::valid_call_key(&key) => Some(key),
        Some(_) => {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(
                    "call_key",
                    "expected 1..256 printable non-space ASCII bytes",
                ),
                (ver, channel, epoch, corr),
                writer,
            )
            .await
        }
    };
    if tool_provider::is_operation(object.get("name").and_then(Value::as_str).unwrap_or("")) {
        if call_key.is_some() {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(
                    "call_key",
                    "provider operations take no envelope call key",
                ),
                (ver, channel, epoch, corr),
                writer,
            )
            .await;
        }
        return tool_provider::serve(&object, (ver, channel, epoch, corr), writer, planes).await;
    }
    if object.get("name").and_then(Value::as_str) == Some(call_records::WITHDRAW_OPERATION) {
        // The key a withdrawal names is `arguments.call_key`. A second key on
        // the envelope would leave it unclear which call is meant.
        if call_key.is_some() {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(
                    "call_key",
                    "withdrawal names arguments.call_key only",
                ),
                (ver, channel, epoch, corr),
                writer,
            )
            .await;
        }
        return handle_tool_withdraw(&object, (ver, channel, epoch, corr), writer, planes).await;
    }
    // Read once, here, so the call record and every audit row the call writes
    // carry the same value. An origin that fails validation never refuses the
    // call: it says who a relaying module claims to be acting for, which is
    // attribution, not authorization. It is recorded as absent with a marker
    // instead, and nothing below this point decides anything by it.
    let origin =
        cerebellum_core::journal::CallOriginRecord::from_request_member(object.get("origin"));
    let Some(call_key) = call_key else {
        let _resumed_run = browser_held::resuming()
            .then(|| {
                let facts = planes.routes.get(channel, epoch)?;
                let key = call_context::current_call_key()?;
                planes.run_calls.register(
                    &facts,
                    &key,
                    planes.cancellations.get((channel, epoch, corr)),
                )
            })
            .flatten();
        let mut observation = CallObservation::new().with_origin(origin);
        if browser_held::resuming() {
            if let Some(key) = call_context::current_call_key() {
                observation = observation.with_key(key);
            }
        }
        return handle_tool_request(frame, writer, planes, &observation).await;
    };
    let flat_tool = matches!(
        object.get("name").and_then(Value::as_str),
        Some(flat_tools::BROWSER_USE | flat_tools::COMPUTER_USE)
    );
    let mut call = frame;
    call.body = serde_json::to_vec(&Value::Object(object)).map_err(ModuleError::Json)?;
    // Without an accepted bind there is no principal to record the call under.
    // Nothing is lost by not recording it: `handle_tool_request` refuses any
    // call on an unbound route (`route_not_bound`) before it does anything.
    let Some(facts) = planes.routes.get(channel, epoch) else {
        return handle_tool_request(
            call,
            writer,
            planes,
            &CallObservation::new().with_origin(origin),
        )
        .await;
    };
    let principal = call_records::principal_label(facts.principal.as_ref());
    // Install before durable admission finishes: a withdrawal can observe the
    // new record as soon as its write completes, before this task resumes.
    // Duplicate/replayed keys must not replace an executing call's handle.
    let _run_call = planes.run_calls.register(
        &facts,
        &call_key,
        planes.cancellations.get((channel, epoch, corr)),
    );
    // Only an admission completed within its budget can authorize execution.
    // The worker keeps its permit through any late refusal write.
    let begun = {
        let calls = Arc::clone(&planes.calls);
        let conversation_key = facts.identity.conversation_key.clone();
        let call_key = call_key.clone();
        // The scope comes from the route's bind stamp, never from the request.
        let scope = facts
            .scope
            .as_ref()
            .map(call_records::ScopeIdentity::from_stamp);
        // Stored on a new record only; the record is still found by the
        // route's principal and the call key alone.
        let origin = origin.clone();
        begin_call_record(planes, (ver, channel, epoch, corr), move || {
            calls.begin_attributed(
                &principal,
                &call_key,
                &conversation_key,
                scope,
                origin,
                wall_clock_ms(),
            )
        })
        .await
    };
    // A previous call result must not bypass current route admission. Preserve
    // that historical record, but do not expose its reply through a flow route.
    if !matches!(&begun, Begin::Execute(_)) {
        if let Some(refusal) = session_flow_refusal(&facts) {
            return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
        }
    }
    let ticket = match begun {
        Begin::Execute(ticket) => ticket,
        Begin::Replay(reply) => {
            // A reconnect can change its declared result reader without changing
            // the recorded action. Adapt only the encoding, never execute again.
            if flat_tool {
                if let Some(result) = reply.result() {
                    if result.get("held").is_some() {
                        let legacy = result.get("structuredContent").cloned().unwrap_or(result);
                        return call_context::CALL_KEY
                            .scope(
                                call_key.clone(),
                                private_content::send_reply(
                                    planes,
                                    &facts,
                                    private_content::replay_plane(&legacy),
                                    writer,
                                    (ver, channel, epoch, corr),
                                    legacy,
                                ),
                            )
                            .await;
                    }
                    let is_content = result.get("content").is_some()
                        && result.get("structuredContent").is_some();
                    let wants_content = tool_result::RESULT_BIND
                        .try_with(|binding| {
                            binding.as_ref().is_some_and(|(_, bind)| {
                                cortexkit_role_tool_provider::consumer_reads_tool_result_v1(
                                    bind.consumer_capabilities(),
                                )
                            })
                        })
                        .unwrap_or(false);
                    if is_content != wants_content {
                        let legacy = result.get("structuredContent").cloned().unwrap_or(result);
                        return private_content::send_reply(
                            planes,
                            &facts,
                            private_content::replay_plane(&legacy),
                            writer,
                            (ver, channel, epoch, corr),
                            legacy,
                        )
                        .await;
                    }
                }
            }
            let response = reply.readdressed(ver, channel, epoch, corr);
            if response.header.ty == FrameType::Response {
                if let Ok(delivered) = serde_json::from_slice::<Value>(&response.body) {
                    private_content::mark_delivered(
                        planes,
                        &facts,
                        private_content::replay_plane(&delivered),
                        &delivered,
                    )
                    .await;
                }
            }
            return send(writer, response).await;
        }
        Begin::InFlight => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_in_flight",
                "a call with this call_key is still in flight; it is not run a second time. Wait \
                 for its reply, or ask what became of it with tool.withdraw",
            )
            .await;
        }
        Begin::NotRetained { outcome } => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_result_not_retained",
                &format!(
                    "a call with this call_key already replied with outcome '{}'; its result \
                     body is no longer retained, and the call is not run again",
                    outcome.as_deref().unwrap_or("unrecorded")
                ),
            )
            .await;
        }
        Begin::OutcomeUnknown => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_outcome_unknown",
                "a call with this call_key started and no reply was recorded (the module \
                 restarted or the route closed first); it may or may not have run, and it is \
                 not run again",
            )
            .await;
        }
        Begin::Unavailable(error) => {
            return send(
                writer,
                call_record_unavailable((ver, channel, epoch, corr), &error),
            )
            .await;
        }
    };

    browser_held::retain(planes, &facts, &call_key, &call);
    if let Some(terminal) = TerminalArbiter::current() {
        let observation = CallObservation::new()
            .with_origin(origin)
            .with_key(call_key.clone());
        let mut pending = Some(PendingSettlement {
            ticket: Some(ticket),
            observation: observation.clone(),
            unattributed_at_start: cerebellum_core::dispatch_witness::unattributed_commit_count(),
            request: (channel, epoch, corr),
        });
        let late = {
            let mut state = terminal.state.lock().unwrap();
            if let Some(chosen) = &state.chosen {
                Some(chosen.clone())
            } else {
                state.settlement = pending.take();
                None
            }
        };
        if let Some(reply) = late {
            // Admission can finish after the terminal has already taken its
            // suffix. Settle that ticket to the chosen reply, never execute it.
            let evidence = journal::call_records::DispatchEvidence {
                gate_dispatched: false,
                committed: false,
                commit_point: false,
                unattributed_commit: false,
                refused_before_dispatch: refused_before_dispatch(&reply),
            };
            let settlement = journal::call_records::Settlement::from_reply(&reply, evidence);
            let calls = Arc::clone(&planes.calls);
            let ticket = pending
                .expect("late admission")
                .ticket
                .expect("admitted ticket");
            settle_call_record(planes, move || {
                calls.settle(ticket, settlement, wall_clock_ms())
            })
            .await;
            return Ok(());
        }
        return call_context::CALL_KEY
            .scope(
                call_key,
                Box::pin(handle_tool_request(call, writer, planes, &observation)),
            )
            .await;
    }

    // The call writes its frames into this channel rather than the route's, so
    // its terminal reply can be recorded before it is forwarded when the write
    // finishes within the settlement budget. Every other frame (a consent
    // question, say) is forwarded untouched.
    let (proxy, mut outgoing) = mpsc::channel::<Frame>(16);
    let mut pending = PendingSettlement {
        ticket: Some(ticket),
        observation: CallObservation::new()
            .with_origin(origin)
            .with_key(call_key.clone()),
        unattributed_at_start: cerebellum_core::dispatch_witness::unattributed_commit_count(),
        request: (channel, epoch, corr),
    };
    let result = {
        let observation = pending.observation.clone();
        let call = call_context::CALL_KEY.scope(
            call_key,
            Box::pin(handle_tool_request(call, &proxy, planes, &observation)),
        );
        tokio::pin!(call);
        loop {
            tokio::select! {
                biased;
                Some(out) = outgoing.recv() => {
                    forward_recording_reply(out, &mut pending, writer, planes).await?;
                }
                result = &mut call => break result,
            }
        }
    };
    drop(proxy);
    while let Ok(out) = outgoing.try_recv() {
        forward_recording_reply(out, &mut pending, writer, planes).await?;
    }
    // No reply: the route closed while the call ran, so nobody is owed one.
    // The call may have acted, which is what the record now says.
    if let Some(ticket) = pending.ticket.take() {
        let calls = Arc::clone(&planes.calls);
        settle_call_record(planes, move || {
            calls.settle_unknown(ticket, wall_clock_ms())
        })
        .await;
    }
    // A task the call started (a consent question still waiting for its answer)
    // can hold a clone of the channel past the call. Keep forwarding for it.
    let writer = writer.clone();
    tokio::spawn(async move {
        while let Some(out) = outgoing.recv().await {
            if send(&writer, out).await.is_err() {
                break;
            }
        }
    });
    result
}

/// What the tool handler watches while one request runs, so a keyed call's
/// record can say whether the action was dispatched, and who the request says
/// it was relayed for.
///
/// Armed for every tool request, keyed or not, so that in a running module a
/// dispatch commitment made under a detached witness always means a commit
/// site lost its request's witness.
#[derive(Clone)]
pub(super) struct CallObservation {
    pub(super) terminal: Option<std::sync::Weak<TerminalArbiter>>,
    /// Marked at a plane's dispatch commitment for this request.
    pub(super) dispatch: cerebellum_core::dispatch_witness::DispatchWitness,
    /// Records whether an external mutation began before the terminal reply was
    /// chosen. Unlike `dispatch`, this covers the interval before the mutation's
    /// audit commitment marks the request's witness.
    pub(super) gate_dispatched: Arc<std::sync::atomic::AtomicBool>,
    /// Set just before the request is handed to a plane every one of whose
    /// dispatches passes a commitment that marks `dispatch`.
    pub(super) commit_point: Arc<std::sync::atomic::AtomicBool>,
    /// The request's `origin`, already validated, for the audit rows the call
    /// writes. Attribution only: admission reads the route's own facts.
    pub(super) origin: cerebellum_core::journal::CallOriginRecord,
    pub(super) call_key: Option<String>,
}

impl CallObservation {
    pub(super) fn new() -> Self {
        let terminal = TerminalArbiter::current();
        Self {
            dispatch: terminal
                .as_ref()
                .map(|t| t.witness.clone())
                .unwrap_or_else(cerebellum_core::dispatch_witness::DispatchWitness::armed),
            gate_dispatched: terminal
                .as_ref()
                .map(|t| Arc::clone(&t.gate_dispatched))
                .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false))),
            commit_point: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            origin: cerebellum_core::journal::CallOriginRecord::Absent,
            call_key: None,
            terminal: terminal.as_ref().map(Arc::downgrade),
        }
    }

    fn with_origin(mut self, origin: cerebellum_core::journal::CallOriginRecord) -> Self {
        self.origin = origin;
        self
    }

    pub(super) fn commit_point_follows(&self) {
        self.commit_point
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn with_key(mut self, key: String) -> Self {
        self.call_key = Some(key);
        self
    }
}

/// A keyed call whose reply has not been recorded yet.
pub(super) struct PendingSettlement {
    pub(super) ticket: Option<journal::call_records::CallTicket>,
    pub(super) observation: CallObservation,
    pub(super) unattributed_at_start: u64,
    pub(super) request: (u16, u32, u64),
}

#[cfg(test)]
// Direct-plane fixtures own their commitments too: a detached fixture witness
// would make concurrently running tool tests lose their proof of no dispatch.
pub(super) fn fixture_dispatch_witness() -> cerebellum_core::dispatch_witness::DispatchWitness {
    cerebellum_core::dispatch_witness::DispatchWitness::armed()
}

#[test]
#[should_panic(expected = "detached dispatch witness committed at")]
fn unarmed_lib_fixture_is_rejected_without_test_setup() {
    cerebellum_core::dispatch_witness::DispatchWitness::detached().mark_committed();
}

/// Return true for replies sent by `handle_tool_request` before dispatch or
/// for a provider resource-busy refusal; neither case dispatched the tool.
pub(super) fn refused_before_dispatch(reply: &Frame) -> bool {
    let envelope: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    let body = envelope.get("structuredContent").unwrap_or(&envelope);
    match reply.header.ty {
        // The envelope and argument checks answer in the reply body.
        FrameType::Response => {
            matches!(
                body["outcome"].as_str(),
                Some(
                    "invalid_request"
                        | "resource_busy"
                        | "action_deadline_exceeded"
                        | "target_busy"
                        | "blocking_capacity_exhausted"
                )
            ) || (body["outcome"] == "consent_unavailable"
                && matches!(
                    body["detail"]["reason"].as_str(),
                    Some(
                        "flow_carrier_not_admitted"
                            | "unattended_flow"
                            | "takeover_not_for_flows"
                            | "agent_run"
                    )
                ))
        }
        FrameType::Error => body["code"].as_str().is_some_and(|code| {
            [
                "invalid_request",
                "route_not_bound",
                "capability_denied",
                "computer_plane_unavailable",
                "call_record_unavailable",
                "request_not_interruptible",
                cerebellum_core::principal::SESSION_CALLER_NOT_ADMITTED,
                CapabilityWithheld::Unknown.reason_code(),
                CapabilityWithheld::BrowserNotConfigured.reason_code(),
                CapabilityWithheld::NotAdmitted.reason_code(),
            ]
            .contains(&code)
        }),
        _ => false,
    }
}

/// Forward one frame of a keyed call. For its terminal reply, wait for the
/// record only within the settlement budget; a late write keeps that reply.
pub(super) async fn forward_recording_reply(
    out: Frame,
    pending: &mut PendingSettlement,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let is_reply = matches!(out.header.ty, FrameType::Response | FrameType::Error)
        && (out.header.channel, out.header.epoch, out.header.corr) == pending.request;
    if is_reply {
        if let Some(ticket) = pending.ticket.take() {
            #[cfg(test)]
            if let Some(before) = planes
                .call_record_workers
                .before_settlement
                .lock()
                .unwrap()
                .take()
            {
                before();
            }
            let evidence = journal::call_records::DispatchEvidence {
                gate_dispatched: pending
                    .observation
                    .gate_dispatched
                    .load(std::sync::atomic::Ordering::SeqCst),
                committed: pending
                    .observation
                    .terminal
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                    .map(|terminal| {
                        terminal
                            .witness_committed
                            .load(std::sync::atomic::Ordering::SeqCst)
                    })
                    .unwrap_or_else(|| pending.observation.dispatch.committed()),
                commit_point: pending
                    .observation
                    .commit_point
                    .load(std::sync::atomic::Ordering::SeqCst),
                unattributed_commit: cerebellum_core::dispatch_witness::unattributed_commit_count()
                    != pending.unattributed_at_start,
                refused_before_dispatch: refused_before_dispatch(&out),
            };
            // Freeze the evidence and reply before detaching the write, so late
            // worker completion cannot replace the terminal settlement.
            let calls = Arc::clone(&planes.calls);
            let settlement = journal::call_records::Settlement::from_reply(&out, evidence);
            // Register before queueing: a caller can withdraw as soon as this
            // frame is sent, even if the settlement exhausts its wait budget.
            let transition = planes.call_record_workers.track_settlement(&ticket);
            settle_call_record(planes, move || {
                calls.settle(ticket, settlement, wall_clock_ms());
                transition.finish();
            })
            .await;
        }
    }
    send(writer, out).await
}

/// `tool.withdraw {call_key, scope?, carrier?}`: what became of a recorded
/// call, interrupting a live codemode call after authorization. Only a record
/// that merely asked a person guarantees its action will never run. The
/// question may still record a grant for a future call.
///
/// The answer is read from the record, so every permitted repeat gets the
/// same bytes. A carrier looks up only its own key; an authorized scope owner
/// may name another carrier. Every found record must match the route's scope.
/// An absent explicit carrier record answers `unknown_call`; an owner with no
/// own record must name a carrier. Neither reveals another carrier's keys.
/// Caller/scope mismatches are contract route
/// errors, and the daemon's `owner_authorized` stamp remains required when an
/// owner acts for another carrier.
async fn handle_tool_withdraw(
    object: &serde_json::Map<String, Value>,
    (ver, channel, epoch, corr): (u8, u16, u32, u64),
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    use journal::call_records::{self, Lookup, ScopeIdentity};

    let invalid = |field: &str, reason: &'static str| Err((field.to_string(), reason));
    let checked = (|| {
        if let Some(field) = object
            .keys()
            .filter(|field| {
                !matches!(
                    field.as_str(),
                    "name" | "arguments" | "progress_token" | "tool_call_id"
                )
            })
            .min()
        {
            return Err((field.clone(), "unknown_field"));
        }
        let arguments = match object.get("arguments") {
            None => return invalid("arguments", "missing_field"),
            Some(Value::Object(arguments)) => arguments,
            Some(_) => return invalid("arguments", "wrong_type"),
        };
        if let Some(field) = arguments
            .keys()
            .filter(|field| !matches!(field.as_str(), "call_key" | "scope" | "carrier"))
            .min()
        {
            return Err((format!("arguments.{field}"), "unknown_field"));
        }
        let call_key = match arguments.get("call_key") {
            None => return invalid("arguments.call_key", "missing_field"),
            Some(Value::String(key)) if call_records::valid_call_key(key) => key.clone(),
            Some(_) => return invalid("arguments.call_key", "wrong_type"),
        };
        // Only the shape is checked here. A scope named in the request is the
        // caller's own claim; below it is compared with the route's stamp and
        // never used in its place.
        let named_scope = match arguments.get("scope") {
            None => None,
            Some(scope) => {
                let named = scope.as_object().and_then(|scope| {
                    (scope.len() == 3).then_some(())?;
                    Some(ScopeIdentity {
                        owner: scope.get("owner")?.as_str()?.to_string(),
                        reference: scope.get("ref")?.as_str()?.to_string(),
                        scope_epoch: scope.get("scope_epoch")?.as_u64()?,
                    })
                });
                match named {
                    Some(named) => Some(named),
                    None => return invalid("arguments.scope", "wrong_type"),
                }
            }
        };
        // The carrier is a principal label such as `reserved:basal`,
        // the form call records are kept under.
        let carrier = match arguments.get("carrier") {
            None => None,
            Some(Value::String(carrier)) if !carrier.is_empty() => Some(carrier.clone()),
            Some(_) => return invalid("arguments.carrier", "wrong_type"),
        };
        Ok((call_key, named_scope, carrier))
    })();
    let (call_key, named_scope, carrier) = match checked {
        Ok(checked) => checked,
        Err((field, reason)) => {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(&field, reason),
                (ver, channel, epoch, corr),
                writer,
            )
            .await
        }
    };
    let Some(facts) = planes.routes.get(channel, epoch) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "route_not_bound",
            "tool.withdraw requires an accepted route.bind",
        )
        .await;
    };
    let principal = call_records::principal_label(facts.principal.as_ref());
    use cortexkit_role_tool_provider::scope::ScopeIdentity as WireScope;
    use cortexkit_role_tool_provider::withdraw::{
        check_record_scope, resolve_carrier, CallerProblem, CarrierResolution, WithdrawArguments,
    };
    let to_wire = |scope: &ScopeIdentity, owner| WireScope {
        owner,
        scope_ref: scope.reference.clone(),
        scope_epoch: scope.scope_epoch,
    };
    let stamped = facts.scope.as_ref().map(ScopeIdentity::from_stamp);
    let wire_stamp = stamped
        .as_ref()
        .map(|scope| to_wire(scope, scope.owner.clone()));
    let mut arguments = WithdrawArguments::new(&call_key);
    // A requested scope can name a pre-rename record. The caller, live stamp,
    // and carrier still use the daemon's exact identity.
    arguments.scope = named_scope
        .as_ref()
        .map(|scope| to_wire(scope, scope.owner_key()));
    arguments.carrier = carrier;
    let resolution = match resolve_carrier(&principal, wire_stamp.as_ref(), &arguments) {
        Ok(resolution) => resolution,
        Err(problem) => {
            return tool_provider::send_error(problem.error(), (ver, channel, epoch, corr), writer)
                .await;
        }
    };
    let (carrier, owner_as_carrier) = match resolution {
        CarrierResolution::Carrier(carrier) => (carrier, false),
        CarrierResolution::OwnerAsCarrier(carrier) => (carrier, true),
    };
    // The contract resolves the carrier; the daemon still decides whether a
    // scope owner may act for somebody else. A claimed owner is not authority.
    if carrier != principal
        && !facts
            .scope
            .as_ref()
            .is_some_and(|stamp| stamp.owner_authorized)
    {
        return tool_provider::send_error(
            CallerProblem::NotPermitted.error(),
            (ver, channel, epoch, corr),
            writer,
        )
        .await;
    }
    // Never search other principals' keys: even a refusal would disclose that
    // another carrier has a record with this opaque key.
    let lookup =
        call_record_supervisor::lookup_call_record(planes, carrier.clone(), call_key.clone()).await;
    if let Lookup::Own(snapshot) = &lookup {
        let record_scope = snapshot
            .scope
            .as_ref()
            .map(|scope| to_wire(scope, scope.owner_key()));
        if let Err(problem) = check_record_scope(record_scope.as_ref(), wire_stamp.as_ref()) {
            return tool_provider::send_error(problem.error(), (ver, channel, epoch, corr), writer)
                .await;
        }
    } else if owner_as_carrier && matches!(lookup, Lookup::Unknown | Lookup::OtherPrincipal) {
        return tool_provider::send_error(
            CallerProblem::CarrierRequired.error(),
            (ver, channel, epoch, corr),
            writer,
        )
        .await;
    }
    match lookup {
        Lookup::Own(snapshot) => {
            if snapshot.state == call_records::CallState::Asked {
                let _ = planes
                    .calls
                    .abandon_browser_request(&carrier, &call_key, wall_clock_ms());
            }
            if let Some(cancel) =
                planes
                    .run_calls
                    .cancellation(&carrier, &call_key, stamped.as_ref())
            {
                planes.browser_resumes.cancel_handle(&cancel);
                cancel.cancel();
                if let (Some(agent), Some(cursor)) = (cancel.cursor_agent(), planes_cursor(planes))
                {
                    cursor.end(&agent);
                }
            }
            let answer = call_records::withdraw_answer(&snapshot);
            // Interruption does not undo dispatched input. Only a record that
            // merely asked a person proves the action will never run; a started
            // call keeps its honest outcome even after cancellation is fired.
            private_content::send_reply(
                planes,
                &facts,
                private_content::replay_plane(&answer),
                writer,
                (ver, channel, epoch, corr),
                answer,
            )
            .await
        }
        Lookup::Unknown => {
            send_tool_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                json!({"answer": "unknown_call"}),
            )
            .await
        }
        Lookup::OtherPrincipal => {
            send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "withdraw_not_permitted",
                "only the principal that raised a call, or the authorized owner of the scope it \
                 was recorded under, may withdraw it",
            )
            .await
        }
        Lookup::Unavailable(error) => {
            send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_record_unavailable",
                &format!("the call records cannot be read ({error})"),
            )
            .await
        }
    }
}

pub(super) async fn handle_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    call: &CallObservation,
) -> Result<(), ModuleError> {
    let user = serde_json::from_slice::<Value>(&frame.body)
        .ok()
        .is_some_and(|body| {
            body["name"] == flat_tools::BROWSER_USE && body["arguments"]["browser"] == "user"
        });
    if !user {
        return Box::pin(handle_tool_request_enforced(frame, writer, planes, call)).await;
    }
    // Tag even admission/schema refusals, which never reach the user adapter.
    // Own calls bypass this forwarding path and keep their original bytes.
    let (tagged, mut replies) = mpsc::channel::<Frame>(16);
    let writer = writer.clone();
    let forwarding = tokio::spawn(async move {
        while let Some(frame) = replies.recv().await {
            let frame = if matches!(frame.header.ty, FrameType::Response | FrameType::Error) {
                let mut body: Value =
                    serde_json::from_slice(&frame.body).map_err(ModuleError::Json)?;
                body["browser"] = json!("user");
                Frame::build_with_version(
                    frame.header.ver,
                    frame.header.ty,
                    frame.header.flags,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    serde_json::to_vec(&body).map_err(ModuleError::Json)?,
                )
                .map_err(|error| ModuleError::Message(error.to_string()))?
            } else {
                frame
            };
            send(&writer, frame).await?;
        }
        Ok::<(), ModuleError>(())
    });
    let result = Box::pin(handle_tool_request_enforced(frame, &tagged, planes, call)).await;
    drop(tagged);
    forwarding
        .await
        .map_err(|error| ModuleError::Message(error.to_string()))??;
    result
}

pub(super) async fn handle_tool_request_enforced(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    call: &CallObservation,
) -> Result<(), ModuleError> {
    let key = (frame.header.channel, frame.header.epoch, frame.header.corr);
    // Passing a large handler by value through the grant watcher multiplies
    // debug poll-frame stack slots. Pin it once so normal completion and
    // cancellation cleanup carry only the pointer.
    let future = Box::pin(handle_tool_request_inner(frame, writer, planes, call));
    match planes.cancellations.get(key) {
        Some(cancel) => grant_enforcement::scope(cancel, future).await,
        None => future.await,
    }
}

pub(super) async fn handle_tool_request_inner(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    call: &CallObservation,
) -> Result<(), ModuleError> {
    browser_held::track_consent(planes);
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Queue);
    }
    let _browser_guard = match browser_queue::enter(&frame, planes).await {
        Ok(guard) => guard,
        Err(outcome) => return send_queue_refusal(writer, &frame, planes, outcome).await,
    };
    let route_bindings = &planes.routes;
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Preflight);
    }
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;

    let request: serde_json::Value = match serde_json::from_slice(&frame.body) {
        Ok(v) => v,
        Err(e) => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "invalid_request",
                &format!("request body not decodable: {e}"),
            )
            .await;
        }
    };

    let Some(object) = request.as_object() else {
        return send_invalid_request_response(writer, ver, channel, epoch, corr, "$", "wrong_type")
            .await;
    };

    // Tool-route envelopes are closed: a member not listed here is refused by
    // name as `unknown_field`. `progress_token` is an optional gateway
    // member, accepted for correlation but not used here. `origin` names the
    // caller behind a relayed call; it was read before this handler (see
    // `handle_keyed_tool_request`) and reaches it only through `call`.
    if let Some(field) = object
        .keys()
        .filter(|field| {
            !matches!(
                field.as_str(),
                "name"
                    | "arguments"
                    | "progress_token"
                    | "origin"
                    | "preset"
                    | "schema_pin"
                    | "tool_call_id"
            )
        })
        .min()
    {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            field,
            "unknown_field",
        )
        .await;
    }

    // This provider declares no presets. An absent or null preset preserves
    // the existing service; it never selects a more capable preset implicitly.
    if let Some(preset) = object.get("preset").filter(|value| !value.is_null()) {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            json!({
                "outcome": "invalid_request",
                "context": null,
                "session": null,
                "detail": {
                    "field": "preset",
                    "reason_code": "unsupported_value",
                    "value": preset,
                },
            }),
        )
        .await;
    }

    let Some(name_value) = object.get("name") else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "name",
            "missing_field",
        )
        .await;
    };
    let Some(name) = name_value.as_str() else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "name",
            "wrong_type",
        )
        .await;
    };

    if object.contains_key("schema_pin") {
        if let Err(error) = tool_provider::check_tool_call(object, planes) {
            return tool_provider::send_error(error, (ver, channel, epoch, corr), writer).await;
        }
    }

    // Route admission is completed before decoding capability arguments.
    // Admitted routes may proceed to their handlers; denied routes perform no
    // reservation, context lookup, grant lookup, or CDP work.
    // `browser.fill_login` is served only by a plane that was given a source
    // of login material. With the rollout switch on, startup gives a running
    // module's plane the live vault source; planes built for tests get none
    // unless a test installs one.
    let browser_admitted = planes.browser_dispatch_admitted();
    let known_capability = dispatchable_tool_with_browser(name, browser_admitted)
        .or_else(|| browser::fill::admitted(name, &planes.browser, browser_admitted));
    #[cfg(all(test, target_os = "windows"))]
    let known_capability = known_capability.or_else(|| {
        // An opted-in fixture supplies the computer plane in place of the
        // native identity reader. The catalog and per-row checks still run.
        (planes
            .computer
            .as_ref()
            .is_ok_and(|plane| plane.wire_dispatch_for_test)
            && (name == flat_tools::COMPUTER_USE || computer_capability::servable(name).is_some()))
        .then_some(name)
    });
    #[cfg(target_os = "linux")]
    let known_capability = known_capability.or_else(|| {
        let desktop = if name == flat_tools::COMPUTER_USE {
            !planes.computer_admitted.is_empty()
        } else {
            computer_capability::servable(name).is_some()
                && !matches!(
                    planes.computer,
                    Err(computer_capability::ComputerPlaneUnavailable::NoLinuxReviews)
                )
        };
        desktop.then_some(name)
    });
    #[cfg(windows)]
    let known_capability = known_capability.or_else(|| {
        (browser_admitted
            && planes.enforce_windows_browser_refusals()
            && windows_withheld::legacy_tool_refusal(name).is_some())
        .then_some(name)
    });
    let Some(capability_name) = known_capability else {
        if matches!(name, flat_tools::BROWSER_USE | flat_tools::COMPUTER_USE) {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::tool_disabled(name),
                (ver, channel, epoch, corr),
                writer,
            )
            .await;
        }
        // Say WHICH kind of unavailable. A caller who named something this build
        // withholds and a caller who named something invented both arrive here,
        // and only one of them can do anything about it.
        let withheld =
            capability_withheld(name, browser_admitted).unwrap_or(CapabilityWithheld::Unknown);
        if matches!(withheld, CapabilityWithheld::Unknown) {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::unknown_tool(name),
                (ver, channel, epoch, corr),
                writer,
            )
            .await;
        }
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            withheld.reason_code(),
            &format!("'{name}' is not served here: {}", withheld.remedy()),
        )
        .await;
    };

    let Some(mut accepted_facts) = route_bindings.get(channel, epoch) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "route_not_bound",
            "browser capability requires an accepted route.bind",
        )
        .await;
    };
    // This request's copy of the route identity carries its own witness, so a
    // browser dispatch committed for it marks this request and no other.
    accepted_facts.identity.witness = call.dispatch.clone();
    // And its own origin, so every audit row written for it names the caller
    // behind it. Set after the route lookup and read by nothing below that
    // admits, refuses or keys the call.
    accepted_facts.identity.origin = call.origin.clone();
    // Session admission, before the capability scope and before anything
    // below reads a grant, asks a person or reserves a journal entry; see
    // `send_session_caller_not_admitted`. Every tool call acts in the route's
    // conversation, so no tool is served outside one.
    if let Some(refusal) = session_flow_refusal(&accepted_facts) {
        return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
    }
    if !accepted_facts.admits_session_calls() {
        return send_session_caller_not_admitted(
            writer,
            ver,
            channel,
            epoch,
            corr,
            &accepted_facts,
        )
        .await;
    }
    if let Err(error) = tool_provider::check_tool_call(object, planes) {
        return tool_provider::send_error(error, (ver, channel, epoch, corr), writer).await;
    }
    if !accepted_facts.allows_capability(capability_name) {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "capability_denied",
            "capability is outside the effective capability scope",
        )
        .await;
    }

    let Some(arguments) = object.get("arguments") else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "arguments",
            "missing_field",
        )
        .await;
    };

    #[cfg(windows)]
    if planes.enforce_windows_browser_refusals() {
        if let Some(refusal) = windows_withheld::tool_refusal(name, arguments) {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                refusal.code,
                refusal.message,
            )
            .await;
        }
    }

    let translated = if name == flat_tools::COMPUTER_USE {
        match flat_tools::translate_computer(arguments) {
            Ok(dispatch) => Some(dispatch),
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        }
    } else if name == flat_tools::BROWSER_USE {
        match flat_tools::translate_browser(arguments) {
            Ok(dispatch) => Some(dispatch),
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        }
    } else {
        None
    };
    if let Some(flat_tools::FlatDispatch::Management { method, params }) = translated.as_ref() {
        let mut management_frame = frame.clone();
        management_frame.body = serde_json::to_vec(&json!({
            "method": method,
            "params": params,
        }))
        .expect("flat management request serializes");
        return handle_management_request_observed(
            management_frame,
            writer,
            &accepted_facts,
            planes,
            call.call_key.as_deref(),
        )
        .await;
    }
    if let Some(flat_tools::FlatDispatch::UserBrowser {
        action,
        capability,
        arguments,
    }) = translated.as_ref()
    {
        if accepted_facts.flow_id.is_some() && !accepted_facts.acts_as_agent {
            return send_tool_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                flow_consent_refusal("unattended_flow"),
            )
            .await;
        }
        if let Some(capability) = capability {
            // The selector cannot widen the route's capability admission. In
            // particular, open_tab and claim_tab have launch's exact authority.
            if !accepted_facts.allows_capability(capability) {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "capability_denied",
                    "capability is outside the effective capability scope",
                )
                .await;
            }
            if let Some(refusal) = browser_session::CONTROL_TOOLS
                .contains(&capability.as_str())
                .then(|| accepted_facts.control_operation_refusal(capability))
                .flatten()
            {
                return send_tool_response(writer, ver, channel, epoch, corr, json!({"browser":"user","outcome":"authorization_denied","reason":refusal.reason_code(),"remedy":accepted_facts.control_refusal_remedy(refusal)})).await;
            }
        }
        call.commit_point_follows();
        // Claims, snapshots, refs and the extension's own route bookkeeping
        // are keyed by the route resolved here: the head's for a run, so a
        // run acts on its head's tabs and its claims outlive the run's route.
        // Cancellation and consent liveness stay on the inbound route.
        let browser_route = match codemode::user_browser_route(planes, channel, epoch) {
            Ok(route) => route,
            Err(refusal) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    refusal.code(),
                    refusal.message(),
                )
                .await
            }
        };
        // A person's-browser screenshot leaves with a handle its bytes resolve
        // by, so a program can pass it to a model call. A refusal carries no
        // image, so minting leaves it as it is.
        let mut result = user_browser::serve(
            planes,
            &accepted_facts,
            writer,
            (channel, epoch, corr),
            browser_route,
            action,
            arguments,
        )
        .await;
        mint_image_handle(planes, &accepted_facts, &mut result);
        if should_say_no_handle(&result) {
            tool_result::image_handle_note(NO_HANDLE_NOTE.to_owned());
        }
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        return private_content::send_reply(
            planes,
            &accepted_facts,
            private_content::ReplyPlane::PersonBrowser,
            writer,
            (ver, channel, epoch, corr),
            result,
        )
        .await;
    }
    let (name, arguments) = match translated.as_ref() {
        Some(flat_tools::FlatDispatch::Computer {
            capability,
            arguments,
        })
        | Some(flat_tools::FlatDispatch::Browser {
            capability,
            arguments,
        }) => (capability.as_str(), arguments),
        Some(flat_tools::FlatDispatch::BrowserKey { arguments, .. }) => (browser::CLICK, arguments),
        Some(flat_tools::FlatDispatch::Management { .. }) => unreachable!("returned above"),
        Some(flat_tools::FlatDispatch::UserBrowser { .. }) => unreachable!("returned above"),
        None => (name, arguments),
    };

    if accepted_facts.flow_id.is_some() && !accepted_facts.acts_as_agent {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("unattended_flow"),
        )
        .await;
    }
    if accepted_facts.flow_id.is_some()
        && matches!(
            name,
            "computer.takeover_move"
                | "computer.takeover_click"
                | "computer.takeover_drag"
                | "computer.takeover_scroll"
        )
    {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("takeover_not_for_flows"),
        )
        .await;
    }
    if codemode::legacy_run(&accepted_facts)
        && matches!(
            name,
            "computer.takeover_move"
                | "computer.takeover_click"
                | "computer.takeover_drag"
                | "computer.takeover_scroll"
        )
    {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            agent_run_consent_refusal(),
        )
        .await;
    }
    if browser_session::CONTROL_TOOLS.contains(&name) {
        // The admission refusal is a reply of this capability like any other,
        // so it goes through the same boundary. A refusal returned from above
        // `finish_reply` is never checked against the declared vocabulary, and
        // it is the reply a caller on a misconfigured route receives first.
        let result = match accepted_facts.control_operation_refusal(name) {
            Some(refusal) => json!({
                "outcome": "authorization_denied",
                "reason": refusal.reason_code(),
                "remedy": accepted_facts.control_refusal_remedy(refusal),
            }),
            None => handle_browser_control(name, arguments, &accepted_facts, planes).await,
        };
        return match planes.browser.finish_reply(name, result) {
            Ok(result) => send_tool_response(writer, ver, channel, epoch, corr, result).await,
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!(
                        "the capability reply violated its frozen result schema ({error}); the \
                         operation may already have completed, so do not retry it based on this \
                         response"
                    ),
                )
                .await
            }
        };
    }

    // Routed by which plane serves the capability, before the browser handler
    // sees it. The two planes share a request envelope and nothing else, so a
    // computer capability reaching the browser handler would be reported as an
    // unknown method -- a refusal that describes the wrong subsystem.
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    if let Some(servable) = computer_capability::servable(name) {
        let clock = planes.lease_clock.as_ref();

        // Refused unless the release gates admitted it, so serving and
        // advertising answer to the same authority.
        //
        // Withholding a capability from the manifest is not by itself a gate.
        // Every capability name is fixed in the action vocabulary, which is a
        // published artifact, so a caller can name one without having seen it
        // in a manifest -- and before this check such a request was served.
        //
        // The code is the same one the browser plane answers for a withheld
        // tool, because it means the same thing: this build knows the name and
        // does not serve it. A consumer keys its handling on the code, and two
        // spellings of one fact would force it to keep a per-plane list.
        #[cfg(not(target_os = "linux"))]
        if !planes.computer_admitted.contains(name) {
            let withheld = CapabilityWithheld::NotAdmitted;
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                withheld.reason_code(),
                &format!("'{name}' is not served here: {}", withheld.remedy()),
            )
            .await;
        }

        // Distinct from withheld: the capability IS admitted, and this host
        // could not build the plane that serves it (an audit journal that will
        // not open, for instance). A caller can do nothing about a build that
        // withholds; an operator can do something about a host that cannot.
        let plane = match planes.computer.as_ref() {
            Ok(plane) => plane,
            Err(reason) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "computer_plane_unavailable",
                    &format!("the computer plane could not be built on this host: {reason}"),
                )
                .await;
            }
        };
        // Every production request registers its cancellation entry before the
        // task that reaches here is spawned, so the absent case is a module bug
        // rather than anything a caller can cause. It is a refusal and not an
        // `expect` because the invariant lives at a DIFFERENT call site than the
        // one that depends on it: a second entry point added later would satisfy
        // the compiler, panic in a spawned task, and leave an indeterminate
        // audit record instead of saying what was wrong. Refusing also cannot be
        // mistaken for the other repair: handing out a never-cancels handle here
        // would make the request uninterruptible and look like success.
        let Some(cancel) = planes.cancellations.get((channel, epoch, corr)) else {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "request_not_interruptible",
                "this request was not registered for interruption before dispatch; \
                 it was refused rather than served without a way to stop it",
            )
            .await;
        };
        // Every computer capability passes the audit journal's dispatch
        // commitment before its first input, so an unmarked witness after this
        // point means nothing was dispatched.
        call.commit_point_follows();
        let context = computer_capability::ServeContext {
            cancel,
            // The durable agent identity, taken from the accepted bind
            // rather than from the request: an identity a caller could
            // choose is a lease granted to whoever asks for it.
            grantee: &accepted_facts.identity.agent_project_id,
            identity: cerebellum_core::journal::JournalIdentity {
                witness: call.dispatch.clone(),
                principal: accepted_facts
                    .principal
                    .as_ref()
                    .map(|principal| format!("{principal:?}"))
                    .unwrap_or_default(),
                conversation_key: accepted_facts.identity.conversation_key.clone(),
                agent_project_id: accepted_facts.identity.agent_project_id.clone(),
                session_kind: accepted_facts.identity.session_kind,
                origin: accepted_facts.identity.origin.clone(),
                computer_order: None,
            },
            management: &planes.management,
            consent: consent_context(planes, &accepted_facts, writer, channel, epoch),
            clock,
            // Wall-clock rather than the lease clock: this stamps a
            // journal entry a person may later read against other
            // records, where the lease clock only answers whether one
            // moment came after another inside this process.
            now_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis() as u64)
                .unwrap_or_default(),
        };
        #[cfg(all(test, target_os = "macos"))]
        let result = if let Some(scripted) = &planes.computer_for_test {
            scripted
                .serve(servable, arguments, context, |_grant| {
                    computer_capability::native_capture_backend()
                })
                .await
        } else {
            plane
                .serve(servable, arguments, context, |_grant| {
                    computer_capability::native_capture_backend()
                })
                .await
        };
        #[cfg(not(all(test, target_os = "macos")))]
        let result = plane
            .serve(servable, arguments, context, |_grant| {
                computer_capability::native_capture_backend()
            })
            .await;
        // A call whose route unbound while it waited on a person has nobody
        // to answer; its reply is dropped rather than sent to a closed route.
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        return match result {
            Ok(result) => {
                // The read's screenshot is thousands of bytes no program can
                // return, so it also leaves with a handle Broca can resolve.
                let mut result = result;
                mint_image_handle(planes, &accepted_facts, &mut result);
                private_content::send_reply(
                    planes,
                    &accepted_facts,
                    private_content::ReplyPlane::DesktopApp,
                    writer,
                    (ver, channel, epoch, corr),
                    result,
                )
                .await
            }
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "computer_result_schema_violation",
                    &format!(
                        "the capability reply violated its frozen result schema ({error}); the \
                         operation may already have completed, so do not retry it based on this \
                         response"
                    ),
                )
                .await
            }
        };
    }

    // ADMISSION AT THE TOP OF THIS FUNCTION ALREADY MADE THIS PARSE TOTAL, and
    // that is the problem with leaving the branch to something else: the
    // invariant lives in `dispatchable_tool_with_browser`, a different function
    // in a different part of this file, and a change there resurrects this arm
    // for whoever is reading THAT code. So this answers rather than delegating,
    // and it answers the SAME route-level envelope the admission check sends --
    // a resurrection then returns the reply the wire already documents instead
    // of a second spelling nobody tests.
    //
    // It used to call `browser::handle_tool`, which re-parsed the name it had
    // just been told does not parse and could therefore only ever return a
    // reply BODY of `{"outcome": "unknown_method"}` -- no `context`, which
    // `reply_schema` makes required, so it would have failed its own schema had
    // anything validated it. That helper is gone; nothing else called it.
    if name == browser::fill::FILL_LOGIN {
        // A fill marks the dispatch commitment before its first CDP command,
        // so an unmarked witness proves nothing reached the page.
        call.commit_point_follows();
        let result = Box::pin(login_fill_consent::serve(
            planes,
            &accepted_facts,
            (channel, epoch, corr),
            arguments,
            BROWSER_CONSENT_PARK_LIMIT
                .try_with(|limit| *limit)
                .unwrap_or(Duration::from_secs(120)),
        ))
        .await;
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        if TerminalArbiter::current().is_some_and(|terminal| terminal.answered_by_cancel()) {
            return Ok(());
        }
        return match result {
            Ok(result) => {
                // A browser screenshot leaves with a handle its bytes resolve
                // by, so a program can pass it to a model call.
                let mut result = result;
                mint_image_handle(planes, &accepted_facts, &mut result);
                if should_say_no_handle(&result) {
                    tool_result::image_handle_note(NO_HANDLE_NOTE.to_owned());
                }
                private_content::send_reply(
                    planes,
                    &accepted_facts,
                    private_content::ReplyPlane::OwnBrowser,
                    writer,
                    (ver, channel, epoch, corr),
                    result,
                )
                .await
            }
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!(
                        "the capability reply violated its frozen result schema ({error}); the \
                         operation may already have completed, so do not retry it based on this \
                         response"
                    ),
                )
                .await
            }
        };
    }
    let Some(capability) = browser::BrowserCapability::parse(name) else {
        let withheld = CapabilityWithheld::Unknown;
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            withheld.reason_code(),
            &format!("'{name}' is not served here: {}", withheld.remedy()),
        )
        .await;
    };
    // These browser capabilities all pass `BrowserPlane::commit` before any
    // CDP command. `wait_for` has no dispatch commitment, so for it an
    // unmarked witness proves nothing.
    if capability != browser::BrowserCapability::WaitFor {
        call.commit_point_follows();
    }
    let serve = Box::pin(serve_browser_with_consent(
        planes,
        &accepted_facts,
        writer,
        (channel, epoch, corr),
        capability,
        arguments,
        BROWSER_CONSENT_PARK_LIMIT
            .try_with(|limit| *limit)
            .unwrap_or(Duration::from_secs(120)),
    ));
    let result = match translated.as_ref() {
        Some(flat_tools::FlatDispatch::BrowserKey { key, .. }) => {
            browser::keys::PRESS_KEY.scope(*key, serve).await
        }
        _ => serve.await,
    };
    if planes.routes.get(channel, epoch).is_none() {
        return Ok(());
    }
    // A Cancel already chose this call's reply in its terminal arbiter
    // (`{"outcome":"cancelled","context":null}` before dispatch, or the
    // uncertain-dispatch body after it). The call's own cancelled reply from
    // its site card carries the route's context instead, so sending it would
    // let scheduling decide which body the caller gets; send nothing.
    if TerminalArbiter::current().is_some_and(|terminal| terminal.answered_by_cancel()) {
        return Ok(());
    }
    match result {
        Ok(result) => {
            // A browser screenshot leaves with a handle its bytes resolve by,
            // so a program can pass it to a model call.
            let mut result = result;
            mint_image_handle(planes, &accepted_facts, &mut result);
            if should_say_no_handle(&result) {
                tool_result::image_handle_note(NO_HANDLE_NOTE.to_owned());
            }
            private_content::send_reply(
                planes,
                &accepted_facts,
                private_content::ReplyPlane::OwnBrowser,
                writer,
                (ver, channel, epoch, corr),
                result,
            )
            .await
        }
        Err(error) => {
            send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                browser::RESULT_SCHEMA_VIOLATION_CODE,
                &format!(
                    "the capability reply violated its frozen result schema ({error}); the \
                     operation may already have completed, so do not retry it based on this \
                     response"
                ),
            )
            .await
        }
    }
}

tokio::task_local! {
    pub(super) static BROWSER_CONSENT_PARK_LIMIT: Duration;
}

/// Exercise the production dispatch with a shorter inline wait, without changing
/// the lifetime of the question that must still accept a late answer.
#[doc(hidden)]
pub async fn handle_browser_consent_deadline_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    deadline: Duration,
) -> Result<(), ModuleError> {
    BROWSER_CONSENT_PARK_LIMIT
        .scope(deadline, async {
            handle_frame(frame, writer, planes).await.map(|_| ())
        })
        .await
}

/// Ask only after dispatch has returned its refusal and released its conversation
/// lane and session operation guard. The outer call queue preserves browser
/// order during consent without holding CDP access.
pub(super) async fn serve_browser_with_consent(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    _writer: &mpsc::Sender<Frame>,
    request: (u16, u32, u64),
    capability: browser::BrowserCapability,
    arguments: &Value,
    park_limit: Duration,
) -> Result<Value, cerebellum_computer::platform::vocabulary::CapabilityResultValidationError> {
    let mut reply = authorization::with_flow(
        facts.flow_id.is_some(),
        authorization::with_standing_caller(
            standing_caller(facts),
            planes.browser.serve(&facts.identity, capability, arguments),
        ),
    )
    .await?;
    let Some(scope) = reply.pointer("/detail/grant_request") else {
        return Ok(reply);
    };
    if browser_held::resuming() {
        return Ok(reply);
    }
    if codemode::legacy_run(facts) {
        reply["outcome"] = json!("consent_unavailable");
        reply["detail"]["reason"] = json!("agent_run");
        reply["remedy"] = agent_run_consent_refusal()["remedy"].clone();
        return planes.browser.finish_reply(capability.name(), reply);
    }
    if facts.flow_id.is_some() {
        let detail = management::browser_missing_grant(
            scope["origins"][0].as_str().expect("grant request origin"),
            scope["severity_tier"].as_u64().expect("grant request tier"),
        );
        reply["outcome"] = json!("consent_unavailable");
        reply["detail"] = detail;
        reply["remedy"] =
            json!("an unattended flow cannot ask a person; configure its owner's standing grant");
        return planes.browser.finish_reply(capability.name(), reply);
    }
    let Some(cancel) = planes.cancellations.get(request) else {
        return Ok(reply);
    };
    let origins = scope["origins"].as_array().and_then(|values| {
        values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    });
    let hazards = scope["hazards"].as_array().and_then(|values| {
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .and_then(authorization::HazardClass::from_wire)
            })
            .collect::<Option<Vec<_>>>()
    });
    let tier = scope["severity_tier"]
        .as_u64()
        .and_then(|tier| u8::try_from(tier).ok());
    let (Some(origins), Some(hazards), Some(tier)) = (origins, hazards, tier) else {
        return Ok(reply);
    };
    let Ok((mut pending, Some(mut question))) = planes
        .management
        .open_in_call_browser_grant(
            &facts.identity.conversation_key,
            origins,
            hazards,
            Some(tier),
            standing_offer_agent(facts),
        )
        .await
    else {
        return Ok(reply);
    };
    if let Err(error) = question.bind_holder(permission_scope::minting_holder(facts)) {
        error.apply_to_reply(&mut reply);
        return planes.browser.finish_reply(capability.name(), reply);
    }
    use cingulate_client::desk::{Ending, InCall, LetGo};
    let live = match browser_consent::live(facts, planes, request.0, request.1) {
        Ok(live) => live,
        Err(ending) => {
            browser_consent::settle_failed(
                &planes.management,
                cingulate_client::card::CardKind::WebsiteAccessInCall,
                &question,
                &ending,
            );
            browser_consent::in_call_refusal(&mut reply, &ending);
            return planes.browser.finish_reply(capability.name(), reply);
        }
    };
    let mut session = match planes.consent.session(&live).await {
        Ok(session) => session,
        Err(error) => {
            let ending = Ending::of_refusal(&error);
            browser_consent::settle_failed(
                &planes.management,
                cingulate_client::card::CardKind::WebsiteAccessInCall,
                &question,
                &ending,
            );
            browser_consent::in_call_refusal(&mut reply, &ending);
            return planes.browser.finish_reply(capability.name(), reply);
        }
    };
    let (id, completion) = match browser_consent::raise(
        &planes.management,
        &planes.consent,
        &live,
        &mut session,
        cingulate_client::card::CardKind::WebsiteAccessInCall,
        &question,
        codemode::active(),
    )
    .await
    {
        Ok(raised) => raised,
        Err(ending) => {
            browser_consent::settle_failed(
                &planes.management,
                cingulate_client::card::CardKind::WebsiteAccessInCall,
                &question,
                &ending,
            );
            browser_consent::in_call_refusal(&mut reply, &ending);
            return planes.browser.finish_reply(capability.name(), reply);
        }
    };
    pending["ask_id"] = json!(id);
    if codemode::active() {
        pending["context"] = reply["context"].clone();
        return planes.browser.finish_reply(capability.name(), pending);
    }
    let mut drain = planes.drain_signal.subscribe();
    let mut draining = false;
    let cancelled = async {
        tokio::select! {
            biased;
            _ = drain.wait_for(|value| *value) => { draining = true; LetGo::Withdraw },
            _ = cancel.cancelled() => if planes.routes.get(request.0, request.1).is_some() && planes.routes.carries_conversation(&facts.identity.conversation_key) { LetGo::Detach } else { LetGo::Withdraw },
        }
    };
    let guard = call_context::ROUTE_GUARD.try_with(Arc::clone).ok();
    let parked = guard.as_ref().map(|guard| guard.park_on_consent());
    let (ending, settled) =
        browser_consent::park(planes, &mut session, &id, completion, park_limit, cancelled).await;
    drop(parked);
    match ending {
        InCall::Settled(_) if matches!(settled, management::BrowserGrantSettlement::Granted(_)) => {
            if !browser_held::can_resume(arguments) || capability.name() == "browser.click_point" {
                return Ok(
                    json!({"outcome":"not_started", "detail":{"consent":"approved","ask_id":id}, "remedy":"Approved; call again to run it."}),
                );
            }
            if let Some(terminal) = TerminalArbiter::current() {
                terminal.track_consent(Arc::clone(&planes.consent), &id);
            }
            authorization::with_standing_caller(
                standing_caller(facts),
                planes.browser.serve(&facts.identity, capability, arguments),
            )
            .await
        }
        InCall::Pending { .. } => {
            pending["context"] = reply["context"].clone();
            planes.browser.finish_reply(capability.name(), pending)
        }
        InCall::Cancelled if !draining => {
            // Stopping the call did not deny permission. Discard the original
            // grant refusal and its ask-again advice so a stopped turn cannot
            // start another consent loop.
            planes.browser.finish_reply(
                capability.name(),
                json!({
                    "outcome": "cancelled", "context": reply["context"],
                }),
            )
        }
        ending => {
            let decision = match &ending {
                InCall::Settled(ending) => {
                    if matches!(
                        settled,
                        management::BrowserGrantSettlement::NotRecorded { .. }
                            | management::BrowserGrantSettlement::UnknownAsk
                    ) {
                        "unavailable"
                    } else {
                        in_call_grant_decision(ending)
                    }
                }
                InCall::Cancelled if draining => "module_draining",
                InCall::Cancelled => "cancelled",
                InCall::RouteClosed => "route_closed",
                InCall::Pending { .. } => unreachable!(),
            };
            reply["detail"]["decision"] = json!(decision);
            if let Some(remedy) = in_call_grant_remedy(decision) {
                reply["remedy"] = json!(remedy);
            }
            planes.browser.finish_reply(capability.name(), reply)
        }
    }
}

/// Use the caller's accepted agent and session scope to resolve its holder.
/// For a flow, only an admitted stamp with `delegates` true identifies the
/// owner's head-agent row; a raw `agent_id` attribute is not authority.
pub(super) fn standing_caller(facts: &AcceptedBindFacts) -> Option<authorization::StandingCaller> {
    permission_scope::authorizing_holder(facts)
        .map(|holder| authorization::StandingCaller { holder })
}

/// Only an admitted primary head may be offered a permanent site grant.
/// Workers and flows must never borrow a head's minting authority.
pub(super) fn standing_offer_agent(facts: &AcceptedBindFacts) -> Option<&str> {
    matches!(
        permission_scope::minting_holder(facts),
        Some(agent_grants::GrantHolder::Head { .. })
    )
    .then_some(facts.identity.agent_project_id.as_str())
}

/// The `detail.decision` a browser action held open on a grant question
/// reports when the question ended without an allowing answer.
///
/// Each ending keeps its own word because each calls for a different next
/// step; reporting a question nobody was shown the same way as one a person
/// ignored would send the caller to wait for an answer that cannot come.
pub(super) fn in_call_grant_decision(ending: &cingulate_client::desk::Ending) -> &'static str {
    browser_consent::word(ending, management::BROWSER_GRANT_DECLINE)
}

/// What the caller should do after each [`in_call_grant_decision`]. It replaces
/// the remedy the `authorization_denied` refusal already carries (open the
/// grant and retry), which is right only for a question a person might still
/// answer. Caller cancellation returns a separate `cancelled` result with no
/// grant remedy. `None` keeps the original remedy for other stop conditions.
pub(super) fn in_call_grant_remedy(decision: &str) -> Option<&'static str> {
    match decision {
        "declined" => Some("the person declined this grant; ask again only if they change their mind"),
        "no_answer" => Some("the person was asked but did not answer in time; retry this action when they are available"),
        "not_put_to_anyone" => Some("the question was shown to no one, and repeating this action puts it to no one either until the caller's consent route can put it to a person"),
        "undeliverable" => Some("the question could not be sent; retry once, and if it fails again the module needs attention"),
        "unrecognized_answer" => Some("the answer was not one this question offered; retry this action to ask again"),
        _ => None,
    }
}

pub(super) async fn handle_browser_control(
    name: &str,
    arguments: &Value,
    accepted: &AcceptedBindFacts,
    planes: &Planes,
) -> Value {
    let clock = planes.lease_clock.as_ref();
    match name {
        browser_session::BROWSER_STATUS => {
            if let Some(invalid) = browser_session::validate_empty_object(arguments) {
                return invalid;
            }
            planes.sessions.status(
                &accepted.identity.conversation_key,
                clock,
                std::time::SystemTime::now(),
            )
        }
        browser_session::BROWSER_CLOSE => {
            let browser_session_id = match browser_session::validate_close(arguments) {
                Ok(id) => id,
                Err(invalid) => return invalid,
            };
            let Some(config) = planes.browser_config.as_ref() else {
                return json!({"outcome":"browser_session_not_found"});
            };
            let sessions = planes.sessions.clone();
            let route = accepted.identity.conversation_key.clone();
            let browser_session_id = browser_session_id.to_owned();
            let config = config.clone();
            let result = match on_call_blocking_pool(move || {
                sessions.close(&route, &browser_session_id, &config)
            })
            .await
            {
                Ok(result) => result,
                Err(_) => return json!({"outcome":"internal_failure"}),
            };
            if result["outcome"] == "closed" {
                planes.browser.end_context(&accepted.identity, false).await;
            }
            result
        }
        browser_session::BROWSER_LAUNCH => {
            if let Some(invalid) = browser_session::validate_empty_object(arguments) {
                return invalid;
            }
            // An admitted route can still carry an empty agent project ID, and
            // login import relaunches bypass the usual tool-call admission check.
            // Refuse before allocating a browser or opening profile storage.
            if accepted.identity.agent_project_id.is_empty() {
                let refusal =
                    cerebellum_core::identity::ControlOperationRefusal::AgentProjectIdUnattested;
                return json!({
                    "outcome": "authorization_denied",
                    "reason": refusal.reason_code(),
                    "remedy": accepted.control_refusal_remedy(refusal),
                });
            }
            if accepted.identity.profile_disposition == ProfileDisposition::None {
                return json!({"outcome": "no_profile", "profile_disposition": "none"});
            }
            let Some(config) = planes.browser_config.as_ref() else {
                return browser_launch_prerequisite(planes.runtime_browser.as_ref())
                    .unwrap_or_else(|| json!({"outcome":"internal_failure"}));
            };
            let browser_session_id = match planes.sessions.acquire_launch_slot_for_profile(
                &accepted.identity.conversation_key,
                (accepted.identity.profile_disposition == ProfileDisposition::Durable)
                    .then_some(accepted.identity.agent_project_id.as_str()),
            ) {
                browser_session::LaunchSlot::Occupied { browser_session_id } => {
                    return json!({
                        "outcome": "browser_session_exists",
                        "browser_session_id": browser_session_id,
                    })
                }
                browser_session::LaunchSlot::Acquired { browser_session_id } => browser_session_id,
                browser_session::LaunchSlot::Refused(refusal) => return refusal,
            };
            let launch = if let Some(refusal) =
                browser_launch_prerequisite(planes.runtime_browser.as_ref())
            {
                Err(refusal)
            } else if let Some(service) = planes.launch_service.clone() {
                let accepted = accepted.clone();
                let id = browser_session_id.clone();
                match tokio::task::spawn_blocking(move || {
                    let holder = accepted
                        .flow_id
                        .as_ref()
                        .map_or_else(cortexkit_resource_busy::Holder::head, |flow_id| {
                            cortexkit_resource_busy::Holder::flow(flow_id.clone())
                        });
                    profile_custody::with_lease_holder(holder, || service.launch(&accepted, &id))
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(json!({"outcome": "internal_failure"})),
                }
            } else if config.executable_path.is_none() {
                Err(json!({"outcome": "executable_missing"}))
            } else if let Some(path) = config
                .executable_path
                .as_ref()
                .filter(|path| !path.is_file())
            {
                Err(json!({"outcome": "executable_missing", "expected_path": path}))
            } else {
                // No launcher exists, and the configuration is correct -- the
                // executable is present and is a file. Every other arm of this
                // chain names something the operator got wrong; this one is
                // reached BECAUSE they got it right, so blaming profile storage
                // sent them to check a disk that was never involved. The build
                // simply has no launcher wired for this platform.
                Err(json!({
                    "outcome": "browser_launch_unsupported",
                    "reason": "this build has no browser launcher for this platform",
                    "platform": std::env::consts::OS,
                }))
            };
            match launch {
                Ok(browser_session::LaunchedBrowser {
                    process,
                    cleanup,
                    executable_identity_checkpoints,
                }) => {
                    let Some((id, lease, cancelled)) = planes.sessions.establish_ready(
                        &accepted.identity.conversation_key,
                        accepted.identity.profile_disposition,
                        config,
                        clock,
                        process,
                        cleanup,
                    ) else {
                        planes
                            .sessions
                            .abandon_launch_slot(&accepted.identity.conversation_key);
                        planes.browser.end_context(&accepted.identity, false).await;
                        return json!({"outcome": "internal_failure"});
                    };
                    if cancelled {
                        let sessions = planes.sessions.clone();
                        let route_key = accepted.identity.conversation_key.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            sessions.wait_until_inactive(&route_key)
                        })
                        .await;
                        planes.browser.end_context(&accepted.identity, false).await;
                        return json!({
                            "outcome": "launch_cancelled",
                            "browser_session_id": id,
                        });
                    }
                    if planes
                        .browser
                        .open_context(accepted.identity.clone())
                        .await
                        .is_err()
                    {
                        let sessions = planes.sessions.clone();
                        let route = accepted.identity.conversation_key.clone();
                        let config = config.clone();
                        if on_call_blocking_pool(move || {
                            sessions.teardown_route(
                                &route,
                                browser_session::BrowserSessionTerminalOutcome::CdpFailure,
                                &config,
                            )
                        })
                        .await
                        .is_err()
                        {
                            return json!({"outcome":"internal_failure"});
                        }
                        let terminal = planes.sessions.status(
                            &accepted.identity.conversation_key,
                            clock,
                            std::time::SystemTime::now(),
                        );
                        return if terminal["outcome"] == "cleanup_failure" {
                            terminal
                        } else {
                            json!({"outcome": "internal_failure"})
                        };
                    }
                    json!({
                        "outcome": "launched",
                        "browser_session_id": id,
                        "profile_disposition": accepted.identity.profile_disposition.as_str(),
                        "executable_identity_checkpoints": executable_identity_checkpoints,
                        "lease": lease.as_json(clock, std::time::SystemTime::now()),
                    })
                }
                Err(outcome) => {
                    planes
                        .sessions
                        .abandon_launch_slot(&accepted.identity.conversation_key);
                    outcome
                }
            }
        }
        _ => json!({"outcome": "internal_failure"}),
    }
}

/// Report the configured executable's state only on the path that starts a
/// browser process. Attached sessions and the Chrome extension do not use it.
fn browser_launch_prerequisite(surface: Option<&BrowserSurface>) -> Option<Value> {
    match surface? {
        BrowserSurface::NotConfigured => Some(json!({
            "outcome":"executable_missing",
            "reason":"Configure browser.executable_path and browser.expected_identity in Cerebellum's settings, then restart the module.",
        })),
        BrowserSurface::Refused(error) => Some(json!({
            "outcome":"identity_unverifiable", "reason_code":error.reason.reason_code(),
            "reason":"Correct the browser executable and its expected identity in Cerebellum's settings, then restart the module.",
        })),
        BrowserSurface::Available(config) => match config.executable_path.as_deref() {
            Some(path) if path.is_file() => None,
            Some(path) => Some(json!({
                "outcome":"executable_missing", "expected_path":path,
                "reason":"Make the configured browser executable available or correct browser.executable_path in Cerebellum's settings.",
            })),
            None => browser_launch_prerequisite(Some(&BrowserSurface::NotConfigured)),
        },
    }
}

pub(super) fn flow_consent_refusal(reason: &str) -> Value {
    json!({"outcome": "consent_unavailable", "detail": {"reason": reason},
        "remedy": "an unattended flow cannot ask a person; configure its owner's standing grants"})
}

pub(super) fn agent_run_consent_refusal() -> Value {
    json!({"outcome":"consent_unavailable", "reason":"agent_run", "detail":{"reason":"agent_run"},
        "remedy":"an agent run cannot ask a person; configure standing grants in an attended session"})
}

/// A scope stamp carrying `flow_id` marks a flow (see `AcceptedBindFacts::flow_id`).
/// Only a route that passes `flow_carrier_admitted` may act for it; every other
/// route carrying such a stamp is refused before capability dispatch.
pub(super) fn session_flow_refusal(facts: &AcceptedBindFacts) -> Option<Value> {
    facts
        .scope
        .as_ref()
        .filter(|stamp| stamp.attributes.flow_id.is_some() && facts.flow_id.is_none())
        .map(|_| {
            json!({
                "outcome": "consent_unavailable",
                "detail": {"reason": "flow_carrier_not_admitted"},
                "remedy": "open the flow route through authorized reserved:basal",
            })
        })
}
