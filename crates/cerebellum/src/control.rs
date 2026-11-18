use super::*;

/// Accepted bind facts retained for the lifetime of a route.
///
/// This is an in-memory route table, not a profile registry or storage layer.
/// It lets data-plane frames inherit the identity and effective scope that the
/// daemon accepted on `route.bind`.
#[derive(Clone, Default)]
pub struct RouteBindings {
    pub(super) inner: Arc<RwLock<HashMap<(u16, u32), AcceptedBindFacts>>>,
    pub(super) removed: Arc<tokio::sync::Notify>,
    /// When each bound route's bind was accepted, as a sequence number that
    /// only grows. Re-recording an already-bound route's facts keeps its
    /// place. Writers lock `inner` before this; `bind_sequence` locks this
    /// alone or while `inner` is held, never the other way round.
    pub(super) bind_order: Arc<std::sync::Mutex<BindOrder>>,
    pub(super) display: Arc<tool_display::Records>,
}

#[derive(Default)]
pub(super) struct BindOrder {
    next: u64,
    sequence: HashMap<(u16, u32), u64>,
}

impl RouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn insert(&self, channel: u16, epoch: u32, facts: AcceptedBindFacts) {
        if let Ok(mut routes) = self.inner.write() {
            routes.insert((channel, epoch), facts);
            let mut order = self
                .bind_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let next = order.next;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                order.sequence.entry((channel, epoch))
            {
                entry.insert(next);
                order.next += 1;
            }
        }
    }

    /// The order in which this route's bind was accepted among all routes
    /// bound now or before; lower is older.
    pub(super) fn bind_sequence(&self, channel: u16, epoch: u32) -> Option<u64> {
        self.bind_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sequence
            .get(&(channel, epoch))
            .copied()
    }

    pub(super) fn get(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        self.inner
            .read()
            .ok()
            .and_then(|routes| routes.get(&(channel, epoch)).cloned())
    }

    /// Return the facts recorded when this route was bound, unchanged.
    #[doc(hidden)]
    pub fn accepted_bind_for_test(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        self.get(channel, epoch)
    }

    /// Record a route's facts without a control bind, for fixtures that need a
    /// head or run route under an exact scope the control path would have to
    /// mint first.
    #[doc(hidden)]
    pub fn insert_for_test(&self, channel: u16, epoch: u32, facts: AcceptedBindFacts) {
        self.insert(channel, epoch, facts);
    }

    /// Every route's scope stamp, for fixtures that must see what a union
    /// walks.
    #[doc(hidden)]
    pub fn scope_stamps_for_test(&self) -> Vec<subc_protocol::scope::ScopeStamp> {
        self.inner
            .read()
            .unwrap()
            .values()
            .filter_map(|facts| facts.scope.clone())
            .collect()
    }

    pub(super) fn remove(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        let facts = self.inner.write().ok().and_then(|mut routes| {
            self.bind_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sequence
                .remove(&(channel, epoch));
            routes.remove(&(channel, epoch))
        });
        self.removed.notify_waiters();
        facts
    }

    pub(super) async fn closed(&self, channel: u16, epoch: u32) {
        loop {
            let removed = self.removed.notified();
            tokio::pin!(removed);
            // Subscribe before checking so an unbind between the check and the
            // wait cannot leave a detached grant question alive on a dead route.
            removed.as_mut().enable();
            if self.get(channel, epoch).is_none() {
                return;
            }
            removed.await;
        }
    }

    /// Whether any bound route carries this conversation. Two routes may carry
    /// one conversation, so a conversation ends only when its last route does.
    pub(super) fn carries_conversation(&self, conversation_key: &str) -> bool {
        self.inner.read().ok().is_some_and(|routes| {
            routes
                .values()
                .any(|facts| facts.identity.conversation_key == conversation_key)
        })
    }

    /// Whether any bound route was stamped with this session scope.
    pub(super) fn carries_scope(&self, key: &scope_watch::ScopeKey) -> bool {
        !self.conversations_under_scope(key).is_empty()
    }

    /// The conversations of the bound routes stamped with this session scope.
    pub(super) fn conversations_under_scope(
        &self,
        key: &scope_watch::ScopeKey,
    ) -> std::collections::BTreeSet<String> {
        self.inner
            .read()
            .map(|routes| {
                routes
                    .values()
                    .filter(|facts| facts.scope.as_ref().is_some_and(|stamp| key.names(stamp)))
                    .map(|facts| facts.identity.conversation_key.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Exact head-scope routes whose person-browser state ends with that scope.
    pub(super) fn user_browser_head_routes_under_scope(
        &self,
        key: &scope_watch::ScopeKey,
    ) -> Vec<user_browser_bridge::Route> {
        self.inner
            .read()
            .expect("route bindings lock poisoned")
            .iter()
            .filter(|(_, facts)| {
                facts.scope.as_ref().is_some_and(|stamp| {
                    stamp.kind == subc_protocol::scope::ScopeKind::Head && key.names(stamp)
                })
            })
            .map(|(&(channel, epoch), _)| user_browser_bridge::Route { channel, epoch })
            .collect()
    }
}

pub(super) async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
    call_record_workers: Option<&CallRecordWorkers>,
    private_content: Option<&private_content::PrivateContent>,
) -> Result<(), ModuleError> {
    let request = match serde_json::from_slice::<ModuleControlRequest>(&frame.body) {
        Ok(request) => request,
        // A control body this build does not recognise is answered on the
        // control channel and the loop goes on. Propagating the parse error
        // would end `module_loop`, which turns every future daemon-side
        // control op (a drain notice, for one) into an instant module exit,
        // the opposite of what an advisory notice asks for.
        Err(error) => {
            let frame = build_error_frame(
                frame.header.ver,
                0,
                0,
                frame.header.corr,
                "unknown_control_op",
                &format!("cerebellum does not recognise this control request: {error}"),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            return send(writer, frame).await;
        }
    };
    let response_body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            identity,
            admission_facts,
            consumer_capabilities,
            target,
            scope,
            // Cerebellum declares no versioned roles today.
            role_versions: _,
            call_mode,
        } => {
            // Basal needs verified flow delegation or a resolved codemode head.
            // Cingulate may bind only to
            // this module's management surface, where its calls are limited to
            // permissions.list/revoke before any grant lookup. Neither needs
            // the unrelated powers that first-party membership would confer.
            let trust = trust_for_principal(&principal);
            // First-party binds are admitted without it, and they are the busiest
            // binders, so they must not drive catalog re-reads.
            let view_reader = !trust.is_first_party()
                && route_bindings
                    .display
                    .admits_view_reader(principal.as_ref(), &target)
                    .await;
            if matches!(principal, Some(subc_protocol::Principal::Reserved { .. }))
                && scope
                    .as_ref()
                    .is_some_and(|stamp| Some(&stamp.owner) != principal.as_ref())
            {
                let _ = route_bindings.display.declarers().await;
            }
            if private_content::is_broca(&principal)
                && !private_content::bind_admitted(&principal, &target)
            {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }
            let mode = call_mode
                .clone()
                .unwrap_or(subc_protocol::call_mode::CallMode::Classic);
            let run_candidate = scope.as_ref().is_some_and(|stamp| {
                cerebellum_core::identity::codemode_carrier_candidate(stamp, &principal, &mode)
            });
            if !trust.is_first_party()
                && !run_candidate
                && !scope.as_ref().is_some_and(|stamp| {
                    cerebellum_core::identity::flow_carrier_admitted(stamp, &principal)
                })
                && !permissions::bind_admitted(&principal, &target)
                && !private_content::bind_admitted(&principal, &target)
                && !crate::agent_data::bind_admitted(&principal, &target)
                && !view_reader
            {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }

            // A capability scope stamped where it is no longer read would, if
            // ignored, leave the route with the permissive default scope. Refuse
            // the bind and bind nothing, so the route serves no request at all.
            if let Some(refusal) =
                AcceptedBindFacts::admission_facts_refusal(admission_facts.as_ref()).or_else(|| {
                    AcceptedBindFacts::scope_facts_refusal(
                        &principal,
                        scope.as_ref(),
                        admission_facts.as_ref(),
                    )
                })
            {
                let body = serde_json::to_vec(&subc_protocol::ErrorBody {
                    code: refusal.reason_code().to_string(),
                    message: refusal.message(),
                    detail: Some(refusal.detail()),
                })
                .map_err(ModuleError::Json)?;
                let frame = Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Error,
                    control_flags(),
                    0,
                    0,
                    frame.header.corr,
                    body,
                )
                .map_err(|e| ModuleError::Message(e.to_string()))?;
                return send(writer, frame).await;
            }

            let head = if run_candidate {
                match route_bindings.run_head(scope.as_ref().expect("run candidate has a scope")) {
                    Ok(head) => Some(head),
                    Err(refusal) => {
                        return send_route_error(
                            writer,
                            frame.header.ver,
                            0,
                            0,
                            frame.header.corr,
                            refusal.code(),
                            refusal.message(),
                        )
                        .await
                    }
                }
            } else {
                None
            };
            // Retain only facts from the accepted bind. Data-plane frames inherit
            // these facts by (channel, epoch); request bodies cannot replace them.
            let mut accepted_facts = AcceptedBindFacts::from_bind(
                &identity,
                principal.clone(),
                admission_facts.as_ref(),
                consumer_capabilities.as_deref(),
                &target,
            )
            // An authorized orchestrator scope stamp supplies identity and
            // delegation. Retaining it also lets call records name the scope
            // and lets its owner withdraw calls when the scope is revoked.
            .with_scope(scope);
            accepted_facts.call_mode =
                call_mode.unwrap_or(subc_protocol::call_mode::CallMode::Classic);
            if let Some(head) = head {
                accepted_facts = accepted_facts.with_codemode_head(&head);
            }
            route_bindings.insert(route_channel, epoch, accepted_facts);
            // Accept the bind — capability scope is checked at dispatch time.
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // Insulated health-v2 lane: the report is a mechanical mapper over
            // atomics stamped by the dispatch path. It never blocks on a lock
            // and never forms its own opinion (Health-Path-Rule-v2).
            let mut report = with_process_gauges(health_state.report());
            if let ModuleControlResponse::HealthCheck {
                metrics: Some(Value::Object(metrics)),
                ..
            } = &mut report
            {
                metrics.insert("toolDisplay".into(), route_bindings.display.metrics());
                metrics.insert(
                    "privateContentStore".into(),
                    json!(private_content.map_or("not_opened", |store| store.health())),
                );
            }
            let mut report = match call_record_workers {
                Some(workers) => workers.health_report(report),
                None => report,
            };
            if let ModuleControlResponse::HealthCheck {
                metrics: Some(Value::Object(metrics)),
                ..
            } = &mut report
            {
                let records = metrics
                    .get("detachedCallRecordWorkers")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let workers = metrics
                    .get("detachedWorkers")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                metrics.insert("detachedWorkers".into(), json!(workers + records));
            }
            report
        }
    };
    let body = serde_json::to_vec(&response_body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        frame.header.ver,
        FrameType::Response,
        control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

/// Send the pinned transport rejection for an ineligible principal.
async fn send_principal_denied(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    corr: u64,
    principal: &Option<subc_protocol::Principal>,
) -> Result<(), ModuleError> {
    let label = principal_label(principal);
    let frame = build_error_frame(
        ver,
        0,
        0,
        corr,
        "principal_denied",
        &format!(
            "cerebellum capabilities are first-party only; principal '{label}' is not eligible"
        ),
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

/// Add the process-wide gauges to a health reply:
///
/// - `crashReportLeftovers: {removed, failed}`, counts of crash-report
///   directories removed or left behind when no session was available to report
///   them. These directories can contain page memory from signed-in sessions;
/// - `privateStateTightenFailures`, the number of state directories or files
///   whose owner-only mode could not be enforced at startup;
/// - `engramCatalogWriteFailures`, the number of startup attempts to write the
///   backup catalog (`engram-catalog.json`) that failed;
/// - `auditReservationCleanupFailures`, unused computer reservations whose Drop
///   cleanup failed to durably close their journal row;
/// - `lateFrontingJournalFailures`, late focus-cleanup records that could not
///   be persisted;
/// - on macOS, `previewCaptureRequests` and `previewFramesWritten`, how many
///   capture requests the background-mode preview has made and how many frame
///   lines it has written to the agent-cursor helper since the process
///   started, so an idle preview can be seen to cost nothing;
/// - on macOS, `cursorHelperBinaryUnavailable`, whether the helper's executable
///   could not be captured or verified against the module's startup executable;
/// - on macOS, `previewNoFrameReasons` counts terminal capture or delivery
///   losses by stage; `previewCaptureWaitTimeouts` counts expired waits even
///   if a frame arrives late, and `previewShowEnqueueDrops` counts show or
///   retarget messages that could not be queued for the helper;
/// - on macOS, `cursorHelperStartOutcomes`, `cursorHelperLastStartFailure`,
///   `cursorHelperExitReasons`, `cursorHelperLastWaitStatus`,
///   `cursorHelperReplyReaderDisconnects`, and `cursorHelperPid` distinguish
///   an unavailable helper from a refused capture or failed frame write;
/// - `turnEndedReceived`, `turnEndedRefused`, and `turnEndedMatchedBadge`, the
///   process-lifetime counts for the quiet `session.turn_ended` adapter, plus
///   `turnEndedLastAtMs`, its last admitted event timestamp or `null`;
/// - on macOS, the live turn-hint subscription's process-lifetime counts:
///   `turnHintSubscriptionsOpened`, `turnHintOpenFailures`,
///   `turnHintSubscriptionsClosed`, `turnHintNoticesReceived` and
///   `turnHintBadgesEnded`, plus `turnHintActiveBadges` (visible cursor badges
///   or previews), `turnHintSubscriptionOpen`, and `turnHintLastOpenFailureReason`
///   (`timeout`, `unavailable`, or `null` before the first failure);
///   `turnHintBrocaEventsReceived`, `turnHintBrocaMissingSession`, and
///   `turnHintBrocaEventsMatched` count Broca run events, events without a plain
///   session header, and end events that hid at least one badge or preview;
/// - `userBrowserConnections` and `userBrowserDisconnects`, how many Chrome
///   extension native-host connections were accepted (after the host's hello
///   was verified) and how many of them ended; `userBrowserConnectedAtMs` and
///   `userBrowserDisconnectedAtMs`, the wall-clock milliseconds of the latest
///   of each or `null`; and `userBrowserLastDisconnectReason`, one word from
///   [`user_browser_bridge::DISCONNECT_REASONS`] for the latest end or `null`;
/// - `sigtermListener`, whether SIGTERM will run the module's teardown or
///   just end the process (see [`sigterm_listener_state`]);
/// - `computerGrantStore`, whether the operator's "always allow" app grants are
///   in force, or withheld because their store could not be read;
/// - `openAppLaunchHistory`, whether optional timing history is available or
///   launches are using default waits after a read or write failure;
/// - `hardwareInputObserver`, whether the
///   timestamp-only hardware observer is running and how often it recovered
///   from a disabled tap. Reading health never starts the observer.
/// - `frontingLockHeldForUnsettledRelease`, how many fronting locks are kept
///   because a held key's release had not settled when its call replied
///   (`count`), and since when the oldest has been held (`oldest_since_ms`,
///   wall-clock milliseconds, or `null`). Such a lock has no time bound: it
///   is released only when that release settles, so a nonzero count that
///   stays is a stuck release, and no app is brought forward meanwhile.
/// - `pictureReadsPastLifetime`, fronted picture reads that outlived their
///   lifetime (`PICTURE_READ_LIFETIME_MS`) and had their fronting lock
///   released as for a timed-out read: how many have still not returned
///   (`still_running`) and how many there have been since the module
///   started (`total`).
///
/// Counters are atomic and none changes the status. The helper PID, when
/// present, is checked against the OS process-start time without waiting on
/// its transport.
pub(super) fn with_process_gauges(mut report: ModuleControlResponse) -> ModuleControlResponse {
    if let ModuleControlResponse::HealthCheck {
        metrics: Some(serde_json::Value::Object(metrics)),
        ..
    } = &mut report
    {
        let counts = browser_crash_reports::leftover_counts();
        metrics.insert(
            "auditReservationCleanupFailures".into(),
            json!(cerebellum_computer::audit::audit_reservation_cleanup_failures()),
        );
        metrics.insert(
            "lateFrontingJournalFailures".into(),
            json!(computer_capability::late_fronting_journal_failures()),
        );
        #[cfg(target_os = "macos")]
        {
            metrics.insert(
                "cursorHelperBinaryUnavailable".into(),
                json!(computer_capability::cursor::helper_binary_unavailable()),
            );
            metrics.insert(
                "cursorAvatarMalformedRows".into(),
                json!(computer_capability::cursor::avatar::malformed_rows()),
            );
            metrics.insert(
                "cursorAvatarReadRefusals".into(),
                json!(computer_capability::cursor::avatar::read_refusals()),
            );
            metrics.insert(
                "previewCaptureRequests".into(),
                json!(computer_capability::preview_capture_requests()),
            );
            metrics.insert(
                "previewFramesWritten".into(),
                json!(computer_capability::preview_frames_written()),
            );
            for report in [
                computer_capability::preview_diagnostics(),
                computer_capability::cursor::helper_health(),
            ] {
                if let serde_json::Value::Object(fields) = report {
                    metrics.extend(fields);
                }
            }
        }
        metrics.insert(
            "privateStateTightenFailures".to_string(),
            serde_json::Value::from(
                PRIVATE_STATE_TIGHTEN_FAILURES.load(std::sync::atomic::Ordering::Relaxed),
            ),
        );
        metrics.insert(
            "engramCatalogWriteFailures".to_string(),
            serde_json::Value::from(
                ENGRAM_CATALOG_WRITE_FAILURES.load(std::sync::atomic::Ordering::Relaxed),
            ),
        );
        metrics.insert(
            "turnEndedReceived".into(),
            json!(TURN_ENDED_RECEIVED.load(std::sync::atomic::Ordering::Relaxed)),
        );
        metrics.insert(
            "turnEndedRefused".into(),
            json!(TURN_ENDED_REFUSED.load(std::sync::atomic::Ordering::Relaxed)),
        );
        metrics.insert(
            "turnEndedMatchedBadge".into(),
            json!(TURN_ENDED_MATCHED_BADGE.load(std::sync::atomic::Ordering::Relaxed)),
        );
        let last_at_ms = if TURN_ENDED_HAS_LAST_AT_MS.load(std::sync::atomic::Ordering::Acquire) {
            json!(TURN_ENDED_LAST_AT_MS.load(std::sync::atomic::Ordering::Relaxed))
        } else {
            Value::Null
        };
        metrics.insert("turnEndedLastAtMs".into(), last_at_ms);
        USER_BROWSER_CONNECTION_GAUGES.insert_into(metrics);
        event_publish::gauges().insert_into(metrics);
        #[cfg(any(target_os = "macos", test))]
        crate::turn_hints::HINT_GAUGES.insert_into(metrics);
        metrics.insert(
            "crashReportLeftovers".to_string(),
            serde_json::json!({"removed": counts.removed, "failed": counts.failed}),
        );
        metrics.insert(
            "sigtermListener".to_string(),
            serde_json::Value::from(sigterm_listener_state()),
        );
        metrics.insert(
            "computerGrantStore".to_string(),
            serde_json::Value::from(computer_grants::durable_grant_store_health()),
        );
        metrics.insert(
            "openAppLaunchHistory".to_string(),
            serde_json::Value::from(open_app_history::durable_history_health()),
        );
        #[cfg(target_os = "macos")]
        let observer = {
            let health = cerebellum_macos::SessionEventTap::hardware_observer_health();
            json!({
                "state": health.state,
                "disabled_reenabled_count": health.disabled_reenabled_count,
                "install_failure_count": health.install_failure_count,
                "coverage_gap_count": health.coverage_gap_count,
                "last_problem": health.last_problem,
            })
        };
        #[cfg(not(target_os = "macos"))]
        let observer = json!({
            "state": "platform_unsupported",
            "disabled_reenabled_count": 0,
            "install_failure_count": 0,
            "coverage_gap_count": 0,
            "last_problem": Value::Null,
        });
        metrics.insert("hardwareInputObserver".to_string(), observer);
        let (count, oldest_since_ms) = crate::terminal_arbiter::unsettled_release_fronting_locks();
        metrics.insert(
            "frontingLockHeldForUnsettledRelease".to_string(),
            json!({"count": count, "oldest_since_ms": oldest_since_ms}),
        );
        let (stalled, stalled_total) = crate::terminal_arbiter::stalled_picture_reads();
        metrics.insert(
            "pictureReadsPastLifetime".to_string(),
            json!({"still_running": stalled, "total": stalled_total}),
        );
        metrics.insert(
            "frontingPreviousBindFailed".to_string(),
            json!(crate::terminal_arbiter::restore_preparation::previous_bind_failures()),
        );
        metrics.insert(
            "frontingRestoreExpiredAtWrite".to_string(),
            json!(crate::terminal_arbiter::restore_preparation::expired_writes()),
        );
        metrics.insert(
            "frontingRestoreExpiredAtWriteOsDelay".to_string(),
            json!(crate::terminal_arbiter::restore_preparation::expired_os_delay()),
        );
        metrics.insert(
            "frontingRestoreExpiredAtWriteInternal".to_string(),
            json!(crate::terminal_arbiter::restore_preparation::expired_internal()),
        );
    }
    report
}
