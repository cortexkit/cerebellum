use super::*;
use crate::ability::binding::{BindingEntry, BindingRead, BindingRecord};

pub(super) struct FakeBinding {
    pub calls: AtomicUsize,
    flows: Mutex<Vec<String>>,
    record: Option<BindingRecord>,
    pending: bool,
    started: tokio::sync::Notify,
}

impl FakeBinding {
    pub fn bound() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            flows: Mutex::new(Vec::new()),
            record: Some(BindingRecord {
                install_id: "install-test".into(),
                version: "1.2.3".into(),
                entries: vec![entry(
                    "family_calendar",
                    Token::Calendar,
                    &["bound", "also-bound"],
                )],
                _description: json!({"tokens":[{"token":Token::Calendar.as_str(),"available":false}]}),
            }),
            pending: false,
            started: tokio::sync::Notify::new(),
        }
    }
}

fn entry(key: &str, token: Token, ids: &[&str]) -> BindingEntry {
    BindingEntry {
        key: key.into(),
        token,
        ids: ids.iter().map(|id| (*id).into()).collect(),
    }
}

impl BindingReader for FakeBinding {
    fn read<'a>(&'a self, flow_id: &'a str) -> BindingRead<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.flows.lock().unwrap().push(flow_id.to_owned());
            self.started.notify_one();
            if self.pending {
                std::future::pending::<()>().await;
            }
            self.record.clone().ok_or(())
        })
    }
}

pub(super) fn fixture_with_binding(
    reader: Arc<dyn BindingReader>,
    platform: Platform,
) -> (Planes, Arc<FakeStatus>) {
    let source = Arc::new(FakeStatus::default());
    let mut planes = fixture(source.clone(), platform);
    Arc::get_mut(&mut planes.management)
        .unwrap()
        .abilities
        .binding = reader;
    (planes, source)
}

#[tokio::test(start_paused = true)]
async fn binding_selects_one_key_token_and_scope_never_a_token_union() {
    let mut fake = FakeBinding::bound();
    let record = fake.record.as_mut().unwrap();
    record.entries.push(entry(
        "work_calendar",
        Token::Calendar,
        &["other-entry-only"],
    ));
    record
        .entries
        .push(entry("contacts", Token::Contacts, &["bound"]));
    let reader = Arc::new(fake);
    let (planes, source) = fixture_with_binding(reader.clone(), Platform::MacOs);
    let before = planes.browser.journal_export_for_test().await;
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap();
    let holder = unit
        .arrive(Arc::new(TerminalArbiter::new(request(
            json!({"method": CALL}),
        ))))
        .unwrap()
        .wait()
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    let mut previous = None;
    for (key, ids) in [
        ("family_calendar", vec!["bound", "outside"]),
        ("missing-key", vec!["bound"]),
        ("contacts", vec!["bound"]),
        ("family_calendar", vec!["other-entry-only"]),
    ] {
        let mut p = valid_params(CALL);
        p["key"] = json!(key);
        p["scope"] = json!({"calendar":ids});
        let reply = exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await;
        assert_refusal(&reply, "ability_out_of_scope");
        if let Some(bytes) = previous {
            assert_eq!(reply.body, bytes);
        }
        previous = Some(reply.body);
        assert!(
            unit.has_users_for_test(1),
            "binding refusal entered the queue"
        );
    }
    assert_eq!(
        tokio::time::Instant::now(),
        start,
        "binding refusal waited for the unit"
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), 4);
    assert_eq!(*reader.flows.lock().unwrap(), vec!["flow-test"; 4]);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
    drop(holder);
}

#[tokio::test(start_paused = true)]
async fn bound_subset_with_unavailable_description_reaches_the_source_unit() {
    let reader = Arc::new(FakeBinding::bound());
    let (planes, source) = fixture_with_binding(reader.clone(), Platform::MacOs);
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap();
    let holder = unit
        .arrive(Arc::new(TerminalArbiter::new(request(
            json!({"method": CALL}),
        ))))
        .unwrap()
        .wait()
        .await
        .unwrap();
    let route = flow();
    let run = exchange(
        &planes,
        &route,
        json!({"method":CALL,"params":valid_params(CALL)}),
    );
    tokio::pin!(run);
    tokio::select! {
        biased;
        _ = &mut run => panic!("authorized call did not wait for its source unit"),
        _ = reader.started.notified() => {}
    }
    assert!(
        unit.has_users_for_test(2),
        "authorized call never entered its unit queue"
    );
    drop(holder);
    assert_refusal(&run.await, "ability_source_failed");
    assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        source.calls.load(Ordering::SeqCst),
        1,
        "authorized call must preflight after reserving"
    );
}

#[tokio::test(start_paused = true)]
async fn binding_failures_and_phase_deadline_fail_closed_before_the_unit() {
    for pending in [false, true] {
        let mut fake = FakeBinding::bound();
        fake.record = None;
        fake.pending = pending;
        let reader = Arc::new(fake);
        let (planes, source) = fixture_with_binding(reader.clone(), Platform::MacOs);
        let before = planes.browser.journal_export_for_test().await;
        let unit = planes
            .management
            .abilities
            .units
            .for_token(Token::Calendar)
            .unwrap();
        let holder = unit
            .arrive(Arc::new(TerminalArbiter::new(request(
                json!({"method": CALL}),
            ))))
            .unwrap()
            .wait()
            .await
            .unwrap();
        let start = tokio::time::Instant::now();
        let reply = exchange(
            &planes,
            &flow(),
            json!({"method":CALL,"params":valid_params(CALL)}),
        )
        .await;
        assert_refusal(&reply, "ability_binding_unavailable");
        assert_eq!(
            start.elapsed(),
            std::time::Duration::from_secs(if pending { 10 } else { 0 })
        );
        assert!(unit.has_users_for_test(1));
        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        assert_eq!(planes.browser.journal_export_for_test().await, before);
        drop(holder);
    }
}

#[tokio::test]
async fn binding_projection_preserves_install_provenance_for_the_journal_boundary() {
    let reader = FakeBinding::bound();
    let scope = validate_scope(Token::Calendar, &json!({"calendar":["bound"]})).unwrap();
    let terminal = Arc::new(TerminalArbiter::new(request(json!({"method": CALL}))));
    let install = binding::authorize(
        &reader,
        "stamped-flow",
        "family_calendar",
        &scope,
        &terminal,
    )
    .await
    .unwrap_or_else(|_| panic!("bound record refused"))
    .unwrap();
    assert_eq!(install, ("install-test".to_owned(), "1.2.3".to_owned()));
    assert_eq!(*reader.flows.lock().unwrap(), ["stamped-flow"]);
}

#[tokio::test(start_paused = true)]
async fn stopped_binding_waits_leave_no_queue_entry_and_keep_each_arbiter_cause() {
    use crate::terminal_arbiter::{run_arbitrated_route, TerminalCause};
    use std::time::Duration;
    for (cause, expected) in [
        (TerminalCause::Cancelled, "cancelled"),
        (TerminalCause::RouteClosed, "route_closed"),
        (TerminalCause::Draining, "module_draining"),
        (TerminalCause::Deadline, "action_deadline_exceeded"),
    ] {
        let mut fake = FakeBinding::bound();
        fake.pending = true;
        let reader = Arc::new(fake);
        let (planes, source) = fixture_with_binding(reader.clone(), Platform::MacOs);
        planes.routes.insert(19, 1, flow());
        let before = planes.browser.journal_export_for_test().await;
        let frame = request(json!({"method":CALL,"params":valid_params(CALL)}));
        let terminal = Arc::new(TerminalArbiter::new(frame.clone()));
        let unit = planes
            .management
            .abilities
            .units
            .for_token(Token::Calendar)
            .unwrap();
        let holder = unit
            .arrive(Arc::new(TerminalArbiter::new(frame.clone())))
            .unwrap()
            .wait()
            .await
            .unwrap();
        let (proxy, outgoing) = tokio::sync::mpsc::channel(8);
        let (writer, mut rx) = tokio::sync::mpsc::channel(8);
        let worker_planes = planes.clone();
        let worker = async move {
            crate::handle_management_request(frame, &proxy, &flow(), &worker_planes).await
        };
        let cancellation = planes.cancellations.register((19, 1, 7));
        let guard = Arc::new(planes.health.enter_request());
        let now = tokio::time::Instant::now();
        // A short envelope exercises the arbiter's deadline while the binding
        // phase is still live; normal envelopes leave room for the whole phase.
        let envelope = now
            + Duration::from_secs(if matches!(cause, TerminalCause::Deadline) {
                1
            } else {
                60
            });
        let arbitration = tokio::spawn(run_arbitrated_route(
            worker,
            outgoing,
            writer,
            planes.clone(),
            cancellation,
            guard,
            terminal.clone(),
            envelope,
            now + Duration::from_secs(120),
        ));
        reader.started.notified().await;
        assert!(
            unit.has_users_for_test(1),
            "binding wait entered the source queue"
        );
        if matches!(cause, TerminalCause::Deadline) {
            tokio::time::advance(Duration::from_secs(1)).await;
        } else {
            assert!(terminal.stop(cause));
        }
        if matches!(cause, TerminalCause::RouteClosed) {
            assert!(rx.recv().await.is_none(), "closed route received a frame");
        } else {
            let response = rx.recv().await.unwrap();
            assert_eq!(body(&response)["outcome"], expected);
        }
        {
            let state = terminal.state.lock().unwrap();
            assert_eq!(body(state.chosen.as_ref().unwrap())["outcome"], expected);
            assert!(
                !state.possibly_dispatched,
                "ability handler marked a mutation"
            );
        }
        arbitration.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while planes.health.detached_workers() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("binding wait did not observe the stop within one second");
        assert!(
            unit.has_users_for_test(1),
            "stopped binding wait left a unit ticket"
        );
        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        assert_eq!(planes.browser.journal_export_for_test().await, before);
        assert!(
            rx.try_recv().is_err(),
            "handler sent another terminal reply"
        );
        drop(holder);
    }
}
