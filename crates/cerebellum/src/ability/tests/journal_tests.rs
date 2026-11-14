use super::*;
use crate::terminal_arbiter::TerminalCause;

async fn entries(planes: &Planes) -> Vec<Value> {
    planes
        .browser
        .journal_export_for_test()
        .await
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

async fn active(planes: &Planes) -> usize {
    planes
        .browser
        .with_ability_journal(|store| {
            Ok(store.map_or(0, |s| s.status().active_reservation_count as usize))
        })
        .await
        .unwrap()
}

async fn fault(planes: &Planes, point: &str, count: usize) {
    planes
        .browser
        .with_ability_journal(|store| {
            store.unwrap().faults.arm(point, count);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn entries_pin_the_fixed_policy_shape_identity_binding_and_counts() {
    let (planes, _) = setup(
        Data {
            items: vec![item(Token::Calendar, "item-secret", "bound")],
            choices: vec![ScopeChoice {
                id: "choice-secret".into(),
                label: "label-secret".into(),
                kind: None,
            }],
            ..Default::default()
        },
        Platform::MacOs,
    );
    let route = flow();
    assert!(route.identity.agent_project_id.is_empty());
    let reply = exchange(&planes, &route, list(Token::Calendar, 100)).await;
    assert_eq!(body(&reply)["items"].as_array().unwrap().len(), 1);
    let row = &entries(&planes).await[0];
    assert_eq!(row["phase"], "dispatched");
    assert!(row["capability"].is_null());
    assert!(row["outcome"].is_null());
    let identity = crate::journal::JournalIdentity {
        principal: crate::principal_label(&route.principal),
        ..crate::browser::journal_identity(&route.identity)
    };
    assert_eq!(row["identity"], serde_json::to_value(identity).unwrap());
    assert_eq!(
        row["detail"],
        json!({
            "event":CALL, "token":Token::Calendar.as_str(), "op":"events.list",
            "key":format!("{}-first", Token::Calendar.as_str()),
            "flow_id":"flow-test", "run_id":null, "install_id":"install", "install_version":"1",
            "bound_count":1, "bound_ids":["bound"], "outcome":"ok", "item_count":1
        })
    );
    reserved(&planes, json!({"method":SCOPE_CHOICES,"params":{"token":Token::Calendar.as_str(),"key":"calendar"}})).await;
    let rows = entries(&planes).await;
    assert_eq!(
        rows[1]["detail"],
        json!({
            "event":SCOPE_CHOICES, "token":Token::Calendar.as_str(), "op":null, "key":"calendar",
            "flow_id":null,"run_id":null,"install_id":null,"install_version":null,
            "bound_count":null,"bound_ids":null,"outcome":"ok","item_count":1
        })
    );
    let before = planes.browser.journal_export_for_test().await;
    exchange(&planes, &route, json!({"method":DESCRIBE})).await;
    assert_eq!(planes.browser.journal_export_for_test().await, before);
    assert_eq!(active(&planes).await, 0);
}

struct ExactBinding(Vec<String>);
impl BindingReader for ExactBinding {
    fn read<'a>(&'a self, _: &'a str) -> BindingRead<'a> {
        Box::pin(async move {
            Ok(BindingRecord {
                install_id: "selected-install".into(),
                version: "9.8.7".into(),
                _description: Value::Null,
                entries: Platform::MacOs
                    .tokens()
                    .iter()
                    .map(|&token| BindingEntry {
                        key: format!("{}-first", token.as_str()),
                        token,
                        ids: self.0.iter().cloned().collect(),
                    })
                    .collect(),
            })
        })
    }
}

#[tokio::test]
async fn bound_ids_are_mac_container_only_and_never_exceed_sixteen_kib() {
    let ids: Vec<_> = (0..64)
        .map(|i| format!("{i:02}{}", "x".repeat(2046)))
        .collect();
    let (mut planes, _) = setup(
        Data {
            containers: ids.iter().cloned().collect(),
            ..Default::default()
        },
        Platform::MacOs,
    );
    Arc::get_mut(&mut planes.management)
        .unwrap()
        .abilities
        .binding = Arc::new(ExactBinding(ids.clone()));
    let mut request = list(Token::Calendar, 100);
    request["params"]["scope"]["calendar"] = json!(ids);
    assert_eq!(body(&reserved(&planes, request).await)["items"], json!([]));
    let rows = entries(&planes).await;
    assert_eq!(rows[0]["detail"]["bound_count"], 64);
    assert!(rows[0]["detail"]["bound_ids"].is_null());
    assert_eq!(rows[0]["detail"]["install_id"], "selected-install");
    assert_eq!(rows[0]["detail"]["install_version"], "9.8.7");
    assert_eq!(active(&planes).await, 0);
}

#[tokio::test]
async fn planted_content_and_private_container_ids_never_reach_entries() {
    const MARKER: &str = "PLANTED-PRIVATE-MARKER";
    for platform in [Platform::MacOs, Platform::Windows, Platform::Linux] {
        for &token in platform.tokens() {
            let private_bound =
                platform != Platform::MacOs || matches!(token, Token::Messages | Token::Mail);
            let id = if private_bound { MARKER } else { "bound" };
            let mut value = item(token, MARKER, id);
            match &mut value {
                Item::Event(v) => {
                    v.title = Some(MARKER.into());
                    v.notes = Some(MARKER.into());
                }
                Item::Reminder(v) => {
                    v.title = Some(MARKER.into());
                    v.notes = Some(MARKER.into());
                }
                Item::Contact(v) => {
                    v.given_name = Some(MARKER.into());
                    v.emails = vec![LabeledValue {
                        label: Some(MARKER.into()),
                        value: MARKER.into(),
                    }];
                }
                Item::Message(v) => {
                    v.text = Some(MARKER.into());
                    v.text_state = TextState::Ok;
                }
                Item::MailSummary(v) => v.subject = Some(MARKER.into()),
                _ => unreachable!(),
            }
            let (mut planes, _) = setup(
                Data {
                    items: vec![value],
                    containers: [id.to_owned()].into(),
                    choices: vec![ScopeChoice {
                        id: MARKER.into(),
                        label: MARKER.into(),
                        kind: (token == Token::Contacts).then_some(GroupKind::Group),
                    }],
                    ..Default::default()
                },
                platform,
            );
            Arc::get_mut(&mut planes.management)
                .unwrap()
                .abilities
                .binding = Arc::new(ExactBinding(vec![id.into()]));
            let mut request = list(token, 100);
            request["params"]["scope"][token.info().scope_key] = json!([id]);
            if matches!(token, Token::Messages | Token::Mail) {
                request["params"]["args"][token.info().scope_key] = json!(id);
            }
            let reply = reserved(&planes, request).await;
            assert!(
                body(&reply)["items"]
                    .as_array()
                    .is_some_and(|v| v.len() == 1),
                "{}",
                body(&reply)
            );
            let choices=reserved(&planes,json!({"method":SCOPE_CHOICES,"params":{"token":token.as_str(),"key":token.info().scope_key}})).await;
            assert!(
                body(&choices).to_string().contains(MARKER),
                "{platform:?} {token:?}: {}",
                body(&choices)
            );
            let export = planes.browser.journal_export_for_test().await;
            assert!(!export.contains(MARKER), "{platform:?} {token:?}: {export}");
            let rows = entries(&planes).await;
            assert_eq!(
                rows[0]["detail"]["bound_ids"],
                if private_bound {
                    Value::Null
                } else {
                    json!(["bound"])
                }
            );
        }
    }
}

#[tokio::test]
async fn failed_reservation_never_calls_source_or_leaves_an_entry() {
    let (planes, source) = setup(Data::default(), Platform::MacOs);
    fault(&planes, "advance_allocator", 1).await;
    assert_refusal(
        &reserved(&planes, list(Token::Calendar, 100)).await,
        "journal_unavailable",
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert!(entries(&planes).await.is_empty());
    assert_eq!(active(&planes).await, 0);
}

#[tokio::test]
async fn failed_commit_settles_only_its_record_before_the_next_journaled_request() {
    for point in ["establish_marker", "commit_rejection"] {
        let (planes, source) = setup(Data::default(), Platform::MacOs);
        let unrelated = planes
            .browser
            .with_ability_journal(|store| {
                store
                    .unwrap()
                    .reserve_policy_event(&crate::browser::journal_identity(&flow().identity))
            })
            .await
            .unwrap();
        let before = active(&planes).await;
        fault(&planes, point, 1).await;
        assert_refusal(
            &reserved(&planes, list(Token::Calendar, 100)).await,
            "journal_unavailable",
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        assert!(entries(&planes).await.is_empty());
        assert_eq!(active(&planes).await, before + 1);
        fault(&planes, point, 0).await;
        let export = planes.browser.journal_export_for_test().await;
        exchange(&planes, &flow(), json!({"method":DESCRIBE})).await;
        assert_eq!(active(&planes).await, before + 1);
        assert_eq!(planes.browser.journal_export_for_test().await, export);
        fault(&planes, "recover_policy_event", 1).await;
        let calls = source.calls.load(Ordering::SeqCst);
        assert_refusal(
            &reserved(&planes, list(Token::Calendar, 100)).await,
            "journal_unavailable",
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), calls);
        assert_eq!(active(&planes).await, before + 1);
        let reply = reserved(&planes, list(Token::Calendar, 100)).await;
        assert_eq!(body(&reply)["items"], json!([]));
        assert_eq!(active(&planes).await, before);
        assert_eq!(
            entries(&planes).await.len(),
            if point == "commit_rejection" { 2 } else { 1 }
        );
        planes
            .browser
            .with_ability_journal(|store| {
                assert!(store.unwrap().recover_policy_event(unrelated.sequence()));
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(active(&planes).await, 0);
    }
}

#[tokio::test]
async fn a_route_closed_during_a_read_commits_its_actual_outcome_and_count() {
    let block = Arc::new(Block::default());
    let release = Release(block.clone());
    let (planes, _) = setup(
        Data {
            block: Some(block.clone()),
            items: vec![item(Token::Calendar, "one", "bound")],
            ..Default::default()
        },
        Platform::MacOs,
    );
    let request_body = list(Token::Calendar, 100);
    let gate = Arc::new(TerminalArbiter::new(request(request_body.clone())));
    let route = flow();
    let run = dispatch(
        &planes.management.abilities,
        &planes.browser,
        &route,
        CALL,
        request_body.as_object().unwrap(),
        gate.clone(),
    );
    tokio::pin!(run);
    tokio::select! { biased; _=&mut run=>panic!("read did not park"), _=block.started.notified()=>{} }
    assert_eq!(active(&planes).await, 1);
    assert!(gate.stop(TerminalCause::RouteClosed));
    drop(release);
    assert!(matches!(run.await, Ok(None)));
    let rows = entries(&planes).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["detail"]["outcome"], "ok");
    assert_eq!(rows[0]["detail"]["item_count"], 1);
    assert_eq!(active(&planes).await, 0);
}

#[tokio::test]
async fn stop_after_reservation_starts_no_source_and_commits_stopped() {
    let (mut planes, source) = setup(Data::default(), Platform::MacOs);
    let request_body = list(Token::Calendar, 100);
    let gate = Arc::new(TerminalArbiter::new(request(request_body.clone())));
    let stop = gate.clone();
    Arc::get_mut(&mut planes.management)
        .unwrap()
        .abilities
        .after_reserve = Some(Arc::new(move |count| {
        assert_eq!(count, 1);
        assert!(stop.stop(TerminalCause::Cancelled));
    }));
    let result = dispatch(
        &planes.management.abilities,
        &planes.browser,
        &flow(),
        CALL,
        request_body.as_object().unwrap(),
        gate,
    )
    .await;
    assert!(matches!(result, Ok(None)));
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    let rows = entries(&planes).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["detail"]["outcome"], "stopped");
    assert!(rows[0]["detail"]["item_count"].is_null());
    assert_eq!(active(&planes).await, 0);
}

#[tokio::test]
async fn non_mac_setup_commits_under_one_lock_while_a_read_holds_the_other_reservation() {
    for platform in [Platform::Windows, Platform::Linux] {
        let block = Arc::new(Block::default());
        let release = Release(block.clone());
        let (mut planes, source) = setup(
            Data {
                block: Some(block.clone()),
                ..Default::default()
            },
            platform,
        );
        let peak = Arc::new(AtomicUsize::new(0));
        let seen = peak.clone();
        Arc::get_mut(&mut planes.management)
            .unwrap()
            .abilities
            .after_reserve = Some(Arc::new(move |count| {
            seen.fetch_max(count, Ordering::SeqCst);
        }));
        let route = flow();
        let run = exchange(&planes, &route, list(Token::Calendar, 100));
        tokio::pin!(run);
        tokio::select! {biased; _=&mut run=>panic!("read did not park"), _=block.started.notified()=>{} }
        assert_eq!(active(&planes).await, 1);
        let calls = source.calls.load(Ordering::SeqCst);
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            exchange(
                &planes,
                &facts("prefrontal-core"),
                json!({"method":SETUP,"params":{"token":Token::Calendar.as_str()}}),
            ),
        )
        .await
        .unwrap();
        assert_eq!(body(&reply), json!({"state":"not_required"}));
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active(&planes).await, 1);
        assert_eq!(source.calls.load(Ordering::SeqCst), calls);
        let rows = entries(&planes).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]["detail"],
            json!({"event":SETUP,"token":Token::Calendar.as_str(),"op":null,"key":null,"flow_id":null,"run_id":null,"install_id":null,"install_version":null,"bound_count":null,"bound_ids":null,"outcome":"not_required","item_count":null})
        );
        drop(release);
        assert_eq!(body(&run.await)["items"], json!([]));
        assert_eq!(active(&planes).await, 0);
    }
}

#[tokio::test]
async fn no_journal_mode_serves_without_writing() {
    let (mut planes, source) = setup(Data::default(), Platform::MacOs);
    planes.browser = Arc::new(crate::browser::BrowserPlane::default());
    assert_eq!(
        body(&reserved(&planes, list(Token::Calendar, 100)).await)["items"],
        json!([])
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert!(entries(&planes).await.is_empty());
    assert_eq!(
        planes.browser.retained_journal_store_count_for_test().await,
        0
    );
}

#[tokio::test(start_paused = true)]
async fn a_call_stopped_in_the_queue_never_reserves_or_calls_source() {
    let (planes, source) = setup(Data::default(), Platform::MacOs);
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap();
    let holder = unit
        .arrive(Arc::new(TerminalArbiter::new(request(
            json!({"method":CALL}),
        ))))
        .unwrap()
        .wait()
        .await
        .unwrap();
    let request_body = list(Token::Calendar, 100);
    let route = flow();
    let gate = Arc::new(TerminalArbiter::new(request(request_body.clone())));
    let run = dispatch(
        &planes.management.abilities,
        &planes.browser,
        &route,
        CALL,
        request_body.as_object().unwrap(),
        gate.clone(),
    );
    tokio::pin!(run);
    tokio::select! {biased; _=&mut run=>panic!("call did not queue"), _=tokio::task::yield_now()=>{} }
    assert!(unit.has_users_for_test(2));
    assert_eq!(active(&planes).await, 0);
    assert!(gate.stop(TerminalCause::Cancelled));
    tokio::time::advance(std::time::Duration::from_millis(250)).await;
    assert!(matches!(run.await, Ok(None)));
    assert!(unit.has_users_for_test(1));
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(active(&planes).await, 0);
    assert!(entries(&planes).await.is_empty());
    drop(holder);
}

#[tokio::test(start_paused = true)]
async fn a_timed_out_read_commits_before_its_quarantined_worker_finishes() {
    let block = Arc::new(Block::default());
    let release = Release(block.clone());
    let (planes, source) = setup(
        Data {
            block: Some(block.clone()),
            ..Default::default()
        },
        Platform::Linux,
    );
    let route = flow();
    let run = exchange(&planes, &route, list(Token::Calendar, 100));
    tokio::pin!(run);
    tokio::select! {biased; _=&mut run=>panic!("read did not park"), _=block.started.notified()=>{} }
    assert_eq!(active(&planes).await, 1);
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    assert_refusal(&run.await, "ability_source_timeout");
    let rows = entries(&planes).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["detail"]["outcome"], "ability_source_timeout");
    assert!(rows[0]["detail"]["item_count"].is_null());
    assert_eq!(active(&planes).await, 0);
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap();
    assert!(unit.quarantined());
    assert_refusal(
        &reserved(&planes, list(Token::Calendar, 100)).await,
        "ability_source_timeout",
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert_eq!(entries(&planes).await.len(), 1);
    drop(release);
    while unit.quarantined() {
        tokio::task::yield_now().await;
    }
    wait_for_status_to_release(unit).await;
    assert_eq!(entries(&planes).await.len(), 1);
}

#[tokio::test]
async fn non_mac_setup_recovers_its_own_failed_commit_without_a_source_call() {
    for platform in [Platform::Windows, Platform::Linux] {
        let (planes, source) = setup(Data::default(), platform);
        let setup = json!({"method":SETUP,"params":{"token":Token::Calendar.as_str()}});
        fault(&planes, "commit_rejection", 1).await;
        assert_refusal(
            &reserved(&planes, setup.clone()).await,
            "journal_unavailable",
        );
        assert_eq!(active(&planes).await, 1);
        fault(&planes, "recover_policy_event", 1).await;
        assert_refusal(
            &reserved(&planes, setup.clone()).await,
            "journal_unavailable",
        );
        assert_eq!(active(&planes).await, 1);
        assert_eq!(
            body(&reserved(&planes, setup).await),
            json!({"state":"not_required"})
        );
        assert_eq!(active(&planes).await, 0);
        assert_eq!(entries(&planes).await.len(), 2);
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn mac_setup_records_its_state_and_calls_carry_the_stamped_run_id() {
    struct Granted;
    impl StatusSource for Granted {
        fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
            Ok(tokens
                .iter()
                .map(|&t| {
                    (
                        t,
                        Availability {
                            unavailable_reason: None,
                        },
                    )
                })
                .collect())
        }
        fn setup(&self, _: Token) -> Result<Value, Refusal> {
            Ok(json!({"state":"granted"}))
        }
    }
    let planes = fixture(Arc::new(Granted), Platform::MacOs);
    let reply = reserved(
        &planes,
        json!({"method":SETUP,"params":{"token":Token::Calendar.as_str()}}),
    )
    .await;
    assert_eq!(body(&reply), json!({"state":"granted"}));
    let rows = entries(&planes).await;
    assert_eq!(rows[0]["detail"]["outcome"], "granted");
    assert_eq!(rows[0]["detail"].as_object().unwrap().len(), 12);
    for key in [
        "op",
        "key",
        "flow_id",
        "run_id",
        "install_id",
        "install_version",
        "bound_count",
        "bound_ids",
        "item_count",
    ] {
        assert!(rows[0]["detail"][key].is_null(), "{key}");
    }
    let (planes, _) = setup(
        Data {
            items: vec![item(Token::Calendar, "one", "bound")],
            ..Default::default()
        },
        Platform::MacOs,
    );
    let route = facts("basal").with_scope(Some(stamp(
        ScopeKind::Ephemeral,
        ScopeAttributes::new()
            .with_flow_id(Some("flow-test".into()))
            .with_run_id(Some("run-test".into())),
    )));
    let reply = exchange(
        &planes,
        &route,
        call(Token::Calendar, "events.get", json!({"id":"one"})),
    )
    .await;
    assert!(body(&reply)["item"].is_object());
    let rows = entries(&planes).await;
    assert_eq!(rows[0]["detail"]["run_id"], "run-test");
    assert_eq!(rows[0]["detail"]["item_count"], 1);
    assert_eq!(active(&planes).await, 0);
}

#[tokio::test]
async fn source_refusals_record_only_the_code_and_no_item_count() {
    for refusal in [
        Refusal::Unavailable("permission_missing"),
        Refusal::ScopeStale,
        Refusal::ItemNotFound,
        Refusal::Unavailable("ability_recurrence_unsupported"),
        Refusal::SourceTimeout,
        Refusal::SourceFailed,
    ] {
        struct Failed(Refusal);
        impl StatusSource for Failed {
            fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
                Ok(tokens
                    .iter()
                    .map(|&t| {
                        (
                            t,
                            Availability {
                                unavailable_reason: None,
                            },
                        )
                    })
                    .collect())
            }
            fn read(
                &self,
                _: Token,
                _: &str,
                _: &ValidatedArgs,
                _: &BoundScope,
            ) -> Result<SourceRead, Refusal> {
                Err(self.0)
            }
        }
        let mut planes = fixture(Arc::new(Failed(refusal)), Platform::MacOs);
        Arc::get_mut(&mut planes.management)
            .unwrap()
            .abilities
            .binding = Arc::new(Bound);
        assert_refusal(
            &reserved(&planes, list(Token::Calendar, 100)).await,
            refusal.wire().0,
        );
        let rows = entries(&planes).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["detail"]["outcome"], refusal.wire().0);
        assert!(rows[0]["detail"]["item_count"].is_null());
        assert_eq!(active(&planes).await, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn unsupported_os_refuses_after_binding_before_the_busy_unit_and_describe_omits_its_tokens() {
    struct CountedBinding {
        bound: Bound,
        calls: AtomicUsize,
    }
    impl BindingReader for CountedBinding {
        fn read<'a>(&'a self, flow_id: &'a str) -> BindingRead<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.bound.read(flow_id)
        }
    }
    let source = Arc::new(FakeStatus::default());
    let binding = Arc::new(CountedBinding {
        bound: Bound,
        calls: AtomicUsize::new(0),
    });
    let mut planes = fixture(source.clone(), Platform::MacOs);
    let management = Arc::get_mut(&mut planes.management).unwrap();
    management.abilities = AbilityPlane::new(Platform::MacOs, source.clone(), false);
    management.abilities.binding = binding.clone();
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap();
    let holder = unit
        .arrive(Arc::new(TerminalArbiter::new(request(
            json!({"method":CALL}),
        ))))
        .unwrap()
        .wait()
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    for token in [Token::Calendar, Token::Reminders] {
        for request in [
            list(token, 100),
            json!({"method":SCOPE_CHOICES,"params":{"token":token.as_str(),"key":token.info().scope_key}}),
            json!({"method":SETUP,"params":{"token":token.as_str()}}),
        ] {
            assert_refusal(&reserved(&planes, request).await, "os_unsupported");
            assert!(unit.has_users_for_test(1));
        }
    }
    assert_eq!(started.elapsed(), std::time::Duration::ZERO);
    assert_eq!(binding.calls.load(Ordering::SeqCst), 2);
    let mut outside = list(Token::Calendar, 100);
    outside["params"]["key"] = json!("not-bound");
    assert_refusal(&reserved(&planes, outside).await, "ability_out_of_scope");
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert!(entries(&planes).await.is_empty());
    assert_eq!(active(&planes).await, 0);
    drop(holder);
    let reply = exchange(
        &planes,
        &facts("prefrontal-core"),
        json!({"method":DESCRIBE}),
    )
    .await;
    let tokens = body(&reply)["tokens"].as_array().unwrap().clone();
    for token in [Token::Calendar, Token::Reminders] {
        let row = tokens
            .iter()
            .find(|row| row["token"] == token.as_str())
            .unwrap();
        assert_eq!(row["available"], false);
        assert_eq!(row["unavailable_reason"], "os_unsupported");
    }
    {
        let seen = source.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen.contains(&vec![Token::Contacts]));
        assert!(seen.contains(&vec![Token::Messages, Token::Mail]));
    }
    assert!(entries(&planes).await.is_empty());
}
