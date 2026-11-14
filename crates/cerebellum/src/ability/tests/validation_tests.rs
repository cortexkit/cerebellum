use super::*;

#[tokio::test(start_paused = true)]
async fn closed_params_shapes_and_call_keys_refuse_before_binding() {
    let reader = Arc::new(binding_tests::FakeBinding::bound());
    let (planes, source) = binding_tests::fixture_with_binding(reader.clone(), Platform::MacOs);
    let before = planes.browser.journal_export_for_test().await;
    for method in [SCOPE_CHOICES, SETUP, CALL] {
        let valid = valid_params(method);
        let mut invalid = vec![Value::Null, json!([]), json!("params"), json!({})];
        for key in valid.as_object().unwrap().keys() {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(key);
            invalid.push(missing);
            for wrong_type in [Value::Null, json!(false), json!(1), json!([])] {
                let mut p = valid.clone();
                p[key] = wrong_type;
                invalid.push(p);
            }
        }
        let mut extra = valid.clone();
        extra["unknown"] = json!("private marker");
        invalid.push(extra);
        if method == CALL {
            for key in ["".to_owned(), "é".repeat(129)] {
                let mut p = valid.clone();
                p["key"] = json!(key);
                invalid.push(p);
            }
        } else if method == SCOPE_CHOICES {
            for (key, value) in [
                ("limit", json!("100")),
                ("limit", json!(1.5)),
                ("cursor", json!(null)),
                ("cursor", json!(1)),
            ] {
                let mut p = valid.clone();
                p[key] = value;
                invalid.push(p);
            }
        }
        let route = if method == CALL {
            flow()
        } else {
            facts("prefrontal-core")
        };
        for params in invalid {
            assert_refusal(
                &exchange(&planes, &route, json!({"method":method,"params":params})).await,
                "ability_args_invalid",
            );
        }
        assert_refusal(
            &exchange(&planes, &route, json!({"method":method})).await,
            "ability_args_invalid",
        );
    }
    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
}

#[tokio::test(start_paused = true)]
async fn scope_and_argument_schemas_refuse_before_binding() {
    let reader = Arc::new(binding_tests::FakeBinding::bound());
    let (planes, source) = binding_tests::fixture_with_binding(reader.clone(), Platform::MacOs);
    let before = planes.browser.journal_export_for_test().await;
    for scope in [
        json!({"wrong":["bound"]}),
        json!({"calendar":["bound"],"extra":[]}),
        json!({"calendar":"bound"}),
        json!({"calendar":[]}),
        json!({"calendar":(0..65).map(|n| n.to_string()).collect::<Vec<_>>()}),
        json!({"calendar":[null]}),
        json!({"calendar":[""]}),
        json!({"calendar":["bound","bound"]}),
        json!({"calendar":["é".repeat(1025)]}),
    ] {
        let mut p = valid_params(CALL);
        p["scope"] = scope;
        assert_refusal(
            &exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await,
            "ability_scope_invalid",
        );
    }
    let cases = [
        (Token::Calendar, "calendars.list", json!({"extra":true})),
        (Token::Calendar, "calendars.list", json!({"limit":0})),
        (Token::Calendar, "calendars.list", json!({"limit":201})),
        (Token::Calendar, "calendars.list", json!({"cursor":null})),
        (
            Token::Calendar,
            "calendars.list",
            json!({"cursor":"invalid"}),
        ),
        (
            Token::Calendar,
            "events.list",
            json!({"from_ms":0,"to_ms":0}),
        ),
        (
            Token::Calendar,
            "events.list",
            json!({"from_ms":0,"to_ms":7_948_800_001_i64}),
        ),
        (Token::Calendar, "events.list", json!({"from_ms":0})),
        (Token::Calendar, "events.get", json!({"id":""})),
        (
            Token::Calendar,
            "events.get",
            json!({"id":"a".repeat(2049)}),
        ),
        (Token::Contacts, "contacts.list", json!({"query":""})),
        (
            Token::Contacts,
            "contacts.list",
            json!({"query":"é".repeat(65)}),
        ),
        (
            Token::Reminders,
            "reminders.list",
            json!({"include_completed":0}),
        ),
        (Token::Messages, "messages.list", json!({"conversation":""})),
        (
            Token::Mail,
            "messages.list",
            json!({"mailbox":"a".repeat(2049)}),
        ),
    ];
    for (token, op, args) in cases {
        let p = json!({"key":"family_calendar","token":token.as_str(),"op":op,"args":args,
            "scope":{token.info().scope_key:["bound"]}});
        assert_refusal(
            &exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await,
            "ability_args_invalid",
        );
    }
    for (key, value) in [
        ("key", json!("wrong")),
        ("limit", json!(-1)),
        ("limit", json!(0)),
        ("limit", json!(201)),
        ("cursor", json!("invalid")),
    ] {
        let mut p = valid_params(SCOPE_CHOICES);
        p[key] = value;
        assert_refusal(
            &exchange(
                &planes,
                &facts("prefrontal-core"),
                json!({"method":SCOPE_CHOICES,"params":p}),
            )
            .await,
            "ability_args_invalid",
        );
    }
    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
}

#[tokio::test(start_paused = true)]
async fn declared_token_sets_and_unknown_ops_precede_scope_and_schema_checks() {
    for platform in [Platform::MacOs, Platform::Windows, Platform::Linux] {
        let reader = Arc::new(binding_tests::FakeBinding::bound());
        let (planes, source) = binding_tests::fixture_with_binding(reader.clone(), platform);
        for token in ["unknown", Token::Messages.as_str(), Token::Mail.as_str()] {
            if Token::parse(token).is_some_and(|token| platform.tokens().contains(&token)) {
                continue;
            }
            for method in [SCOPE_CHOICES, SETUP, CALL] {
                let mut p = valid_params(method);
                p["token"] = json!(token);
                assert_refusal(
                    &exchange(
                        &planes,
                        &if method == CALL {
                            flow()
                        } else {
                            facts("prefrontal-core")
                        },
                        json!({"method":method,"params":p}),
                    )
                    .await,
                    "ability_token_unknown",
                );
            }
        }
        let mut p = valid_params(CALL);
        p["op"] = json!("events.delete");
        p["scope"] = json!({});
        assert_refusal(
            &exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await,
            "ability_op_unknown",
        );
        assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn message_container_must_be_in_request_scope_before_binding_or_source_lookup() {
    let reader = Arc::new(binding_tests::FakeBinding::bound());
    let (planes, source) = binding_tests::fixture_with_binding(reader.clone(), Platform::MacOs);
    let before = planes.browser.journal_export_for_test().await;
    for token in [Token::Messages, Token::Mail] {
        let mut previous = None;
        for id in ["unbound-present-in-source", "unknown-to-source"] {
            let p = json!({"key":"messages", "token":token.as_str(), "op":"messages.list",
                "args":{token.info().scope_key:id}, "scope":{token.info().scope_key:["bound"]}});
            let reply = exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await;
            assert_refusal(&reply, "ability_out_of_scope");
            if let Some(bytes) = previous {
                assert_eq!(reply.body, bytes);
            }
            previous = Some(reply.body);
        }
    }
    assert_eq!(reader.calls.load(Ordering::SeqCst), 0);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
}

#[tokio::test(start_paused = true)]
async fn shared_cursors_are_checked_before_binding_with_the_same_default_and_scope_rules() {
    use cerebellum_ability::items::{Container, Item};
    let reader = Arc::new(binding_tests::FakeBinding::bound());
    let (planes, source) = binding_tests::fixture_with_binding(reader.clone(), Platform::MacOs);
    let scope =
        validate_scope(Token::Calendar, &json!({"calendar":["also-bound","bound"]})).unwrap();
    let args = validate_args(Token::Calendar, "calendars.list", &json!({"limit":1})).unwrap();
    let last = Item::Container(Container {
        id: "item".into(),
        ..Default::default()
    });
    let cursor = CursorContext::for_call(Token::Calendar, "calendars.list", &args, &scope)
        .unwrap()
        .mint(&last)
        .unwrap();
    let mut p = valid_params(CALL);
    p["scope"] = json!({"calendar":["bound","also-bound"]});
    p["args"] = json!({"cursor":cursor,"limit":200});
    // Changing only limit or id order is allowed. The default adapter's data
    // refusal follows preflight, proving argument and binding admission passed.
    assert_refusal(
        &exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await,
        "ability_source_failed",
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    p["key"] = json!("another-key");
    assert_refusal(
        &exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await,
        "ability_out_of_scope",
    );
    assert_eq!(
        reader.calls.load(Ordering::SeqCst),
        2,
        "cursor incorrectly included the ability key"
    );
    p["scope"] = json!({"calendar":["bound"]});
    assert_refusal(
        &exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await,
        "ability_args_invalid",
    );
    p["scope"] = scope.as_json();
    p["op"] = json!("events.list");
    p["args"]["from_ms"] = json!(0);
    p["args"]["to_ms"] = json!(1);
    assert_refusal(
        &exchange(&planes, &flow(), json!({"method":CALL,"params":p})).await,
        "ability_args_invalid",
    );
    assert_eq!(reader.calls.load(Ordering::SeqCst), 2);
    let choices_cursor = CursorContext::for_choices(Token::Calendar, "calendar")
        .unwrap()
        .mint(&last)
        .unwrap();
    let mut p = valid_params(SCOPE_CHOICES);
    p["cursor"] = json!(choices_cursor);
    p["limit"] = json!(200);
    assert_refusal(
        &exchange(
            &planes,
            &facts("prefrontal-core"),
            json!({"method":SCOPE_CHOICES,"params":p}),
        )
        .await,
        "ability_source_failed",
    );
    p["token"] = json!(Token::Reminders.as_str());
    p["key"] = json!("list");
    assert_refusal(
        &exchange(
            &planes,
            &facts("prefrontal-core"),
            json!({"method":SCOPE_CHOICES,"params":p}),
        )
        .await,
        "ability_args_invalid",
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}
