use super::*;
use subc_client_rs::config::{ConfigLayer, ConfigLayerSnapshot};

fn snapshot(layer: ConfigLayer, value: &str) -> ConfigLayerSnapshot {
    ConfigLayerSnapshot::file(
        "cerebellum",
        layer,
        "/fixtures/cerebellum.jsonc",
        Some(value.as_bytes().to_vec()),
    )
}

fn review_text(text: &str, base: Option<ConfigView>) -> ConfigReviewReply {
    let generation = base.as_ref().map_or(0, |view| view.generation);
    config_review(
        "cerebellum",
        ConfigReviewRequest::new(generation, vec![snapshot(ConfigLayer::User, text)], base),
    )
}

fn defaults(status: ConfigStatus) -> ConfigView {
    let tuple = SCHEMA
        .1
        .review_tuple(&[], &ValidationContext::new("cerebellum", None))
        .unwrap();
    ConfigView::new(0, tuple.effective, tuple.sources, vec![], status)
}

#[test]
fn schema_and_defaults_are_accepted() {
    let declaration = config_declaration(Path::new("/fixtures/cerebellum.jsonc")).unwrap();
    Schema::new(declaration.schema).unwrap();
    let startup = StartupSettings::from_view(&defaults(ConfigStatus::Unstamped)).unwrap();
    assert_eq!(startup.health, HealthConfig::DEFAULT);
    assert!(startup.agent_cursor);
    assert!(matches!(startup.browser, BrowserSurface::NotConfigured));
    assert_eq!(startup.live, LiveSettings::default());
    assert!(startup.legacy_file.is_none());
}

#[test]
fn published_subc_settings_vectors_match_schema_and_default_sources() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/config-settings-v1/schema.reply.json"
    ))
    .unwrap();
    let show: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/config-settings-v1/show-default.reply.json"
    ))
    .unwrap();
    let admitted = Schema::new(schema["schema"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(admitted.digest().unwrap()).unwrap(),
        schema["schema_digest"]
    );
    // config.show through the default layer is a projection, not a complete
    // delivery tuple: the example's required credential is absent by design.
    assert_eq!(admitted.defaults(), show["effective"]);
    let sources: std::collections::BTreeMap<String, Layer> =
        serde_json::from_value(show["sources"].clone()).unwrap();
    assert_eq!(
        sources,
        [
            ("/group/enabled".into(), Layer::Default),
            ("/limit".into(), Layer::Default)
        ]
        .into()
    );
}

#[cfg(unix)]
#[test]
fn existing_macos_jsonc_reviews_without_conversion() {
    let legacy = include_str!("../../tests/fixtures/legacy-macos-settings.jsonc");
    let reply = review_text(legacy, None);
    assert!(reply.refusals.is_empty(), "{:?}", reply.refusals);
    assert_eq!(reply.fields.len(), 11);
    let expected = browser_config::parse_browser_config(legacy)
        .unwrap()
        .unwrap();
    let value = serde_json::from_str(&subc_jsonc::jsonc_to_json(legacy).unwrap()).unwrap();
    let tuple = SCHEMA
        .1
        .review_tuple(
            &[LayerValue::new(Layer::User, value)],
            &ValidationContext::new("cerebellum", None),
        )
        .unwrap();
    let view = ConfigView::new(
        0,
        tuple.effective,
        tuple.sources,
        vec![],
        ConfigStatus::Unstamped,
    );
    let startup = StartupSettings::from_view(&view).unwrap();
    assert_eq!(startup.browser, BrowserSurface::Available(expected));
    assert_eq!(startup.health, config::parse_config(legacy).unwrap().health);
}

fn absolute_path() -> &'static str {
    if cfg!(windows) {
        r"C:\fixture\browser"
    } else {
        "/fixture/browser"
    }
}

#[test]
fn review_reports_every_changed_field_and_source() {
    let value = json!({"health":{"dispatch_heartbeat_stale_ms": 12,"queue_age_stale_ms": 24},
        "computer_use":{"agent_cursor":false,"app_use":"foreground"},
        "browser":{"executable_path": absolute_path(), "expected_identity":"fixture",
            "launch_handshake_deadline_ms": 1234, "termination_grace_period_ms": 2345,
            "browser_idle_timeout_ms": 3456, "browser_exit_observation_deadline_ms": 4567,
            "navigation_settle_deadline_ms": crate::browser::QUIET_MS + 1}});
    let eligible = review_text(&value.to_string(), Some(defaults(ConfigStatus::Active)));
    assert!(eligible.refusals.is_empty(), "{:?}", eligible.refusals);
    assert_eq!(eligible.fields.len(), 11);
    for field in &eligible.fields {
        assert_eq!(
            field.new,
            RecordedValue::new(value.pointer(&field.path).unwrap().clone())
        );
        assert_eq!(field.old_source, Layer::Default);
        assert_eq!(field.new_source, Layer::User);
        assert_eq!(
            field.apply,
            if field.path == APP_USE {
                ApplyKind::Live
            } else {
                ApplyKind::ModuleRestart
            }
        );
    }
    let unchanged = review_text("{}", Some(defaults(ConfigStatus::Active)));
    assert!(unchanged.fields.is_empty());
    let same_value_new_source = review_text(
        r#"{"computer_use":{"app_use":"background"}}"#,
        Some(defaults(ConfigStatus::Active)),
    );
    assert_eq!(same_value_new_source.fields.len(), 1);
    assert_eq!(same_value_new_source.fields[0].new_source, Layer::User);
    assert_eq!(
        same_value_new_source.fields[0].old,
        same_value_new_source.fields[0].new
    );
    let new_install = review_text("{}", None);
    assert_eq!(new_install.fields.len(), 11);
    assert!(new_install
        .fields
        .iter()
        .all(|field| field.old == RecordedValue::new(Value::Null)));
}

#[test]
fn review_refuses_invalid_values_with_legacy_reasons() {
    let cases = [
        (
            "health",
            "dispatch_heartbeat_stale_ms",
            json!(0),
            "not_positive",
        ),
        ("health", "queue_age_stale_ms", json!(23.5), "not_integer"),
        ("computer_use", "agent_cursor", json!(1), "not_boolean"),
        ("computer_use", "app_use", json!("front"), "not_one_of"),
        (
            "browser",
            "executable_path",
            json!("relative/path"),
            "path_not_absolute",
        ),
        ("browser", "expected_identity", json!(""), "wrong_type"),
        (
            "browser",
            "launch_handshake_deadline_ms",
            json!(MAX_LAUNCH_DEADLINE_MS + 1),
            "above_deadline_cap",
        ),
        (
            "browser",
            "termination_grace_period_ms",
            json!(MAX_TERMINATION_DEADLINE_MS + 1),
            "above_deadline_cap",
        ),
        (
            "browser",
            "browser_idle_timeout_ms",
            json!(0),
            "not_positive",
        ),
        (
            "browser",
            "browser_exit_observation_deadline_ms",
            json!(MAX_TERMINATION_DEADLINE_MS + 1),
            "above_deadline_cap",
        ),
        (
            "browser",
            "navigation_settle_deadline_ms",
            json!(crate::browser::QUIET_MS),
            "below_settlement_quiet_window",
        ),
    ];
    for (section, field, value, reason) in cases {
        let reply = review_text(&json!({section:{field:value}}).to_string(), None);
        assert!(reply.fields.is_empty(), "{section}.{field}");
        assert_eq!(reply.refusals[0].paths, [format!("/{section}/{field}")]);
        assert_eq!(reply.refusals[0].reasons, [reason]);
    }
    let reply = review_text(
        &json!({"browser":{"executable_path":absolute_path()}}).to_string(),
        None,
    );
    assert_eq!(reply.refusals[0].paths, [PATH, IDENTITY]);
    assert_eq!(reply.refusals[0].reasons, ["expected_identity_required"]);
}

#[test]
fn review_rejects_unrecognized_shapes_and_non_user_layers() {
    for (text, reason) in [
        (r#"{"extra": true}"#, "value_invalid"),
        (r#"{"browser":null}"#, "value_invalid"),
        (r#"{"computer_use":{"app_use":null}}"#, "value_invalid"),
        (
            r#"{"health":{"dispatch_heartbeat_stale_ms": {"value": 30}}}"#,
            "value_invalid",
        ),
    ] {
        assert_eq!(review_text(text, None).refusals[0].code, reason, "{text}");
    }
    let reply = config_review(
        "cerebellum",
        ConfigReviewRequest::new(0, vec![snapshot(ConfigLayer::Workspace, "{}")], None),
    );
    assert_eq!(reply.refusals[0].code, "layer_forbidden");
    assert!(review_text(
        "{ /* comment */ \"computer_use\": { \"app_use\": \"foreground\", }, }",
        None
    )
    .refusals
    .is_empty());
}

#[test]
fn effective_app_use_tracks_delivery_status() {
    for status in [
        ConfigStatus::Unstamped,
        ConfigStatus::Active,
        ConfigStatus::Pending,
    ] {
        let mut view = defaults(status.clone());
        view.effective["computer_use"]["app_use"] = json!("foreground");
        assert_eq!(
            config_apply(&view).unwrap(),
            LiveSettings {
                app_use: AppUse::Foreground,
                approved: status != ConfigStatus::Unstamped,
            }
        );
        view.status = ConfigStatus::Failed;
        assert!(config_apply(&view).is_err());
    }
}

#[test]
fn invalid_browser_pairing_refuses_the_whole_unstamped_view() {
    let mut view = defaults(ConfigStatus::Unstamped);
    view.effective["computer_use"]["app_use"] = json!("foreground");
    view.effective["browser"]["executable_path"] = json!(absolute_path());
    view.sources.insert(PATH.into(), Layer::User);
    assert!(config_apply(&view)
        .unwrap_err()
        .contains("required when browser.executable_path is set"));
}

#[test]
fn legacy_jsonc_is_loaded_as_unstamped_only_from_the_supplied_path() {
    let path = std::env::temp_dir().join(format!(
        "cerebellum-legacy-settings-{}.jsonc",
        std::process::id()
    ));
    std::fs::write(
        &path,
        r#"{ "computer_use": { "app_use": "foreground", "agent_cursor": false, }, }"#,
    )
    .unwrap();
    let settings = config_files(Some(&path));
    std::fs::remove_file(&path).unwrap();
    let settings = settings.unwrap();
    assert_eq!(
        settings.live,
        LiveSettings {
            app_use: AppUse::Foreground,
            approved: false
        }
    );
    assert!(!settings.agent_cursor);
    assert_eq!(settings.legacy_file.as_deref(), Some(path.as_path()));
    assert_eq!(
        config_files(Some(&path)).unwrap().live,
        LiveSettings::default()
    );
}
