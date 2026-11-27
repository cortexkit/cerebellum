use super::*;

// `views.rs` imports the type only where it serves a stored definition; the
// tests also build one when they regenerate a new pin's check document.
use cortexkit_role_tool_provider::views::ViewTool;

fn current_definitions() -> Vec<CatalogTool> {
    let browser = browser_tools()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();
    let computer = cerebellum_computer::audit::ComputerCapability::ALL
        .into_iter()
        .map(|capability| capability.capability_id().to_string())
        .filter(|name| crate::computer_capability::servable(name).is_some())
        .filter(|name| name != "computer.takeover_click" && name != "computer.takeover_drag")
        .collect::<Vec<_>>();
    definitions(&browser, &computer)
}

fn pin(tool: &CatalogTool) -> String {
    SchemaPin::new(&tool.name, &tool.schema_digest, tool.semantics)
        .encode()
        .unwrap()
}

#[test]
fn published_pins_schemas_and_reads_are_kept_byte_for_byte() {
    // This release's table is append-only. A future release keeps this file and
    // its digest, and adds another table for newly published pins.
    assert_eq!(
        manifest::sha256_hex(PUBLISHED.as_bytes()),
        "24c1c1a38f0cdf5dfcddc6346d2cd544d60bfa7df311f53f42fede9bafdbb7e0"
    );
    let kept: BTreeMap<String, Value> = serde_json::from_str(PUBLISHED).unwrap();
    let served = published();
    for (pin, entry) in kept {
        let view = &served[&pin];
        assert_eq!(
            serde_json::to_vec(&serde_json::to_value(&view.record_schema).unwrap()).unwrap(),
            serde_json::to_vec(&entry["record_schema"]).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&view.reads).unwrap(),
            serde_json::to_vec(&entry["reads"]).unwrap()
        );
    }
    for tool in current_definitions() {
        assert_eq!(served[&pin(&tool)].record_schema, tool_display::schema());
    }
}

#[test]
fn pointer_fronting_publication_is_a_separately_frozen_addition() {
    assert_eq!(
        manifest::sha256_hex(POINTER_FRONTING_PUBLISHED.as_bytes()),
        "c4a12dab86d1ceebe50aa5f3b8b22c3536fb318d4aec51779673865ab5ca719f"
    );
    let addition: BTreeMap<String, Value> =
        serde_json::from_str(POINTER_FRONTING_PUBLISHED).unwrap();
    assert_eq!(addition.len(), 1);
    let legacy: BTreeMap<String, Value> = serde_json::from_str(PUBLISHED).unwrap();
    let served = published();
    for (pin, entry) in addition {
        assert!(!legacy.contains_key(&pin));
        assert_eq!(entry["tool"]["name"], "computer_use");
        assert_eq!(
            serde_json::to_value(&served[&pin].record_schema).unwrap(),
            entry["record_schema"]
        );
    }
}

#[test]
fn move_scroll_only_publication_keeps_both_historical_tables() {
    assert_eq!(
        manifest::sha256_hex(POINTER_MOVE_SCROLL_PUBLISHED.as_bytes()),
        "ae2dde192735556ff3e8f95349aeeb17f840ed8750d198ea857d578d32c718f0"
    );
    let addition: BTreeMap<String, Value> =
        serde_json::from_str(POINTER_MOVE_SCROLL_PUBLISHED).unwrap();
    assert_eq!(addition.len(), 1);
    let served = published();
    for (pin, entry) in addition {
        assert!(served.contains_key(&pin));
        let bytes = entry.to_string();
        assert!(!bytes.contains("takeover_click"));
        assert!(!bytes.contains("takeover_drag"));
    }
}

#[test]
fn every_published_pin_recomputes_from_its_stored_tool() {
    // The display server rebuilds a pin from the view's `tool`, so a stored
    // definition that no longer hashes to its key would turn a working row into
    // an unknown view.
    let mut kept: BTreeMap<String, Value> = serde_json::from_str(PUBLISHED).unwrap();
    kept.extend(
        serde_json::from_str::<BTreeMap<String, Value>>(POINTER_FRONTING_PUBLISHED).unwrap(),
    );
    kept.extend(
        serde_json::from_str::<BTreeMap<String, Value>>(POINTER_MOVE_SCROLL_PUBLISHED).unwrap(),
    );
    kept.extend(
        serde_json::from_str::<BTreeMap<String, Value>>(BROWSER_FILTERED_WAIT_PUBLISHED).unwrap(),
    );
    kept.extend(serde_json::from_str::<BTreeMap<String, Value>>(BROWSER_KEYS_PUBLISHED).unwrap());
    for (pin, entry) in &kept {
        let tool: ViewTool = serde_json::from_value(entry["tool"].clone()).unwrap();
        assert_eq!(tool.name, SchemaPin::parse(pin).unwrap().tool, "{pin}");
        assert_eq!(
            tool.semantics,
            SchemaPin::parse(pin).unwrap().semantics,
            "{pin}"
        );
        assert_eq!(
            cortexkit_role_tool_provider::catalog::schema_digest(
                &cortexkit_role_tool_provider::catalog::structural_schema(&tool.input_schema)
            )
            .unwrap(),
            SchemaPin::parse(pin).unwrap().schema_digest,
            "{pin}"
        );
        let view = published().remove(pin).unwrap();
        assert!(view.check_pin(pin).unwrap(), "{pin}");
    }
    // Every current catalog definition is still one of the published pins.
    for tool in current_definitions() {
        assert!(kept.contains_key(&pin(&tool)));
    }
}

#[test]
fn filtered_browser_wait_publication_keeps_historical_pins() {
    assert_eq!(
        manifest::sha256_hex(BROWSER_FILTERED_WAIT_PUBLISHED.as_bytes()),
        "c0c11d94cb48675a9a41976f96900880f0bdaafb2f797f88bdab9f8a37203468"
    );
    let addition: BTreeMap<String, Value> =
        serde_json::from_str(BROWSER_FILTERED_WAIT_PUBLISHED).unwrap();
    assert_eq!(addition.len(), 1);
    let served = published();
    for (pin, entry) in addition {
        assert_eq!(entry["tool"]["name"], "browser_use");
        assert!(served[&pin].check_pin(&pin).unwrap());
        assert!(entry["tool"]["input_schema"]["properties"]
            .get("wait_for_ms")
            .is_some());
    }
}

#[test]
fn browser_key_view_keeps_the_previous_pin_and_uses_its_own_revision() {
    assert_eq!(
        manifest::sha256_hex(BROWSER_KEYS_PUBLISHED.as_bytes()),
        "d831d2472cb2fda35969506a676d51827f460700dd06e8f5b24d2a36090ca480"
    );
    let existing: BTreeMap<String, Value> =
        serde_json::from_str(BROWSER_FILTERED_WAIT_PUBLISHED).unwrap();
    let mut added: BTreeMap<String, Value> = serde_json::from_str(BROWSER_KEYS_PUBLISHED).unwrap();
    let (pin, _) = added.pop_first().expect("published key view");
    assert!(added.is_empty());
    let served = published();
    for old in existing.keys() {
        let view = &served[old];
        assert_eq!(view.template_revision, TEMPLATE_REVISION);
        assert_eq!(view.template["row"]["source"], BROWSER_ROW);
    }
    let view = &served[&pin];
    assert_eq!(view.template_revision, BROWSER_KEYS_TEMPLATE_REVISION);
    assert!(view.template["row"]["source"]
        .as_str()
        .unwrap()
        .contains("input.key"));
    assert!(view.check_pin(&pin).unwrap());
}

#[test]
fn a_pin_outside_the_current_catalog_is_still_served_with_its_tool() {
    // A fixture table whose single pin no longer appears in the live catalog,
    // the situation a browser_use or computer_use definition change creates.
    let tool = ViewTool::new(
        flat_tools::BROWSER_USE,
        json!({"type":"object","properties":{"action":{"type":"string","enum":["retired_action"]}}}),
        1,
    );
    let pin = tool.schema_pin().unwrap();
    assert!(current_definitions()
        .iter()
        .all(|current| self::pin(current) != pin));
    let table = json!({
        pin.clone(): {
            "record_schema": tool_display::schema(),
            "reads": [],
            "tool": tool,
        }
    });
    let table: BTreeMap<String, Value> = serde_json::from_value(table).unwrap();
    let (kept_pin, entry) = table.iter().next().unwrap();
    let view = view(kept_pin, entry);
    assert!(view.check_pin(&pin).unwrap());
    assert_eq!(view.tool.as_ref().unwrap(), &tool);
    let reply = ViewsReply::new(
        [(pin.clone(), ViewEntry::Manifest(view))]
            .into_iter()
            .collect(),
    );
    let request = ViewsRequest::new(vec![pin.clone()]);
    reply.validate_for(&request).unwrap();
    let served: Value = serde_json::to_value(&reply).unwrap();
    assert_eq!(
        served["views"][&pin]["tool"]["name"],
        flat_tools::BROWSER_USE
    );
    assert_eq!(
        served["views"][&pin]["tool"]["input_schema"],
        json!({"type":"object","properties":{"action":{"type":"string","enum":["retired_action"]}}})
    );
}

#[test]
fn provider_view_tool_vectors_agree_with_what_views_serve() {
    // The provider crate's shared vectors state when a view's `tool` matches its
    // pin, and what an encoded view's bytes are. Cerebellum serves the matching
    // shape, so the same checks must hold for every published view.
    let vectors: Value =
        serde_json::from_str(cortexkit_role_tool_provider::vectors::VIEW_TOOLS_JSON).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let view: ViewManifest = serde_json::from_value(case["view"].clone()).unwrap();
        let pin = case["pin"].as_str().unwrap();
        match case["check"].as_str().unwrap() {
            "present" => {
                assert!(view.check_pin(pin).unwrap(), "{}", case["name"]);
                assert_eq!(view.tool.as_ref().unwrap().schema_pin().unwrap(), pin);
            }
            "mismatch" => {
                assert!(view.check_pin(pin).is_err(), "{}", case["name"]);
                let computed = view.tool.as_ref().unwrap().schema_pin().unwrap();
                assert_eq!(computed, case["computed_pin"].as_str().unwrap());
            }
            "absent" => {
                assert!(!view.check_pin(pin).unwrap(), "{}", case["name"]);
                assert_eq!(
                    serde_json::to_string(&view).unwrap(),
                    case["encoded"].as_str().unwrap(),
                    "a legacy view keeps its bytes"
                );
            }
            other => panic!("unexpected check {other}"),
        }
    }
    let served = published();
    for (pin, entry) in &served {
        assert!(entry.check_pin(pin).unwrap());
    }
}

#[test]
fn views_embed_exact_template_bytes_and_checked_inputs() {
    let served = published();
    for tool in current_definitions() {
        let check = match tool.name.as_str() {
            flat_tools::BROWSER_USE => {
                include_str!("../../../resources/tool-views/browser-check.json")
            }
            flat_tools::COMPUTER_USE => {
                include_str!("../../../resources/tool-views/computer-check.json")
            }
            _ => unreachable!(),
        };
        let (templates, revision) = tool_templates(&tool.name, &tool.input_schema);
        let row = templates["row"]["source"].as_str().unwrap();
        let page = templates["page"]["source"].as_str().unwrap();
        let view = &served[&pin(&tool)];
        assert_eq!(
            view.template["row"]["source"].as_str().unwrap().as_bytes(),
            row.as_bytes()
        );
        assert_eq!(
            view.template["page"]["source"].as_str().unwrap().as_bytes(),
            page.as_bytes()
        );
        assert_eq!(view.template_revision, revision);
        let check: Value = serde_json::from_str(check).unwrap();
        assert_eq!(check["input_schema"], tool.input_schema);
        // The published view carries the shipped definition behind its pin,
        // stored rather than rebuilt. A pin covers the schema's structure, so
        // the stored copy is the shipped schema with description text removed.
        let kept = view.tool.as_ref().expect("published view carries its tool");
        assert_eq!(kept.name, tool.name);
        assert_eq!(kept.semantics, tool.semantics);
        assert_eq!(
            cortexkit_role_tool_provider::catalog::structural_schema(&check["input_schema"]),
            kept.input_schema
        );
        assert_eq!(
            cortexkit_role_tool_provider::catalog::schema_digest(&check["input_schema"]).unwrap(),
            tool.schema_digest
        );
        assert_eq!(check["view"], serde_json::to_value(view).unwrap());
        assert!(!row.contains("input.text"));
        assert!(!row.contains("input.secret"));
        assert!(!page.contains("input.secret"));
    }
}

#[test]
fn tool_pages_do_not_show_raw_replies() {
    for page in [BROWSER_PAGE, COMPUTER_PAGE] {
        assert!(!page.contains("view.output"));
    }
}

#[test]
fn row_badges_fit_short_slots_at_phone_width() {
    // occipital-check uses eight units per character. Occipital's catalog gives a
    // short Slot twelve digit widths and a badge six units of padding per side.
    let phone_width = 320;
    let slot_width = 12 * 8;
    assert!(slot_width <= phone_width);
    for row in [BROWSER_ROW, COMPUTER_ROW] {
        let badge_source = row
            .split_once("<Slot width=\"short\">\n{outcome")
            .expect("outcome uses a short Slot")
            .1
            .split_once("</Slot>")
            .unwrap()
            .0;
        let mut labels = badge_source
            .split('"')
            .enumerate()
            .filter_map(|(index, text)| {
                (index % 2 == 1 && text.chars().next().is_some_and(char::is_uppercase))
                    .then_some(text)
            })
            .collect::<Vec<_>>();
        for label in &labels {
            let width = label.chars().count() * 8 + 2 * 6;
            assert!(
                width <= slot_width,
                "{label:?} needs {width} units, beyond the {slot_width}-unit short Slot at width 320"
            );
        }
        labels.sort_unstable();
        assert_eq!(
            labels,
            ["Asked you", "Done", "Refused", "Signed out", "Unknown"]
        );
    }
}

#[test]
fn views_validate_requests_and_answer_only_requested_pins() {
    let pins = published().into_keys().collect::<Vec<_>>();
    assert_eq!(pins.len(), 6);
    let request = cortexkit_role_tool_provider::views::ViewsRequest::new(vec![
        pins[0].clone(),
        pins[0].clone(),
        "not-a-served-pin".into(),
    ]);
    let answer = answer(serde_json::to_value(&request).unwrap().as_object().unwrap()).unwrap();
    let reply: ViewsReply = serde_json::from_value(answer).unwrap();
    reply.validate_for(&request).unwrap();
    assert_eq!(reply.views.len(), 2);
    assert!(matches!(reply.views[&pins[0]], ViewEntry::Manifest(_)));
    assert!(matches!(
        reply.views["not-a-served-pin"],
        ViewEntry::Unknown
    ));
    assert_eq!(
        super::answer(json!({"pins":[]}).as_object().unwrap()).unwrap(),
        json!({"views":{}})
    );
    for (args, field) in [
        (json!({}), "pins"),
        (json!({"pins":null}), "pins"),
        (json!({"pins":["bad pin"]}), "pins[0]"),
        (json!({"pins":vec!["pin";65]}), "pins"),
        (json!({"pins":[],"extra":true}), "extra"),
    ] {
        let error = super::answer(args.as_object().unwrap()).unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.detail.unwrap()["field"], field);
    }
}

/// Regenerate the occipital-check view documents and sample calls from the
/// same definitions the catalog uses.
/// Published schemas, reads and stored tool definitions are deliberately not
/// regenerated here: each pin is served from what was published, never from
/// today's code. This generator only reprints a new entry's definition: its
/// pinned schema is the structural form, which a tp1 pin hashes.
#[test]
#[ignore = "explicit fixture generator"]
fn export_checker_inputs() {
    let root = std::env::var_os("CK_TOOL_VIEW_CHECK_OUTPUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/tool-views")
        });
    let mut browser_keys = BTreeMap::new();
    for tool in current_definitions() {
        let name = if tool.name == flat_tools::BROWSER_USE {
            "browser"
        } else {
            "computer"
        };
        let (templates, revision) = tool_templates(&tool.name, &tool.input_schema);
        let view = ViewManifest::new(tool_display::schema(), vec![], templates)
            .with_template_revision(revision)
            .with_tool(ViewTool::new(
                &tool.name,
                cortexkit_role_tool_provider::catalog::structural_schema(&tool.input_schema),
                tool.semantics,
            ));
        let input = if name == "browser" {
            json!({"action":"snapshot","url":"https://example.com/start"})
        } else {
            json!({"action":"read_state","target":"Notes"})
        };
        let mut samples = vec![];
        for record in [
            Value::Null,
            json!({"outcome":"success","durationMs":1200,"queuedMs":12,"heldMs":500,"postsReturned":0,"site":"https://example.com:8443"}),
            json!({"outcome":"held","reason":"consent","durationMs":20}),
            json!({"outcome":"held","reason":"login_handoff","durationMs":20}),
            json!({"outcome":"error","reason":"screen_locked","durationMs":20}),
            json!({"outcome":"partial","reason":"outcome_unknown","durationMs":20}),
        ] {
            samples.push(if record.is_null() {
                json!({"input":input})
            } else {
                json!({"input":input,"record":record})
            });
        }
        for completion in [
            json!({"outcome":"success","durationMs":1500}),
            json!({"outcome":"error","reason":"consent_declined"}),
        ] {
            samples.push(json!({"input":input,"record":{"outcome":"held","reason":"consent","durationMs":20},"completion":completion}));
        }
        for reason in [
            "element_disabled",
            "point_in_another_window",
            "consent_expired",
            "state_changed_by_person",
            "operator_app_blocked",
            "scope_ended",
            "cancelled",
            "some_future_reason",
        ] {
            samples.push(
                json!({"input":input,"record":{"outcome":"error","reason":reason,"durationMs":20}}),
            );
        }
        for reason in ["consent", "login_handoff"] {
            let long_place = if name == "browser" {
                json!({"action":"snapshot","url":"https://a-long-site-name-for-phone-layout.example.com/page"})
            } else {
                json!({"action":"read_state","target":"A long app name that must not crowd the outcome badge"})
            };
            samples.push(json!({"input":long_place,"record":{"outcome":"held","reason":reason,"durationMs":20}}));
        }
        if name == "browser" {
            samples.push(
                json!({"input":{"action":"status"},"record":{"outcome":"success","durationMs":10}}),
            );
            samples.push(json!({"input":{"action":"type","text":"Text kept only on the page"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"press_key","key":"enter"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"fill_login","secret":"must-not-render","username_ref":"user","password_ref":"pass","otp_ref":"otp"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"navigate","url":"https://user:password@example.com:8443/path?q=1#fragment"}}));
            samples.push(json!({"input":{"action":"navigate","url":"https://[::1]:8443/path"},"record":{"outcome":"success","durationMs":10,"site":"https://[::1]:8443"}}));
        } else {
            samples.push(json!({"input":{"action":"open_app","target":"com.apple.Notes"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"read_state","app":"com.apple.Notes"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"read_state","target":"Notes.app for Work"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"write_text","target":"Notes","text":"Text kept only on the page"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"wait","app":"Notes"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"read_state","target":"com.apple.TextEdit","bring_to_front":true},"record":{"outcome":"success","durationMs":20,"app":"com.apple.TextEdit"}}));
            samples.push(json!({"input":{"action":"write_text","element_id":"elem-1","text":"Text kept only on the page","write_mode":"replace_value"},"record":{"outcome":"error","reason":"state_changed_by_person","durationMs":20,"app":"com.apple.TextEdit"}}));
            samples.push(json!({"input":{"action":"press_element","element_id":"elem-1"},"record":{"outcome":"success","durationMs":20,"app":"com.apple.TextEdit"}}));
        }
        let check = json!({"input_schema":tool.input_schema,"view":view,"samples":samples});
        std::fs::write(
            root.join(format!("{name}-check.json")),
            format!("{}\n", serde_json::to_string_pretty(&check).unwrap()),
        )
        .unwrap();
        if name == "browser" && std::env::var_os("CK_TOOL_VIEW_CHECK_OUTPUT").is_some() {
            browser_keys.insert(
                pin(&tool),
                json!({"record_schema":view.record_schema,"reads":view.reads,"tool":view.tool}),
            );
        }
        println!(
            "{} {}",
            pin(&tool),
            serde_json::to_string(&json!({
                "record_schema": tool_display::schema(),
                "reads": [],
                "tool": ViewTool::new(
                    &tool.name,
                    cortexkit_role_tool_provider::catalog::structural_schema(&tool.input_schema),
                    tool.semantics,
                ),
            }))
            .unwrap()
        );
    }
    if !browser_keys.is_empty() {
        std::fs::write(
            root.join("published-v5.json"),
            format!("{}\n", serde_json::to_string_pretty(&browser_keys).unwrap()),
        )
        .unwrap();
    }
}
