use super::*;

fn current_definitions() -> Vec<CatalogTool> {
    let browser = browser_tools()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();
    let computer = cerebellum_computer::audit::ComputerCapability::ALL
        .into_iter()
        .map(|capability| capability.capability_id().to_string())
        .filter(|name| crate::computer_capability::servable(name).is_some())
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
        "610accc6a37aa873edf9edf5fb8996481aa89a8cf875d813ab63b818ac88c00f"
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
fn views_embed_exact_template_bytes_and_checked_inputs() {
    let served = published();
    for tool in current_definitions() {
        let (row, page, check) = match tool.name.as_str() {
            flat_tools::BROWSER_USE => (
                BROWSER_ROW,
                BROWSER_PAGE,
                include_str!("../../../resources/tool-views/browser-check.json"),
            ),
            flat_tools::COMPUTER_USE => (
                COMPUTER_ROW,
                COMPUTER_PAGE,
                include_str!("../../../resources/tool-views/computer-check.json"),
            ),
            _ => unreachable!(),
        };
        let view = &served[&pin(&tool)];
        assert_eq!(
            view.template["row"]["source"].as_str().unwrap().as_bytes(),
            row.as_bytes()
        );
        assert_eq!(
            view.template["page"]["source"].as_str().unwrap().as_bytes(),
            page.as_bytes()
        );
        assert_eq!(view.template_revision, 1);
        let check: Value = serde_json::from_str(check).unwrap();
        assert_eq!(check["input_schema"], tool.input_schema);
        assert_eq!(check["view"], serde_json::to_value(view).unwrap());
        assert!(!row.contains("input.text"));
        assert!(!row.contains("input.secret"));
        assert!(!page.contains("input.secret"));
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
            assert!(width <= slot_width, "{label:?} needs {width} units, beyond the {slot_width}-unit short Slot at width 320");
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
    assert_eq!(pins.len(), 2);
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
/// Published schemas and reads are deliberately not regenerated here.
#[test]
#[ignore = "explicit fixture generator"]
fn export_checker_inputs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/tool-views");
    for tool in current_definitions() {
        let name = if tool.name == flat_tools::BROWSER_USE {
            "browser"
        } else {
            "computer"
        };
        let (row, page) = if name == "browser" {
            (BROWSER_ROW, BROWSER_PAGE)
        } else {
            (COMPUTER_ROW, COMPUTER_PAGE)
        };
        let view = ViewManifest::new(
            tool_display::schema(),
            vec![],
            json!({"row":template("tool_row",row),"page":template("tool_page",page)}),
        )
        .with_template_revision(1);
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
            samples.push(json!({"input":{"action":"fill_login","secret":"must-not-render","username_ref":"user","password_ref":"pass","otp_ref":"otp"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"navigate","url":"https://user:password@example.com:8443/path?q=1#fragment"}}));
            samples.push(json!({"input":{"action":"navigate","url":"https://[::1]:8443/path"},"record":{"outcome":"success","durationMs":10,"site":"https://[::1]:8443"}}));
        } else {
            samples.push(json!({"input":{"action":"open_app","target":"com.apple.Notes"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"read_state","app":"com.apple.Notes"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"read_state","target":"Notes.app for Work"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"write_text","target":"Notes","text":"Text kept only on the page"},"record":{"outcome":"success","durationMs":10}}));
            samples.push(json!({"input":{"action":"wait","app":"Notes"},"record":{"outcome":"success","durationMs":10}}));
        }
        let check = json!({"input_schema":tool.input_schema,"view":view,"samples":samples});
        std::fs::write(
            root.join(format!("{name}-check.json")),
            format!("{}\n", serde_json::to_string_pretty(&check).unwrap()),
        )
        .unwrap();
        println!(
            "{} {}",
            pin(&tool),
            serde_json::to_string(&json!({"record_schema":tool_display::schema(),"reads":[]}))
                .unwrap()
        );
    }
}
