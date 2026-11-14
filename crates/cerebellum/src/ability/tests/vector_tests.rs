//! Host-independent wire examples exercised through the management dispatcher.

use super::*;
use crate::ability::{
    binding::{BindingEntry, BindingRead, BindingRecord},
    serving::{ScopeChoice, SourceRead, SourceRecord},
};
use cerebellum_ability::{filter::TaggedItem, items::Event, Item};
use std::{collections::BTreeSet, path::PathBuf};

const DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/ability-v1");

#[derive(Default)]
struct VectorSource {
    reasons: Vec<(Token, &'static str)>,
    failed_status: Vec<Token>,
    calls: AtomicUsize,
    data_calls: AtomicUsize,
    setup_state: Option<&'static str>,
    read_error: Option<Refusal>,
    stale: bool,
}

impl StatusSource for VectorSource {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if tokens
            .iter()
            .any(|token| self.failed_status.contains(token))
        {
            return Err(());
        }
        Ok(tokens
            .iter()
            .map(|&token| {
                let reason = self
                    .reasons
                    .iter()
                    .find(|(candidate, _)| *candidate == token);
                (
                    token,
                    Availability {
                        unavailable_reason: reason.map(|(_, reason)| *reason),
                    },
                )
            })
            .collect())
    }

    fn setup(&self, _: Token) -> Result<Value, Refusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let state = self.setup_state.expect("setup case has a state");
        Ok(if state == "needs_person_action" {
            json!({"state":state,"executable_path":"/fixture/ck-cerebellum-fda"})
        } else {
            json!({"state":state})
        })
    }

    fn choices(&self, _: Token) -> Result<Vec<ScopeChoice>, Refusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.data_calls.fetch_add(1, Ordering::SeqCst);
        Ok([
            ("outside", "Other calendar"),
            ("bound", "Family calendar"),
            ("also-bound", "Work calendar"),
        ]
        .map(|(id, label)| ScopeChoice {
            id: id.into(),
            label: label.into(),
            kind: None,
        })
        .into())
    }

    fn read(
        &self,
        _: Token,
        _: &str,
        _: &ValidatedArgs,
        _: &BoundScope,
    ) -> Result<SourceRead, Refusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.data_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.read_error {
            return Err(error);
        }
        Ok(SourceRead {
            containers: if self.stale {
                BTreeSet::new()
            } else {
                ["bound".into(), "also-bound".into(), "outside".into()].into()
            },
            time_zone: Some("America/New_York".into()),
            records: [
                ("outside-event", "outside", 1),
                ("event-b", "bound", 20),
                ("event-a", "bound", 10),
            ]
            .map(|(id, calendar, start)| SourceRecord {
                tagged: TaggedItem::from_item(Item::Event(Event {
                    id: id.into(),
                    calendar: calendar.into(),
                    title: Some(format!("Fixture {id}")),
                    start_ms: Some(start),
                    end_ms: Some(start + 5),
                    ..Default::default()
                })),
                reminder_due: None,
            })
            .into(),
        })
    }
}

#[derive(Clone, Copy, Default)]
enum BindingMode {
    #[default]
    Bound,
    Unavailable,
    OtherKey,
}

struct VectorBinding {
    mode: BindingMode,
    calls: AtomicUsize,
}
impl BindingReader for VectorBinding {
    fn read<'a>(&'a self, flow_id: &'a str) -> BindingRead<'a> {
        Box::pin(async move {
            assert_eq!(flow_id, "flow-test");
            self.calls.fetch_add(1, Ordering::SeqCst);
            if matches!(self.mode, BindingMode::Unavailable) {
                return Err(());
            }
            Ok(BindingRecord {
                install_id: "vector-install".into(),
                version: "1.0.0".into(),
                _description: json!({"tokens":[{"token":Token::Calendar.as_str(),"available":false}]}),
                entries: vec![BindingEntry {
                    key: if matches!(self.mode, BindingMode::OtherKey) {
                        "other_key".into()
                    } else {
                        "family_calendar".into()
                    },
                    token: Token::Calendar,
                    ids: ["bound".into(), "also-bound".into()].into(),
                }],
            })
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum Row {
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    SevenA,
    SevenB,
    SevenC,
    Eight,
    Nine,
    Ten(&'static str),
    Eleven,
    Twelve,
    Thirteen,
    Fourteen,
    Fifteen,
}
impl Row {
    fn early(self) -> bool {
        matches!(
            self,
            Self::One
                | Self::Two
                | Self::Three
                | Self::Four
                | Self::Five
                | Self::Six
                | Self::Seven
                | Self::SevenA
                | Self::SevenB
                | Self::SevenC
                | Self::Eight
        )
    }
    fn no_source(self) -> bool {
        self.early()
    }
    fn no_binding(self) -> bool {
        matches!(
            self,
            Self::One | Self::Two | Self::Three | Self::Four | Self::Five | Self::Six | Self::Seven
        )
    }
    fn code(self) -> &'static str {
        match self {
            Self::One => "principal_denied",
            Self::Two | Self::Six => "ability_args_invalid",
            Self::Three => "ability_token_unknown",
            Self::Four => "ability_op_unknown",
            Self::Five => "ability_scope_invalid",
            Self::Seven | Self::SevenB => "ability_out_of_scope",
            Self::SevenA => "ability_binding_unavailable",
            Self::SevenC => "os_unsupported",
            Self::Eight | Self::Fourteen => "ability_source_timeout",
            Self::Nine => "journal_unavailable",
            Self::Ten(reason) => reason,
            Self::Eleven => "ability_scope_stale",
            Self::Twelve => "ability_item_not_found",
            Self::Thirteen => "ability_recurrence_unsupported",
            Self::Fifteen => "ability_source_failed",
        }
    }
}

struct Case {
    name: String,
    platform: Platform,
    modern_macos: bool,
    source: VectorSource,
    binding: BindingMode,
    route: AcceptedBindFacts,
    request: Value,
    row: Option<Row>,
    time_zone: Option<&'static str>,
    hold_unit: bool,
}
impl Case {
    fn new(name: &str, platform: Platform, request: Value) -> Self {
        let route = if request["method"] == CALL {
            flow()
        } else {
            facts("prefrontal-core")
        };
        Self {
            name: name.into(),
            platform,
            modern_macos: true,
            source: VectorSource::default(),
            binding: BindingMode::Bound,
            route,
            request,
            row: None,
            time_zone: None,
            hold_unit: false,
        }
    }
}

fn event_call(op: &str, args: Value) -> Value {
    let mut request = json!({"method":CALL,"params":valid_params(CALL)});
    request["params"]["op"] = json!(op);
    request["params"]["args"] = args;
    request
}

fn refusal_case(row: Row) -> Case {
    let mut case = Case::new(
        &format!("refusal.{row:?}").to_lowercase(),
        Platform::MacOs,
        event_call("events.list", json!({"from_ms":0,"to_ms":100})),
    );
    case.row = Some(row);
    match row {
        Row::One => case.route = facts("prefrontal-core"),
        Row::Two => case.request["params"]["scope"] = json!([]),
        Row::Three => case.request["params"]["token"] = json!("cap/unknown.read@1"),
        Row::Four => case.request["params"]["op"] = json!("events.write"),
        Row::Five => case.request["params"]["scope"]["calendar"] = json!([""]),
        Row::Six => case.request = event_call("events.get", json!({"id":"x".repeat(2049)})),
        Row::Seven => {
            case.request["params"]["token"] = json!(Token::Mail.as_str());
            case.request["params"]["op"] = json!("messages.list");
            case.request["params"]["scope"] = json!({"mailbox":["bound"]});
            case.request["params"]["args"] = json!({"mailbox":"outside"});
        }
        Row::SevenA => case.binding = BindingMode::Unavailable,
        Row::SevenB => case.binding = BindingMode::OtherKey,
        Row::SevenC => {
            case.modern_macos = false;
            case.hold_unit = true;
            case.source.failed_status = vec![Token::Contacts];
        }
        Row::Eight => case.hold_unit = true,
        Row::Nine => {}
        Row::Ten(reason) => {
            let (platform, token) = match reason {
                "classic_outlook_missing" | "outlook_not_running" | "outlook_guard_may_prompt" => {
                    (Platform::Windows, Token::Calendar)
                }
                "data_service_missing" => (Platform::Linux, Token::Calendar),
                "source_missing" | "format_unrecognized" => (Platform::MacOs, Token::Mail),
                _ => (Platform::MacOs, Token::Calendar),
            };
            case.platform = platform;
            case.name = format!("refusal.10.{reason}");
            case.source.reasons = platform
                .tokens()
                .iter()
                .map(|&token| (token, reason))
                .collect();
            case.request = json!({"method":SCOPE_CHOICES,"params":{"token":token.as_str(),"key":token.info().scope_key}});
            case.route = facts("prefrontal-core");
        }
        Row::Eleven => case.source.stale = true,
        Row::Twelve => case.request = event_call("events.get", json!({"id":"unknown"})),
        Row::Thirteen => {
            case.platform = Platform::Linux;
            case.source.read_error = Some(Refusal::RecurrenceUnsupported);
        }
        Row::Fourteen => case.source.read_error = Some(Refusal::SourceTimeout),
        Row::Fifteen => case.source.read_error = Some(Refusal::SourceFailed),
    }
    case
}

const ROW_TEN: &[&str] = &[
    "helper_unverified",
    "helper_revision_mismatch",
    "permission_missing",
    "source_missing",
    "format_unrecognized",
    "classic_outlook_missing",
    "outlook_not_running",
    "outlook_guard_may_prompt",
    "data_service_missing",
];

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (platform, name) in [
        (Platform::MacOs, "macos"),
        (Platform::Windows, "windows"),
        (Platform::Linux, "linux"),
    ] {
        cases.push(Case::new(
            &format!("describe.{name}"),
            platform,
            json!({"method":DESCRIBE}),
        ));
        let reasons: &[&str] = match platform {
            Platform::MacOs => &[
                "helper_unverified",
                "helper_revision_mismatch",
                "permission_missing",
                "source_missing",
                "format_unrecognized",
                "source_unresponsive",
            ],
            Platform::Windows => &[
                "classic_outlook_missing",
                "outlook_not_running",
                "outlook_guard_may_prompt",
                "permission_missing",
                "source_unresponsive",
            ],
            Platform::Linux => &[
                "data_service_missing",
                "format_unrecognized",
                "source_unresponsive",
            ],
        };
        for &reason in reasons {
            let mut case = Case::new(
                &format!("describe.{name}.{reason}"),
                platform,
                json!({"method":DESCRIBE,"params":{}}),
            );
            // A failed status request affects its whole unit. Store-specific
            // failures on macOS apply only to the Full Disk Access helper.
            let tokens: Vec<_> = platform
                .tokens()
                .iter()
                .copied()
                .filter(|token| {
                    platform != Platform::MacOs
                        || !matches!(reason, "source_missing" | "format_unrecognized")
                        || matches!(token, Token::Messages | Token::Mail)
                })
                .collect();
            if reason == "source_unresponsive" {
                // Keep the FDA unit responsive to pin partial describe replies.
                case.source.failed_status = if platform == Platform::MacOs {
                    vec![Token::Contacts]
                } else {
                    tokens
                };
            } else {
                case.source.reasons = tokens.into_iter().map(|token| (token, reason)).collect();
            }
            cases.push(case);
        }
    }
    let mut old = Case::new(
        "describe.macos.before14_missing_pim",
        Platform::MacOs,
        json!({"method":DESCRIBE}),
    );
    old.modern_macos = false;
    old.source.reasons = vec![(Token::Contacts, "helper_unverified")];
    cases.push(old);
    let mut partial = Case::new(
        "describe.linux.contacts_missing",
        Platform::Linux,
        json!({"method":DESCRIBE}),
    );
    partial.source.reasons = vec![(Token::Contacts, "data_service_missing")];
    cases.push(partial);

    cases.push(Case::new("scope_choices.page", Platform::Linux, json!({"method":SCOPE_CHOICES,"params":{"token":Token::Calendar.as_str(),"key":"calendar","limit":1}})));
    for state in [
        "granted",
        "denied",
        "unanswered",
        "needs_person_action",
        "not_required",
    ] {
        let platform = if state == "not_required" {
            Platform::Linux
        } else {
            Platform::MacOs
        };
        let token = if state == "needs_person_action" {
            Token::Mail
        } else {
            Token::Calendar
        };
        let mut case = Case::new(
            &format!("setup.{state}"),
            platform,
            json!({"method":SETUP,"params":{"token":token.as_str()}}),
        );
        case.source.setup_state = Some(state);
        cases.push(case);
    }
    for (name, op, args) in [
        (
            "call.list_page",
            "events.list",
            json!({"from_ms":0,"to_ms":100,"limit":1}),
        ),
        ("call.get", "events.get", json!({"id":"event-a"})),
    ] {
        let mut case = Case::new(name, Platform::Linux, event_call(op, args));
        case.time_zone = Some("America/New_York");
        cases.push(case);
    }
    cases.extend(
        [
            Row::One,
            Row::Two,
            Row::Three,
            Row::Four,
            Row::Five,
            Row::Six,
            Row::Seven,
            Row::SevenA,
            Row::SevenB,
            Row::SevenC,
            Row::Eight,
            Row::Nine,
            Row::Eleven,
            Row::Twelve,
            Row::Thirteen,
            Row::Fourteen,
            Row::Fifteen,
        ]
        .map(refusal_case),
    );
    cases.extend(ROW_TEN.iter().map(|&reason| refusal_case(Row::Ten(reason))));
    cases
}

fn route_notation(facts: &AcceptedBindFacts) -> Value {
    let stamp = facts.scope.as_ref().map(|stamp| {
        json!({
            "kind":stamp.kind,
            "agent_id":stamp.attributes.agent_id,
            "run_id":stamp.attributes.run_id,
            "flow_id":stamp.attributes.flow_id,
        })
    });
    json!({"principal":crate::principal_label(&facts.principal), "flow_id":facts.flow_id,
        "call_mode":facts.call_mode, "codemode_head":facts.codemode_head.as_deref().map(route_notation),
        "acts_as_agent":facts.acts_as_agent,"stamp":stamp})
}

fn sorted(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let ordered: std::collections::BTreeMap<_, _> =
                std::mem::take(map).into_iter().collect();
            for (key, mut value) in ordered {
                sorted(&mut value);
                map.insert(key, value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(sorted),
        _ => {}
    }
}

async fn run(case: Case) -> (String, Value) {
    let describe_expectations: Vec<_> = case
        .platform
        .tokens()
        .iter()
        .map(|&token| {
            let reason = if case.platform == Platform::MacOs
                && !case.modern_macos
                && matches!(token, Token::Calendar | Token::Reminders)
            {
                Some("os_unsupported")
            } else if case.source.failed_status.contains(&token)
                || (case.platform == Platform::MacOs
                    && case.source.failed_status.contains(&Token::Contacts)
                    && matches!(token, Token::Calendar | Token::Reminders))
            {
                Some("source_unresponsive")
            } else {
                case.source
                    .reasons
                    .iter()
                    .find(|(candidate, _)| *candidate == token)
                    .map(|(_, reason)| *reason)
            };
            (token, reason)
        })
        .collect();
    let source = Arc::new(case.source);
    let binding = Arc::new(VectorBinding {
        mode: case.binding,
        calls: AtomicUsize::new(0),
    });
    let mut planes = fixture(source.clone(), case.platform);
    let plane = &mut Arc::get_mut(&mut planes.management).unwrap().abilities;
    plane.macos_14_or_newer = case.modern_macos;
    plane.binding = binding.clone();
    let holder = if case.hold_unit {
        Some(
            plane
                .units
                .for_token(Token::Calendar)
                .unwrap()
                .arrive(Arc::new(TerminalArbiter::new(request(
                    case.request.clone(),
                ))))
                .unwrap()
                .wait()
                .await
                .unwrap(),
        )
    } else {
        None
    };
    if matches!(case.row, Some(Row::Nine)) {
        planes
            .browser
            .with_ability_journal(|store| {
                store.unwrap().faults.arm("advance_allocator", 1);
                Ok(())
            })
            .await
            .unwrap();
    }
    let before = planes.browser.journal_export_for_test().await;
    let frame = exchange(&planes, &case.route, case.request.clone()).await;
    drop(holder);
    let reply = body(&frame);
    if let Some(row) = case.row {
        assert_refusal(&frame, row.code());
        assert_ne!(reply["code"], "source_unresponsive");
        if row.early() {
            assert_eq!(
                planes.browser.journal_export_for_test().await,
                before,
                "{:?} wrote an entry",
                row
            );
        }
        if row.no_source() || matches!(row, Row::Nine) {
            assert_eq!(
                source.calls.load(Ordering::SeqCst),
                0,
                "{:?} called a source",
                row
            );
        }
        if row.no_binding() {
            assert_eq!(
                binding.calls.load(Ordering::SeqCst),
                0,
                "{:?} read a binding",
                row
            );
        }
        if matches!(row, Row::Ten(_)) {
            assert_eq!(source.data_calls.load(Ordering::SeqCst), 0);
        }
    } else {
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "{}: {reply}",
            case.name
        );
        assert!(reply.get("outcome").is_none());
        assert!(reply.get("image").is_none());
        if case.request["method"] == DESCRIBE {
            let tokens = reply["tokens"].as_array().unwrap();
            assert_eq!(tokens.len(), case.platform.tokens().len());
            for (value, (token, reason)) in tokens.iter().zip(describe_expectations) {
                assert_eq!(value["token"], token.as_str());
                assert_eq!(value["available"], reason.is_none());
                assert_eq!(
                    value.get("unavailable_reason"),
                    reason.map(|reason| json!(reason)).as_ref()
                );
            }
        } else if case.request["method"] == SETUP {
            assert_eq!(reply["state"], source.setup_state.unwrap());
            assert_eq!(
                reply.get("executable_path").is_some(),
                source.setup_state == Some("needs_person_action")
            );
            if case.platform != Platform::MacOs {
                assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            }
        } else if case.name == "scope_choices.page" {
            assert_eq!(
                reply["choices"],
                json!([{"id":"also-bound","label":"Work calendar"}])
            );
            assert!(reply["next_cursor"].is_string());
        } else {
            let item = if case.name == "call.list_page" {
                assert_eq!(reply["items"].as_array().unwrap().len(), 1);
                assert!(reply["next_cursor"].is_string());
                &reply["items"][0]
            } else {
                &reply["item"]
            };
            assert_eq!(item["id"], "event-a");
            assert_eq!(item["calendar"], "bound");
        }
    }
    let mut vector = json!({"tag":"ability-v1", "method":case.request["method"],
        "route":route_notation(&case.route), "request":case.request});
    vector[if frame.header.ty == FrameType::Error {
        "error"
    } else {
        "reply"
    }] = reply;
    if let Some(zone) = case.time_zone {
        vector["time_zone"] = json!(zone);
    }
    sorted(&mut vector);
    (case.name, vector)
}

#[tokio::test]
async fn committed_vectors_match_handler_bytes_on_every_host() {
    let mut expected = BTreeSet::new();
    for case in cases() {
        let (name, vector) = run(case).await;
        let filename = format!("{name}.json");
        assert!(expected.insert(filename.clone()), "duplicate vector name");
        let bytes = format!("{}\n", serde_json::to_string_pretty(&vector).unwrap());
        if let Some(output) = std::env::var_os("ABILITY_VECTOR_OUTPUT_DIR") {
            let path = PathBuf::from(output);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join(&filename), bytes).unwrap();
        } else {
            let path = PathBuf::from(DIRECTORY).join(&filename);
            assert_eq!(
                std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
                bytes.as_bytes(),
                "{filename}"
            );
        }
    }
    let actual: BTreeSet<_> = std::fs::read_dir(DIRECTORY)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "README.md" && name != "catalog-token-mapping.json")
        .collect();
    if std::env::var_os("ABILITY_VECTOR_OUTPUT_DIR").is_none() {
        assert_eq!(
            actual, expected,
            "unexpected corpus files or digest companions"
        );
    }
}

macro_rules! row_test {
    ($name:ident, $row:expr) => {
        #[tokio::test]
        async fn $name() {
            run(refusal_case($row)).await;
        }
    };
}
row_test!(refusal_row_01, Row::One);
row_test!(refusal_row_02, Row::Two);
row_test!(refusal_row_03, Row::Three);
row_test!(refusal_row_04, Row::Four);
row_test!(refusal_row_05, Row::Five);
row_test!(refusal_row_06, Row::Six);
row_test!(refusal_row_07, Row::Seven);
row_test!(refusal_row_07a, Row::SevenA);
row_test!(refusal_row_07b, Row::SevenB);
row_test!(refusal_row_07c, Row::SevenC);
row_test!(refusal_row_08, Row::Eight);
row_test!(refusal_row_09, Row::Nine);
row_test!(
    refusal_row_10_helper_unverified,
    Row::Ten("helper_unverified")
);
row_test!(
    refusal_row_10_helper_revision_mismatch,
    Row::Ten("helper_revision_mismatch")
);
row_test!(
    refusal_row_10_permission_missing,
    Row::Ten("permission_missing")
);
row_test!(refusal_row_10_source_missing, Row::Ten("source_missing"));
row_test!(
    refusal_row_10_format_unrecognized,
    Row::Ten("format_unrecognized")
);
row_test!(
    refusal_row_10_classic_outlook_missing,
    Row::Ten("classic_outlook_missing")
);
row_test!(
    refusal_row_10_outlook_not_running,
    Row::Ten("outlook_not_running")
);
row_test!(
    refusal_row_10_outlook_guard_may_prompt,
    Row::Ten("outlook_guard_may_prompt")
);
row_test!(
    refusal_row_10_data_service_missing,
    Row::Ten("data_service_missing")
);
row_test!(refusal_row_11, Row::Eleven);
row_test!(refusal_row_12, Row::Twelve);
row_test!(refusal_row_13, Row::Thirteen);
row_test!(refusal_row_14, Row::Fourteen);
row_test!(refusal_row_15, Row::Fifteen);

#[tokio::test]
async fn refusal_row_precedence_and_request_only_boundaries() {
    let mut first = refusal_case(Row::One);
    first.request["params"] = Value::Null;
    run(first).await;

    let mut third = refusal_case(Row::Three);
    third.request["params"]["op"] = json!("unknown");
    third.request["params"]["scope"] = json!({"calendar":[""]});
    run(third).await;
    let mut fourth = refusal_case(Row::Four);
    fourth.request["params"]["scope"] = json!({"calendar":[""]});
    run(fourth).await;
    let mut fifth = refusal_case(Row::Five);
    fifth.request["params"]["args"] = json!({"unexpected":true});
    run(fifth).await;

    // Wrong JSON types precede token lookup; value/range validation follows it.
    for (limit, row) in [(json!("wrong type"), Row::Two), (json!(0), Row::Three)] {
        let mut case = refusal_case(row);
        case.route = facts("prefrontal-core");
        case.request = json!({"method":SCOPE_CHOICES,"params":{"token":"unknown","key":"calendar","limit":limit}});
        run(case).await;
    }
    for key in ["".to_owned(), "k".repeat(257)] {
        let mut case = refusal_case(Row::Two);
        case.request["params"]["scope"] = json!({"calendar":["bound"]});
        case.request["params"]["key"] = json!(key);
        run(case).await;
    }
    let mut seventh = refusal_case(Row::Seven);
    seventh.binding = BindingMode::Unavailable;
    run(seventh).await;
    for row in [Row::SevenA, Row::SevenB] {
        let mut case = refusal_case(row);
        case.modern_macos = false;
        run(case).await;
    }
    // The unsupported OS decision must not wait for a busy or broken helper.
    run(refusal_case(Row::SevenC)).await;
    let mut unsupported_missing = refusal_case(Row::SevenC);
    unsupported_missing.source.failed_status.clear();
    unsupported_missing.source.reasons = vec![(Token::Contacts, "helper_unverified")];
    run(unsupported_missing).await;

    let mut stale = refusal_case(Row::Eleven);
    stale.request = event_call("events.get", json!({"id":"unknown"}));
    run(stale).await;
    let mut unavailable = refusal_case(Row::Ten("permission_missing"));
    unavailable.source.stale = true;
    unavailable.request = event_call("events.get", json!({"id":"unknown"}));
    unavailable.route = flow();
    run(unavailable).await;
}
