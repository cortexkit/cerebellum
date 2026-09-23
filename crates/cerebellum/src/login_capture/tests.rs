use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_core::identity::AcceptedBindFacts;
use serde_json::{json, Value};
use subc_protocol::Principal;

use super::test_support::{
    contains_bytes, fixture, fixture_with, BrowserScript, FakeEntry, Fixture, PLANTED_VALUE, ROOT,
};
use super::*;
use crate::elicit::AskOutcome;

fn accepted() -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string()),
        Some(Principal::Direct),
        None,
        Some(&["elicitation".to_string()]),
        &subc_protocol::RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
    )
}

fn ollama() -> CaptureRequest {
    CaptureRequest {
        credential_domain: "ollama.com".to_string(),
        account: "work".to_string(),
        fetch_url: "https://ollama.com/settings".to_string(),
        login_url: "https://ollama.com/signin".to_string(),
    }
}

fn allow() -> AskOutcome {
    AskOutcome::Answered(json!({"decision": "allow"}))
}

/// Run one capture, answering the consent question with `answer`. Returns the
/// outcome and the question that was put, if one was.
async fn capture(
    fixture: &Fixture,
    request: &CaptureRequest,
    answer: AskOutcome,
) -> (CaptureOutcome, Option<Value>) {
    capture_cancelling(fixture, request, answer, || false).await
}

async fn capture_cancelling(
    fixture: &Fixture,
    request: &CaptureRequest,
    answer: AskOutcome,
    cancelled: impl Fn() -> bool,
) -> (CaptureOutcome, Option<Value>) {
    let asked = Arc::new(Mutex::new(None));
    let recorded = Arc::clone(&asked);
    let facts = accepted();
    let outcome = fixture
        .module
        .run(
            request,
            CaptureCall {
                accepted: &facts,
                declares_elicitation: true,
                ask: move |question: Value, _deadline: Duration| {
                    *recorded.lock().unwrap() = Some(question);
                    async move { answer }
                },
                cancelled,
            },
        )
        .await;
    let question = asked.lock().unwrap().take();
    (outcome, question)
}

fn nothing_captured(fixture: &Fixture) {
    assert!(
        fixture.fs.files().is_empty(),
        "a file was written: {:?}",
        fixture.fs.contents()
    );
}

// --- leak -----------------------------------------------------------------

/// The planted cookie value reaches the one file and nothing else. The scanner
/// is first shown to find the value where it was planted, so an absence below
/// is evidence rather than a scanner that finds nothing anywhere.
#[tokio::test]
async fn a_planted_cookie_value_reaches_only_the_capture_file() {
    let fixture = fixture();
    let (outcome, question) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);

    let files = fixture.fs.files();
    assert_eq!(files.len(), 1);
    assert!(
        contains_bytes(&files[0].1, PLANTED_VALUE),
        "positive control: the scanner must find the planted value in the file"
    );
    assert_eq!(
        files[0].1,
        format!("session={PLANTED_VALUE}; csrf=t0k3n").as_bytes()
    );

    let reply = serde_json::to_vec(&outcome.reply).unwrap();
    assert!(
        !contains_bytes(&reply, PLANTED_VALUE),
        "the reply leaked it"
    );
    assert!(
        !contains_bytes(&reply, "csrf"),
        "the reply leaked a cookie name"
    );
    let journal = serde_json::to_vec(&outcome.journal).unwrap();
    assert!(
        !contains_bytes(&journal, PLANTED_VALUE),
        "the journal leaked it"
    );
    assert!(!contains_bytes(&journal, "csrf"));
    let question = serde_json::to_vec(&question.expect("a question was put")).unwrap();
    assert!(
        !contains_bytes(&question, PLANTED_VALUE),
        "the ask leaked it"
    );
    assert_eq!(outcome.journal.bytes, files[0].1.len() as u64);
}

#[test]
fn a_cookie_header_formats_as_its_length_only() {
    let header = CookieHeader::from_pairs([("session", PLANTED_VALUE)]).unwrap();
    let debug = format!("{header:?}");
    assert!(!debug.contains(PLANTED_VALUE), "{debug}");
    assert!(debug.contains(&header.len().to_string()));
}

#[test]
fn a_cookie_header_refuses_bytes_that_would_split_it() {
    assert_eq!(
        CookieHeader::from_pairs(Vec::<(&str, &str)>::new()).unwrap_err(),
        CookieHeaderError::Empty
    );
    for (name, value) in [("a;b", "v"), ("a", "v;w"), ("a", "v\r\nX: y"), ("", "v")] {
        assert_eq!(
            CookieHeader::from_pairs([(name, value)]).unwrap_err(),
            CookieHeaderError::Unusable,
            "{name:?}={value:?}"
        );
    }
}

// --- placement ------------------------------------------------------------

/// A directory tmutil reports as included refuses before any file or profile
/// directory exists, and before anything is launched.
#[tokio::test]
async fn an_included_capture_directory_refuses_before_any_file_or_profile_exists() {
    let fixture = fixture();
    *fixture.exclusion.answer.lock().unwrap() = Ok(false);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_location_not_excluded");
    assert_eq!(outcome.reply["tool"], "tmutil");
    assert_eq!(outcome.reply["path"], ROOT);
    assert_eq!(outcome.reply["reason"], "included");
    assert!(
        fixture.fs.contents().is_empty(),
        "{:?}",
        fixture.fs.contents()
    );
    assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
    assert_eq!(
        outcome.journal.outcome,
        "refused:capture_location_not_excluded"
    );
    assert_eq!(outcome.journal.deletion_succeeded, None);
}

#[tokio::test]
async fn a_timed_out_exclusion_tool_is_a_typed_refusal() {
    for (add, answer, reason) in [
        (Some(ToolError::TimedOut), Ok(true), "timed_out"),
        (None, Err(ToolError::TimedOut), "timed_out"),
        (None, Err(ToolError::Failed), "failed"),
    ] {
        let fixture = fixture();
        *fixture.exclusion.add_fails.lock().unwrap() = add;
        *fixture.exclusion.answer.lock().unwrap() = answer;
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        assert_eq!(outcome.reply["outcome"], "capture_location_not_excluded");
        assert_eq!(outcome.reply["reason"], reason);
        assert!(fixture.fs.contents().is_empty());
        assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
    }
}

/// Exclusion is proven on every capture, not once, because the person can
/// change Time Machine settings between two of them.
#[tokio::test]
async fn exclusion_is_proven_again_on_every_capture() {
    let fixture = fixture();
    let (first, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(first.reply["outcome"], "captured");
    let path = PathBuf::from(first.reply["path"].as_str().unwrap());
    fixture.fs.remove_file(&path).unwrap();
    *fixture.exclusion.answer.lock().unwrap() = Ok(false);
    let (second, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(second.reply["outcome"], "capture_location_not_excluded");
    let checks = fixture
        .events
        .snapshot()
        .into_iter()
        .filter(|event| event == "tmutil_isexcluded")
        .count();
    assert_eq!(checks, 2);
}

#[tokio::test]
async fn tmutil_output_is_read_strictly() {
    assert_eq!(parse_isexcluded("[Excluded]    /private/var/x\n"), Ok(true));
    assert_eq!(parse_isexcluded("[Included]    /Users/x\n"), Ok(false));
    assert_eq!(parse_isexcluded(""), Err(ToolError::Failed));
    assert_eq!(parse_isexcluded("Excluded"), Err(ToolError::Failed));
}

/// The bound on a tool call holds even when the tool never answers.
#[cfg(unix)]
#[test]
fn a_tool_that_never_answers_times_out() {
    let started = std::time::Instant::now();
    let result = run_bounded(
        Path::new("/bin/sleep"),
        &["5".as_ref()],
        Duration::from_millis(100),
    );
    assert_eq!(result, Err(ToolError::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(3));
}

// --- ordering -------------------------------------------------------------

/// The browser is closed and the throwaway profile deleted before the capture
/// returns, so a caller replying afterwards never replies while a second copy
/// of the session exists.
#[tokio::test]
async fn the_profile_is_deleted_before_the_capture_returns() {
    let fixture = fixture();
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured");
    let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
    assert!(
        !fixture.fs.exists(placement.profile_directory()),
        "the profile outlived the capture"
    );
    let events = fixture.events.snapshot();
    let position = |name: &str| events.iter().position(|event| event == name).unwrap();
    assert!(position("file_written") < position("browser_closed"));
    assert!(position("browser_closed") < position("profile_deleted"));
    assert_eq!(outcome.journal.deletion_succeeded, Some(true));
}

/// A profile that cannot be deleted leaves two copies of the session, so the
/// file is withdrawn and the capture reports the profile by path.
#[tokio::test]
async fn an_undeletable_profile_withdraws_the_file() {
    let fixture = fixture();
    fixture
        .fs
        .directories_undeletable
        .store(true, Ordering::SeqCst);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_profile_not_deleted");
    let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
    assert_eq!(
        outcome.reply["path"],
        placement.profile_directory().display().to_string()
    );
    nothing_captured(&fixture);
    assert_eq!(outcome.journal.deletion_succeeded, Some(false));
    assert!(outcome.captured_file.is_none());

    // The profile left behind is residue, and the next capture says so.
    fixture
        .fs
        .directories_undeletable
        .store(false, Ordering::SeqCst);
    let (next, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(next.reply["outcome"], "capture_residue_present");
    assert_eq!(
        next.reply["path"],
        placement.profile_directory().display().to_string()
    );
    assert!(next.reply["reason"]
        .as_str()
        .unwrap()
        .starts_with("deletion_failed:"));
}

// --- residue --------------------------------------------------------------

#[tokio::test]
async fn leftover_residue_refuses_the_next_capture_by_path() {
    for entry in [FakeEntry::File(b"old".to_vec()), FakeEntry::Dir] {
        let fixture = fixture();
        let leftover = Path::new(ROOT).join("login-leftover.cookie");
        fixture
            .fs
            .plant(Path::new(ROOT), FakeEntry::Dir, fixture.clock.now());
        fixture.fs.plant(&leftover, entry, fixture.clock.now());
        let (outcome, question) = capture(&fixture, &ollama(), allow()).await;
        assert_eq!(outcome.reply["outcome"], "capture_residue_present");
        assert_eq!(outcome.reply["path"], leftover.display().to_string());
        assert!(outcome.reply["remedy"]
            .as_str()
            .unwrap()
            .contains(&leftover.display().to_string()));
        assert!(question.is_none(), "the person was asked anyway");
        assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn a_startup_sweep_that_cannot_delete_leaves_the_refusal_in_place() {
    let fixture = fixture();
    let stale = Path::new(ROOT).join("login-stale.cookie");
    fixture
        .fs
        .plant(Path::new(ROOT), FakeEntry::Dir, fixture.clock.now());
    fixture.fs.plant(
        &stale,
        FakeEntry::File(b"x".to_vec()),
        fixture.clock.now() - FILE_LIFETIME - Duration::from_secs(1),
    );
    fixture.fs.undeletable.lock().unwrap().insert(stale.clone());

    fixture.module.sweep_at_startup();
    assert!(fixture.fs.exists(&stale));
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_residue_present");
    assert_eq!(outcome.reply["path"], stale.display().to_string());
    assert_eq!(outcome.reply["reason"], "deletion_failed:PermissionDenied");
}

#[tokio::test]
async fn the_startup_sweep_deletes_stale_residue_and_schedules_the_rest() {
    let fixture = fixture();
    let now = fixture.clock.now();
    let stale = Path::new(ROOT).join("login-stale.cookie");
    let young = Path::new(ROOT).join("login-young.cookie");
    fixture.fs.plant(Path::new(ROOT), FakeEntry::Dir, now);
    fixture.fs.plant(
        &stale,
        FakeEntry::File(b"x".to_vec()),
        now - FILE_LIFETIME - Duration::from_secs(1),
    );
    let young_written = now - Duration::from_secs(60);
    fixture
        .fs
        .plant(&young, FakeEntry::File(b"y".to_vec()), young_written);

    fixture.module.sweep_at_startup();
    assert!(!fixture.fs.exists(&stale));
    assert!(fixture.fs.exists(&young));
    assert_eq!(
        fixture.scheduler.deadlines(),
        vec![young_written + FILE_LIFETIME]
    );
    fixture.scheduler.run_due(young_written + FILE_LIFETIME);
    assert!(!fixture.fs.exists(&young));
}

#[tokio::test]
async fn a_second_concurrent_capture_refuses() {
    let fixture = fixture();
    let _held = fixture.module.try_begin().expect("first custody");
    let (outcome, question) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_in_progress");
    assert!(question.is_none());
}

// --- consent --------------------------------------------------------------

/// Only an affirmative answer proceeds. Each other ending writes nothing,
/// launches nothing and proves nothing about placement, because none of it
/// was consented to.
#[tokio::test]
async fn only_an_affirmative_answer_proceeds() {
    let cases = [
        (AskOutcome::Answered(json!({"decision": "deny"})), "deny"),
        (AskOutcome::NoAnswer, "no_answer"),
        (AskOutcome::NotPutToAnyone, "not_put_to_anyone"),
        (AskOutcome::Undeliverable, "undeliverable"),
        (
            AskOutcome::Answered(json!({"decision": "no_answer"})),
            "unrecognized_answer",
        ),
        (
            AskOutcome::Answered(json!({"decision": "not_put_to_anyone"})),
            "unrecognized_answer",
        ),
        (
            AskOutcome::Answered(json!({"decision": "yes"})),
            "unrecognized_answer",
        ),
        (AskOutcome::Answered(json!({})), "unrecognized_answer"),
    ];
    for (answer, reason) in cases {
        let fixture = fixture();
        let (outcome, question) = capture(&fixture, &ollama(), answer).await;
        assert!(question.is_some());
        assert_eq!(outcome.reply["outcome"], "capture_consent_not_given");
        assert_eq!(outcome.reply["reason"], reason);
        assert!(fixture.fs.contents().is_empty(), "{reason}");
        assert_eq!(
            fixture.launcher.launches.load(Ordering::SeqCst),
            0,
            "{reason}"
        );
        assert!(
            !fixture.events.contains_prefix("tmutil"),
            "{reason}: placement ran without consent"
        );
    }
}

#[test]
fn the_question_names_the_holder_site_account_and_lifetime() {
    let question = consent_question(&ollama(), FILE_LIFETIME);
    assert_eq!(
        question["params"]["message"],
        "insula will hold a copy of your ollama.com login"
    );
    let context = question["params"]["context"].as_str().unwrap();
    assert!(context.contains("Account: work"));
    assert!(context.contains("deleted after 10 minutes"));
    assert!(context.contains("ck auth put"));
    assert_eq!(
        question["params"]["requestedSchema"]["properties"]["decision"]["enum"],
        json!(["allow", "deny"])
    );
}

#[tokio::test]
async fn an_undeclared_elicitation_route_is_refused_without_asking() {
    let fixture = fixture();
    let facts = accepted();
    let outcome = fixture
        .module
        .run(
            &ollama(),
            CaptureCall {
                accepted: &facts,
                declares_elicitation: false,
                ask: |_: Value, _: Duration| async { AskOutcome::Undeliverable },
                cancelled: || false,
            },
        )
        .await;
    assert_eq!(outcome.reply["outcome"], "elicitation_undeclared");
    assert!(fixture.fs.contents().is_empty());
}

// --- domain ---------------------------------------------------------------

#[test]
fn urls_are_admitted_only_on_the_credential_domain() {
    let admitted = [
        ("https://qwencloud.com/x", "qwencloud.com"),
        ("https://cs-data.qwencloud.com/api", "qwencloud.com"),
        ("https://a.b.qwencloud.com", "qwencloud.com"),
        ("https://CS-Data.QwenCloud.com/api", "qwencloud.com"),
        ("https://app.factory.ai/login", "factory.ai"),
        ("https://api.factory.ai/api/billing/limits", "factory.ai"),
    ];
    for (url, domain) in admitted {
        assert!(host_within_domain(url, domain).is_some(), "{url}");
    }
    let refused = [
        ("https://evilqwencloud.com/", "qwencloud.com"),
        ("https://qwencloud.com.evil.net/", "qwencloud.com"),
        ("http://qwencloud.com/", "qwencloud.com"),
        ("https://user@qwencloud.com/", "qwencloud.com"),
        ("https://evil.net@qwencloud.com/", "qwencloud.com"),
        ("https://qwencloud.com:8443/", "qwencloud.com"),
        ("https://.qwencloud.com/", "qwencloud.com"),
        ("https://x..qwencloud.com/", "qwencloud.com"),
        ("https://qwencloud.com /", "qwencloud.com"),
        ("qwencloud.com", "qwencloud.com"),
        ("https:///path", "qwencloud.com"),
    ];
    for (url, domain) in refused {
        assert!(host_within_domain(url, domain).is_none(), "{url}");
    }
}

#[tokio::test]
async fn a_url_outside_the_credential_domain_is_refused_by_name() {
    for (field, url) in [
        ("fetch_url", "https://evilollama.com/settings"),
        ("login_url", "https://ollama.com.evil.net/signin"),
        ("fetch_url", "http://ollama.com/settings"),
    ] {
        let fixture = fixture();
        let mut request = ollama();
        match field {
            "fetch_url" => request.fetch_url = url.to_string(),
            _ => request.login_url = url.to_string(),
        }
        let (outcome, question) = capture(&fixture, &request, allow()).await;
        assert_eq!(outcome.reply["outcome"], "capture_url_outside_domain");
        assert_eq!(outcome.reply["url"], url);
        assert!(question.is_none());
        assert!(fixture.fs.contents().is_empty());
    }
}

/// factory.ai logs in on one subdomain and serves the quota on another. The
/// login observation is keyed on the login page's origin; the header is read
/// for the fetch URL.
#[tokio::test]
async fn login_and_fetch_on_different_subdomains_are_admitted() {
    let fixture = fixture();
    let request = CaptureRequest {
        credential_domain: "factory.ai".to_string(),
        account: "work".to_string(),
        fetch_url: "https://api.factory.ai/api/billing/limits".to_string(),
        login_url: "https://app.factory.ai".to_string(),
    };
    let (outcome, _) = capture(&fixture, &request, allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
    let events = fixture.events.snapshot();
    assert!(events.contains(&"navigate:https://app.factory.ai".to_string()));
    assert!(events.contains(&"cookie_names:https://app.factory.ai".to_string()));
    assert!(events.contains(&"cookie_header:https://api.factory.ai/api/billing/limits".to_string()));
    assert_eq!(outcome.journal.origin, "https://app.factory.ai");
    assert_eq!(outcome.reply["credential_id"], "cookie:factory.ai:work");
}

#[test]
fn request_parameters_are_closed_and_the_account_is_required() {
    let valid = json!({
        "credential_domain": "ollama.com",
        "account": "work",
        "fetch_url": "https://ollama.com/settings",
        "login_url": "https://ollama.com/signin",
    });
    assert_eq!(parse_request(valid.as_object().unwrap()).unwrap(), ollama());
    let cases = [
        ("extra", json!(true), "extra", "unknown_field"),
        ("account", json!(""), "account", "unsupported_value"),
        ("account", json!("a b"), "account", "unsupported_value"),
        ("account", json!("a;rm"), "account", "unsupported_value"),
        ("account", json!(7), "account", "wrong_type"),
        (
            "credential_domain",
            json!("Ollama.com"),
            "credential_domain",
            "unsupported_value",
        ),
        (
            "credential_domain",
            json!("com"),
            "credential_domain",
            "unsupported_value",
        ),
    ];
    for (key, value, field, reason) in cases {
        let mut params = valid.as_object().unwrap().clone();
        params.insert(key.to_string(), value);
        let error = parse_request(&params).unwrap_err();
        assert_eq!((error.field.as_str(), error.reason), (field, reason));
    }
    let mut missing = valid.as_object().unwrap().clone();
    missing.remove("account");
    let error = parse_request(&missing).unwrap_err();
    assert_eq!(
        (error.field.as_str(), error.reason),
        ("account", "missing_field")
    );
}

// --- commands -------------------------------------------------------------

/// Compared against literal strings rather than strings built the way the code
/// under test builds them.
#[tokio::test]
async fn the_printed_commands_carry_exactly_the_requested_id_and_selector() {
    let fixture = fixture();
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    let path = outcome.reply["path"].as_str().unwrap().to_string();
    assert!(path.starts_with("/fake-tmp/ck-cerebellum-capture/login-"));
    assert_eq!(
        outcome.reply["commands"],
        json!([
            format!("ck auth put --id cookie:ollama.com:work --payload-file {path}"),
            "ck auth grant --principal reserved:insula --selector-kind exact --selector cookie:ollama.com:work --operation read",
        ])
    );
    assert_eq!(outcome.reply["credential_id"], "cookie:ollama.com:work");
    assert_eq!(outcome.reply["holder"], "reserved:insula");
    assert!(outcome.reply["replace_note"]
        .as_str()
        .unwrap()
        .contains("--replace"));
}

#[test]
fn a_path_that_needs_quoting_is_quoted() {
    let [put, _] = operator_commands("cookie:ollama.com:work", Path::new("/tmp/a b/it's.cookie"));
    assert_eq!(
        put,
        "ck auth put --id cookie:ollama.com:work --payload-file '/tmp/a b/it'\\''s.cookie'"
    );
}

// --- reply ----------------------------------------------------------------

/// A captured reply carries every field the operator needs and passes the
/// declared closed reply schema.
#[tokio::test]
async fn a_captured_reply_is_complete_and_passes_its_schema() {
    let fixture = fixture();
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    for field in [
        "outcome",
        "path",
        "bytes",
        "expires_at",
        "credential_id",
        "holder",
        "commands",
        "replace_note",
    ] {
        assert!(outcome.reply.get(field).is_some(), "missing {field}");
    }
    assert_eq!(outcome.reply["expires_at"], "2026-09-21T14:23:20.000Z");
    crate::browser::validate_browser_result(crate::management::CAPTURE_LOGIN, &outcome.reply)
        .expect("the captured reply matches its schema");
}

// --- handoff endings --------------------------------------------------------

#[tokio::test]
async fn a_closed_window_ends_with_no_login_observed_and_nothing_written() {
    let fixture = fixture();
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        exits_at_poll: Some(1),
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "no_login_observed");
    nothing_captured(&fixture);
    assert!(fixture.events.contains_prefix("profile_deleted"));
    assert_eq!(outcome.journal.outcome, "no_login_observed");
    assert_eq!(outcome.journal.deletion_succeeded, Some(true));
}

#[tokio::test]
async fn an_unobserved_login_expires_with_nothing_written() {
    let fixture = fixture_with(|env| env.handoff_duration = Duration::from_millis(30));
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        logs_in: false,
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "expired");
    nothing_captured(&fixture);
    assert!(fixture.events.contains_prefix("profile_deleted"));
}

#[tokio::test]
async fn a_cancel_during_the_handoff_writes_nothing_and_deletes_the_profile() {
    let fixture = fixture();
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        logs_in: false,
        ..BrowserScript::default()
    };
    let presented = fixture.events.clone();
    let (outcome, _) = capture_cancelling(&fixture, &ollama(), allow(), move || {
        presented.contains_prefix("present")
    })
    .await;
    assert_eq!(outcome.reply["outcome"], "cancelled");
    nothing_captured(&fixture);
    assert!(fixture.events.contains_prefix("browser_closed"));
    assert!(fixture.events.contains_prefix("profile_deleted"));
}

#[tokio::test]
async fn zero_cookies_for_the_fetch_url_writes_nothing() {
    let fixture = fixture();
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        cookies: Vec::new(),
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_no_cookies_for_url");
    assert_eq!(outcome.reply["url"], "https://ollama.com/settings");
    nothing_captured(&fixture);
    assert!(fixture.events.contains_prefix("profile_deleted"));
}

#[tokio::test]
async fn a_refused_launch_deletes_the_profile_directory() {
    let fixture = fixture();
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        launch_refusal: Some("executable_identity".to_string()),
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_launch_failed");
    assert_eq!(outcome.reply["stage"], "executable_identity");
    assert!(
        fixture.fs.contents().is_empty(),
        "{:?}",
        fixture.fs.contents()
    );
}

#[tokio::test]
async fn an_unsupported_platform_refuses_before_touching_anything() {
    let fixture = fixture_with(|env| env.platform_supported = false);
    let (outcome, question) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_unsupported_on_platform");
    assert!(question.is_none());
    assert!(fixture.fs.contents().is_empty());
    assert!(!fixture.events.contains_prefix("tmutil"));
}

// --- deletion -------------------------------------------------------------

#[tokio::test]
async fn the_file_is_unlinked_at_its_deadline() {
    let fixture = fixture();
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    let path = outcome.captured_file.clone().unwrap();
    let deadline = fixture.clock.now() + FILE_LIFETIME;
    assert_eq!(fixture.scheduler.deadlines(), vec![deadline]);
    fixture.scheduler.run_due(deadline - Duration::from_secs(1));
    assert!(fixture.fs.exists(&path), "deleted before its deadline");
    fixture.clock.advance(FILE_LIFETIME);
    fixture.scheduler.run_due(deadline);
    assert!(!fixture.fs.exists(&path));
}

/// A failed unlink at the deadline is kept, not swallowed: the next capture
/// refuses, naming the file and why it could not be removed.
#[tokio::test]
async fn a_failed_unlink_at_the_deadline_surfaces_as_residue() {
    let fixture = fixture();
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    let path = outcome.captured_file.clone().unwrap();
    fixture.fs.undeletable.lock().unwrap().insert(path.clone());
    fixture
        .scheduler
        .run_due(fixture.clock.now() + FILE_LIFETIME);
    assert!(fixture.fs.exists(&path));
    let (next, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(next.reply["outcome"], "capture_residue_present");
    assert_eq!(next.reply["path"], path.display().to_string());
    assert_eq!(next.reply["reason"], "deletion_failed:PermissionDenied");
}

/// The production scheduler really runs the deletion when the deadline comes.
#[tokio::test]
async fn the_production_scheduler_deletes_at_the_deadline() {
    let fixture = fixture_with(|env| {
        env.clock = Arc::new(SystemWallClock);
        env.scheduler = Arc::new(TokioDeletionScheduler);
        env.file_lifetime = Duration::from_millis(50);
    });
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    let path = outcome.captured_file.clone().unwrap();
    assert!(fixture.fs.exists(&path));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !fixture.fs.exists(&path),
        "the deadline passed and the file stayed"
    );
}
