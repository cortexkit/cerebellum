use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use cerebellum_core::identity::AcceptedBindFacts;
use serde_json::{json, Value};
use subc_protocol::Principal;

use super::test_support::{
    contains_bytes, fixture, fixture_with, BrowserScript, FakeEntry, FakeReply, Fixture,
    ScriptedVerification, PLANTED_VALUE, ROOT,
};
use super::vault::VaultReachError;
use super::*;
use crate::cingulate_client::desk::ConsentDesk;
use crate::cingulate_client::live_call::{LiveCall, NotLive};
use crate::cingulate_client::wire;
use crate::cingulate_client::{Reply, ScriptedCingulate};
use crate::computer_grants::{AlwaysOpenRoute, LoginCapability, QuestionCarrier};

fn accepted() -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string()),
        Some(Principal::Direct),
        None,
        None,
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

/// The Cingulate id the scripted capture card is raised under, which an
/// approval names as the deposit's consent.
const ELICITATION_ID: &str = "el_test_approval_1";

/// How the scripted Cingulate ends the capture card.
enum Answer {
    /// The person chose this option on the card raised as [`ELICITATION_ID`].
    Chose(&'static str),
    /// The person chose this option on a card Cingulate raised under this id.
    ChoseOn(String, &'static str),
    /// The card expired unanswered.
    Expired,
    /// Cingulate refused to raise the card, with this refusal code.
    Refused(&'static str),
    /// The route to Cingulate failed while the card was being raised.
    Transport,
}

fn allow() -> Answer {
    Answer::Chose("allow")
}

impl Answer {
    /// A scripted Cingulate whose replies end one capture card as `self`
    /// says. For `Refused` and `Transport` the `consent.request` itself fails
    /// and no card is raised; otherwise the card is raised and the capture
    /// call's wait on it (`consent.await`) returns its ending at once.
    fn script(self) -> Arc<ScriptedCingulate> {
        let script = ScriptedCingulate::new();
        let (id, mut record) = match self {
            Answer::Refused(code) => {
                script.then(wire::CONSENT_REQUEST, Reply::Refused(code));
                return script;
            }
            Answer::Transport => {
                script.then(wire::CONSENT_REQUEST, Reply::Transport);
                return script;
            }
            Answer::Chose(choice) => (
                ELICITATION_ID.to_string(),
                json!({"state":"answered","answered_choice_id":choice}),
            ),
            Answer::ChoseOn(id, choice) => {
                (id, json!({"state":"answered","answered_choice_id":choice}))
            }
            Answer::Expired => (ELICITATION_ID.to_string(), json!({"state":"expired"})),
        };
        record["elicitation_id"] = json!(id);
        script
            .then(
                wire::CONSENT_REQUEST,
                Reply::Result(json!({"elicitation_id": id})),
            )
            .then(wire::CONSENT_AWAIT, Reply::Result(record));
        script
    }
}

/// The agent call the capture card is raised under: a live call from an
/// admitted agent session, or, when `scoped` is false, a call that carries no
/// agent session and so can raise no card.
struct Carrier {
    desk: Arc<ConsentDesk>,
    guard: Arc<cerebellum_core::dispatch::InFlightGuard>,
    scoped: bool,
}

impl QuestionCarrier for Carrier {
    fn desk(&self) -> Arc<ConsentDesk> {
        Arc::clone(&self.desk)
    }
    fn live(&self) -> Result<LiveCall, NotLive> {
        let stamp = crate::computer_grants::tests::stamp("test-project");
        LiveCall::from_inbound(
            self.scoped.then_some(&stamp),
            &self.guard,
            Arc::new(AlwaysOpenRoute),
        )
    }
}

/// The consent request of one capture call: its card goes to `script`, and
/// `scoped` says whether the call comes from an agent session (see
/// [`Carrier`]).
fn consent(
    script: &Arc<ScriptedCingulate>,
    request: &CaptureRequest,
    scoped: bool,
) -> LoginConsentRequest {
    let clock = cerebellum_core::clock::FakeClock::new();
    let timing = Arc::new(cerebellum_core::dispatch::DispatchTimingState::new(&clock));
    let carrier = Arc::new(Carrier {
        desk: Arc::new(ConsentDesk::new(Arc::new(Arc::clone(script)))),
        guard: Arc::new(timing.enter(&clock)),
        scoped,
    });
    // The module never drains during these tests. The sender is kept alive
    // on purpose: a wait on a closed drain signal ends at once, which the
    // consent wait would read as the module draining.
    let (drain_signal, drain) = tokio::sync::watch::channel(false);
    std::mem::forget(drain_signal);
    LoginConsentRequest {
        conversation_key: "conversation".into(),
        capability: LoginCapability::CaptureLogin,
        parameters: request.consent_parameters(),
        carrier,
        cancel: None,
        drain,
        route: Arc::new(AlwaysOpenRoute),
        park_guard: None,
    }
}

/// The header the fake browser's default cookies make.
fn planted_header() -> String {
    format!("session={PLANTED_VALUE}; csrf=t0k3n")
}

/// Run one capture, its card ending as `answer`. Returns the outcome and the
/// card (`consent.request` params) that was raised, if one was.
async fn capture(
    fixture: &Fixture,
    request: &CaptureRequest,
    answer: Answer,
) -> (CaptureOutcome, Option<Value>) {
    capture_cancelling(fixture, request, answer, || false).await
}

async fn capture_cancelling(
    fixture: &Fixture,
    request: &CaptureRequest,
    answer: Answer,
    cancelled: impl Fn() -> bool,
) -> (CaptureOutcome, Option<Value>) {
    capture_with(fixture, request, &answer.script(), true, cancelled).await
}

async fn capture_with(
    fixture: &Fixture,
    request: &CaptureRequest,
    script: &Arc<ScriptedCingulate>,
    scoped: bool,
    cancelled: impl Fn() -> bool,
) -> (CaptureOutcome, Option<Value>) {
    let grants = Arc::new(ComputerGrants::in_memory());
    let facts = accepted();
    let outcome = fixture
        .module
        .run(
            request,
            CaptureCall {
                accepted: &facts,
                grants: &grants,
                consent: consent(script, request, scoped),
                cancelled,
            },
        )
        .await;
    let question = script
        .calls()
        .into_iter()
        .find(|(method, _)| method == wire::CONSENT_REQUEST)
        .map(|(_, params)| params);
    (outcome, question)
}

/// Nothing was written to disk and nothing was sent to the vault.
fn nothing_captured(fixture: &Fixture) {
    assert!(
        fixture.fs.files().is_empty(),
        "a file was written: {:?}",
        fixture.fs.contents()
    );
    assert_eq!(fixture.vault.calls(), 0, "a deposit was made");
}

/// The reply's keys, sorted.
fn keys(reply: &Value) -> Vec<String> {
    let mut keys = reply
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

// --- leak -----------------------------------------------------------------

/// The planted cookie value reaches the vault request and nothing else. The
/// scanner is first shown to find the value where it was planted, so an
/// absence below is evidence rather than a scanner that finds nothing anywhere.
#[tokio::test]
async fn a_planted_cookie_value_reaches_only_the_vault_request() {
    let fixture = fixture();
    let (outcome, question) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);

    let requests = fixture.vault.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert!(
        contains_bytes(&requests[0], PLANTED_VALUE),
        "positive control: the scanner must find the planted value in the request"
    );
    assert_eq!(
        fixture.vault.request_params()[0]["cookie"],
        planted_header()
    );
    assert!(fixture.fs.files().is_empty(), "{:?}", fixture.fs.contents());

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
    assert_eq!(outcome.journal.bytes, planted_header().len() as u64);
}

/// Every way a deposit can end, the planted value stays out of the reply, the
/// journal record and the remedy text. The vault's request is the positive
/// control each time, so a pass is not a capture that never read the cookie.
#[tokio::test]
async fn a_planted_cookie_value_never_reaches_the_reply_the_journal_or_an_error() {
    let endings = [
        ("stored", vec![]),
        (
            "refused",
            vec![FakeReply::refused("permanent", "not_found")],
        ),
        (
            "transient",
            vec![FakeReply::refused("transient", "store_busy"); 4],
        ),
        (
            "malformed",
            vec![FakeReply::Raw(json!({"result": {"id": 1}}))],
        ),
        (
            "call failed",
            vec![FakeReply::Fails(VaultReachError::CallFailed { code: None })],
        ),
    ];
    for (ending, replies) in endings {
        let fixture = fixture();
        fixture.vault.script(replies);
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        assert!(
            fixture
                .vault
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| contains_bytes(request, PLANTED_VALUE)),
            "{ending}: positive control: every request carries the planted value"
        );
        assert!(
            fixture.vault.calls() >= 1,
            "{ending}: nothing was deposited"
        );
        for (what, bytes) in [
            ("reply", serde_json::to_vec(&outcome.reply).unwrap()),
            ("journal", serde_json::to_vec(&outcome.journal).unwrap()),
            ("debug", format!("{outcome:?}").into_bytes()),
        ] {
            assert!(
                !contains_bytes(&bytes, PLANTED_VALUE),
                "{ending}: the {what} leaked it"
            );
            assert!(
                !contains_bytes(&bytes, "csrf"),
                "{ending}: the {what} named a cookie"
            );
        }
    }
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
    // An exclusion is added only to a root not already excluded, so the
    // add's failure is reached only when the first read says included.
    for (add, answer, reason) in [
        (Some(ToolError::TimedOut), Ok(false), "timed_out"),
        (None, Err(ToolError::TimedOut), "timed_out"),
        (None, Err(ToolError::Failed), "failed"),
    ] {
        let fixture = fixture();
        *fixture.exclusion.add_fails.lock().unwrap() = add;
        *fixture.exclusion.answer.lock().unwrap() = answer;
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        assert_eq!(outcome.reply["outcome"], "capture_location_not_excluded");
        assert_eq!(outcome.reply["reason"], reason);
        // A tool that did not answer says nothing about the exclusion, so
        // the remedy must not send the caller to fix one.
        let remedy = outcome.reply["remedy"].as_str().unwrap();
        assert_eq!(
            remedy.contains("as excluded"),
            reason != "timed_out",
            "{reason}: {remedy}"
        );
        assert!(fixture.fs.contents().is_empty());
        assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
    }
}

/// A root already excluded is captured without `tmutil addexclusion`, which
/// was measured at about 11 s on the desk Mac and outran the tool deadline
/// every time. A root not yet excluded gets the exclusion added and is read
/// again before anything is written.
#[tokio::test]
async fn an_exclusion_is_added_only_when_the_root_is_not_already_excluded() {
    let tmutil_calls = |fixture: &Fixture| -> Vec<String> {
        fixture
            .events
            .snapshot()
            .into_iter()
            .filter(|event| event.starts_with("tmutil_"))
            .collect()
    };

    let excluded = fixture();
    let (outcome, _) = capture(&excluded, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
    assert_eq!(tmutil_calls(&excluded), ["tmutil_isexcluded"]);

    let included = fixture();
    *included.exclusion.answer.lock().unwrap() = Ok(false);
    *included.exclusion.answer_after_add.lock().unwrap() = Some(Ok(true));
    let (outcome, _) = capture(&included, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
    assert_eq!(
        tmutil_calls(&included),
        [
            "tmutil_isexcluded",
            "tmutil_addexclusion",
            "tmutil_isexcluded"
        ]
    );
}

/// Exclusion is proven on every capture, not once, because the person can
/// change Time Machine settings between two of them.
#[tokio::test]
async fn exclusion_is_proven_again_on_every_capture() {
    let fixture = fixture();
    let (first, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(first.reply["outcome"], "captured");
    *fixture.exclusion.answer.lock().unwrap() = Ok(false);
    let (second, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(second.reply["outcome"], "capture_location_not_excluded");
    let checks = fixture
        .events
        .snapshot()
        .into_iter()
        .filter(|event| event == "tmutil_isexcluded")
        .count();
    // One read for the first capture, which was already excluded; two for the
    // second, which read included, added the exclusion and read again.
    assert_eq!(checks, 3);
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

/// The browser is closed and the throwaway profile deleted before the login is
/// deposited and before the capture returns, so once the login is stored no
/// second copy of the session exists.
#[tokio::test]
async fn the_profile_is_deleted_before_the_deposit_and_the_return() {
    let fixture = fixture();
    // Held inside the deletion so that a deletion moved off the return path
    // would still be running when the check below looks.
    *fixture.fs.removal_delay.lock().unwrap() = Duration::from_millis(50);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured");
    let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
    assert!(
        !fixture.fs.exists(placement.profile_directory()),
        "the profile outlived the capture"
    );
    let events = fixture.events.snapshot();
    let position = |name: &str| events.iter().position(|event| event == name).unwrap();
    assert!(position("cookie_header:https://ollama.com/settings") < position("browser_closed"));
    assert!(position("browser_closed") < position("profile_deleted"));
    assert!(position("profile_deleted") < position("vault_open"));
    assert_eq!(outcome.journal.deletion_succeeded, Some(true));
}

/// A profile that cannot be deleted would leave a second copy of the session
/// beside a stored one, and a deposit cannot be withdrawn, so nothing is
/// stored and the capture reports the profile by path.
#[tokio::test]
async fn an_undeletable_profile_stores_nothing() {
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
    assert_eq!(fixture.vault.opens.load(Ordering::SeqCst), 0);
    assert_eq!(outcome.journal.deletion_succeeded, Some(false));

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
        fixture.fs.plant(Path::new(ROOT), FakeEntry::Dir);
        fixture.fs.plant(&leftover, entry);
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
    let stale = Path::new(ROOT).join("profile-stale");
    fixture.fs.plant(Path::new(ROOT), FakeEntry::Dir);
    fixture.fs.plant(&stale, FakeEntry::Dir);
    fixture.fs.undeletable.lock().unwrap().insert(stale.clone());

    fixture.module.sweep_at_startup();
    assert!(fixture.fs.exists(&stale));
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_residue_present");
    assert_eq!(outcome.reply["path"], stale.display().to_string());
    assert_eq!(outcome.reply["reason"], "deletion_failed:PermissionDenied");
}

/// At startup nothing in the capture root is in use, so all of it goes at
/// once: a profile a crashed capture left, and a cookie file an earlier build
/// wrote.
#[tokio::test]
async fn the_startup_sweep_deletes_all_residue() {
    let fixture = fixture();
    let profile = Path::new(ROOT).join("profile-crashed");
    let old_file = Path::new(ROOT).join("login-old.cookie");
    fixture.fs.plant(Path::new(ROOT), FakeEntry::Dir);
    fixture.fs.plant(&profile, FakeEntry::Dir);
    fixture.fs.plant(
        &old_file,
        FakeEntry::File(PLANTED_VALUE.as_bytes().to_vec()),
    );

    fixture.module.sweep_at_startup();
    assert!(
        fixture.fs.contents().is_empty(),
        "{:?}",
        fixture.fs.contents()
    );
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
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
        (Answer::Chose("deny"), "deny"),
        (Answer::Expired, "no_answer"),
        (
            Answer::Refused("elicitation_requester_refused"),
            "not_put_to_anyone",
        ),
        (Answer::Transport, "undeliverable"),
        (Answer::Chose("no_answer"), "unrecognized_answer"),
        (Answer::Chose("not_put_to_anyone"), "unrecognized_answer"),
        (Answer::Chose("yes"), "unrecognized_answer"),
    ];
    for (answer, reason) in cases {
        let fixture = fixture();
        let (outcome, question) = capture(&fixture, &ollama(), answer).await;
        assert!(question.is_some());
        assert_eq!(outcome.reply["outcome"], "capture_consent_not_given");
        assert_eq!(outcome.reply["reason"], reason);
        // A question nobody saw must not tell the caller to ask again: the
        // next one reaches nobody either, so that remedy is a loop.
        let remedy = outcome.reply["remedy"].as_str().unwrap();
        assert_eq!(
            remedy.contains("Ask again"),
            reason != "not_put_to_anyone" && reason != "undeliverable",
            "{reason}: {remedy}"
        );
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
fn the_question_names_the_holder_site_account_and_the_vault() {
    let question = consent_question(&ollama());
    crate::consent_card::assert_contract(&question, &["allow", "deny"], "deny");
    // Only the params are rendered: the id the deposit later names as its
    // consent is the one Cingulate gives the card when it is raised.
    assert!(question.get("id").is_none(), "{question}");
    assert_eq!(
        question["params"]["prompt"],
        "insula will hold a copy of your ollama.com login."
    );
    assert_eq!(question["params"]["urgency"], "high");
    assert_eq!(
        question["params"]["scope"],
        json!({"credential_domain": "ollama.com", "account": "work"})
    );
    let facts = &question["params"]["facts"];
    assert_eq!(facts[0], json!({"label": "Account", "value": "work"}));
    let text = facts.to_string();
    assert!(text.contains("stored in the vault for insula"), "{text}");
    assert!(
        text.contains("Some sites allow one sign-in at a time; signing in here may sign you out of this site in your other browsers."),
        "{text}"
    );
    assert!(!text.contains("ck auth"), "{text}");
}

/// The deposit names the card the person approved by the id Cingulate raised
/// it under; the vault binds that id into its audit row.
#[tokio::test]
async fn the_deposit_names_the_card_the_person_answered_as_its_consent() {
    let fixture = fixture();
    let answer = Answer::ChoseOn("el_7Qx-relay.card:42".into(), "allow");
    let (outcome, question) = capture(&fixture, &ollama(), answer).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
    validate(&outcome.reply);
    assert_eq!(
        fixture.vault.request_params()[0]["consent_ref"],
        "el_7Qx-relay.card:42"
    );
    // The card sent to Cingulate carries no id of this module's own, so the
    // `consent_ref` above can only be the id Cingulate returned.
    assert!(question.unwrap().get("id").is_none());
}

/// An approval of a card whose Cingulate id cannot serve as the deposit's
/// consent reference is refused right after consent: no browser is
/// launched, nothing is placed or written, and the vault is never opened.
#[tokio::test]
async fn an_approval_without_a_usable_elicitation_id_refuses_before_launch() {
    let long = "x".repeat(129);
    for (case, id) in [
        ("empty", ""),
        ("whitespace", "el 1"),
        ("tab", "el\t1"),
        ("too long", long.as_str()),
        ("non-ASCII", "el_é"),
    ] {
        let fixture = fixture();
        let (outcome, _) = capture(
            &fixture,
            &ollama(),
            Answer::ChoseOn(id.to_string(), "allow"),
        )
        .await;
        let reply = &outcome.reply;
        assert_eq!(reply["outcome"], "capture_not_stored", "{case}: {reply}");
        assert_eq!(reply["reason"], CONSENT_NOT_LINKABLE, "{case}: {reply}");
        assert!(
            reply["remedy"]
                .as_str()
                .unwrap()
                .contains("cannot serve as the vault's consent reference"),
            "{case}: {reply}"
        );
        validate(reply);
        assert_eq!(
            outcome.journal.outcome, "refused:capture_not_stored",
            "{case}"
        );
        assert_eq!(
            fixture.launcher.launches.load(Ordering::SeqCst),
            0,
            "{case}"
        );
        assert_eq!(fixture.vault.opens.load(Ordering::SeqCst), 0, "{case}");
        assert!(fixture.fs.contents().is_empty(), "{case}");
        assert!(!fixture.events.contains_prefix("tmutil"), "{case}");
    }
}

/// A module with no vault to deposit into refuses before the person is asked
/// to sign in, rather than after.
#[tokio::test]
async fn a_module_without_a_vault_refuses_before_asking() {
    let fixture = super::test_support::fixture_without_vault();
    let script = allow().script();
    let (outcome, question) = capture_with(&fixture, &ollama(), &script, true, || false).await;
    assert_eq!(outcome.reply["outcome"], "capture_not_stored");
    assert_eq!(outcome.reply["reason"], VAULT_UNREACHABLE);
    assert!(question.is_none(), "the person was asked anyway");
    assert_eq!(script.opens(), 0);
    assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
}

/// A call from no agent session raises no card: no route to Cingulate is
/// opened, and the reply says where the call must come from.
#[tokio::test]
async fn a_call_without_consent_admission_is_refused_without_asking() {
    let fixture = fixture();
    let script = allow().script();
    let (outcome, question) = capture_with(&fixture, &ollama(), &script, false, || false).await;
    assert_eq!(outcome.reply["outcome"], "consent_unavailable");
    assert_eq!(outcome.reply["detail"]["reason"], "no_agent_session");
    assert_eq!(
        outcome.reply["detail"]["remedy"],
        "call from the agent session that needs the permission; it can raise the card"
    );
    crate::browser::validate_browser_result(crate::management::CAPTURE_LOGIN, &outcome.reply)
        .unwrap();
    assert!(question.is_none());
    assert_eq!(script.opens(), 0);
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

// --- the vault ------------------------------------------------------------

fn validate(reply: &Value) {
    crate::browser::validate_browser_result(crate::management::CAPTURE_LOGIN, reply)
        .unwrap_or_else(|error| panic!("{reply} does not match its schema: {error:?}"));
}

/// Compared against literal values rather than ones built the way the code
/// under test builds them.
#[tokio::test]
async fn created_and_replaced_each_reply_captured_with_the_vault_fields() {
    for (vault_outcome, version) in [("created", 1), ("replaced", 4)] {
        let fixture = fixture();
        fixture.vault.script([FakeReply::Stored {
            outcome: vault_outcome,
            version,
        }]);
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        assert_eq!(
            outcome.reply,
            json!({
                "outcome": "captured",
                "credential_id": "cookie:ollama.com:work",
                "vault_outcome": vault_outcome,
                "record_version": version,
            })
        );
        validate(&outcome.reply);
        assert_eq!(outcome.journal.outcome, format!("captured:{vault_outcome}"));
        assert_eq!(outcome.journal.credential_id, "cookie:ollama.com:work");
        assert_eq!(outcome.journal.bytes, planted_header().len() as u64);
        assert_eq!(fixture.vault.opens.load(Ordering::SeqCst), 1);
    }
}

/// Each vault refusal code becomes `capture_not_stored` with that code as the
/// reason and the remedy written for it. The refusal is scripted for every
/// attempt, so this holds whether or not the code is retried; which codes are
/// retried is checked by the retry tests below.
#[tokio::test]
async fn each_vault_refusal_is_capture_not_stored_with_its_reason_and_remedy() {
    for (class, code, remedy) in [
        ("permanent", "not_found", "deposit grant"),
        (
            "permanent",
            "not_permitted",
            "operator-managed vault record already holds cookie:ollama.com:work",
        ),
        ("permanent", "invalid_id", "internal fault"),
        ("permanent", "invalid_payload", "internal fault"),
        ("permanent", "invalid_params", "internal fault"),
        ("transient", "store_busy", "Capture again shortly"),
        ("transient", "store_error", "Capture again shortly"),
    ] {
        let fixture = fixture();
        fixture
            .vault
            .script(vec![FakeReply::refused(class, code); 4]);
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        let reply = &outcome.reply;
        assert_eq!(reply["outcome"], "capture_not_stored", "{code}: {reply}");
        assert_eq!(reply["reason"], code, "{reply}");
        assert_eq!(reply["credential_id"], "cookie:ollama.com:work");
        assert!(
            reply["remedy"].as_str().unwrap().contains(remedy),
            "{code}: {reply}"
        );
        assert!(
            reply["remedy"]
                .as_str()
                .unwrap()
                .contains("nothing was stored"),
            "{code}: {reply}"
        );
        assert_eq!(
            keys(reply),
            ["credential_id", "outcome", "reason", "remedy"]
        );
        validate(reply);
        assert_eq!(
            outcome.journal.outcome,
            format!("refused:capture_not_stored:{code}")
        );
        assert_eq!(outcome.journal.bytes, planted_header().len() as u64);
        assert!(fixture.fs.files().is_empty());
        assert!(fixture.events.contains_prefix("profile_deleted"));
    }
}

/// Every reply body in claustrum's pinned contract, sent byte for byte
/// through a whole capture, gives the reply and remedy the tests above expect
/// of its case.
#[tokio::test]
async fn every_fixture_reply_gives_the_capture_reply_it_should() {
    use super::test_support::contract_reply;
    let ufuk = CaptureRequest {
        account: "ufuk".to_string(),
        ..ollama()
    };
    for (case, version) in [("created", 1), ("replaced", 2)] {
        let fixture = fixture();
        fixture
            .vault
            .script([FakeReply::Bytes(contract_reply(case))]);
        let (outcome, _) = capture(&fixture, &ufuk, allow()).await;
        assert_eq!(
            outcome.reply,
            json!({
                "outcome": "captured",
                "credential_id": "cookie:ollama.com:ufuk",
                "vault_outcome": case,
                "record_version": version,
            })
        );
        validate(&outcome.reply);
        assert_eq!(outcome.journal.outcome, format!("captured:{case}"));
    }
    // Each refusal is scripted for every attempt, so this holds whether or not
    // its code is retried; which codes are retried is the retry tests' check,
    // except that the contract's one transient code is seen to be retried.
    for (code, remedy, calls) in [
        ("invalid_id", "internal fault", None),
        ("invalid_payload", "internal fault", None),
        ("not_found", "deposit grant", None),
        (
            "not_permitted",
            "operator-managed vault record already holds cookie:ollama.com:ufuk",
            None,
        ),
        ("store_error", "Capture again shortly", Some(4)),
    ] {
        let fixture = fixture();
        fixture
            .vault
            .script(vec![FakeReply::Bytes(contract_reply(code)); 4]);
        let (outcome, _) = capture(&fixture, &ufuk, allow()).await;
        let reply = &outcome.reply;
        assert_eq!(reply["outcome"], "capture_not_stored", "{code}: {reply}");
        assert_eq!(reply["reason"], code, "{reply}");
        let text = reply["remedy"].as_str().unwrap();
        assert!(text.contains(remedy), "{code}: {reply}");
        assert!(text.contains("nothing was stored"), "{code}: {reply}");
        validate(reply);
        if let Some(calls) = calls {
            assert_eq!(fixture.vault.calls(), calls, "{code}");
        }
    }
}

/// A transport Error frame with `invalid_params` is the vault saying it could
/// not decode the request: this module's bug, reported as an internal fault
/// and not retried. Any other Error frame code is a failed call.
#[tokio::test]
async fn an_invalid_params_error_frame_is_an_internal_fault() {
    let fixture = fixture();
    fixture
        .vault
        .script([FakeReply::Fails(VaultReachError::CallFailed {
            code: Some("invalid_params".to_string()),
        })]);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_not_stored");
    assert_eq!(
        outcome.reply["reason"], "invalid_params",
        "{}",
        outcome.reply
    );
    assert!(outcome.reply["remedy"]
        .as_str()
        .unwrap()
        .contains("internal fault"));
    validate(&outcome.reply);
    assert_eq!(
        outcome.journal.outcome,
        "refused:capture_not_stored:invalid_params"
    );
    assert_eq!(fixture.vault.calls(), 1);
}

#[tokio::test]
async fn any_other_error_frame_code_is_a_failed_call() {
    let fixture = fixture();
    fixture
        .vault
        .script([FakeReply::Fails(VaultReachError::CallFailed {
            code: Some("route_closed".to_string()),
        })]);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(
        outcome.reply["reason"], VAULT_CALL_FAILED,
        "{}",
        outcome.reply
    );
    let remedy = outcome.reply["remedy"].as_str().unwrap();
    assert!(remedy.contains("route_closed"), "{remedy}");
    assert!(!remedy.contains("internal fault"), "{remedy}");
    validate(&outcome.reply);
}

/// A header over the vault's 16384-byte limit is refused by name and never
/// sent; one at the limit is stored. The profile is still deleted.
#[tokio::test]
async fn a_cookie_header_the_vault_would_refuse_is_never_sent() {
    // `session=` is eight bytes of the header.
    for (value_bytes, stored) in [
        (vault_wire::MAX_COOKIE_BYTES - 8, true),
        (vault_wire::MAX_COOKIE_BYTES - 7, false),
    ] {
        let fixture = fixture();
        *fixture.launcher.script.lock().unwrap() = BrowserScript {
            cookies: vec![("session".to_string(), "v".repeat(value_bytes))],
            ..BrowserScript::default()
        };
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        let reply = &outcome.reply;
        validate(reply);
        assert!(fixture.events.contains_prefix("profile_deleted"));
        if stored {
            assert_eq!(reply["outcome"], "captured", "{value_bytes}: {reply}");
            assert_eq!(fixture.vault.calls(), 1);
            continue;
        }
        assert_eq!(reply["outcome"], "capture_not_stored", "{reply}");
        assert_eq!(reply["reason"], COOKIE_NOT_STORABLE, "{reply}");
        assert!(
            reply["remedy"].as_str().unwrap().contains("16384"),
            "{reply}"
        );
        assert_eq!(fixture.vault.opens.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.vault.calls(), 0);
        assert_eq!(
            outcome.journal.bytes,
            vault_wire::MAX_COOKIE_BYTES as u64 + 1
        );
    }
}

#[tokio::test]
async fn a_transient_refusal_is_retried_until_the_vault_stores_it() {
    let fixture = fixture();
    fixture.vault.script([
        FakeReply::refused("transient", "store_busy"),
        FakeReply::refused("transient", "store_error"),
        FakeReply::refused("transient", "store_busy"),
        FakeReply::Stored {
            outcome: "replaced",
            version: 2,
        },
    ]);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
    assert_eq!(outcome.reply["vault_outcome"], "replaced");
    assert_eq!(fixture.vault.calls(), 4);
    // Every retry rides the one route opened for the deposit.
    assert_eq!(fixture.vault.opens.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_transient_refusal_that_outlasts_the_retries_is_not_stored() {
    let fixture = fixture();
    fixture
        .vault
        .script(vec![FakeReply::refused("transient", "store_busy"); 10]);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_not_stored");
    assert_eq!(outcome.reply["reason"], "store_busy");
    // The first attempt and three retries.
    assert_eq!(fixture.vault.calls(), 1 + vault::RETRY_BACKOFF.len());
    assert_eq!(fixture.vault.calls(), 4);
}

/// The vault would store on a second attempt, so a retry of a permanent
/// refusal shows up as a captured login rather than only as a call count.
#[tokio::test]
async fn a_permanent_refusal_is_never_retried() {
    for code in ["not_found", "not_permitted", "invalid_params"] {
        let fixture = fixture();
        fixture
            .vault
            .script([FakeReply::refused("permanent", code)]);
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        assert_eq!(
            outcome.reply["outcome"], "capture_not_stored",
            "{code}: {}",
            outcome.reply
        );
        assert_eq!(fixture.vault.calls(), 1, "{code} was retried");
    }
}

/// The request is exactly the contract's: the method and four keys, `email`
/// only when the account label is an email address. Any other key is refused
/// by the vault as `invalid_params`.
#[tokio::test]
async fn the_vault_request_carries_exactly_the_contract_keys() {
    for (account, email) in [("work", None), ("me@example.com", Some("me@example.com"))] {
        let fixture = fixture();
        let request = CaptureRequest {
            account: account.to_string(),
            ..ollama()
        };
        let (outcome, _) = capture(&fixture, &request, allow()).await;
        assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
        let sent: Value =
            serde_json::from_slice(&fixture.vault.requests.lock().unwrap()[0]).unwrap();
        let mut params = json!({
            "id": format!("cookie:ollama.com:{account}"),
            "cookie": planted_header(),
            "consent_ref": ELICITATION_ID,
        });
        if let Some(email) = email {
            params["email"] = json!(email);
        }
        assert_eq!(
            sent,
            json!({"method": "credential.deposit_cookie", "params": params}),
            "{account}"
        );
    }
}

#[test]
fn only_an_email_shaped_account_label_is_sent_as_email() {
    for (account, email) in [
        ("me@example.com", true),
        ("first.last+tag@mail.example.co", true),
        ("work", false),
        ("me@localhost", false),
        ("@example.com", false),
        ("me@.com", false),
        ("me@example.", false),
        ("a@b@example.com", false),
    ] {
        let request = CaptureRequest {
            account: account.to_string(),
            ..ollama()
        };
        assert_eq!(request.account_email().is_some(), email, "{account}");
    }
}

/// A daemon that cannot be reached, a route the daemon refuses, and a route
/// that fails after the request was sent each say which, so the caller can
/// tell a daemon that is down from one that will not route to the vault.
#[tokio::test]
async fn an_unreachable_vault_and_a_refused_route_each_have_their_own_reason() {
    for (open_fails, reply, reason, calls) in [
        (
            Some(VaultReachError::Unreachable),
            None,
            VAULT_UNREACHABLE,
            0,
        ),
        (
            Some(VaultReachError::RouteRefused {
                code: Some("capability_forbidden".to_string()),
            }),
            None,
            VAULT_ROUTE_REFUSED,
            0,
        ),
        (
            None,
            Some(FakeReply::Fails(VaultReachError::CallFailed { code: None })),
            VAULT_CALL_FAILED,
            1,
        ),
    ] {
        let fixture = fixture();
        *fixture.vault.open_fails.lock().unwrap() = open_fails;
        fixture.vault.script(reply);
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        assert_eq!(outcome.reply["outcome"], "capture_not_stored");
        assert_eq!(outcome.reply["reason"], reason, "{}", outcome.reply);
        assert_eq!(fixture.vault.calls(), calls, "{reason}");
        validate(&outcome.reply);
        assert_eq!(
            outcome.journal.outcome,
            format!("refused:capture_not_stored:{reason}")
        );
    }
    let fixture = fixture();
    *fixture.vault.open_fails.lock().unwrap() = Some(VaultReachError::RouteRefused {
        code: Some("capability_forbidden".to_string()),
    });
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert!(outcome.reply["remedy"]
        .as_str()
        .unwrap()
        .contains("capability_forbidden"));
}

/// A vault that never answers cannot hold the call open: the deposit's
/// deadline ends it, and the reply says the login may have been stored.
#[tokio::test]
async fn a_vault_that_never_answers_is_bounded_by_the_deposit_deadline() {
    let fixture = fixture_with(|env| env.deposit_deadline = Duration::from_millis(50));
    fixture.vault.script([FakeReply::Hangs]);
    let (outcome, _) = tokio::time::timeout(
        Duration::from_secs(5),
        capture(&fixture, &ollama(), allow()),
    )
    .await
    .expect("the deposit deadline ended the wait");
    assert_eq!(outcome.reply["outcome"], "capture_not_stored");
    assert_eq!(outcome.reply["reason"], VAULT_DEADLINE_EXCEEDED);
    assert!(outcome.reply["remedy"]
        .as_str()
        .unwrap()
        .contains("may or may not"));
}

/// A stored reply that names another id answers some other request, so it is
/// not taken as this login's.
#[tokio::test]
async fn a_reply_for_another_id_is_not_taken_as_stored() {
    let fixture = fixture();
    fixture.vault.script([FakeReply::Raw(json!({
        "result": {"id": "cookie:other.com:work", "outcome": "created", "record_version": 1}
    }))]);
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "capture_not_stored");
    assert_eq!(outcome.reply["reason"], VAULT_REPLY_MALFORMED);
}

/// The file path and the operator commands are gone: no reply names a capture
/// file or a `ck auth` command, and the schema no longer declares the fields
/// that carried them.
#[tokio::test]
async fn no_reply_names_a_capture_file_or_a_command() {
    let schema = reply_schema();
    for field in ["commands", "expires_at", "replace_note", "holder", "bytes"] {
        assert!(
            schema["properties"].get(field).is_none(),
            "the reply schema still declares {field}"
        );
    }
    for (case, arrange) in [
        ("stored", None),
        (
            "refused",
            Some(FakeReply::refused("permanent", "not_found")),
        ),
    ] {
        let fixture = fixture();
        fixture.vault.script(arrange);
        let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
        let text = outcome.reply.to_string();
        for absent in ["ck auth", "--payload-file", ROOT, ".cookie"] {
            assert!(!text.contains(absent), "{case}: {text}");
        }
        assert!(outcome.reply.get("path").is_none(), "{case}: {text}");
        assert!(fixture.fs.files().is_empty(), "{case}");
    }
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

/// A liveness reading that fails says nothing about the window, so the handoff
/// keeps polling and still sees the login when it happens.
#[tokio::test]
async fn an_unreadable_liveness_keeps_the_handoff_open_until_the_login_is_observed() {
    let fixture = fixture();
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        liveness_unreadable: true,
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured");
}

/// With no login and no readable liveness, the handoff runs to its deadline
/// rather than reporting a window the person never closed.
#[tokio::test]
async fn an_unreadable_liveness_never_ends_the_handoff_as_a_closed_window() {
    let fixture = fixture_with(|env| env.handoff_duration = Duration::from_millis(30));
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        logs_in: false,
        liveness_unreadable: true,
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "expired");
    nothing_captured(&fixture);
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
    // Nobody signed in, so nothing was verified and the reply does not claim
    // a sign-in that failed to verify.
    assert_eq!(fixture.launcher.verifications.count(), 0);
    assert!(outcome.reply.get("reason").is_none(), "{}", outcome.reply);
}

// --- session verification ---------------------------------------------------

fn probe(final_url: &str, status: Option<u16>, credential_field: bool) -> SessionProbe {
    SessionProbe {
        final_url: final_url.to_string(),
        status,
        credential_field,
    }
}

#[test]
fn the_fetch_url_served_signed_in_verifies() {
    assert_eq!(
        session_verified(
            "https://ollama.com/settings",
            &probe("https://ollama.com/settings", Some(200), false)
        ),
        Ok(())
    );
    // Another page on the same origin, such as a settings page that moved,
    // still shows the session works.
    assert_eq!(
        session_verified(
            "https://ollama.com/settings",
            &probe("https://ollama.com/settings/keys", Some(204), false)
        ),
        Ok(())
    );
}

/// Everything else about the load passes, so only the origin can refuse it.
#[test]
fn an_off_origin_final_url_is_refused() {
    for final_url in [
        "https://signin.ollama.com/",
        "https://ollama.com.evil.example/settings",
        "http://ollama.com/settings",
        "about:blank",
    ] {
        assert_eq!(
            session_verified(
                "https://ollama.com/settings",
                &probe(final_url, Some(200), false)
            ),
            Err(VerificationFailure::OffOrigin),
            "{final_url}"
        );
    }
}

#[test]
fn a_sign_in_page_on_the_same_origin_is_refused() {
    // Served at the requested URL, but asking for a password.
    assert_eq!(
        session_verified(
            "https://ollama.com/settings",
            &probe("https://ollama.com/settings", Some(200), true)
        ),
        Err(VerificationFailure::SignInPage)
    );
    // Redirected to a sign-in path whose first step asks only for an email.
    for final_url in [
        "https://ollama.com/signin?next=%2Fsettings",
        "https://ollama.com/auth/Login",
        "https://ollama.com/sign-in/",
    ] {
        assert_eq!(
            session_verified(
                "https://ollama.com/settings",
                &probe(final_url, Some(200), false)
            ),
            Err(VerificationFailure::SignInPage),
            "{final_url}"
        );
    }
    // A word inside a segment or in the query is not a sign-in path.
    assert_eq!(
        session_verified(
            "https://ollama.com/settings",
            &probe("https://ollama.com/settings?from=login", Some(200), false)
        ),
        Ok(())
    );
    // A fetch URL that is itself on such a path cannot be told apart from a
    // redirect to it, so the path alone does not refuse it.
    assert_eq!(
        session_verified(
            "https://example.com/login/status",
            &probe("https://example.com/login/status", Some(200), false)
        ),
        Ok(())
    );
}

#[test]
fn a_status_outside_2xx_or_none_is_refused() {
    for status in [Some(199), Some(301), Some(401), Some(403), Some(500), None] {
        assert_eq!(
            session_verified(
                "https://ollama.com/settings",
                &probe("https://ollama.com/settings", status, false)
            ),
            Err(VerificationFailure::Status(status)),
            "{status:?}"
        );
    }
}

/// A multi-step sign-in (Ollama's goes through a separate sign-in host)
/// satisfies the login heuristic between steps, before the session works. The
/// first verification fails there, the handoff stays open, and the capture
/// happens only once a later verification passes.
#[tokio::test]
async fn a_failed_verification_keeps_the_handoff_open_until_one_passes() {
    let fixture = fixture();
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        verifications: vec![
            ScriptedVerification::redirected_off_origin(),
            ScriptedVerification::works(),
        ],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
    assert_eq!(fixture.launcher.verifications.count(), 2);
    assert_eq!(fixture.vault.calls(), 1);
    let events = fixture.events.snapshot();
    let verified = events
        .iter()
        .rposition(|event| event == "verify:https://ollama.com/settings")
        .unwrap();
    let read = events
        .iter()
        .position(|event| event.starts_with("cookie_header:"))
        .unwrap();
    assert!(
        verified < read,
        "the cookie was read before the passing verification: {events:?}"
    );
}

#[tokio::test]
async fn a_session_that_never_verifies_expires_as_not_verified_with_nothing_written() {
    let fixture = fixture_with(|env| env.handoff_duration = Duration::from_millis(100));
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        verifications: vec![ScriptedVerification::redirected_off_origin()],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "expired", "{}", outcome.reply);
    assert_eq!(outcome.reply["reason"], LOGIN_NOT_VERIFIED);
    assert!(fixture.launcher.verifications.count() >= 1);
    nothing_captured(&fixture);
    assert!(!fixture.events.contains_prefix("cookie_header:"));
    assert!(fixture.events.contains_prefix("profile_deleted"));
    // The journal record carries the plain outcome; the reason is reply-only.
    assert_eq!(outcome.journal.outcome, "expired");
    crate::browser::validate_browser_result(crate::management::CAPTURE_LOGIN, &outcome.reply)
        .expect("the not-verified reply matches its schema");
}

#[tokio::test]
async fn a_sign_in_page_on_the_same_origin_never_captures() {
    let fixture = fixture_with(|env| env.handoff_duration = Duration::from_millis(100));
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        verifications: vec![ScriptedVerification::Ends {
            final_url: Some("https://ollama.com/signin".to_string()),
            status: Some(200),
            credential_field: true,
        }],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "expired", "{}", outcome.reply);
    assert_eq!(outcome.reply["reason"], LOGIN_NOT_VERIFIED);
    assert!(outcome.reply["remedy"]
        .as_str()
        .unwrap()
        .contains("ended on a sign-in page"));
    nothing_captured(&fixture);
}

/// A browser that cannot carry out the load is not a working session either,
/// and does not end the handoff.
#[tokio::test]
async fn a_verification_the_browser_cannot_run_keeps_the_handoff_open() {
    let fixture = fixture();
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        verifications: vec![
            ScriptedVerification::DriveFails,
            ScriptedVerification::works(),
        ],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(outcome.reply["outcome"], "captured", "{}", outcome.reply);
}

#[tokio::test]
async fn a_window_closed_after_a_failed_verification_says_so() {
    let fixture = fixture_with(|env| env.verification_retry_interval = Duration::from_secs(60));
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        exits_at_poll: Some(6),
        verifications: vec![ScriptedVerification::redirected_off_origin()],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(
        outcome.reply["outcome"], "no_login_observed",
        "{}",
        outcome.reply
    );
    assert_eq!(outcome.reply["reason"], LOGIN_NOT_VERIFIED);
    nothing_captured(&fixture);
}

/// The gap between the end of one verification and the start of the next.
fn verification_gaps(fixture: &Fixture) -> Vec<Duration> {
    let spans = fixture.launcher.verifications.spans.lock().unwrap().clone();
    spans
        .windows(2)
        .map(|pair| pair[1].0.saturating_duration_since(pair[0].1))
        .collect()
}

/// A site whose cookie names change on every poll would otherwise be
/// verified on every poll. Changed inputs make a verification due, but never
/// sooner than the minimum spacing, and never two at once.
#[tokio::test]
async fn changed_inputs_reverify_no_sooner_than_the_minimum_spacing() {
    let spacing = Duration::from_millis(40);
    let fixture = fixture_with(|env| {
        env.handoff_duration = Duration::from_millis(400);
        env.verification_min_spacing = spacing;
        env.verification_retry_interval = Duration::from_secs(60);
    });
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        cookie_names_churn: true,
        verifications: vec![ScriptedVerification::redirected_off_origin()],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(
        outcome.reply["reason"], LOGIN_NOT_VERIFIED,
        "{}",
        outcome.reply
    );
    let gaps = verification_gaps(&fixture);
    assert!(
        !gaps.is_empty(),
        "changed inputs never re-verified within the handoff"
    );
    for gap in &gaps {
        assert!(*gap >= spacing, "re-verified after {gap:?}: {gaps:?}");
    }
    assert_eq!(
        fixture
            .launcher
            .verifications
            .max_in_flight
            .load(Ordering::SeqCst),
        1
    );
}

/// With nothing the heuristic reads changing, polls that keep satisfying it
/// do not verify again until the retry interval has passed.
#[tokio::test]
async fn unchanged_inputs_wait_for_the_retry_interval() {
    let fixture = fixture_with(|env| {
        env.handoff_duration = Duration::from_millis(150);
        env.verification_min_spacing = Duration::from_millis(1);
        env.verification_retry_interval = Duration::from_secs(60);
    });
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        verifications: vec![ScriptedVerification::redirected_off_origin()],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(
        outcome.reply["reason"], LOGIN_NOT_VERIFIED,
        "{}",
        outcome.reply
    );
    assert_eq!(fixture.launcher.verifications.count(), 1);

    let retry = Duration::from_millis(40);
    let fixture = fixture_with(|env| {
        env.handoff_duration = Duration::from_millis(400);
        env.verification_min_spacing = Duration::from_millis(1);
        env.verification_retry_interval = retry;
    });
    *fixture.launcher.script.lock().unwrap() = BrowserScript {
        verifications: vec![ScriptedVerification::redirected_off_origin()],
        ..BrowserScript::default()
    };
    let (outcome, _) = capture(&fixture, &ollama(), allow()).await;
    assert_eq!(
        outcome.reply["reason"], LOGIN_NOT_VERIFIED,
        "{}",
        outcome.reply
    );
    let gaps = verification_gaps(&fixture);
    assert!(!gaps.is_empty(), "the retry interval never re-verified");
    for gap in &gaps {
        assert!(*gap >= retry, "re-verified after {gap:?}: {gaps:?}");
    }
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

/// A cancel that arrives while the card is still open ends the capture
/// without waiting for the person, and nothing is placed or launched.
#[tokio::test]
async fn a_cancel_while_the_question_is_open_ends_the_capture() {
    let fixture = fixture();
    let script = ScriptedCingulate::new();
    script
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(json!({"elicitation_id": ELICITATION_ID})),
        )
        .then(wire::CONSENT_AWAIT, Reply::Hang);
    let waiting = Arc::clone(&script);
    let (outcome, _) = tokio::time::timeout(
        Duration::from_secs(5),
        capture_with(&fixture, &ollama(), &script, true, move || {
            waiting
                .methods()
                .iter()
                .any(|method| method == wire::CONSENT_AWAIT)
        }),
    )
    .await
    .expect("the cancel ended the wait on the person");
    assert_eq!(outcome.reply["outcome"], "cancelled");
    assert!(fixture.fs.contents().is_empty());
    assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
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
