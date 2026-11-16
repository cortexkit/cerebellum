use super::*;
use crate::test_support::HANG_GUARD;

fn plan(root: &std::path::Path) -> login_import::LoginImportPlan {
    let executable = root.join("browser");
    let login_import::PreparedImport::Ready(plan) = login_import::prepare_import(
        "https://example.com",
        "project",
        &executable,
        login_import::DurableProfileLocation {
            managed_root: root.to_path_buf(),
            profile_directory: root.join("profile"),
        },
        login_import::ImportSettings::for_test(
            root.join("sqlite"),
            root.join("data"),
            root.join("cookies"),
            vec![login_import::BrowserSource {
                id: "chrome",
                display_name: "Chrome",
                data_directory: "chrome".into(),
                executable: executable.clone(),
            }],
        ),
    ) else {
        panic!("prepared import")
    };
    plan
}

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "login-import-consent-{}",
        login_import::new_ask_id()
    ));
    assert!(!root.exists());
    root
}

use super::tests::{late_answer, ScriptedConsent};
use cingulate_client::wire::{
    CONSENT_ACK, CONSENT_ANSWERS, CONSENT_AWAIT, CONSENT_DETACH, CONSENT_REPORT_EXECUTION,
    CONSENT_REQUEST,
};

/// Planes whose management route (channel 1, epoch 1) belongs to an
/// admitted agent session, and whose consent cards go to `consent`'s
/// scripted Cingulate. Building them again over the same `consent`
/// stands for a restarted module: same registry file, same Cingulate.
fn planes(consent: &ScriptedConsent) -> Planes {
    consent.wire(super::tests::management_bound_planes(1, 1), 1, 1)
}

/// Run one import until it replies, returning the card it raised (its
/// `consent.request` params), if any, and the reply.
async fn import(
    planes: &Planes,
    consent: &ScriptedConsent,
    root: &std::path::Path,
    writer: &mpsc::Sender<Frame>,
) -> (Option<Value>, Value) {
    let raised_before = consent.cards().len();
    let facts = planes.routes.get(1, 1).unwrap();
    let running = {
        let planes = planes.clone();
        let writer = writer.clone();
        let plan = plan(root);
        tokio::spawn(async move {
            computer_grants::tests::with_live(complete_login_import(
                &planes, &facts, &writer, 1, 1, plan, None,
            ))
            .await
        })
    };
    let reply = tokio::time::timeout(HANG_GUARD, running)
        .await
        .expect("the import replies")
        .unwrap();
    (consent.cards().into_iter().nth(raised_before), reply)
}

/// Let one call on the session read a consent answer that arrived after
/// the import call returned, then check that it was stored for the next
/// import (as a single-use approval or a remembered refusal).
async fn await_remembered(planes: &Planes) {
    computer_grants::tests::drain_call(planes, 1, 1).await;
    assert!(
        planes.consent.has_single_use_approvals()
            || planes.management.computer_grants().remembers_login_answer()
    );
}

#[tokio::test]
async fn cancelling_the_import_card_has_no_refusal_or_retry_advice() {
    let consent = ScriptedConsent::new();
    consent.raises("el_imp_stop");
    consent
        .script
        .then(CONSENT_AWAIT, cingulate_client::Reply::Hang)
        .then(
            CONSENT_DETACH,
            cingulate_client::Reply::Result(json!({
                "elicitation_id":"el_imp_stop", "state":"pending", "detached":true,
            })),
        );
    let planes = planes(&consent);
    let root = root();
    let (tx, _rx) = mpsc::channel(8);
    let facts = planes.routes.get(1, 1).unwrap();
    let cancel = CancelHandle::pending();
    let waiting = computer_grants::tests::with_live(complete_login_import(
        &planes,
        &facts,
        &tx,
        1,
        1,
        plan(&root),
        Some(cancel.clone()),
    ));
    let stop = async {
        tokio::time::timeout(HANG_GUARD, async {
            while consent.methods().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("import is waiting on its card");
        cancel.cancel();
    };
    let (reply, ()) = tokio::time::timeout(HANG_GUARD, async { tokio::join!(waiting, stop) })
        .await
        .expect("cancelled import answers promptly");
    assert_eq!(reply["outcome"], "cancelled");
    assert!(reply.get("remedy").is_none());
    assert!(reply.get("grant_request").is_none());
    browser::validate_browser_result(management::IMPORT_LOGIN, &reply).unwrap();
    assert_eq!(
        consent.methods(),
        [CONSENT_REQUEST, CONSENT_AWAIT, CONSENT_DETACH]
    );
    assert_eq!(
        planes
            .consent
            .unapplied(&computer_grants::tests::session_key("test-project"))
            .len(),
        1,
        "the cancelled call leaves its card answerable but cannot transfer a login"
    );
    assert!(!root.join("profile").exists());
}

#[tokio::test]
async fn the_import_card_is_sent_for_thirty_minutes_with_late_execution() {
    let consent = ScriptedConsent::new();
    consent.raises("el_imp_1").unanswered("el_imp_1");
    let planes = planes(&consent);
    let root = root();
    let (tx, _rx) = mpsc::channel(8);
    let (asked, reply) = import(&planes, &consent, &root, &tx).await;
    let asked = asked.expect("a card was raised");
    assert_eq!(asked["expires_in_ms"], 1_800_000, "{asked}");
    assert_eq!(asked["late_execution"], "execute", "{asked}");
    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    assert_eq!(reply["ask_id"], "el_imp_1", "{reply}");
    assert_eq!(
        reply["remedy"],
        computer_grants::LOGIN_CONSENT_PENDING_REMEDY,
        "{reply}"
    );
    assert_eq!(
        consent.methods(),
        [CONSENT_REQUEST, CONSENT_AWAIT, CONSENT_DETACH]
    );
    assert_eq!(
        planes
            .consent
            .unapplied(&computer_grants::tests::session_key("test-project"))
            .len(),
        1
    );
}

/// A granting answer that arrives after the call returned is used by the
/// retry with the same origin, with no second card, and only once. The
/// retry tells Cingulate what became of the approval before it replies.
#[tokio::test]
async fn a_late_import_approval_is_used_once_by_the_retry() {
    let consent = ScriptedConsent::new();
    consent.raises("el_imp_2").unanswered("el_imp_2");
    let planes = planes(&consent);
    let root = root();
    let (tx, _rx) = mpsc::channel(8);
    let (_, reply) = import(&planes, &consent, &root, &tx).await;
    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    consent.feed(late_answer("el_imp_2", "hand_off"));
    await_remembered(&planes).await;
    consent.takes_report("el_imp_2");
    let (card, reply) = import(&planes, &consent, &root, &tx).await;
    assert!(card.is_none(), "a second card was raised");
    assert_eq!(reply["outcome"], "hand_off", "{reply}");
    assert_eq!(consent.methods().last().unwrap(), CONSENT_REPORT_EXECUTION);
    assert_eq!(
        consent.script.calls().last().unwrap().1["elicitation_id"],
        "el_imp_2"
    );
    consent.raises("el_imp_3").unanswered("el_imp_3");
    let (card, reply) = import(&planes, &consent, &root, &tx).await;
    assert!(card.is_some(), "the approval was used twice");
    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
}

/// An import approval given after its call returned survives a module
/// restart: on the restarted module, the session's next call reads it
/// from the answers feed and acknowledges it, and the retry uses it once
/// and reports it to Cingulate before replying. A second restart has
/// nothing left to apply and opens no route to Cingulate.
#[tokio::test]
async fn a_late_import_approval_survives_a_restart_and_is_applied_once() {
    use cingulate_client::desk::RegistryStore;

    let consent = ScriptedConsent::new();
    consent
        .raises("el_imp_restart")
        .unanswered("el_imp_restart");
    let root = root();
    let (tx, _rx) = mpsc::channel(8);
    {
        let planes = planes(&consent);
        let (_, reply) = import(&planes, &consent, &root, &tx).await;
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    }
    assert_eq!(consent.store().load().unwrap().len(), 1);

    // The person approves while the module is down.
    let restarted = planes(&consent);
    consent.feed(late_answer("el_imp_restart", "hand_off"));
    let before = consent.methods().len();
    computer_grants::tests::drain_call(&restarted, 1, 1).await;
    assert_eq!(consent.methods()[before..], [CONSENT_ANSWERS, CONSENT_ACK]);
    assert!(consent
        .store()
        .load()
        .unwrap()
        .iter()
        .all(|card| card.applied && card.lifecycle.acked));
    consent.takes_report("el_imp_restart");
    let (card, reply) = import(&restarted, &consent, &root, &tx).await;
    assert!(card.is_none(), "a second card was raised");
    assert_eq!(reply["outcome"], "hand_off", "{reply}");
    assert_eq!(
        consent.methods()[before..],
        [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_REPORT_EXECUTION]
    );
    assert_eq!(
        consent.script.calls().last().unwrap().1["elicitation_id"],
        "el_imp_restart"
    );
    assert!(!restarted.consent.has_single_use_approvals());

    let again = planes(&consent);
    let opens = consent.script.opens();
    computer_grants::tests::drain_call(&again, 1, 1).await;
    assert_eq!(consent.script.opens(), opens, "nothing was left to apply");
    assert!(!again.consent.has_single_use_approvals());
}

/// A refusal that arrives after the call returned refuses the retry as
/// denied, with no second card.
#[tokio::test]
async fn a_late_import_refusal_denies_the_retry() {
    let consent = ScriptedConsent::new();
    consent.raises("el_imp_4").unanswered("el_imp_4");
    let planes = planes(&consent);
    let root = root();
    let (tx, _rx) = mpsc::channel(8);
    import(&planes, &consent, &root, &tx).await;
    consent.feed(late_answer("el_imp_4", "deny"));
    await_remembered(&planes).await;
    let (card, reply) = import(&planes, &consent, &root, &tx).await;
    assert!(card.is_none(), "a second card was raised");
    assert_eq!(reply["outcome"], "denied", "{reply}");
}

/// When Cingulate refuses to raise the card, so nobody is shown it, the
/// import ends at once with `not_put_to_anyone`.
#[tokio::test]
async fn a_card_nobody_was_shown_ends_the_import_at_once() {
    let consent = ScriptedConsent::new();
    consent.script.then(
        CONSENT_REQUEST,
        cingulate_client::Reply::Refused("elicitation_requester_refused"),
    );
    let planes = planes(&consent);
    let root = root();
    let (tx, _rx) = mpsc::channel(8);
    let (card, reply) = import(&planes, &consent, &root, &tx).await;
    assert!(card.is_some());
    assert_eq!(reply["outcome"], "not_put_to_anyone", "{reply}");
    assert_eq!(consent.methods(), [CONSENT_REQUEST]);
    assert!(!planes.management.computer_grants().remembers_login_answer());
}

/// Each way the import card can end without an answer gets its own
/// outcome, and a choice the card did not offer is reported as
/// `unrecognized_answer`, not as a refusal.
#[test]
fn every_unanswered_ending_concludes_as_itself() {
    use cingulate_client::desk::{Ending, NoCard};
    let root = root();
    for (ending, outcome) in [
        (
            Ending::Declined {
                choice_id: "deny".into(),
            },
            "denied",
        ),
        (
            Ending::Declined {
                choice_id: "maybe".into(),
            },
            "unrecognized_answer",
        ),
        (Ending::NoAnswer, "no_answer"),
        (Ending::NotPutToAnyone, "not_put_to_anyone"),
        (Ending::DeliveryFailed, "undeliverable"),
        (Ending::Withdrawn, "question_withdrawn"),
        (
            Ending::NoCard(NoCard::NoAgentSession),
            "consent_unavailable",
        ),
    ] {
        let result = plan(&root).conclude(&ending);
        assert_eq!(result.outcome, outcome, "{ending:?}");
        assert_eq!(result.remedy.is_some(), outcome != "denied", "{ending:?}");
        assert_eq!(result.rows, 0, "{ending:?}");
    }
    let result = plan(&root).conclude(&Ending::NoCard(NoCard::NoAgentSession));
    assert_eq!(result.reason, Some("no_agent_session"));
}
