//! The client's wire tests, against the scripted Cingulate in `double.rs`.
//!
//! Part one pins every card kind's bytes. Part two drives `ConsentDesk`
//! through each ending Cingulate's `consent-requester-v2` contract allows.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
use subc_protocol::Principal;

use super::card::{consent_request, phone_visible, CardKind, CardRequest};
use super::desk::{
    pending_reply, Apply, ConsentDesk, DrainReport, Ending, FileRegistryStore, InCall, LetGo,
    NoCard, RaisedCard, RegistryStore, CINGULATE_RAISED_FORMAT,
};
use super::double::{
    vector, vector_reply, vector_result, Reply, ScriptedCingulate, DETACH_PENDING, DETACH_SETTLED,
    DETACH_WRONG_OWNER,
};
use super::live_call::{CallHold, LiveCall, NotLive};
use super::route::CallError;
use super::subject;
use super::wire::{self, Record};

// ---------------------------------------------------------------------------
// Every card kind, as the production builders render it
// ---------------------------------------------------------------------------

/// The call key every golden card carries as its `requester_ref`.
const GOLDEN_CALL_KEY: &str = "pf:card-golden";

/// One card of each kind, built by the production builder with the deadline
/// its call site enforces.
fn todays_cards() -> Vec<(CardKind, &'static str, Value, Duration)> {
    cards_with_standing(true)
}

fn cards_with_standing(standing: bool) -> Vec<(CardKind, &'static str, Value, Duration)> {
    use crate::authorization::{HazardClass, Severity};
    use crate::computer_grants::{AppIdentity, GrantNeed, NoIdentityReader};
    use crate::consent_card::{Urgency, LOGIN_CARD_LIFETIME};
    use crate::management::{browser_grant_question, PHONE_CONSENT_DEADLINE};

    let origins = vec!["https://example.com".to_string()];
    let hazards = vec![HazardClass::CredentialFormSubmit.as_str().to_string()];
    let holder = if standing {
        crate::agent_grants::GrantHolder::Head {
            agent_id: "agent-golden".into(),
        }
    } else {
        crate::agent_grants::GrantHolder::Worker {
            agent_id: "agent-golden".into(),
            scope_ref: "worker-golden".into(),
        }
    };
    let computer = crate::computer_grants::ComputerGrants::open(
        Arc::new(crate::computer_grants::InMemoryGrantStorage::new()),
        Some("machine-golden".into()),
    );
    let caller = crate::computer_grants::GrantCaller {
        holder: Some(holder.clone()),
        conversation_key: "conversation-golden".into(),
        agent_project_id: "agent-golden".into(),
        durable_identity_attested: standing,
    };
    let site = |urgency| {
        browser_grant_question(
            &origins,
            &hazards,
            Severity::new(4, true, false),
            urgency,
            &crate::permission_cards::browser_choices(
                &origins,
                &std::collections::BTreeSet::from([HazardClass::CredentialFormSubmit]),
                Severity::new(4, true, false),
                Some(&holder),
                true,
            ),
        )
    };
    let app = GrantNeed::App {
        bundle_identity: "com.example.Editor".into(),
        display_name: "Editor".into(),
        code: Arc::new(NoIdentityReader),
    };
    let team = AppIdentity {
        team_id: Some("ABCDE12345".into()),
        designated_requirement: "certificate leaf[subject.OU] = \"ABCDE12345\"".into(),
        ad_hoc: false,
        apple_anchored: false,
    };
    let presence = crate::login_import::BrowserPresence {
        browser: "chrome".into(),
        name: "Google Chrome".into(),
        persistent_rows: 1,
        session_rows: 0,
        transfer: "available",
        reason: None,
    };
    let capture = crate::login_capture::CaptureRequest {
        credential_domain: "ollama.com".into(),
        account: "work".into(),
        fetch_url: "https://ollama.com/settings".into(),
        login_url: "https://ollama.com/signin".into(),
    };
    let rebind = {
        use crate::profile::{BirthTime, ManagedRootIdentity, RebindReport, RootIdentityFacts};
        let birth_time = BirthTime {
            unix_seconds: 1_700_000_000,
            nanoseconds: 5,
        };
        let new_identity = RootIdentityFacts {
            formula: 2,
            path: "/Users/someone/Library/Application Support/cerebellum/profiles".into(),
            inode: 42,
            birth_time,
        };
        let preview = RebindReport {
            old_identity: ManagedRootIdentity::HashOnly("a1b2c3".into()),
            new_identity: new_identity.clone(),
            generation_before: 7,
            generation_after: 8,
            record_count: 3,
        };
        crate::management::profile_root_rebind_question(&new_identity.path, &preview)
    };
    let clear = {
        use crate::launch_recovery::{
            ClearPreview, ProcessReading, ProfileEvidence, SingletonLockReading,
        };
        let preview = ClearPreview {
            agent_project_id: "project-1".into(),
            profile_uuid: "7f0c2a8e-0000-4000-8000-000000000001".into(),
            sequence: 12,
            reason: crate::browser_launch::RecoveryPendingReason::AttestationUntrusted,
            launched_at: None,
            evidence: ProfileEvidence {
                processes: ProcessReading::NoneNamesDirectory { examined: 3 },
                singleton_lock: SingletonLockReading::Absent,
            },
        };
        crate::management::launch_recovery_clear_question(&preview)
    };
    let user_browser_site = crate::user_browser::site_question_with_choices(
        "https://example.net",
        3,
        &std::collections::BTreeSet::from([HazardClass::CredentialFormSubmit]),
        &crate::permission_cards::browser_choices(
            &["https://example.net".into()],
            &std::collections::BTreeSet::from([HazardClass::CredentialFormSubmit]),
            Severity::new(3, true, false),
            Some(&holder),
            true,
        ),
    );
    vec![
        (
            CardKind::WebsiteAccessInCall,
            "website-access-in-call.json",
            site(Urgency::High),
            PHONE_CONSENT_DEADLINE,
        ),
        (
            CardKind::WebsiteAccessInAdvance,
            "website-access-in-advance.json",
            site(Urgency::Normal),
            PHONE_CONSENT_DEADLINE,
        ),
        (
            CardKind::AppControl,
            "app-control.json",
            crate::computer_grants::question_body(
                &app,
                &computer.offered_choices(&caller, &app, Some(&team)),
                false,
                Some(&team),
            ),
            crate::computer_grants::APP_QUESTION_DEADLINE,
        ),
        (
            CardKind::Takeover,
            "takeover.json",
            crate::computer_grants::question_body(
                &GrantNeed::Takeover,
                &computer.offered_choices(&caller, &GrantNeed::Takeover, None),
                false,
                None,
            ),
            crate::computer_grants::TAKEOVER_QUESTION_DEADLINE,
        ),
        (
            CardKind::LoginImport,
            "login-import.json",
            crate::login_import::import_question("https://x.com", "x.com", &[presence]),
            LOGIN_CARD_LIFETIME,
        ),
        (
            CardKind::LoginCapture,
            "login-capture.json",
            crate::login_capture::consent_question(&capture),
            LOGIN_CARD_LIFETIME,
        ),
        (
            CardKind::ProfileReidentification,
            "profile-reidentification.json",
            rebind,
            PHONE_CONSENT_DEADLINE,
        ),
        (
            CardKind::StuckProfileClearance,
            "stuck-profile-clearance.json",
            clear,
            PHONE_CONSENT_DEADLINE,
        ),
        (
            CardKind::UserBrowserSite,
            "user-browser-site.json",
            user_browser_site,
            USER_BROWSER_SITE_DEADLINE,
        ),
    ]
}

/// How long the user-browser site card waits, as `user_browser` enforces it.
const USER_BROWSER_SITE_DEADLINE: Duration = crate::user_browser::CONSENT_DEADLINE;

fn request_for(kind: CardKind, body: &Value, deadline: Duration) -> CardRequest {
    consent_request(kind, body, deadline, Some(GOLDEN_CALL_KEY), None, None)
        .unwrap_or_else(|error| panic!("{kind:?}: {error:?}"))
}

/// The params as the reverse elicitation lane (see `mod.rs`) sent them: the
/// builder's params with the enforced deadline stamped as `expires_in_ms`.
/// Written out here rather than taken from the mapping, so the comparison
/// below is with that earlier wire and not with the mapping's own idea of it.
fn as_the_reverse_lane_sent_it(body: &Value, deadline: Duration) -> Value {
    let mut params = body["params"].clone();
    params["expires_in_ms"] = json!(deadline.as_millis() as u64);
    params
}

/// The keys Cingulate accepts in a `consent.request` and in an option. It
/// refuses any other, so a card carrying one would be shown to nobody.
const REQUEST_KEYS: [&str; 23] = [
    "kind",
    "title",
    "prompt",
    "options",
    "default",
    "urgency",
    "on_expiry",
    "material_damage",
    "late_execution",
    "target",
    "expires_in_ms",
    "scope",
    "args_digest",
    "dedup_key",
    "duration",
    "facts",
    "preview",
    "binding",
    "at_console",
    "session_ref",
    "parent_session_ref",
    "requester_ref",
    "single_use",
];
const OPTION_KEYS: [&str; 5] = ["id", "label", "effect", "detail", "group"];

/// Every kind maps to a kind-`consent` request Cingulate's closed decoder
/// accepts, and differs from the card the reverse elicitation lane sent only
/// by what Cingulate's closed format requires: no `requestedSchema`, no
/// `call_key`, no option `next_step`, and the call key as `requester_ref`.
/// So every field the phone renders is unchanged.
#[test]
fn every_card_kind_shows_the_phone_what_it_showed_before() {
    for (kind, name, body, deadline) in todays_cards() {
        let request = request_for(kind, &body, deadline);
        let params = request.params.as_object().unwrap();
        assert_eq!(params["kind"], wire::KIND_CONSENT, "{name}");
        for key in params.keys() {
            assert!(
                REQUEST_KEYS.contains(&key.as_str()),
                "{name}: carries {key}"
            );
        }
        for option in params["options"].as_array().unwrap() {
            for key in option.as_object().unwrap().keys() {
                assert!(
                    OPTION_KEYS.contains(&key.as_str()),
                    "{name}: option carries {key}"
                );
            }
        }
        assert_eq!(params["requester_ref"], GOLDEN_CALL_KEY, "{name}");
        assert!(
            params.get("at_console").is_none(),
            "{name}: at_console is not set yet"
        );

        let mut before = as_the_reverse_lane_sent_it(&body, deadline);
        before.as_object_mut().unwrap().remove("requestedSchema");
        for option in before["options"].as_array_mut().unwrap() {
            option.as_object_mut().unwrap().remove("next_step");
        }
        let mut after = request.params.clone();
        after.as_object_mut().unwrap().remove("requester_ref");
        assert_eq!(
            after, before,
            "{name}: the card changed beyond what Cingulate requires"
        );
        assert_eq!(
            serde_json::to_string(&phone_visible(&request.params)).unwrap(),
            serde_json::to_string(&phone_visible(&as_the_reverse_lane_sent_it(
                &body, deadline
            )))
            .unwrap(),
            "{name}: the phone-visible fields are not byte-identical"
        );
    }
}

#[test]
fn single_use_is_negotiated_only_for_login_cards_across_all_kinds() {
    for standing in [true, false] {
        for (kind, name, body, deadline) in cards_with_standing(standing) {
            for features in [
                super::features::CingulateFeatures::default(),
                super::features::CingulateFeatures {
                    option_group: true,
                    single_use: true,
                    no_expiry: false,
                },
            ] {
                let card = request_for(kind, &body, deadline).for_features(features);
                let expected = features.single_use
                    && matches!(kind, CardKind::LoginCapture | CardKind::LoginImport);
                if expected {
                    assert_eq!(card.params["single_use"], true, "{name}");
                } else {
                    assert!(
                        card.params.get("single_use").is_none(),
                        "{name}: non-login or unsupported card carries single_use"
                    );
                }
            }
        }
    }
}

/// The agent's next step after an option never rides the card: the card
/// carries only the options the operator chooses between. The login import
/// card is the one with a next step ("sign in yourself, then call present"),
/// and it is kept for cerebellum's reply.
#[test]
fn no_card_carries_a_next_step() {
    let mut saw_a_step = false;
    for (kind, name, body, deadline) in todays_cards() {
        let request = request_for(kind, &body, deadline);
        assert!(
            !request.params.to_string().contains("next_step"),
            "{name}: the card carries a next step"
        );
        let steps_before: Vec<(String, String)> = body["params"]["options"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|option| {
                Some((
                    option["id"].as_str()?.to_string(),
                    option.get("next_step")?.as_str()?.to_string(),
                ))
            })
            .collect();
        let steps_after: Vec<(String, String)> = request.next_steps.clone().into_iter().collect();
        assert_eq!(
            steps_after, steps_before,
            "{name}: next steps for the reply"
        );
        saw_a_step |= !steps_after.is_empty();
    }
    assert!(
        saw_a_step,
        "no builder renders a next step any more; check this test still bites"
    );
}

/// Each kind's request, pinned as the exact bytes sent. `SHA256SUMS` beside
/// the files pins each file. Run with
/// `CEREBELLUM_WRITE_CINGULATE_CARD_GOLDENS=1` to rewrite them after a
/// deliberate change to a card.
#[test]
fn every_card_kind_matches_its_golden() {
    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/cingulate-consent-cards-v1"
    );
    let write = std::env::var_os("CEREBELLUM_WRITE_CINGULATE_CARD_GOLDENS").is_some();
    let mut sums = String::new();
    let mut kinds = Vec::new();
    for (kind, name, body, deadline) in todays_cards() {
        let request = request_for(kind, &body, deadline);
        let rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&request.params).unwrap()
        );
        let path = std::path::Path::new(DIR).join(name);
        if write {
            std::fs::create_dir_all(DIR).unwrap();
            std::fs::write(&path, &rendered).unwrap();
        }
        let pinned = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{name}: {error}\nrendered:\n{rendered}"));
        assert_eq!(pinned, rendered, "{name}: the card changed from its golden");
        use sha2::{Digest, Sha256};
        let digest: String = Sha256::digest(pinned.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        sums.push_str(&format!("{digest}  {name}\n"));
        kinds.push(kind);
    }
    assert_eq!(kinds, CardKind::ALL, "a card kind has no golden");
    let sums_path = std::path::Path::new(DIR).join("SHA256SUMS");
    if write {
        std::fs::write(&sums_path, &sums).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&sums_path).unwrap(), sums);
}

/// Takeover cards keep `at_console` off for now (no console answering
/// surface, no machine id source), but the mapping carries it when given.
#[test]
fn at_console_is_carried_only_when_given() {
    let (_, _, body, deadline) = todays_cards()
        .into_iter()
        .find(|(kind, ..)| *kind == CardKind::Takeover)
        .unwrap();
    let with = consent_request(
        CardKind::Takeover,
        &body,
        deadline,
        None,
        None,
        Some("mac-1"),
    )
    .unwrap();
    assert_eq!(with.params["at_console"], "mac-1");
    let without = consent_request(CardKind::Takeover, &body, deadline, None, None, None).unwrap();
    assert!(without.params.get("at_console").is_none());
}

/// A call key that Cingulate would refuse as `requester_ref` is left off:
/// it is correlation only, and a refused request is a card nobody sees.
#[test]
fn an_unfit_call_key_is_left_off_the_card() {
    let (kind, _, body, deadline) = todays_cards().remove(0);
    let request = consent_request(
        kind,
        &body,
        deadline,
        Some("bad\nkey"),
        Some("dedup-1"),
        None,
    )
    .unwrap();
    assert!(request.params.get("requester_ref").is_none());
    assert_eq!(request.params["dedup_key"], "dedup-1");
}

// ---------------------------------------------------------------------------
// The desk against the scripted Cingulate
// ---------------------------------------------------------------------------

/// A held call whose holding a test can end.
struct TestHold(AtomicBool);

impl CallHold for TestHold {
    fn held(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn stamp(scope_ref: &str, agent: Option<&str>) -> ScopeStamp {
    ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        scope_ref,
        3,
        ScopeKind::Head,
    )
    .with_attributes(ScopeAttributes::new().with_agent_id(agent.map(str::to_string)))
    .with_owner_authorized(true)
}

/// A live call on the session `sc_head_alf`, and the switch that ends it.
fn live_call(scope_ref: &str) -> (LiveCall, Arc<TestHold>) {
    let hold = Arc::new(TestHold(AtomicBool::new(true)));
    let live = LiveCall::new(Some(&stamp(scope_ref, Some("agent-alf"))), hold.clone()).unwrap();
    (live, hold)
}

/// The card Cingulate served its vectors for (an app card offering
/// `allow_once` and `deny`), as a request of `kind`.
fn vector_card(kind: CardKind) -> CardRequest {
    let body = json!({"params": vector("cerebellum-ref-request.json")["params"]});
    consent_request(
        kind,
        &body,
        Duration::from_secs(60),
        Some("tool-call-42"),
        None,
        None,
    )
    .unwrap()
}

fn answered() -> Value {
    vector_result("cerebellum-ref-answers-reply.json")["records"][0].clone()
}

fn pending() -> Value {
    vector_result("cerebellum-ref-await-reply.json")
}

/// Cingulate's served reply to the first `consent.detach` of a pending card.
fn detached() -> Value {
    vector_result(DETACH_PENDING)
}

fn created() -> Reply {
    Reply::Result(vector_result("cerebellum-ref-reply.json"))
}

/// The raise sends the vector's own request bytes, with the call key as
/// `requester_ref`, and the desk remembers the card under the returned id.
#[tokio::test]
async fn a_raised_card_is_the_vector_request_and_is_remembered() {
    let cingulate = ScriptedCingulate::new();
    cingulate.then(wire::CONSENT_REQUEST, created());
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "com.apple.TextEdit")
        .await
        .unwrap();
    assert_eq!(id, "el_1");
    let (method, params) = cingulate.calls().remove(0);
    assert_eq!(
        String::from_utf8(wire::envelope(&method, params)).unwrap(),
        String::from_utf8(
            std::fs::read(
                std::path::Path::new(super::double::VECTORS).join("cerebellum-ref-request.json")
            )
            .unwrap()
        )
        .unwrap()
    );
    let card = desk.raised("el_1").unwrap();
    assert_eq!(card.session, *live.session());
    assert_eq!(card.grant_ids, vec!["allow_once".to_string()]);
}

/// Every card kind goes out as its golden request.
#[tokio::test]
async fn every_card_kind_is_raised_with_cingulate() {
    for (kind, name, body, deadline) in todays_cards() {
        let cingulate = ScriptedCingulate::new();
        cingulate.then(wire::CONSENT_REQUEST, created());
        let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
        let (live, _) = live_call("sc_head_alf");
        let request = request_for(kind, &body, deadline);
        let expected = request.params.clone();
        let mut session = desk.session(&live).await.unwrap();
        session.raise(request, name).await.unwrap();
        assert_eq!(
            cingulate.calls(),
            vec![(wire::CONSENT_REQUEST.to_string(), expected)],
            "{name}"
        );
        assert_eq!(desk.raised("el_1").unwrap().kind, kind, "{name}");
    }
}

/// An answer that lands while the call holds the card is answered in the
/// call, after one await capped at Cingulate's `consent.await` limit of two
/// minutes (`wire::AWAIT_CAP_MS`). The park does not mark it applied: the
/// flow that acts on it does, once, after storing the effect.
#[tokio::test]
async fn an_answer_inside_the_park_is_answered_in_the_call() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(answered()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ending = session
        .park(&id, Duration::from_secs(600), std::future::pending())
        .await;
    assert_eq!(
        ending,
        InCall::Settled(Ending::Granted {
            choice_id: "allow_once".into()
        })
    );
    assert_eq!(cingulate.calls()[1].1, wire::await_params("el_1", 120_000));
    assert_eq!(
        cingulate.methods(),
        vec![wire::CONSENT_REQUEST, wire::CONSENT_AWAIT],
        "an answered card is not detached"
    );
    assert!(
        !desk.raised("el_1").unwrap().applied,
        "the park marked the answer applied before any flow acted on it"
    );
    assert_eq!(desk.mark_applied("el_1"), Ok(true));
    assert_eq!(
        desk.mark_applied("el_1"),
        Ok(false),
        "a second caller was told it marked the answer"
    );
}

/// The call stops waiting on the card unanswered: the card is detached at
/// that moment and the call reports it pending, telling the agent it will be
/// woken by Cingulate's notice when the card settles.
#[tokio::test]
async fn an_unanswered_park_detaches_and_is_pending_with_a_wake() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, Reply::Result(detached()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ending = session
        .park(&id, Duration::from_secs(120), std::future::pending())
        .await;
    assert_eq!(
        ending,
        InCall::Pending {
            ask_id: "el_1".into(),
        }
    );
    assert_eq!(cingulate.calls()[2].1, json!({"elicitation_id": "el_1"}));
    let reply = pending_reply("el_1");
    assert_eq!(reply["outcome"], "consent_pending");
    assert_eq!(reply["ask_id"], "el_1");
    assert!(reply["remedy"].as_str().unwrap().contains("woken"));
}

#[tokio::test]
async fn single_use_login_answers_stay_attached_and_timeouts_detach_before_pending() {
    let create_reply: Value = serde_json::from_str(include_str!(
        "../../tests/vectors/consent-outcomes-refs-v1/single-use-reply.json"
    ))
    .unwrap();
    let capture_card = || {
        cards_with_standing(true)
            .into_iter()
            .find(|(kind, _, _, _)| *kind == CardKind::LoginCapture)
            .map(|(kind, name, body, deadline)| (request_for(kind, &body, deadline), name))
            .unwrap()
    };
    let features = Some(super::features::CingulateFeatures {
        option_group: true,
        single_use: true,
        no_expiry: false,
    });

    let cingulate = ScriptedCingulate::new();
    cingulate.report_features(features);
    cingulate
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(create_reply["result"].clone()),
        )
        .then(
            wire::CONSENT_AWAIT,
            Reply::Result(json!({
                "elicitation_id": "el_1",
                "state": "answered",
                "answered_choice_id": "allow"
            })),
        );
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let (request, name) = capture_card();
    let id = session.raise(request, name).await.unwrap();
    assert_eq!(cingulate.calls()[0].1["single_use"], true);
    assert_eq!(id, "el_1");
    let ending = session
        .park(&id, Duration::from_secs(600), std::future::pending())
        .await;
    assert_eq!(
        ending,
        InCall::Settled(Ending::Granted {
            choice_id: "allow".into()
        })
    );
    assert_eq!(
        cingulate.methods(),
        vec![wire::CONSENT_REQUEST, wire::CONSENT_AWAIT],
        "an answer consumed while waiting must stay attached"
    );

    let cingulate = ScriptedCingulate::new();
    cingulate.report_features(features);
    cingulate
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(create_reply["result"].clone()),
        )
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, Reply::Result(detached()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let (request, name) = capture_card();
    let id = session.raise(request, name).await.unwrap();
    assert_eq!(cingulate.calls()[0].1["single_use"], true);
    let ending = session
        .park(&id, Duration::from_secs(120), std::future::pending())
        .await;
    assert_eq!(ending, InCall::Pending { ask_id: id.clone() });
    assert_eq!(
        cingulate.methods(),
        vec![
            wire::CONSENT_REQUEST,
            wire::CONSENT_AWAIT,
            wire::CONSENT_DETACH
        ],
        "the card must detach before its call reports pending"
    );
    let reply = pending_reply(&id);
    assert_eq!(reply["outcome"], "consent_pending");
    assert_eq!(reply["ask_id"], id);
}

/// A card that settled before the detach landed is answered in the call:
/// Cingulate will never notify the agent about it. The settlement is left
/// unmarked for the flow that acts on it.
#[tokio::test]
async fn a_card_settled_at_detach_is_answered_in_the_call() {
    let cingulate = ScriptedCingulate::new();
    // Cingulate's settled-detach vector answers `el_2`.
    cingulate
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(json!({"elicitation_id": "el_2"})),
        )
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, vector_reply(DETACH_SETTLED));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ending = session
        .park(&id, Duration::from_secs(120), std::future::pending())
        .await;
    assert_eq!(
        ending,
        InCall::Settled(Ending::Granted {
            choice_id: "allow_once".into()
        })
    );
    assert!(
        !desk.raised("el_2").unwrap().applied,
        "the park marked the answer applied before any flow acted on it"
    );
}

/// A card that could not be detached (the consent module refuses
/// `consent.detach` as an unknown method) would stay open with no notice to
/// come for it. It is withdrawn, and the call ends `DeliveryFailed` rather
/// than reporting a pending card nobody would ever hear about.
#[tokio::test]
async fn an_undetached_card_is_withdrawn_and_undeliverable() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, Reply::Refused("unknown_method"))
        .then(wire::CONSENT_WITHDRAW, Reply::Result(withdrawn()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ending = session
        .park(&id, Duration::from_secs(120), std::future::pending())
        .await;
    assert_eq!(ending, InCall::Settled(Ending::DeliveryFailed));
    assert_eq!(
        cingulate.methods(),
        vec![
            wire::CONSENT_REQUEST,
            wire::CONSENT_AWAIT,
            wire::CONSENT_DETACH,
            wire::CONSENT_WITHDRAW
        ]
    );
    assert_eq!(desk.raised("el_1"), None);
}

/// A detach refusal other than `unknown_method` ends the call with its typed
/// `Ending`, here `DeliveryFailed` for `consent_unavailable`.
#[tokio::test]
async fn another_detach_refusal_is_a_typed_ending() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, Reply::Refused("consent_unavailable"));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ending = session
        .park(&id, Duration::from_secs(120), std::future::pending())
        .await;
    assert_eq!(ending, InCall::Settled(Ending::DeliveryFailed));
}

/// A withdrawn card's record, as `consent.withdraw` reads it back.
fn withdrawn() -> Value {
    let mut record = pending();
    record["state"] = json!("withdrawn");
    record
}

/// The same card past its deadline.
fn expired() -> Value {
    let mut record = pending();
    record["state"] = json!("expired");
    record
}

/// A cancel that lands after the await is in flight, as a caller's would,
/// asking for `let_go`.
async fn cancel_after_a_moment(let_go: LetGo) -> LetGo {
    tokio::time::sleep(Duration::from_millis(20)).await;
    let_go
}

/// Cancelling the call when nobody is left to want the answer withdraws its
/// card, and the desk forgets it.
#[tokio::test]
async fn a_cancelled_call_withdraws_its_card() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Hang)
        .then(wire::CONSENT_WITHDRAW, Reply::Result(withdrawn()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ending = session
        .park(
            &id,
            Duration::from_secs(120),
            cancel_after_a_moment(LetGo::Withdraw),
        )
        .await;
    assert_eq!(ending, InCall::Cancelled);
    assert_eq!(cingulate.methods()[2], wire::CONSENT_WITHDRAW);
    assert_eq!(desk.raised("el_1"), None);
}

/// Cancelling the call while its conversation is still bound detaches the
/// card instead: it stays answerable and remembered, and its answer reaches
/// the agent as a late answer.
#[tokio::test]
async fn a_cancelled_call_of_a_bound_conversation_detaches_its_card() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Hang)
        .then(wire::CONSENT_DETACH, vector_reply(DETACH_PENDING));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ending = session
        .park(
            &id,
            Duration::from_secs(120),
            cancel_after_a_moment(LetGo::Detach),
        )
        .await;
    assert_eq!(ending, InCall::Cancelled);
    assert_eq!(
        cingulate.methods(),
        vec![
            wire::CONSENT_REQUEST,
            wire::CONSENT_AWAIT,
            wire::CONSENT_DETACH
        ],
        "a cancel of a bound conversation withdrew the card"
    );
    assert!(desk.raised("el_1").is_some_and(|card| !card.applied));
}

/// If the route the call arrived on closes while the call waits on the card,
/// the card is withdrawn, as on cancellation.
#[tokio::test]
async fn a_closed_route_withdraws_its_card() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Hang)
        .then(wire::CONSENT_WITHDRAW, Reply::Result(withdrawn()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, hold) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let closer = {
        let hold = hold.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            hold.0.store(false, Ordering::SeqCst);
        })
    };
    let ending = session
        .park(&id, Duration::from_secs(120), std::future::pending())
        .await;
    closer.await.unwrap();
    assert_eq!(ending, InCall::RouteClosed);
    assert_eq!(cingulate.methods()[2], wire::CONSENT_WITHDRAW);
}

/// What a test's `apply` saw, by elicitation id.
#[derive(Default)]
struct Applied(Mutex<Vec<(String, Ending)>>);

impl Applied {
    fn apply(&self, card: &RaisedCard, _record: &Record, ending: &Ending) {
        self.0
            .lock()
            .unwrap()
            .push((card.elicitation_id.clone(), ending.clone()));
    }
    fn seen(&self) -> Vec<(String, Ending)> {
        self.0.lock().unwrap().clone()
    }
}

async fn drain(desk: &ConsentDesk, live: &LiveCall, applied: &Applied) -> DrainReport {
    let mut session = desk.session(live).await.unwrap();
    session
        .drain_answers(&mut |card, record, ending| {
            applied.apply(card, record, ending);
            Ok(Apply::Applied)
        })
        .await
        .unwrap()
}

/// A card that settles after its call detached is not answered in that
/// call; the session's next call reads it from the answers feed, applies
/// it, and acknowledges the feed.
#[tokio::test]
async fn a_detached_card_settled_later_is_picked_up_on_the_next_call() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, Reply::Result(detached()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    {
        let (first, _) = live_call("sc_head_alf");
        let mut session = desk.session(&first).await.unwrap();
        let id = session
            .raise(vector_card(CardKind::AppControl), "app")
            .await
            .unwrap();
        let ending = session
            .park(&id, Duration::from_secs(120), std::future::pending())
            .await;
        assert!(matches!(ending, InCall::Pending { .. }), "{ending:?}");
    }
    cingulate
        .then(
            wire::CONSENT_ANSWERS,
            Reply::Result(vector_result("cerebellum-ref-answers-reply.json")),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok": true})));
    let (next, _) = live_call("sc_head_alf");
    let applied = Applied::default();
    let report = drain(&desk, &next, &applied).await;
    assert_eq!(
        applied.seen(),
        vec![(
            "el_1".to_string(),
            Ending::Granted {
                choice_id: "allow_once".into()
            }
        )]
    );
    assert_eq!(report.acked, Some(1));
    assert_eq!(cingulate.calls().last().unwrap().1, json!({"cursor": 1}));
    assert!(desk.raised("el_1").unwrap().lifecycle.acked);
}

/// An answer in the feed to a card this desk did not raise on this session
/// is never applied, whatever it chose: only cards cerebellum raised mint
/// grants.
#[tokio::test]
async fn an_answer_to_a_card_cerebellum_did_not_raise_mints_nothing() {
    let cingulate = ScriptedCingulate::new();
    cingulate.then(wire::CONSENT_REQUEST, created());
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    {
        // el_1 raised on another session of the same agent.
        let (other, _) = live_call("sc_other");
        let mut session = desk.session(&other).await.unwrap();
        session
            .raise(vector_card(CardKind::AppControl), "app")
            .await
            .unwrap();
    }
    let mut feed = vector_result("cerebellum-ref-answers-reply.json");
    let mut foreign = answered();
    foreign["elicitation_id"] = json!("el_9");
    feed["records"].as_array_mut().unwrap().push(foreign);
    cingulate
        .then(wire::CONSENT_ANSWERS, Reply::Result(feed))
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok": true})));
    let (live, _) = live_call("sc_head_alf");
    let applied = Applied::default();
    let report = drain(&desk, &live, &applied).await;
    assert_eq!(
        applied.seen(),
        vec![],
        "a grant was minted from a card nobody here raised"
    );
    assert_eq!(report.ignored, vec!["el_1".to_string(), "el_9".to_string()]);
    assert!(
        desk.raised("el_1").is_some(),
        "the other session's card is kept"
    );
}

/// A late approval of a login card is single-use: the retry takes it once,
/// and reports its execution to Cingulate once.
#[tokio::test]
async fn a_late_login_approval_is_used_once_and_reported() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, Reply::Result(detached()))
        .then(
            wire::CONSENT_ANSWERS,
            Reply::Result(vector_result("cerebellum-ref-answers-reply.json")),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok": true})));
    let mut executed = answered();
    executed["execution"] = json!("executed");
    cingulate.then(wire::CONSENT_REPORT_EXECUTION, Reply::Result(executed));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone())).with_clock(Arc::new(|| 11001));
    let (first, _) = live_call("sc_head_alf");
    {
        let mut session = desk.session(&first).await.unwrap();
        let id = session
            .raise(vector_card(CardKind::LoginImport), "import:https://x.com")
            .await
            .unwrap();
        session
            .park(&id, Duration::from_secs(120), std::future::pending())
            .await;
    }
    let (retry, _) = live_call("sc_head_alf");
    let applied = Applied::default();
    drain(&desk, &retry, &applied).await;
    let (id, _) = desk
        .take_single_use_approval(retry.session(), "import:https://x.com")
        .expect("the late approval is recorded for the retry");
    assert_eq!(
        desk.take_single_use_approval(retry.session(), "import:https://x.com"),
        None,
        "one approval admitted two retries"
    );
    let mut session = desk.session(&retry).await.unwrap();
    session
        .report_execution(&id, wire::Execution::Executed)
        .await
        .unwrap();
    let reports: Vec<_> = cingulate
        .calls()
        .into_iter()
        .filter(|(method, _)| method == wire::CONSENT_REPORT_EXECUTION)
        .collect();
    assert_eq!(
        reports,
        vec![(
            wire::CONSENT_REPORT_EXECUTION.to_string(),
            json!({"elicitation_id": "el_1", "execution": "executed"})
        )]
    );
}

/// The registry in memory, shared across "restarts", whose saves can be
/// made to fail.
#[derive(Default)]
struct MemoryStore {
    cards: Mutex<Vec<RaisedCard>>,
    failing: AtomicBool,
    saves: AtomicUsize,
}

impl RegistryStore for MemoryStore {
    fn load(&self) -> Result<Vec<RaisedCard>, String> {
        Ok(self.cards.lock().unwrap().clone())
    }
    fn save(&self, cards: &[RaisedCard]) -> Result<(), String> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err("disk full".into());
        }
        *self.cards.lock().unwrap() = cards.to_vec();
        Ok(())
    }
}

/// A crash after a late answer was applied but before the feed was
/// acknowledged loses nothing: the answer is read again and applied again
/// (the effect is idempotent), and once the applied mark is stored a lost
/// acknowledgment never applies it a second time.
#[tokio::test]
async fn a_crash_between_apply_and_ack_reapplies_once_without_duplicating() {
    let store = Arc::new(MemoryStore::default());
    let cingulate = ScriptedCingulate::new();
    cingulate.then(wire::CONSENT_REQUEST, created());
    {
        let desk = ConsentDesk::with_store(Arc::new(cingulate.clone()), store.clone());
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        session
            .raise(vector_card(CardKind::AppControl), "app")
            .await
            .unwrap();
    }
    let feed = || Reply::Result(vector_result("cerebellum-ref-answers-reply.json"));
    let applied = Applied::default();

    // Applied, then the applied mark cannot be stored: no acknowledgment.
    store.failing.store(true, Ordering::SeqCst);
    cingulate.then(wire::CONSENT_ANSWERS, feed());
    {
        let desk = ConsentDesk::with_store(Arc::new(cingulate.clone()), store.clone());
        let (live, _) = live_call("sc_head_alf");
        let report = drain(&desk, &live, &applied).await;
        assert_eq!(report.acked, None);
    }
    assert_eq!(applied.seen().len(), 1);

    // Restarted: read again and applied again, then the acknowledgment is lost.
    store.failing.store(false, Ordering::SeqCst);
    cingulate
        .then(wire::CONSENT_ANSWERS, feed())
        .then(wire::CONSENT_ACK, Reply::Transport);
    {
        let desk = ConsentDesk::with_store(Arc::new(cingulate.clone()), store.clone());
        let (live, _) = live_call("sc_head_alf");
        let report = drain(&desk, &live, &applied).await;
        assert_eq!(report.acked, None);
    }
    assert_eq!(
        applied.seen().len(),
        2,
        "the unmarked answer was not re-applied"
    );

    // Restarted again: the mark survived, so it is acknowledged, not re-applied.
    cingulate
        .then(wire::CONSENT_ANSWERS, feed())
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok": true})));
    let desk = ConsentDesk::with_store(Arc::new(cingulate.clone()), store.clone());
    let (live, _) = live_call("sc_head_alf");
    let report = drain(&desk, &live, &applied).await;
    assert_eq!(report.acked, Some(1));
    assert_eq!(
        applied.seen().len(),
        2,
        "an answer marked applied was applied again"
    );
    assert!(
        store
            .load()
            .unwrap()
            .iter()
            .all(|card| card.applied && card.lifecycle.acked),
        "the acknowledgment must retain the execution receipt"
    );
}

/// Every refusal code, named with the ending it must map to:
///
/// - `NotPutToAnyone` only where nobody can be reached and asking again
///   cannot help until something outside cerebellum changes: cerebellum is
///   not an admitted requester, the card has no safe default, the agent is
///   retired.
/// - `DeliveryFailed` where cerebellum built a card Cingulate cannot accept
///   (a defect here: retry once, then the module needs attention), and where
///   the request could not be carried.
/// - `NoAnswer` where the card is gone from this requester's view.
#[test]
fn every_refusal_code_maps_to_its_typed_ending() {
    use super::double::refusal;
    let table: [(&str, Ending); 17] = [
        // Nobody can be reached.
        ("elicitation_requester_refused", Ending::NotPutToAnyone),
        ("elicitation_fail_closed_required", Ending::NotPutToAnyone),
        ("consent_retired", Ending::NotPutToAnyone),
        ("access_no_head", Ending::NotPutToAnyone),
        // Cerebellum built a bad card.
        ("elicitation_invalid_request", Ending::DeliveryFailed),
        ("elicitation_unknown_kind", Ending::DeliveryFailed),
        ("elicitation_request_too_large", Ending::DeliveryFailed),
        ("invalid_request", Ending::DeliveryFailed),
        // The request could not be carried.
        ("unknown_method", Ending::DeliveryFailed),
        ("consent_unavailable", Ending::DeliveryFailed),
        ("access_unavailable", Ending::DeliveryFailed),
        ("elicitation_store_error", Ending::DeliveryFailed),
        ("cancelled", Ending::DeliveryFailed),
        ("elicitation_invalid_execution", Ending::DeliveryFailed),
        ("some_future_code", Ending::DeliveryFailed),
        // The card is gone from this requester's view.
        ("elicitation_not_owner", Ending::NoAnswer),
        ("elicitation_not_found", Ending::NoAnswer),
    ];
    let wrong: Vec<String> = table
        .iter()
        .filter_map(|(code, expected)| {
            let got = Ending::of_refusal(&refusal(code));
            (got != *expected).then(|| format!("{code}: expected {expected:?}, got {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "mismapped refusal codes:\n{}",
        wrong.join("\n")
    );
    // Every code the client knows is in the table, so none is left to the
    // match's default by accident.
    for (code, _) in table.iter().filter(|(code, _)| *code != "some_future_code") {
        assert!(
            !matches!(
                super::wire::RefusalCode::parse(code),
                super::wire::RefusalCode::Unknown(_)
            ),
            "{code} is not a known refusal code"
        );
    }
    assert_eq!(
        Ending::of_refusal(&CallError::Transport { code: None }),
        Ending::DeliveryFailed
    );
}

/// A call that cannot get a card raised for reasons that are not about
/// Cingulate or the person ends on its own `consent_unavailable` row, never
/// as `DeliveryFailed` ("undeliverable, retry"), which would send the agent
/// retrying something no retry fixes.
#[test]
fn calls_that_cannot_raise_a_card_take_their_refusal_rows() {
    let transport = |code: &str| CallError::Transport {
        code: Some(code.into()),
    };
    for (error, expected) in [
        (CallError::NotLive, NoCard::CallEnded),
        (CallError::RegistryUnreadable, NoCard::RegistryUnreadable),
        (transport("scope_not_carrier"), NoCard::NotACarrier),
        (transport("scope_ended"), NoCard::ScopeEnded),
    ] {
        assert_eq!(
            Ending::of_refusal(&error),
            Ending::NoCard(expected),
            "{error:?}"
        );
    }
    assert_eq!(
        Ending::of_refusal(&transport("some_other_open_refusal")),
        Ending::DeliveryFailed
    );
    for (not_live, expected) in [
        (NotLive::Unscoped, NoCard::NoAgentSession),
        (NotLive::NoAgent, NoCard::NoAgentSession),
        (NotLive::CallEnded, NoCard::CallEnded),
    ] {
        assert_eq!(NoCard::of_not_live(not_live), expected, "{not_live:?}");
    }
    let rows: Vec<(Option<&str>, Option<&str>)> = [
        NoCard::NoAgentSession,
        NoCard::NotACarrier,
        NoCard::ScopeEnded,
        NoCard::RegistryUnreadable,
        NoCard::CallEnded,
    ]
    .into_iter()
    .map(|row| (row.reason(), row.remedy()))
    .collect();
    assert_eq!(
        rows,
        vec![
            (
                Some("no_agent_session"),
                Some(
                    "call from the agent session that needs the permission; it can raise the card"
                )
            ),
            (
                Some("not_a_carrier"),
                Some(
                    "the agent session does not list cerebellum as a carrier; restart the session"
                )
            ),
            (
                Some("scope_ended"),
                Some("this session has ended; call from the current session")
            ),
            (
                Some("consent_registry_unreadable"),
                Some("the consent registry file is newer or damaged; update cerebellum")
            ),
            (None, None),
        ]
    );
}

/// A daemon that refuses the route to Cingulate replies with its own code,
/// and the call ends with that code's `NoCard` reason: `scope_not_carrier`
/// is `NotACarrier`, `scope_ended` is `ScopeEnded`.
#[tokio::test]
async fn a_refused_route_open_takes_its_refusal_row() {
    for (code, expected) in [
        ("scope_not_carrier", NoCard::NotACarrier),
        ("scope_ended", NoCard::ScopeEnded),
    ] {
        let cingulate = ScriptedCingulate::new();
        *cingulate.refuse_open.lock().unwrap() = Some(code);
        let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
        let (live, _) = live_call("sc_head_alf");
        let error = desk.session(&live).await.err().unwrap();
        assert_eq!(
            Ending::of_refusal(&error),
            Ending::NoCard(expected),
            "{code}"
        );
        assert!(cingulate.methods().is_empty(), "{code}");
    }
}

/// A refused raise ends as its typed ending and leaves nothing remembered.
#[tokio::test]
async fn a_refused_raise_is_a_typed_ending() {
    for (code, ending) in [
        ("elicitation_requester_refused", Ending::NotPutToAnyone),
        ("elicitation_unknown_kind", Ending::DeliveryFailed),
        ("consent_unavailable", Ending::DeliveryFailed),
    ] {
        let cingulate = ScriptedCingulate::new();
        cingulate.then(wire::CONSENT_REQUEST, Reply::Refused(code));
        let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        let raised = session
            .raise(vector_card(CardKind::AppControl), "app")
            .await;
        assert_eq!(raised, Err(ending), "{code}");
        assert_eq!(desk.raised("el_1"), None, "{code}");
    }
}

/// Settled records read against the card they answer: a grant option, the
/// decline, an option the card did not offer as a grant, expiry, withdrawal.
#[test]
fn settled_records_map_to_endings_against_their_card() {
    let card = RaisedCard {
        elicitation_id: "el_1".into(),
        session: live_call("sc_head_alf").0.session().clone(),
        kind: CardKind::AppControl,
        subject: "app".into(),
        grant_ids: vec!["allow_once".into()],
        decline_id: "deny".into(),
        next_steps: Default::default(),
        applied: false,
        lifecycle: Default::default(),
    };
    let with = |state: &str, choice: Option<&str>| {
        let mut record = answered();
        record["state"] = json!(state);
        match choice {
            Some(choice) => record["answered_choice_id"] = json!(choice),
            None => {
                record.as_object_mut().unwrap().remove("answered_choice_id");
            }
        }
        Ending::of_record(&Record::parse(record).unwrap(), &card)
    };
    assert_eq!(
        with("answered", Some("allow_once")),
        Some(Ending::Granted {
            choice_id: "allow_once".into()
        })
    );
    assert_eq!(
        with("answered", Some("deny")),
        Some(Ending::Declined {
            choice_id: "deny".into()
        })
    );
    assert_eq!(
        with("answered", Some("allow_always")),
        Some(Ending::Declined {
            choice_id: "allow_always".into()
        })
    );
    assert_eq!(with("expired", None), Some(Ending::NoAnswer));
    assert_eq!(with("withdrawn", None), Some(Ending::Withdrawn));
    assert_eq!(with("pending", None), None);
}

/// No route to Cingulate is opened unless a live inbound call from the
/// session is held at that moment: not for a call that has returned or whose
/// route unbound, not for an unscoped route, not for a scope with no agent.
#[tokio::test]
async fn the_route_is_never_opened_without_a_live_inbound_call() {
    let cingulate = ScriptedCingulate::new();
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));

    let (live, hold) = live_call("sc_head_alf");
    hold.0.store(false, Ordering::SeqCst);
    assert_eq!(desk.session(&live).await.err(), Some(CallError::NotLive));
    assert_eq!(
        cingulate.opens(),
        0,
        "a route was opened for a call no longer held"
    );

    let ended = Arc::new(TestHold(AtomicBool::new(false)));
    assert_eq!(
        LiveCall::new(Some(&stamp("sc_head_alf", Some("agent-alf"))), ended).err(),
        Some(NotLive::CallEnded)
    );
    let held = Arc::new(TestHold(AtomicBool::new(true)));
    assert_eq!(
        LiveCall::new(None, held.clone()).err(),
        Some(NotLive::Unscoped)
    );
    assert_eq!(
        LiveCall::new(Some(&stamp("sc_head_alf", None)), held.clone()).err(),
        Some(NotLive::NoAgent)
    );
    let mut flow = stamp("sc_flow", Some("agent-alf"));
    flow.attributes = flow.attributes.with_flow_id(Some("flow-1".into()));
    assert_eq!(
        LiveCall::new(Some(&flow), held).err(),
        Some(NotLive::NoAgent)
    );

    // Positive control: a held call opens exactly one route.
    let (live, _) = live_call("sc_head_alf");
    assert!(desk.session(&live).await.is_ok());
    assert_eq!(cingulate.opens(), 1);
}

/// The production hold follows the inbound call itself: it holds while the
/// request's in-flight guard is alive and its route is bound, and ends when
/// the frame loop drops the guard (the call replied) or the route unbinds.
#[tokio::test]
async fn the_production_hold_ends_with_the_inbound_call() {
    use cerebellum_core::clock::SystemClock;
    use cerebellum_core::dispatch::DispatchTimingState;

    struct Route(AtomicBool);
    impl crate::computer_grants::RouteLiveness for Route {
        fn route_open(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
        fn conversation_open(&self) -> bool {
            true
        }
    }

    let clock = SystemClock::new();
    let timing = Arc::new(DispatchTimingState::new(&clock));
    let scope = stamp("sc_head_alf", Some("agent-alf"));
    let cingulate = ScriptedCingulate::new();
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));

    // The call replied: its guard is dropped.
    let guard = Arc::new(timing.enter(&clock));
    let route = Arc::new(Route(AtomicBool::new(true)));
    let live = LiveCall::from_inbound(Some(&scope), &guard, route.clone()).unwrap();
    assert!(live.is_held());
    drop(guard);
    assert!(!live.is_held());
    assert_eq!(desk.session(&live).await.err(), Some(CallError::NotLive));

    // The call's route unbound while its guard was still alive.
    let guard = Arc::new(timing.enter(&clock));
    let live = LiveCall::from_inbound(Some(&scope), &guard, route.clone()).unwrap();
    route.0.store(false, Ordering::SeqCst);
    assert_eq!(desk.session(&live).await.err(), Some(CallError::NotLive));
    assert_eq!(
        LiveCall::from_inbound(Some(&scope), &guard, route).err(),
        Some(NotLive::CallEnded)
    );
    assert_eq!(cingulate.opens(), 0);
}

// ---------------------------------------------------------------------------
// Holding a card that is never detached
// ---------------------------------------------------------------------------

/// A held card answered in the call is returned as the answer, with no
/// detach and no withdrawal, and is left for the flow to mark applied.
#[tokio::test]
async fn a_held_card_answered_in_the_wait_is_the_answer() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(answered()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::UserBrowserSite), "site")
        .await
        .unwrap();
    let ending = session
        .hold(&id, USER_BROWSER_SITE_DEADLINE, std::future::pending())
        .await;
    assert_eq!(
        ending,
        InCall::Settled(Ending::Granted {
            choice_id: "allow_once".into()
        })
    );
    assert_eq!(
        cingulate.methods(),
        vec![wire::CONSENT_REQUEST, wire::CONSENT_AWAIT]
    );
    assert!(desk.raised("el_1").is_some_and(|card| !card.applied));
}

/// A legacy card that expired needs no withdrawal or detach. It can no longer
/// be answered, so a stray feed record must not mint a grant.
#[tokio::test]
async fn a_held_card_that_expires_is_forgotten_and_never_detached() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(expired()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    {
        let mut session = desk.session(&live).await.unwrap();
        let id = session
            .raise(vector_card(CardKind::UserBrowserSite), "site")
            .await
            .unwrap();
        let ending = session
            .hold(&id, USER_BROWSER_SITE_DEADLINE, std::future::pending())
            .await;
        assert_eq!(ending, InCall::Settled(Ending::NoAnswer));
    }
    assert_eq!(
        cingulate.methods(),
        vec![wire::CONSENT_REQUEST, wire::CONSENT_AWAIT,],
        "a held card was detached"
    );
    assert_eq!(desk.raised("el_1"), None, "the expired card is remembered");
    assert!(desk.unapplied(live.session()).is_empty());

    cingulate
        .then(
            wire::CONSENT_ANSWERS,
            Reply::Result(vector_result("cerebellum-ref-answers-reply.json")),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok": true})));
    let applied = Applied::default();
    let report = drain(&desk, &live, &applied).await;
    assert_eq!(report.ignored, vec!["el_1".to_string()]);
    assert!(applied.seen().is_empty());
}

/// A bounded unanswered wait detaches. Cancellation withdraws the unwanted
/// card; a failed withdrawal remains recorded for a later call to reconcile.
#[tokio::test]
async fn a_held_card_detaches_on_timeout_and_withdraws_on_cancellation() {
    // Still pending as the wait ends.
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Result(pending()))
        .then(wire::CONSENT_DETACH, Reply::Result(detached()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::UserBrowserSite), "site")
        .await
        .unwrap();
    let ending = session
        .hold(&id, USER_BROWSER_SITE_DEADLINE, std::future::pending())
        .await;
    assert_eq!(ending, InCall::Pending { ask_id: id });
    assert!(desk.raised("el_1").is_some());

    // Cancelled, and the withdrawal fails in transit.
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_AWAIT, Reply::Hang)
        .then(wire::CONSENT_WITHDRAW, Reply::Transport);
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise(vector_card(CardKind::UserBrowserSite), "site")
        .await
        .unwrap();
    let ending = session
        .hold(
            &id,
            USER_BROWSER_SITE_DEADLINE,
            tokio::time::sleep(Duration::from_millis(20)),
        )
        .await;
    assert_eq!(ending, InCall::Cancelled);
    assert!(!cingulate
        .methods()
        .contains(&wire::CONSENT_DETACH.to_string()));
    assert!(desk.raised("el_1").is_some());
}

// ---------------------------------------------------------------------------
// Cards asked ahead
// ---------------------------------------------------------------------------

/// A card asked ahead is raised and detached at once, never awaited, and
/// remembered for the session's next call.
#[tokio::test]
async fn a_card_asked_ahead_is_detached_at_once_and_never_awaited() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_DETACH, vector_reply(DETACH_PENDING));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session
        .raise_detached(vector_card(CardKind::WebsiteAccessInAdvance), "site")
        .await
        .unwrap();
    assert_eq!(id, "el_1");
    assert_eq!(
        cingulate.methods(),
        vec![wire::CONSENT_REQUEST, wire::CONSENT_DETACH]
    );
    assert_eq!(cingulate.calls()[1].1, wire::id_params("el_1"));
    assert_eq!(desk.unapplied(live.session()).len(), 1);
}

/// A card asked ahead that cannot be detached is withdrawn, and the call
/// ends `DeliveryFailed`. A refused `consent.request` ends with that
/// refusal's ending and no detach is attempted.
#[tokio::test]
async fn a_card_asked_ahead_that_cannot_be_detached_is_withdrawn() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_DETACH, Reply::Refused("unknown_method"))
        .then(wire::CONSENT_WITHDRAW, Reply::Result(withdrawn()));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let raised = session
        .raise_detached(vector_card(CardKind::ProfileReidentification), "rebind")
        .await;
    assert_eq!(raised, Err(Ending::DeliveryFailed));
    assert_eq!(
        cingulate.methods(),
        vec![
            wire::CONSENT_REQUEST,
            wire::CONSENT_DETACH,
            wire::CONSENT_WITHDRAW
        ]
    );
    assert_eq!(desk.raised("el_1"), None);

    let cingulate = ScriptedCingulate::new();
    cingulate.then(
        wire::CONSENT_REQUEST,
        Reply::Refused("elicitation_requester_refused"),
    );
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let mut session = desk.session(&live).await.unwrap();
    let raised = session
        .raise_detached(vector_card(CardKind::StuckProfileClearance), "clear")
        .await;
    assert_eq!(raised, Err(Ending::NotPutToAnyone));
    assert_eq!(cingulate.methods(), vec![wire::CONSENT_REQUEST]);
}

// ---------------------------------------------------------------------------
// Withdrawal
// ---------------------------------------------------------------------------

/// A withdrawal that succeeds, or that Cingulate refuses because the card
/// is not this session's or no longer exists, forgets the card: no answer
/// to it can ever be read. A withdrawal that failed in transit, or was
/// refused for another reason, keeps it.
#[tokio::test]
async fn a_withdrawal_refused_as_gone_forgets_the_card() {
    for (reply, forgotten) in [
        (vector_reply(DETACH_WRONG_OWNER), true),
        (Reply::Refused("elicitation_not_found"), true),
        (Reply::Result(withdrawn()), true),
        (Reply::Transport, false),
        (Reply::Refused("consent_unavailable"), false),
    ] {
        let cingulate = ScriptedCingulate::new();
        cingulate
            .then(wire::CONSENT_REQUEST, created())
            .then(wire::CONSENT_WITHDRAW, reply);
        let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        let id = session
            .raise(vector_card(CardKind::AppControl), "app")
            .await
            .unwrap();
        let withdrawal = session.withdraw(&id).await;
        assert_eq!(
            desk.raised("el_1").is_none(),
            forgotten,
            "withdrawal ended {withdrawal:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Settlements with no record to apply to
// ---------------------------------------------------------------------------

/// A settlement the flow has no record for is acknowledged without effect:
/// listed in `without_effect`, not in `applied`, marked so it is never read
/// again, and, for a single-use card, never recorded as an approval.
#[tokio::test]
async fn a_settlement_with_no_record_is_acked_without_effect() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(wire::CONSENT_REQUEST, created())
        .then(
            wire::CONSENT_ANSWERS,
            Reply::Result(vector_result("cerebellum-ref-answers-reply.json")),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok": true})));
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    session
        .raise(vector_card(CardKind::LoginImport), "login")
        .await
        .unwrap();
    let report = session
        .drain_answers(&mut |_, _, _| Ok(Apply::NoRecord))
        .await
        .unwrap();
    assert_eq!(report.without_effect, vec!["el_1".to_string()]);
    assert!(report.applied.is_empty());
    assert_eq!(report.acked, Some(1));
    assert!(desk.raised("el_1").unwrap().lifecycle.acked);
    assert_eq!(
        desk.take_single_use_approval(live.session(), "login"),
        None,
        "an approval with no record was kept for a retry"
    );
}

// ---------------------------------------------------------------------------
// The registry file
// ---------------------------------------------------------------------------

static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

/// A fresh directory for one test, outside the operator's data home so the
/// live journal and its format-floor file (the record of which durable
/// formats are on disk) are never touched, removed when the guard drops
/// (also after a failed assertion).
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "cerebellum-cingulate-raised-{name}-{}-{}",
            std::process::id(),
            SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }

    fn store(&self) -> FileRegistryStore {
        FileRegistryStore::new(self.0.join("cingulate_raised.json"))
            .with_format_floor(cerebellum_core::format_floor::FormatFloor::at(self.floor()))
    }

    fn floor(&self) -> std::path::PathBuf {
        self.0.join("format-floor.json")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The registry file carries its version and survives a restart. Its format
/// is recorded in the format-floor file when the registry is first written,
/// not when it is merely loaded.
#[tokio::test]
async fn the_registry_file_is_versioned_and_survives_a_restart() {
    let scratch = Scratch::new("restart");
    let cingulate = ScriptedCingulate::new();
    cingulate.then(wire::CONSENT_REQUEST, created());
    {
        let desk = ConsentDesk::with_store(Arc::new(cingulate.clone()), Arc::new(scratch.store()));
        assert!(
            !scratch.floor().exists(),
            "the floor was raised before anything was written"
        );
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        session
            .raise(vector_card(CardKind::LoginCapture), "login")
            .await
            .unwrap();
    }
    let floor = std::fs::read_to_string(scratch.floor()).unwrap();
    assert!(floor.contains(CINGULATE_RAISED_FORMAT.name), "{floor}");
    let file: Value =
        serde_json::from_slice(&std::fs::read(scratch.0.join("cingulate_raised.json")).unwrap())
            .unwrap();
    assert_eq!(file["version"], 2);
    let desk = ConsentDesk::with_store(Arc::new(cingulate.clone()), Arc::new(scratch.store()));
    let card = desk.raised("el_1").expect("the card did not survive");
    assert_eq!(card.kind, CardKind::LoginCapture);
    assert_eq!(card.subject, "login");
}

/// A registry file this build cannot read (a newer version, damaged, or
/// unversioned) is never overwritten, and while it stands no route is
/// opened and no card is raised: every call ends
/// `NoCard::RegistryUnreadable`, reason `consent_registry_unreadable`.
#[tokio::test]
async fn an_unreadable_registry_is_refused_and_never_overwritten() {
    for (name, bytes) in [
        ("newer", br#"{"version":3,"cards":[]}"#.to_vec()),
        ("damaged", b"{not json".to_vec()),
        ("unversioned", b"[]".to_vec()),
    ] {
        let scratch = Scratch::new(name);
        let path = scratch.0.join("cingulate_raised.json");
        std::fs::write(&path, &bytes).unwrap();
        assert!(scratch.store().load().is_err(), "{name}");
        let cingulate = ScriptedCingulate::new();
        let desk = ConsentDesk::with_store(Arc::new(cingulate.clone()), Arc::new(scratch.store()));
        let (live, _) = live_call("sc_head_alf");
        let error = desk.session(&live).await.err();
        assert_eq!(error, Some(CallError::RegistryUnreadable), "{name}");
        assert_eq!(
            Ending::of_refusal(&error.unwrap()),
            Ending::NoCard(NoCard::RegistryUnreadable)
        );
        assert_eq!(cingulate.opens(), 0, "{name}: a route was opened");
        assert!(desk.mark_applied("el_1").is_err(), "{name}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name}: overwritten");
        assert!(!scratch.floor().exists(), "{name}: the floor was raised");
    }
}

/// `unapplied` lists only the given session's unapplied cards. A call uses
/// it to decide whether there is anything to read from Cingulate's answers
/// feed, and so whether to open a route at all.
#[tokio::test]
async fn unapplied_lists_one_sessions_open_cards() {
    let cingulate = ScriptedCingulate::new();
    cingulate.then(wire::CONSENT_REQUEST, created()).then(
        wire::CONSENT_REQUEST,
        Reply::Result(json!({"elicitation_id": "el_2"})),
    );
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let (alf, _) = live_call("sc_head_alf");
    let (other, _) = live_call("sc_other");
    desk.session(&alf)
        .await
        .unwrap()
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    desk.session(&other)
        .await
        .unwrap()
        .raise(vector_card(CardKind::AppControl), "app")
        .await
        .unwrap();
    let ids = |live: &LiveCall| -> Vec<String> {
        desk.unapplied(live.session())
            .into_iter()
            .map(|card| card.elicitation_id)
            .collect()
    };
    assert_eq!(ids(&alf), vec!["el_1".to_string()]);
    assert_eq!(desk.mark_applied("el_1"), Ok(true));
    assert!(ids(&alf).is_empty());
    assert_eq!(ids(&other), vec!["el_2".to_string()]);
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

/// Each kind has one subject function. Subjects of different kinds never
/// collide, even where the same conversation key is all they carry; both
/// website kinds give the same subject for the same origins in any order,
/// so a navigate joins an open `open_grant` card; and a login subject reads
/// back into its parts.
#[test]
fn every_kind_has_one_subject_and_kinds_never_collide() {
    use crate::computer_grants::LoginCapability;
    let conversation = "conv-1";
    let origins = vec![
        "https://b.example".to_string(),
        "https://a.example".to_string(),
    ];
    let reversed: Vec<String> = origins.iter().rev().cloned().collect();
    let by_kind = [
        (
            CardKind::WebsiteAccessInCall,
            subject::website_access_in_call(conversation, &origins),
        ),
        (
            CardKind::WebsiteAccessInAdvance,
            subject::website_access_in_advance(conversation, &reversed),
        ),
        (
            CardKind::AppControl,
            subject::app_control(conversation, "com.example.Editor"),
        ),
        (CardKind::Takeover, subject::takeover(conversation)),
        (
            CardKind::LoginImport,
            subject::login_import(conversation, "{\"origin\":\"https://x.com\"}"),
        ),
        (
            CardKind::LoginCapture,
            subject::login_capture(conversation, "{\"origin\":\"https://x.com\"}"),
        ),
        (
            CardKind::ProfileReidentification,
            subject::profile_reidentification(conversation),
        ),
        (
            CardKind::StuckProfileClearance,
            subject::stuck_profile_clearance("project-1", 12),
        ),
        (
            CardKind::UserBrowserSite,
            subject::user_browser_site("https://a.example"),
        ),
    ];
    assert_eq!(
        by_kind.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        CardKind::ALL,
        "a card kind has no subject function"
    );
    assert_eq!(
        by_kind[0].1, by_kind[1].1,
        "a navigate would not join an open open_grant card"
    );
    let distinct: std::collections::BTreeSet<&String> =
        by_kind[1..].iter().map(|(_, subject)| subject).collect();
    assert_eq!(distinct.len(), by_kind.len() - 1, "{by_kind:#?}");
    assert_ne!(
        subject::app_control(conversation, "com.a"),
        subject::app_control(conversation, "com.b")
    );
    assert_ne!(
        subject::stuck_profile_clearance("project-1", 12),
        subject::stuck_profile_clearance("project-1", 13)
    );

    let login = subject::login_parts(&by_kind[5].1).unwrap();
    assert_eq!(login.conversation_key, conversation);
    assert_eq!(login.capability, LoginCapability::CaptureLogin);
    assert_eq!(login.parameters, "{\"origin\":\"https://x.com\"}");
    assert_eq!(
        subject::login_parts(&by_kind[4].1).unwrap().capability,
        LoginCapability::ImportLogin
    );
    assert_eq!(subject::login_parts(&by_kind[3].1), None);
}

mod agent_permission_cards;
mod features;
mod no_expiry;
mod worker_options;
