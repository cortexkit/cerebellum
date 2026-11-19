//! Worker requests and refusals checked against the JSON vectors copied from
//! Cingulate's `test-vectors/consent-requester-v2/` at main `6bb5f4d`.

use std::sync::Arc;
use std::time::Duration;

use subc_protocol::scope::{ScopeKind, ScopeParent, ScopeStamp};
use subc_protocol::Principal;

use super::card::{consent_request, CardKind};
use super::desk::{ConsentDesk, Ending};
use super::double::{vector, vector_reply, ScriptedCingulate};
use super::live_call::{CallHold, LiveCall};
use super::wire;

struct Held;
impl CallHold for Held {
    fn held(&self) -> bool {
        true
    }
}

pub(crate) fn worker_stamp() -> ScopeStamp {
    let owner = Principal::Reserved {
        module_id: "prefrontal".into(),
    };
    let mut stamp = ScopeStamp::new(owner.clone(), "sc_worker", 3, ScopeKind::Worker)
        .with_owner_authorized(true);
    stamp.parent = Some(ScopeParent::new(owner, "sc_head_alf", 7));
    stamp
}

#[tokio::test]
async fn worker_request_and_read_use_the_served_vectors() {
    let cingulate = ScriptedCingulate::new();
    cingulate
        .then(
            wire::CONSENT_REQUEST,
            vector_reply("worker-consent-reply.json"),
        )
        .then(
            wire::CONSENT_GET,
            vector_reply("worker-consent-get-reply.json"),
        );
    let desk = ConsentDesk::new(Arc::new(cingulate.clone()));
    let live = LiveCall::new(Some(&worker_stamp()), Arc::new(Held)).unwrap();
    let mut session = desk.session(&live).await.unwrap();
    let card = consent_request(
        CardKind::AppControl,
        &vector("worker-consent-request.json"),
        Duration::from_secs(60),
        None,
        None,
        None,
    )
    .unwrap();
    let id = session.raise(card, "app").await.unwrap();
    let record = session.get(&id).await.unwrap();
    assert_eq!(record.raw["subject"]["via_worker"], true);
    assert_eq!(record.raw["subject"]["agent_id"], "agent-alf");
    assert_eq!(desk.raised(&id).unwrap().session, *live.session());
    assert_eq!(live.scope().scope_ref, "sc_worker");
    assert_eq!(cingulate.scopes(), vec![live.scope().clone()]);
    assert_eq!(
        cingulate.calls()[0].1,
        vector("worker-consent-request.json")["params"]
    );
    assert_eq!(
        cingulate.calls()[1].1,
        vector("worker-consent-get-request.json")["params"]
    );
}

#[tokio::test]
async fn worker_head_refusal_vectors_have_typed_endings() {
    for (file, ending) in [
        ("worker-no-parent-refusal.json", Ending::NotPutToAnyone),
        ("worker-head-gone-refusal.json", Ending::NotPutToAnyone),
        (
            "worker-head-unavailable-refusal.json",
            Ending::DeliveryFailed,
        ),
    ] {
        let cingulate = ScriptedCingulate::new();
        cingulate.then(wire::CONSENT_REQUEST, vector_reply(file));
        let desk = ConsentDesk::new(Arc::new(cingulate));
        let live = LiveCall::new(Some(&worker_stamp()), Arc::new(Held)).unwrap();
        let mut session = desk.session(&live).await.unwrap();
        let card = consent_request(
            CardKind::AppControl,
            &vector("worker-consent-request.json"),
            Duration::from_secs(60),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(session.raise(card, "app").await, Err(ending), "{file}");
        assert!(desk.raised("el_1").is_none(), "{file}");
    }
}
