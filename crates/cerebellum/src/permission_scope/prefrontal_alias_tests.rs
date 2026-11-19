use super::worker_parent;
use cerebellum_core::identity::AcceptedBindFacts;
use subc_protocol::{
    scope::{ScopeKind, ScopeParent, ScopeStamp},
    BindIdentity, Principal, RouteTarget,
};

#[tokio::test]
async fn worker_parent_is_described_once_under_the_current_owner() {
    let owner = Principal::Reserved {
        module_id: "prefrontal".into(),
    };
    let mut facts = AcceptedBindFacts::from_bind(
        &BindIdentity::new("test", "conversation"),
        Some(owner.clone()),
        None,
        None,
        &RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    );
    facts.scope = Some(
        ScopeStamp::new(owner.clone(), "worker", 3, ScopeKind::Worker)
            .with_owner_authorized(true)
            .with_parent(Some(ScopeParent::new(owner.clone(), "head", 7))),
    );
    let scopes = crate::scope_watch::ScopeRevocation::default();
    let mut answer = super::test_support::live_head();
    answer["scope"]["ref"] = "head".into();
    let (writer, mut sent) = tokio::sync::mpsc::channel::<subc_protocol::Frame>(4);
    assert!(scopes.control.connect(&writer));
    let respond = async {
        let frame = sent.recv().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(body["owner"]["module_id"], "prefrontal");
        assert_eq!(body["ref"], "head");
        assert!(scopes.control.deliver(
            frame.header.corr,
            crate::scope_watch::ControlAnswer::Response(answer),
        ));
    };
    let (resolved, ()) = tokio::join!(super::resolve_worker(&facts, &scopes), respond);
    assert!(sent.try_recv().is_err());
    let resolved = resolved.unwrap().unwrap();
    assert_eq!(resolved.parent.owner, owner);
    assert_eq!(
        resolved.holder,
        crate::agent_grants::GrantHolder::Worker {
            agent_id: "test-project".into(),
            scope_ref: "worker".into(),
        }
    );
    super::WORKER_HOLDER
        .scope(Some(resolved), async {
            assert!(super::authorizing_holder(&facts).is_some());
            facts.scope.as_mut().unwrap().scope_epoch += 1;
            assert!(super::authorizing_holder(&facts).is_none());
            facts.scope.as_mut().unwrap().scope_epoch -= 1;
            facts.scope.as_mut().unwrap().scope_ref = "different".into();
            assert!(super::authorizing_holder(&facts).is_none());
        })
        .await;
}

#[test]
fn only_prefrontal_admits_worker_parent_owners_and_callers() {
    let cases = [
        (
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            false,
        ),
        (
            Principal::Reserved {
                module_id: "prefrontal".into(),
            },
            true,
        ),
        (
            Principal::Reserved {
                module_id: "prefrontal-corex".into(),
            },
            false,
        ),
        (Principal::Unverified, false),
        (Principal::Direct, false),
    ];
    for (owner, owner_admitted) in &cases {
        for (caller, caller_admitted) in &cases {
            for authorized in [true, false] {
                let mut facts = AcceptedBindFacts::from_bind(
                    &BindIdentity::new("test", "conversation"),
                    Some(caller.clone()),
                    None,
                    None,
                    &RouteTarget::ToolProvider {
                        module_id: "cerebellum".into(),
                    },
                );
                facts.scope = Some(
                    ScopeStamp::new(owner.clone(), "worker", 1, ScopeKind::Worker)
                        .with_owner_authorized(authorized)
                        .with_parent(Some(ScopeParent::new(owner.clone(), "head", 7))),
                );
                let expected = *owner_admitted && *caller_admitted && authorized;
                let parent = worker_parent(&facts);
                assert_eq!(
                    parent.is_some(),
                    expected,
                    "owner={owner:?}, caller={caller:?}, authorized={authorized}"
                );
                if let Some(parent) = parent {
                    assert_eq!(&parent.owner, owner);
                    assert_eq!(parent.scope_ref, "head");
                    assert_eq!(parent.scope_epoch, 7);
                }
                facts.flow_id = Some("flow".into());
                assert!(worker_parent(&facts).is_none());
                facts.flow_id = None;
                facts.scope.as_mut().unwrap().attributes.flow_id = Some("flow".into());
                assert!(worker_parent(&facts).is_none());
                facts.scope.as_mut().unwrap().attributes.flow_id = None;
                for (other_owner, _) in &cases {
                    if other_owner != owner {
                        facts.scope.as_mut().unwrap().parent.as_mut().unwrap().owner =
                            other_owner.clone();
                        assert!(worker_parent(&facts).is_none());
                    }
                }
            }
        }
    }
}
