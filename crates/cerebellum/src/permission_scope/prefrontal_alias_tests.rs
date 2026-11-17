use super::worker_parent;
use cerebellum_core::identity::AcceptedBindFacts;
use subc_protocol::{
    scope::{ScopeKind, ScopeParent, ScopeStamp},
    BindIdentity, Principal, RouteTarget,
};

#[tokio::test]
async fn rename_followup_worker_parent_uses_live_alias_without_changing_request_owner() {
    for (before, after) in [
        ("prefrontal-core", "prefrontal"),
        ("prefrontal", "prefrontal-core"),
    ] {
        let owner = |name: &str| Principal::Reserved {
            module_id: name.into(),
        };
        let mut facts = AcceptedBindFacts::from_bind(
            &BindIdentity::new("test", "conversation"),
            Some(owner(after)),
            None,
            None,
            &RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
        );
        facts.scope = Some(
            ScopeStamp::new(owner(after), "worker", 3, ScopeKind::Worker)
                .with_owner_authorized(true)
                .with_parent(Some(ScopeParent::new(owner(before), "head", 7))),
        );
        let scopes = crate::scope_watch::ScopeRevocation::default();
        let (writer, mut sent) = tokio::sync::mpsc::channel::<subc_protocol::Frame>(4);
        assert!(scopes.control.connect(&writer));
        let respond = async {
            let mut owners = Vec::new();
            for _ in 0..2 {
                let Ok(Some(frame)) =
                    tokio::time::timeout(std::time::Duration::from_secs(1), sent.recv()).await
                else {
                    break;
                };
                let body: serde_json::Value = serde_json::from_slice(&frame.body).unwrap();
                let requested = body["owner"]["module_id"].as_str().unwrap();
                owners.push(requested.to_owned());
                let mut answer = super::test_support::live_head();
                answer["scope"]["owner"] = serde_json::to_value(owner(after)).unwrap();
                answer["scope"]["ref"] = "head".into();
                if requested == before {
                    answer["status"] = "ended".into();
                    answer["scope"] = serde_json::Value::Null;
                }
                scopes.control.deliver(
                    frame.header.corr,
                    crate::scope_watch::ControlAnswer::Response(answer),
                );
            }
            owners
        };
        let (resolved, owners) = tokio::join!(super::resolve_worker(&facts, &scopes), respond);
        let resolved = resolved.unwrap().unwrap();
        assert_eq!(
            resolved.holder,
            crate::agent_grants::GrantHolder::Worker {
                agent_id: "test-project".into(),
                scope_ref: "worker".into()
            }
        );
        assert_eq!(owners, [before, after]);
        assert_eq!(resolved.parent.owner, owner(before));
        let mut renamed = facts.clone();
        renamed.scope.as_mut().unwrap().owner = owner(before);
        renamed
            .scope
            .as_mut()
            .unwrap()
            .parent
            .as_mut()
            .unwrap()
            .owner = owner(after);
        super::WORKER_HOLDER
            .scope(Some(resolved), async {
                assert!(super::authorizing_holder(&renamed).is_some());
                renamed.scope.as_mut().unwrap().scope_epoch += 1;
                assert!(super::authorizing_holder(&renamed).is_none());
                renamed.scope.as_mut().unwrap().scope_epoch -= 1;
                renamed.scope.as_mut().unwrap().scope_ref = "different".into();
                assert!(super::authorizing_holder(&renamed).is_none());
            })
            .await;
    }
}

#[test]
fn prefrontal_aliases_admit_worker_parent_owners_and_callers() {
    let cases = [
        (
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            true,
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
                // Only the orchestrator's two registrations share an owner
                // identity; unrelated principals cannot name its parent.
                for (other_owner, other_admitted) in &cases {
                    if other_owner != owner {
                        facts.scope.as_mut().unwrap().parent.as_mut().unwrap().owner =
                            other_owner.clone();
                        assert_eq!(worker_parent(&facts).is_some(), expected && *other_admitted);
                    }
                }
            }
        }
    }
}
