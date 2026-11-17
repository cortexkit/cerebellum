use super::worker_parent;
use cerebellum_core::identity::AcceptedBindFacts;
use subc_protocol::{
    scope::{ScopeKind, ScopeParent, ScopeStamp},
    BindIdentity, Principal, RouteTarget,
};

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
                // Scope keys keep their original owner; the two registration
                // names do not make distinct parent keys interchangeable.
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
