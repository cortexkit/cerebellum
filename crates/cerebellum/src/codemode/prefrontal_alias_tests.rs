use super::admitted_head_scope;
use cerebellum_core::identity::AcceptedBindFacts;
use subc_protocol::{
    scope::{ScopeAttributes, ScopeKind, ScopeStamp},
    BindIdentity, Principal, RouteTarget,
};

#[test]
fn a_legacy_tab_owner_matches_an_admitted_head_but_cannot_name_a_live_run_parent() {
    use subc_protocol::scope::{ParentState, ScopeParent};
    let current = Principal::Reserved {
        module_id: "prefrontal".into(),
    };
    let legacy = Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    let routes = crate::RouteBindings::default();
    let mut facts = AcceptedBindFacts::from_bind(
        &BindIdentity::new("test", "conversation"),
        Some(current.clone()),
        None,
        None,
        &RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    );
    facts.identity.agent_project_id = "agent".into();
    facts.agent_project_id_attested = true;
    facts.session_kind_attested = true;
    facts.scope = Some(
        ScopeStamp::new(current.clone(), "head", 7, ScopeKind::Head)
            .with_owner_authorized(true)
            .with_attributes(ScopeAttributes::new().with_agent_id(Some("agent".into()))),
    );
    routes.insert(1, 1, facts);
    let stored_owner = serde_json::to_string(&legacy).unwrap();
    assert!(routes.has_user_browser_session(&stored_owner, "head"));
    assert!(!routes.has_user_browser_session(&stored_owner, "different"));

    let mut run = ScopeStamp::new(current.clone(), "run", 1, ScopeKind::Ephemeral)
        .with_attributes(ScopeAttributes::new().with_agent_id(Some("agent".into())))
        .with_parent(Some(ScopeParent::new(legacy, "head", 7)))
        .with_parent_state(Some(ParentState::Linked));
    assert!(routes.run_head(&run).is_err());
    run.parent.as_mut().unwrap().owner = current;
    assert!(routes.run_head(&run).is_ok());
    run.parent.as_mut().unwrap().scope_ref = "different".into();
    assert!(routes.run_head(&run).is_err());
    run.parent.as_mut().unwrap().scope_ref = "head".into();
    run.parent.as_mut().unwrap().scope_epoch += 1;
    assert!(routes.run_head(&run).is_err());
}

#[test]
fn rename_run_cancellation_follows_scope_alias_but_not_another_ref_or_epoch() {
    for (before, after) in [
        ("prefrontal-core", "prefrontal"),
        ("prefrontal", "prefrontal-core"),
    ] {
        let owner = |name: &str| Principal::Reserved {
            module_id: name.into(),
        };
        let old = ScopeStamp::new(owner(before), "run", 7, ScopeKind::Ephemeral);
        let facts = AcceptedBindFacts::from_bind(
            &BindIdentity::new("test", "conversation"),
            Some(owner("basal")),
            None,
            None,
            &RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
        )
        .with_scope(Some(old));
        let facts = facts.clone().with_codemode_head(&facts);
        let calls = super::RunCalls::default();
        let cancel = crate::CancelHandle::pending();
        let _registration = calls
            .register(&facts, "call", Some(cancel.clone()))
            .unwrap();
        let mut scope = crate::journal::call_records::ScopeIdentity {
            owner: format!("reserved:{after}"),
            reference: "different".into(),
            scope_epoch: 7,
        };
        assert!(calls
            .cancellation("reserved:basal", "call", Some(&scope))
            .is_none());
        scope.reference = "run".into();
        scope.scope_epoch += 1;
        assert!(calls
            .cancellation("reserved:basal", "call", Some(&scope))
            .is_none());
        scope.scope_epoch -= 1;
        assert!(calls
            .cancellation("reserved:aft", "call", Some(&scope))
            .is_none());
        calls
            .cancellation("reserved:basal", "call", Some(&scope))
            .expect("the renamed scope can cancel its held call")
            .cancel();
        assert!(cancel.is_cancelled());
    }
}

#[test]
fn only_prefrontal_admits_head_owners_and_callers() {
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
                // Supply the other required facts independently so a rejected
                // principal cannot hide behind missing identity attestation.
                facts.identity.agent_project_id = "agent".into();
                facts.agent_project_id_attested = true;
                facts.session_kind_attested = true;
                facts.scope = Some(
                    ScopeStamp::new(owner.clone(), "head", 1, ScopeKind::Head)
                        .with_owner_authorized(authorized)
                        .with_attributes(
                            ScopeAttributes::new().with_agent_id(Some("agent".into())),
                        ),
                );
                let expected = *owner_admitted && *caller_admitted && authorized;
                assert_eq!(
                    admitted_head_scope(&facts).is_some(),
                    expected,
                    "owner={owner:?}, caller={caller:?}, authorized={authorized}"
                );
                facts.scope.as_mut().unwrap().attributes.run_id = Some("run".into());
                assert!(admitted_head_scope(&facts).is_none());
                facts.scope.as_mut().unwrap().attributes.run_id = None;
                facts.scope.as_mut().unwrap().attributes.flow_id = Some("flow".into());
                assert!(admitted_head_scope(&facts).is_none());
            }
        }
    }
}
