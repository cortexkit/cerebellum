use super::admitted_head_scope;
use cerebellum_core::identity::AcceptedBindFacts;
use subc_protocol::{
    scope::{ScopeAttributes, ScopeKind, ScopeStamp},
    BindIdentity, Principal, RouteTarget,
};

#[test]
fn prefrontal_aliases_admit_head_owners_and_callers() {
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
