use super::*;

fn retained_rows() -> Vec<AgentGrant> {
    let mut rows = Vec::new();
    for (suffix, holder, expiry) in [
        ("head", head("agent-alf"), None),
        ("one", worker("worker-one"), Some(END)),
        ("two", worker("worker-two"), Some(END)),
    ] {
        rows.push(row(
            &format!("app-{suffix}"),
            holder.clone(),
            GrantSubject::App("editor".into()),
            expiry,
            &format!("app-{suffix}"),
        ));
        for (target, prefix) in [
            (BrowserTarget::AgentProfile, "profile"),
            (BrowserTarget::UserBrowser, "user"),
        ] {
            let mut site = row(
                &format!("{prefix}-{suffix}"),
                holder.clone(),
                GrantSubject::Domain("example.com".into()),
                expiry,
                &format!("{prefix}-{suffix}"),
            );
            site.browser_target = Some(target);
            rows.push(site);
        }
    }
    rows.push(row(
        "other-app",
        head("other"),
        GrantSubject::App("editor".into()),
        None,
        "other-card",
    ));
    rows.push(row(
        "temporary-app",
        head("agent-alf"),
        GrantSubject::App("temporary".into()),
        Some(END),
        "temporary-card",
    ));
    rows.push(row(
        "whole",
        head("agent-alf"),
        GrantSubject::WholeComputer,
        None,
        "whole-card",
    ));
    rows
}
fn ids(store: &AgentGrants) -> Vec<String> {
    let mut ids: Vec<_> = store
        .live_rows(None, NOW)
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    ids.sort();
    ids
}
fn browser_row(suffix: &str, expires: Option<u64>) -> Value {
    json!({"agent_id":"agent-alf","subject":{"domain":"example.com"},"max_level":3,"hazards":[],"expires_at_ms":expires,"granted_at_ms":1_000_000,"consent_ref":format!("profile-{suffix}"),"revoked_at_ms":null})
}
fn app_row(agent: &str) -> Value {
    json!({"grantee":agent,"bundle_identity":"editor","created_at_ms":1_000_000})
}

#[tokio::test]
async fn retained_management_ops_assert_exact_head_and_two_worker_rows() {
    let (planes, store, _, backend) = fixture(retained_rows());
    let app_inventory = json!({"grants":[app_row("agent-alf"),app_row("other")],"other_machine_grants":[],"unbound_grants":[],"store":{"state":"loaded"}});
    assert_eq!(
        call(
            &planes,
            facts(Principal::Direct),
            management::LIST_APP_GRANTS,
            json!({})
        )
        .await
        .1,
        app_inventory
    );
    assert_eq!(
        call(
            &planes,
            facts(Principal::Direct),
            management::LIST_GRANTS,
            json!({"agent_id":"agent-alf"})
        )
        .await
        .1,
        json!({
            "agent_id":"agent-alf",
            "browser":{"grants":[browser_row("head", None),browser_row("one", Some(END)),browser_row("two", Some(END))],"store":{"state":"loaded"}},
            "apps":{"grants":[app_row("agent-alf")],"store":{"state":"loaded"}}
        })
    );
    let before = backend.load().unwrap();
    assert_eq!(
        call(
            &planes,
            facts(Principal::Direct),
            management::REVOKE_APP_GRANT,
            json!({"grantee":"agent-alf","bundle_identity":"editor","dry_run":true})
        )
        .await
        .1,
        json!({"outcome":"would_revoke","records":1})
    );
    assert_eq!(backend.load().unwrap(), before);
    assert_eq!(
        call(
            &planes,
            facts(Principal::Direct),
            management::REVOKE_APP_GRANT,
            json!({"grantee":"agent-alf","bundle_identity":"editor"})
        )
        .await
        .1,
        json!({"outcome":"revoked","records":1})
    );
    assert_eq!(
        ids(&store),
        [
            "app-one",
            "app-two",
            "other-app",
            "profile-head",
            "profile-one",
            "profile-two",
            "temporary-app",
            "user-head",
            "user-one",
            "user-two",
            "whole"
        ]
    );
    assert_eq!(
        call(
            &planes,
            facts(Principal::Direct),
            management::REVOKE_APP_GRANT,
            json!({"grantee":"agent-alf","bundle_identity":"temporary","dry_run":true})
        )
        .await
        .1,
        json!({"outcome":"grant_not_found"})
    );
    assert_eq!(
        call(
            &planes,
            facts(Principal::Direct),
            management::REVOKE_GRANT,
            json!({"agent_id":"agent-alf","domain":"example.com"})
        )
        .await
        .1,
        json!({"outcome":"revoked","revoked":3})
    );
    assert_eq!(
        ids(&store),
        [
            "app-one",
            "app-two",
            "other-app",
            "temporary-app",
            "user-head",
            "user-one",
            "user-two",
            "whole"
        ]
    );
    assert_eq!(
        call(
            &planes,
            facts(Principal::Direct),
            management::LIST_GRANTS,
            json!({"agent_id":"agent-alf"})
        )
        .await
        .1,
        json!({"agent_id":"agent-alf","browser":{"grants":[],"store":{"state":"loaded"}},"apps":{"grants":[],"store":{"state":"loaded"}}})
    );
}

fn worker_facts() -> AcceptedBindFacts {
    let mut stamp = crate::cingulate_client::worker_vectors::worker_stamp();
    stamp.scope_ref = "worker-one".into();
    AcceptedBindFacts::from_bind(&subc_protocol::BindIdentity::new("/fixture/project", "test", "worker"), crate::session_caller_principal_for_test(), Some(&json!({"agentProjectId":"agent-alf","sessionKind":"subagent","effectiveCapabilityScope":["*"]})), None, &RouteTarget::ManagementSurface { module_id:"cerebellum".into() }).with_scope(Some(stamp))
}

#[tokio::test]
async fn retained_self_revoke_only_removes_callers_rows_on_the_called_target() {
    let (planes, store, _, _) = fixture(retained_rows());
    let mut description = crate::permission_scope::test_support::live_head();
    description["scope"]["attributes"]["agent_id"] = json!("agent-alf");
    crate::permission_scope::test_support::describe(&planes, description);
    assert_eq!(
        call(
            &planes,
            worker_facts(),
            management::REVOKE_ACCESS,
            json!({"domain":"example.com"})
        )
        .await
        .1,
        json!({"outcome":"revoked","revoked":1})
    );
    assert_eq!(
        ids(&store),
        [
            "app-head",
            "app-one",
            "app-two",
            "other-app",
            "profile-head",
            "profile-two",
            "temporary-app",
            "user-head",
            "user-one",
            "user-two",
            "whole"
        ]
    );
}
