use super::*;
use crate::authorization::{
    with_standing_caller, AuthorizationCommitError, AuthorizationRequest, GrantStore, Severity,
    StandingCaller,
};
use crate::browser_standing_grants::ManualWallClock;
use crate::computer_grants::SignedByFixtureTeam;

fn head() -> GrantHolder {
    GrantHolder::Head {
        agent_id: "head".into(),
    }
}
fn worker(scope_ref: &str) -> GrantHolder {
    GrantHolder::Worker {
        agent_id: "head".into(),
        scope_ref: scope_ref.into(),
    }
}
fn store() -> (Arc<AgentGrants>, Arc<ManualWallClock>) {
    let clock = Arc::new(ManualWallClock::at(100));
    (
        Arc::new(AgentGrants::in_memory(Some("machine".into())).with_clock(clock.clone())),
        clock,
    )
}
fn row(holder: GrantHolder, subject: GrantSubject, target: Option<BrowserTarget>) -> AgentGrant {
    AgentGrant {
        id: String::new(),
        holder,
        subject,
        browser_target: target,
        machine_uuid: "machine".into(),
        granted_at_ms: 100,
        expires_at_ms: Some(1_800_100),
        card_ref: Some("card".into()),
        max_level: 3,
        hazards: vec![],
        team_id: Some("TESTTEAM".into()),
        designated_requirement: Some("certificate leaf[subject.OU] = \"FIXTURE001\"".into()),
    }
}
fn browser(target: BrowserTarget) -> GrantDemand {
    GrantDemand::Browser {
        target,
        origin: "https://example.com".into(),
        severity: Severity::new(3, false, false),
        hazards: Default::default(),
    }
}
fn app() -> GrantDemand {
    GrantDemand::App {
        bundle: "com.example.Editor".into(),
        code: Arc::new(SignedByFixtureTeam),
    }
}

#[test]
fn worker_scope_ref_never_lends_authority_to_another_holder_even_after_restart() {
    let backing = Arc::new(InMemoryAgentGrantStorage::default());
    struct Empty;
    impl LegacyGrantSource for Empty {
        fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
            Ok(AgentGrantStoreState::default())
        }
    }
    let clock = Arc::new(ManualWallClock::at(100));
    let store = Arc::new(
        AgentGrants::open(backing.clone(), &Empty, Some("machine".into()))
            .with_clock(clock.clone()),
    );
    store
        .upsert(
            row(worker("same-ref"), GrantSubject::WholeComputer, None),
            100,
        )
        .unwrap();
    let check = |store: &Arc<AgentGrants>| {
        assert!(store.authorize(&worker("same-ref"), app()).is_some());
        for other in [head(), worker("another-ref")] {
            assert!(
                store.authorize(&other, app()).is_none(),
                "holder {other:?} borrowed a worker's row"
            );
        }
    };
    check(&store);
    check(&Arc::new(
        AgentGrants::open(backing, &Empty, Some("machine".into())).with_clock(clock),
    ));
}

#[test]
fn most_specific_row_and_browser_target_are_selected_independent_of_store_order() {
    for reverse in [false, true] {
        let (store, _) = store();
        let mut rows = vec![
            row(
                head(),
                GrantSubject::AllSites,
                Some(BrowserTarget::AgentProfile),
            ),
            row(
                head(),
                GrantSubject::Domain("example.com".into()),
                Some(BrowserTarget::AgentProfile),
            ),
            row(
                head(),
                GrantSubject::Origin("https://example.com".into()),
                Some(BrowserTarget::AgentProfile),
            ),
            row(head(), GrantSubject::WholeComputer, None),
            row(head(), GrantSubject::App("com.example.Editor".into()), None),
        ];
        if reverse {
            rows.reverse();
        }
        for row in rows {
            store.upsert(row, 100).unwrap();
        }
        assert_eq!(
            store
                .authorize(&head(), browser(BrowserTarget::AgentProfile))
                .unwrap()
                .row()
                .subject,
            GrantSubject::Origin("https://example.com".into())
        );
        assert_eq!(
            store.authorize(&head(), app()).unwrap().row().subject,
            GrantSubject::App("com.example.Editor".into())
        );
        assert!(store
            .authorize(&head(), browser(BrowserTarget::UserBrowser))
            .is_none());
        let origin_id = store
            .authorize(&head(), browser(BrowserTarget::AgentProfile))
            .unwrap()
            .row()
            .id
            .clone();
        store.revoke(&origin_id, 100).unwrap();
        assert_eq!(
            store
                .authorize(&head(), browser(BrowserTarget::AgentProfile))
                .unwrap()
                .row()
                .subject,
            GrantSubject::Domain("example.com".into())
        );
        let user_id = store
            .upsert(
                row(
                    head(),
                    GrantSubject::Origin("https://example.com".into()),
                    Some(BrowserTarget::UserBrowser),
                ),
                100,
            )
            .unwrap();
        let profile = store
            .authorize(&head(), browser(BrowserTarget::AgentProfile))
            .unwrap();
        let user = store
            .authorize(&head(), browser(BrowserTarget::UserBrowser))
            .unwrap();
        assert_eq!(user.row().id, user_id);
        assert_ne!(profile.row().id, user_id);
        store.revoke(&user_id, 100).unwrap();
        assert!(profile.is_live());
        assert!(!user.is_live());
    }
}

#[tokio::test]
async fn browser_commit_rechecks_revocation_expiry_tier_and_hazards_of_the_same_id() {
    for change in ["revoke", "expire", "tier", "hazard"] {
        let (store, clock) = store();
        let mut initial = row(
            head(),
            GrantSubject::Origin("https://example.com".into()),
            Some(BrowserTarget::AgentProfile),
        );
        initial.hazards = vec![crate::authorization::HazardClass::CredentialFormSubmit];
        let id = store.upsert(initial.clone(), 100).unwrap();
        let grants = GrantStore::default().with_agent_grants(store.clone());
        let decision = with_standing_caller(Some(StandingCaller { holder: head() }), async {
            grants
                .authorize(
                    AuthorizationRequest::navigate(
                        "conversation",
                        Severity::new(3, true, false),
                        "invocation",
                        "head",
                    ),
                    "https://example.com",
                )
                .unwrap()
        })
        .await;
        assert!(grants.commit(&decision).is_ok());
        match change {
            "revoke" => {
                store.revoke(&id, 100).unwrap();
            }
            "expire" => clock.advance_ms(1_800_000),
            "tier" => {
                initial.max_level = 2;
                assert_eq!(store.upsert(initial, 100).unwrap(), id);
            }
            "hazard" => {
                initial.hazards.clear();
                assert_eq!(store.upsert(initial, 100).unwrap(), id);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            grants.commit(&decision),
            Err(AuthorizationCommitError::GrantRevoked),
            "change {change}"
        );
    }
}

#[test]
fn all_sites_never_covers_private_origins_or_sensitive_hazards_and_unsigned_apps_grant_nothing() {
    let (store, _) = store();
    store
        .upsert(
            row(
                head(),
                GrantSubject::AllSites,
                Some(BrowserTarget::AgentProfile),
            ),
            100,
        )
        .unwrap();
    for (origin, severity, hazards) in [
        ("http://127.0.0.1", Severity::new(3, false, false), vec![]),
        ("https://example.com", Severity::new(3, true, false), vec![]),
        ("https://example.com", Severity::new(3, false, true), vec![]),
        (
            "https://example.com",
            Severity::new(3, false, false),
            vec![crate::authorization::HazardClass::UnverifiedFormContents],
        ),
    ] {
        assert!(store
            .authorize(
                &head(),
                GrantDemand::Browser {
                    target: BrowserTarget::AgentProfile,
                    origin: origin.into(),
                    severity,
                    hazards: hazards.into_iter().collect()
                }
            )
            .is_none());
    }
    let mut unsigned = row(head(), GrantSubject::App("com.example.Editor".into()), None);
    unsigned.designated_requirement = None;
    store.upsert(unsigned, 100).unwrap();
    assert!(store.authorize(&head(), app()).is_none());
}

#[tokio::test(start_paused = true)]
async fn takeover_cancels_at_its_wall_clock_expiry_and_nothing_commits_afterwards() {
    let (store, clock) = store();
    let id = store
        .upsert(row(head(), GrantSubject::WholeComputer, None), 100)
        .unwrap();
    let used = store.authorize(&head(), GrantDemand::Takeover).unwrap();
    let cancel = crate::CancelHandle::pending();
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        let used = used.clone();
        async move {
            crate::grant_enforcement::scope(cancel.clone(), async move {
                crate::grant_enforcement::track(&used);
                ready.send(()).unwrap();
                cancel.cancelled().await;
                assert!(!crate::grant_enforcement::commit_current());
            })
            .await;
        }
    });
    started.await.unwrap();
    assert!(store.is_in_use(&id));
    clock.advance_ms(1_799_999);
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    assert!(!cancel.is_cancelled());
    assert!(used.is_live());
    clock.advance_ms(1);
    tokio::time::timeout(std::time::Duration::from_millis(1), cancel.cancelled())
        .await
        .expect("the injected wall clock wakes the takeover at its exact expiry");
    task.await.unwrap();
    assert!(cancel.is_cancelled());
    assert!(!used.is_live());
    assert!(!store.is_in_use(&id));
}

#[tokio::test]
async fn revoking_the_selected_row_stops_inflight_work_but_revoking_a_covering_row_does_not() {
    for change in ["selected", "other", "replacement"] {
        let (store, _) = store();
        let whole = store
            .upsert(row(head(), GrantSubject::WholeComputer, None), 100)
            .unwrap();
        let selected = store
            .upsert(
                row(head(), GrantSubject::App("com.example.Editor".into()), None),
                100,
            )
            .unwrap();
        let used = store.authorize(&head(), app()).unwrap();
        assert_eq!(used.row().id, selected);
        let cancel = crate::CancelHandle::pending();
        let (ready, started) = tokio::sync::oneshot::channel();
        let (finish, finished) = tokio::sync::oneshot::channel();
        let task = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                crate::grant_enforcement::scope(cancel.clone(), async move {
                crate::grant_enforcement::track(&used);
                ready.send(()).unwrap();
                tokio::select! { _ = cancel.cancelled() => false, _ = finished => crate::grant_enforcement::commit_current() }
            }).await
            }
        });
        started.await.unwrap();
        match change {
            "selected" => {
                store.revoke(&selected, 100).unwrap();
            }
            "other" => {
                store.revoke(&whole, 100).unwrap();
            }
            "replacement" => {
                let mut changed = row(head(), GrantSubject::App("com.example.Editor".into()), None);
                changed.designated_requirement = Some("another signer".into());
                assert_eq!(store.upsert(changed, 100).unwrap(), selected);
            }
            _ => unreachable!(),
        }
        if change == "other" {
            finish.send(()).unwrap();
            assert!(task.await.unwrap());
            assert!(!cancel.is_cancelled());
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(2), cancel.cancelled())
                .await
                .unwrap();
            assert!(!task.await.unwrap());
            assert!(
                store.authorize(&head(), app()).is_some(),
                "the broader row still covers a new dispatch"
            );
        }
    }
}

#[test]
fn app_signature_and_target_are_rechecked_on_every_commit() {
    let (store, _) = store();
    let mut initial = row(head(), GrantSubject::App("com.example.Editor".into()), None);
    let id = store.upsert(initial.clone(), 100).unwrap();
    let used = store.authorize(&head(), app()).unwrap();
    initial.designated_requirement = Some("another signer".into());
    assert_eq!(store.upsert(initial, 100).unwrap(), id);
    assert!(!used.is_live());
    assert!(store.authorize(&head(), app()).is_none());
    assert!(
        store.authorize(&head(), GrantDemand::Takeover).is_none(),
        "an app row is not whole-computer consent"
    );
}

#[tokio::test]
async fn native_mutation_gate_rechecks_same_id_before_async_cancel_can_run() {
    let (store, _) = store();
    let mut initial = row(head(), GrantSubject::App("com.example.Editor".into()), None);
    let id = store.upsert(initial.clone(), 100).unwrap();
    let used = store.authorize(&head(), app()).unwrap();
    let request = subc_protocol::Frame::build(
        subc_protocol::FrameType::Request,
        subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
        1,
        1,
        1,
        br#"{}"#.to_vec(),
    )
    .unwrap();
    let terminal = Arc::new(crate::TerminalArbiter::new(request));
    crate::CALL_TERMINAL
        .scope(
            terminal.clone(),
            crate::grant_enforcement::scope(crate::CancelHandle::pending(), async {
                crate::grant_enforcement::track(&used);
                assert!(terminal.gate.begin_mutation());
                initial.designated_requirement = Some("another signer".into());
                assert_eq!(store.upsert(initial, 100).unwrap(), id);
                assert!(!terminal.gate.begin_mutation());
                assert!(terminal.gate.stopped());
            }),
        )
        .await;
    assert!(
        !store.is_in_use(&id),
        "completed calls are not reported as running even if their terminal is retained"
    );
}

#[tokio::test]
async fn unified_authorization_ignores_conversation_grants_and_requires_the_bound_holder() {
    let (store, _) = store();
    let grants = GrantStore::new([crate::authorization::ActionGrant::new(
        "conversation-only",
        1,
        "conversation",
        Severity::new(3, false, false),
        ["https://example.com"],
    )])
    .with_agent_grants(store.clone());
    let attempt = |bind| {
        AuthorizationRequest::navigate(
            "conversation",
            Severity::new(3, false, false),
            "invocation",
            bind,
        )
    };
    assert!(with_standing_caller(None, async {
        grants.authorize(attempt("head"), "https://example.com")
    })
    .await
    .is_err());
    store
        .upsert(
            row(
                head(),
                GrantSubject::Origin("https://example.com".into()),
                Some(BrowserTarget::AgentProfile),
            ),
            100,
        )
        .unwrap();
    assert!(with_standing_caller(None, async {
        grants.authorize(attempt("head"), "https://example.com")
    })
    .await
    .is_err());
    with_standing_caller(Some(StandingCaller { holder: head() }), async {
        assert!(grants
            .authorize(attempt("another-agent"), "https://example.com")
            .is_err());
        assert!(grants
            .authorize(attempt("head"), "https://example.com")
            .is_ok());
    })
    .await;
}
