use super::*;
use crate::agent_grants::{GrantHolder, GrantSubject};

fn grants() -> Arc<ComputerGrants> {
    Arc::new(ComputerGrants::open(
        Arc::new(InMemoryGrantStorage::new()),
        Some("machine-card".into()),
    ))
}

#[tokio::test]
async fn takeover_once_never_writes_a_row_and_the_next_call_asks_again() {
    let service = CardService::new();
    let carrier = TestCarrier::new(&service);
    let grants = grants();
    for number in 1..=2 {
        let task = {
            let grants = grants.clone();
            let context = context(carrier.clone());
            tokio::spawn(async move {
                grants
                    .require(&GrantNeed::Takeover, &context, &CancelHandle::pending())
                    .await
            })
        };
        let card = service.card(1, 1).await;
        assert!(service.answer(
            card.header.corr,
            ScriptedAnswer::Answered(json!({"decision":"allow_once"}))
        ));
        let admission = task.await.unwrap().unwrap();
        assert!(admission.commit());
        assert!(admission.row.is_none());
        assert!(grants
            .agent_grants()
            .live_rows(None, grants.agent_grants().now_ms())
            .unwrap()
            .is_empty());
        assert!(!grants.holds(&context(carrier.clone()).caller, &GrantNeed::Takeover));
        assert_eq!(
            service
                .calls()
                .iter()
                .filter(|(method, _)| method == wire::CONSENT_REQUEST)
                .count(),
            number
        );
    }
}

#[tokio::test]
async fn computer_once_remains_usable_without_a_holder_or_recording_store() {
    for no_holder in [true, false] {
        for need in [
            GrantNeed::Takeover,
            GrantNeed::App {
                bundle_identity: "com.example.Editor".into(),
                display_name: "Editor".into(),
                code: Arc::new(SignedByFixtureTeam),
            },
        ] {
            let service = CardService::new();
            let carrier = TestCarrier::new(&service);
            let grants =
                if no_holder {
                    grants()
                } else {
                    Arc::new(ComputerGrants::in_memory().with_agent_grants(Arc::new(
                        crate::agent_grants::AgentGrants::in_memory(None),
                    )))
                };
            let task = {
                let grants = grants.clone();
                let mut context = context(carrier);
                if no_holder {
                    context.caller.holder = None;
                }
                tokio::spawn(async move {
                    grants
                        .require(&need, &context, &CancelHandle::pending())
                        .await
                })
            };
            let card = service.card(1, 1).await;
            assert!(service.answer(
                card.header.corr,
                ScriptedAnswer::Answered(json!({"decision":"allow_once"}))
            ));
            let admission = task.await.unwrap().unwrap();
            assert!(admission.commit());
            assert!(admission.row.is_none());
            assert!(grants.agent_grants().live_rows(None, 0).unwrap().is_empty());
        }
    }
}

#[test]
fn filtered_computer_card_without_a_grant_choice_has_a_typed_refusal() {
    use crate::permission_cards::{require_grant_choice, GrantCardRefusal};
    for need in [
        GrantNeed::Takeover,
        GrantNeed::App {
            bundle_identity: "com.example.Editor".into(),
            display_name: "Editor".into(),
            code: Arc::new(SignedByFixtureTeam),
        },
    ] {
        let body = question_body(&need, &[DENY], false, None);
        assert_eq!(
            require_grant_choice(&body, None),
            Err(GrantCardRefusal::NoGrantHolder)
        );
        assert_eq!(
            require_grant_choice(
                &body,
                Some(&GrantHolder::Head {
                    agent_id: "head".into()
                })
            ),
            Err(GrantCardRefusal::GrantStoreUnavailable)
        );
    }
}

#[test]
fn app_and_takeover_card_answers_replace_in_place_and_worker_always_is_refused() {
    let grants = grants();
    let mut open = AnsweredQuestion {
        holder: Some(GrantHolder::Head {
            agent_id: "head".into(),
        }),
        card_ref: "card-one".into(),
        subject: Subject::App {
            conversation_key: "one".into(),
            bundle_identity: "com.example.Editor".into(),
        },
        offered: vec![ALLOW_30M, ALLOW_ALWAYS, COMPUTER_30M, COMPUTER_ALWAYS],
        identity: Some(SignedByFixtureTeam.identity().unwrap()),
    };
    for (temporary, permanent, subject) in [
        (
            ALLOW_30M,
            ALLOW_ALWAYS,
            GrantSubject::App("com.example.Editor".into()),
        ),
        (COMPUTER_30M, COMPUTER_ALWAYS, GrantSubject::WholeComputer),
    ] {
        let before = grants
            .agent_grants()
            .live_rows(None, grants.agent_grants().now_ms())
            .unwrap()
            .len();
        assert!(matches!(
            grants.apply_answer(
                &open,
                &CardEnding::Granted {
                    choice_id: temporary.into()
                }
            ),
            Settlement::Allowed { .. }
        ));
        let first = grants
            .agent_grants()
            .live_rows(None, grants.agent_grants().now_ms())
            .unwrap()
            .into_iter()
            .find(|row| row.subject == subject)
            .unwrap();
        assert_eq!(first.expires_at_ms, Some(first.granted_at_ms + 1_800_000));
        open.card_ref = "card-upgrade".into();
        assert!(matches!(
            grants.apply_answer(
                &open,
                &CardEnding::Granted {
                    choice_id: permanent.into()
                }
            ),
            Settlement::Allowed { .. }
        ));
        let rows = grants
            .agent_grants()
            .live_rows(None, grants.agent_grants().now_ms())
            .unwrap();
        assert_eq!(rows.len(), before + 1);
        let replaced = rows.into_iter().find(|row| row.subject == subject).unwrap();
        assert_eq!(replaced.id, first.id);
        assert_eq!(replaced.expires_at_ms, None);
        assert_eq!(replaced.card_ref.as_deref(), Some("card-upgrade"));
    }
    open.holder = Some(GrantHolder::Worker {
        agent_id: "head".into(),
        scope_ref: "worker".into(),
    });
    assert!(matches!(
        grants.apply_answer(
            &open,
            &CardEnding::Granted {
                choice_id: COMPUTER_ALWAYS.into()
            }
        ),
        Settlement::Ended {
            reason: "grant_not_recorded",
            ..
        }
    ));
}

#[test]
fn computer_offers_follow_holder_storage_and_signer_without_making_danger_the_only_grant() {
    let grants = grants();
    let mut caller = GrantCaller::new("conversation".into(), "head".into(), true);
    let need = GrantNeed::App {
        bundle_identity: "com.example.Editor".into(),
        display_name: "Editor".into(),
        code: Arc::new(SignedByFixtureTeam),
    };
    let identity = SignedByFixtureTeam.identity().unwrap();
    assert_eq!(
        grants.offered_choices(&caller, &need, Some(&identity)),
        [ALLOW_30M, ALLOW_ALWAYS, COMPUTER_30M, COMPUTER_ALWAYS, DENY]
    );
    assert_eq!(
        grants.offered_choices(&caller, &GrantNeed::Takeover, None),
        [ALLOW_ONCE, COMPUTER_30M, COMPUTER_ALWAYS, DENY]
    );
    let unreadable = ComputerGrants::in_memory().with_agent_grants(Arc::new(
        crate::agent_grants::AgentGrants::unavailable(
            crate::agent_grants::AgentGrantStoreError::NoMachineIdentity,
        ),
    ));
    assert_eq!(
        unreadable.offered_choices(&caller, &need, Some(&identity)),
        [ALLOW_ONCE, DENY]
    );
    caller.holder = Some(GrantHolder::Worker {
        agent_id: "head".into(),
        scope_ref: "worker".into(),
    });
    assert_eq!(
        grants.offered_choices(&caller, &need, Some(&identity)),
        [ALLOW_30M, COMPUTER_30M, DENY]
    );
    assert_eq!(
        grants.offered_choices(&caller, &GrantNeed::Takeover, None),
        [ALLOW_ONCE, COMPUTER_30M, DENY]
    );
    caller.holder = None;
    assert_eq!(
        grants.offered_choices(&caller, &need, Some(&identity)),
        [ALLOW_ONCE, DENY]
    );
}

#[test]
fn a_stripped_computer_danger_answer_never_mints_a_row() {
    let grants = grants();
    let open = AnsweredQuestion {
        holder: Some(GrantHolder::Head {
            agent_id: "head".into(),
        }),
        card_ref: "card".into(),
        subject: Subject::Takeover {
            conversation_key: "conversation".into(),
        },
        offered: vec![ALLOW_ONCE, COMPUTER_30M, COMPUTER_ALWAYS, DENY],
        identity: None,
    };
    assert!(matches!(
        grants.apply_answer(
            &open,
            &CardEnding::Declined {
                choice_id: COMPUTER_30M.into()
            }
        ),
        Settlement::Ended {
            reason: "unrecognized_answer",
            ..
        }
    ));
    assert!(grants
        .agent_grants()
        .live_rows(None, grants.agent_grants().now_ms())
        .unwrap()
        .is_empty());
}
