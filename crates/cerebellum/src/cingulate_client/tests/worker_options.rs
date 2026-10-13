//! Exact worker option sets for all card families, including single-use cards.

use super::*;

#[test]
fn every_worker_card_kind_has_only_conversation_or_single_use_options() {
    let facts = crate::tests::management_bound_planes(1, 1)
        .routes
        .get(1, 1)
        .unwrap()
        .with_scope(Some(super::super::worker_vectors::worker_stamp()));
    assert!(crate::standing_offer_agent(&facts).is_none());
    let cards = cards_with_standing(crate::standing_offer_agent(&facts).is_some());
    let expected = [
        (
            CardKind::WebsiteAccessInCall,
            vec!["allow_conversation", "deny"],
        ),
        (
            CardKind::WebsiteAccessInAdvance,
            vec!["allow_conversation", "deny"],
        ),
        (CardKind::AppControl, vec!["allow_conversation", "deny"]),
        (CardKind::Takeover, vec!["allow_conversation", "deny"]),
        (
            CardKind::LoginImport,
            vec!["transfer:chrome", "hand_off", "deny"],
        ),
        (CardKind::LoginCapture, vec!["allow", "deny"]),
        (CardKind::ProfileReidentification, vec!["allow", "deny"]),
        (CardKind::StuckProfileClearance, vec!["clear", "keep"]),
        (CardKind::UserBrowserSite, vec!["allow_once", "deny"]),
    ];
    assert_eq!(cards.len(), CardKind::ALL.len());
    assert_eq!(expected.len(), CardKind::ALL.len());
    for (kind, _, body, deadline) in cards {
        let card = consent_request(kind, &body, deadline, None, None, None).unwrap();
        let ids: Vec<_> = card.params["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            expected.iter().find(|row| row.0 == kind).unwrap().1,
            "{kind:?}"
        );
        let raised = RaisedCard {
            elicitation_id: "el_worker".into(),
            session: LiveCall::new(
                Some(&super::super::worker_vectors::worker_stamp()),
                Arc::new(TestHold(AtomicBool::new(true))),
            )
            .unwrap()
            .session()
            .clone(),
            kind,
            subject: "test".into(),
            grant_ids: card.grant_ids,
            decline_id: card.decline_id,
            next_steps: card.next_steps,
            applied: false,
        };
        for forbidden in [
            "allow_always",
            "allow_origin_always",
            "allow_all_sites_10m",
            "allow_all_sites_always",
        ] {
            let record = Record::parse(json!({"elicitation_id":"el_worker","state":"answered","answered_choice_id":forbidden})).unwrap();
            assert_eq!(
                Ending::of_record(&record, &raised),
                Some(Ending::Declined {
                    choice_id: forbidden.into()
                }),
                "{kind:?}: {forbidden}"
            );
        }
    }
}
