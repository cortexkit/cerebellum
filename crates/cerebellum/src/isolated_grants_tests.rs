use std::sync::Arc;

use crate::agent_grants::{BrowserTarget, GrantHolder, GrantSubject};
use crate::authorization::{HazardClass, MUTATE_DURABLE};
use crate::cingulate_client::desk::Ending;
use crate::management::{BrowserGrantChoice, BrowserGrantSettlement};
use crate::{JournalPersistence, Planes};
use cerebellum_core::health::HealthState;

#[tokio::test]
async fn default_isolated_planes_record_agent_browser_answers_in_unified_store() {
    let standing = Arc::new(crate::browser_standing_grants::StandingBrowserGrants::open(
        Arc::new(crate::browser_standing_grants::InMemoryStandingGrantStorage::new()),
        Some("isolated-plane".into()),
    ));
    let planes = Planes::with_browser_config_journaling_and_standing_grants(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
        Some(standing),
    );
    let management = &planes.management;
    let (_, question) = management
        .open_browser_grant_at_tier(
            "conversation",
            vec!["http://127.0.0.1:53967".into()],
            vec![HazardClass::CredentialFormSubmit],
            None,
            true,
            Some("test-agent"),
        )
        .await
        .unwrap();
    let question = question.expect("a recordable store offers a site grant");
    management.record_prepared_consent(&question, &question.ask_id);
    assert_eq!(
        management
            .settle_browser_grant_sync(
                &question.ask_id,
                Some(&Ending::Granted {
                    choice_id: "allow_30m".into(),
                }),
            )
            .unwrap(),
        BrowserGrantSettlement::Granted(BrowserGrantChoice::SiteThirtyMinutes)
    );
    let store = management.agent_grants();
    let rows = store.live_rows(None, store.now_ms()).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "isolated browser answers must use the production AgentGrants store, not legacy ActionGrant"
    );
    let row = &rows[0];
    assert_eq!(
        row.holder,
        GrantHolder::Head {
            agent_id: "test-agent".into()
        }
    );
    assert_eq!(
        row.subject,
        GrantSubject::Origin("http://127.0.0.1:53967".into())
    );
    assert_eq!(row.browser_target, Some(BrowserTarget::AgentProfile));
    assert_eq!(row.machine_uuid, "isolated-plane");
    assert_eq!(row.card_ref.as_deref(), Some(question.ask_id.as_str()));
    assert_eq!(row.expires_at_ms, Some(row.granted_at_ms + 1_800_000));
    assert_eq!(row.max_level, MUTATE_DURABLE);
    assert_eq!(row.hazards, vec![HazardClass::CredentialFormSubmit]);
    assert_eq!(management.browser_grant_count().await, 0);
}
