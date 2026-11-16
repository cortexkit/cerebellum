use super::*;

#[tokio::test]
async fn only_successful_imports_record_a_signed_in_domain() {
    let signed_in = Arc::new(browser_signed_in::SignedInDomains::default());
    signed_in
        .initialize_profile("agent", "default", "new-agent-profile", true)
        .unwrap();
    signed_in
        .initialize_profile("other-agent", "default", "new-other-profile", true)
        .unwrap();
    let planes = Planes::with_browser_state(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
        None,
        Some(Arc::clone(&signed_in)),
    );
    let bind = subc_protocol::BindIdentity::new("test", "import-facts");
    let identity = RouteIdentity::from_accepted_bind(
        &bind,
        &None,
        Some(&json!({"agentProjectId": "agent", "sessionKind": "primary"})),
    );
    for ending in ["denied", "hand_off", "transfer_failed"] {
        let result =
            login_import::ImportResult::refusal("https://login.example.com", ending, "retry");
        let reply = journal_login_import_result(&planes, &identity, result).await;
        assert_eq!(reply["outcome"], ending);
        assert!(!signed_in.is_signed_in("agent", "default", "https://account.example.com"));
    }
    let mut imported =
        login_import::ImportResult::refusal("https://login.example.com", "transferred", "");
    imported.remedy = None;
    imported.browser = Some("chrome".into());
    imported.rows = 1;
    let reply = journal_login_import_result(&planes, &identity, imported).await;
    assert_eq!(reply["outcome"], "transferred");
    assert!(signed_in.is_signed_in("agent", "default", "https://account.example.com"));
    assert!(!signed_in.is_signed_in("other-agent", "default", "https://account.example.com"));
}
