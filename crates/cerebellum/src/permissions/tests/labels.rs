use super::*;
use crate::authorization::HazardClass;

#[tokio::test]
async fn provider_site_labels_explain_access_without_internal_tiers() {
    for (level, access) in [
        (1, "read"),
        (2, "read, click and type"),
        (3, "read, click, type and make reversible changes"),
        (4, "read, click, type and make lasting changes"),
    ] {
        for (subject, site) in [
            (
                GrantSubject::Origin("https://github.com".into()),
                "https://github.com",
            ),
            (GrantSubject::Domain("github.com".into()), "github.com"),
        ] {
            let mut grant = row("site", head("agent-alf"), subject, None, "card");
            grant.max_level = level;
            let (planes, _, _, _) = fixture(vec![grant]);
            let (ty, reply) = call(&planes, aggregator(), LIST, json!({})).await;
            assert_eq!(ty, FrameType::Response);
            let listed = &reply["grants"][0];
            assert_eq!(listed["subject_label"], format!("{site}: {access}"));
            assert_eq!(
                listed["holder"],
                json!({"kind":"agent","agent_id":"agent-alf"})
            );
        }
    }
}

#[tokio::test]
async fn provider_site_labels_describe_disclosed_form_hazards() {
    for (hazards, consent) in [
        (vec![HazardClass::CredentialFormSubmit], "sign-in forms"),
        (vec![HazardClass::FinancialFormSubmit], "payment forms"),
        (
            vec![HazardClass::UnverifiedFormContents],
            "forms with unverified contents",
        ),
        (
            vec![
                HazardClass::CredentialFormSubmit,
                HazardClass::FinancialFormSubmit,
                HazardClass::UnverifiedFormContents,
            ],
            "sign-in forms, payment forms, forms with unverified contents",
        ),
    ] {
        let mut grant = row(
            "site",
            head("agent-alf"),
            GrantSubject::Origin("https://github.com".into()),
            Some(END),
            "card",
        );
        grant.max_level = 4;
        grant.hazards = hazards;
        let (planes, _, _, _) = fixture(vec![grant]);
        let (ty, reply) = call(&planes, aggregator(), LIST, json!({})).await;
        assert_eq!(ty, FrameType::Response);
        assert_eq!(
            reply["grants"][0]["scope_label"],
            format!("the site https://github.com in the agent browser; consent includes {consent}")
        );
    }
}

struct UnnamedApps;
impl management::TargetResolver for UnnamedApps {
    fn resolve(&self, bundle: &str) -> TargetResolution {
        if bundle == "com.example.Stopped" {
            TargetResolution::NotRunning
        } else {
            TargetResolution::Resolved(ProcessGrant {
                pid: 42,
                bundle_identity: bundle.into(),
                process_generation_evidence: "fixture".into(),
            })
        }
    }
}

#[tokio::test]
async fn provider_app_labels_use_display_names_or_the_stored_public_app_identity() {
    let (planes, _, _, _) = fixture(vec![row(
        "app",
        head("agent-alf"),
        GrantSubject::App("com.apple.TextEdit".into()),
        None,
        "card",
    )]);
    let (_, reply) = call(&planes, aggregator(), LIST, json!({})).await;
    assert_eq!(reply["grants"][0]["subject_label"], "TextEdit");
    assert_eq!(reply["grants"][0]["scope_label"], "the app TextEdit");

    for app in ["com.example.Stopped", "example-editor"] {
        let (mut planes, store, _, _) = fixture(vec![row(
            "app",
            head("agent-alf"),
            GrantSubject::App(app.into()),
            None,
            "card",
        )]);
        planes.management = Arc::new(
            management::ManagementPlane::new(Arc::new(UnnamedApps)).with_agent_grants(store),
        );
        let (_, reply) = call(&planes, aggregator(), LIST, json!({})).await;
        assert_eq!(reply["grants"][0]["subject_label"], app);
        assert_eq!(reply["grants"][0]["scope_label"], format!("the app {app}"));
    }
}
