use super::*;
use crate::cingulate_client::features::{discover, CingulateFeatures};
use subc_protocol::manifest::CapabilityDeclarations;

#[tokio::test]
async fn catalog_discovery_decodes_protocol_types_and_rechecks_absent_error_and_present_peers() {
    use subc_control::{CatalogEntry, ClientControlRequest, ClientControlResponse};
    use subc_transport::{read_frame, write_frame};
    for mode in ["absent", "error", "present", "other-module", "malformed"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let peer = tokio::spawn(async move {
            let frame = read_frame(&mut server).await.unwrap().unwrap();
            assert_eq!((frame.header.channel, frame.header.epoch), (0, 0));
            let request: ClientControlRequest = serde_json::from_slice(&frame.body).unwrap();
            assert_eq!(
                request,
                ClientControlRequest::CatalogList {
                    module_id: Some("cingulate".into())
                }
            );
            let entry = CatalogEntry::new(
                if mode == "other-module" {
                    "unrelated"
                } else {
                    "cingulate"
                },
                vec![],
                vec![],
            )
            .with_capabilities(Some(CapabilityDeclarations {
                provides: if mode == "absent" {
                    vec![]
                } else {
                    vec!["consent-option-group/v1".into()]
                },
                requires: vec![],
                must_never_reach: vec![],
            }));
            let response = ClientControlResponse::CatalogList {
                generation: 1,
                modules: vec![entry],
                subc_ops: vec![],
            };
            let body = if mode == "malformed" {
                b"{}".to_vec()
            } else {
                serde_json::to_vec(&response).unwrap()
            };
            let reply = subc_protocol::Frame::build(
                if mode == "error" {
                    subc_protocol::FrameType::Error
                } else {
                    subc_protocol::FrameType::Response
                },
                crate::control_flags(),
                0,
                0,
                frame.header.corr,
                body,
            )
            .unwrap();
            write_frame(&mut server, &reply).await.unwrap();
        });
        let features = discover(&mut client).await;
        assert_eq!(
            features,
            match mode {
                "present" => Some(CingulateFeatures { option_group: true }),
                "absent" | "other-module" => Some(CingulateFeatures {
                    option_group: false
                }),
                _ => None,
            },
            "{mode}"
        );
        peer.await.unwrap();
    }
}

async fn check_filed_cards(reported: Option<CingulateFeatures>, full: bool) {
    for (kind, name, body, deadline) in cards_with_standing(true) {
        let service = ScriptedCingulate::new();
        service.report_features(reported);
        service.then(wire::CONSENT_REQUEST, created());
        let desk = ConsentDesk::new(Arc::new(service.clone()));
        let (live, _) = live_call("head-features");
        let mut session = desk.session(&live).await.unwrap();
        let card = request_for(kind, &body, deadline);
        let mut expected = card.params.clone();
        if !full {
            expected["options"]
                .as_array_mut()
                .unwrap()
                .retain(|option| option["group"] != "danger");
        }
        let id = session.raise(card.clone(), name).await.unwrap();
        let sent = &service.calls()[0].1;
        assert_eq!(*sent, expected, "{name}");
        crate::consent_card::core_verdict(sent).unwrap();
        let raised = desk.raised(&id).unwrap();
        assert_eq!(
            raised.grant_ids,
            sent["options"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|option| option["effect"] == "grant")
                .map(|option| option["id"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        );
        if !full {
            assert!(
                sent["options"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|option| option.get("group").is_none()),
                "{name}"
            );
            for forbidden in [
                "computer_30m",
                "computer_always",
                "allow_all_sites_30m",
                "allow_all_sites_always",
            ] {
                let record = Record::parse(
                    json!({"elicitation_id":id,"state":"answered","answered_choice_id":forbidden}),
                )
                .unwrap();
                assert_eq!(
                    Ending::of_record(&record, &raised),
                    Some(Ending::Declined {
                        choice_id: forbidden.into()
                    })
                );
            }
        }
    }
}

#[tokio::test]
async fn old_or_unknown_cingulate_receives_only_safe_options_and_records_only_safe_answers() {
    check_filed_cards(None, false).await;
    check_filed_cards(
        Some(CingulateFeatures {
            option_group: false,
        }),
        false,
    )
    .await;
}

#[tokio::test]
async fn supporting_cingulate_receives_the_full_card_and_records_danger_answers() {
    check_filed_cards(Some(CingulateFeatures { option_group: true }), true).await;
}
