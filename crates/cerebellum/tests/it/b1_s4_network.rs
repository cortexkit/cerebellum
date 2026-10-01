#![allow(dead_code, unused_imports)]

//! Network policy and connector acceptance fixtures.
//!
//! The module is used through the library rather than included by path, so
//! these fixtures exercise the same code the crate ships. A path include
//! compiles a second copy with a different set of sibling modules in scope,
//! which is why the tests could pass over code the library could not build.

use cerebellum::network::{
    address_policy_fixture, parse_canonical_url, AuthorizationDecision, ChildIdentity,
    CommitmentKind, Connector, ConnectorAdmission, ConnectorError, NetworkRequest,
    RequestAttribution, RequestClass, StaticResolver, TransitionTargetCache,
};
use std::sync::Arc;

fn connector() -> (Connector<StaticResolver>, Arc<StaticResolver>) {
    let resolver = Arc::new(StaticResolver::new());
    resolver.set(
        "public.example",
        vec!["192.0.2.1".into(), "93.184.216.34".into()],
    );
    resolver.set("other.example", vec!["93.184.216.34".into()]);
    let mut connector = Connector::new(address_policy_fixture().unwrap(), Arc::clone(&resolver));
    connector.admit(ConnectorAdmission::new(ChildIdentity {
        process_id: 11,
        generation: 1,
        custody_digest: "a".repeat(64),
    }));
    connector
        .register_decision(AuthorizationDecision::new(
            "decision-1",
            ["https://public.example"],
        ))
        .unwrap();
    (connector, resolver)
}

fn request(url: &str, class: RequestClass, decision: Option<&str>) -> NetworkRequest {
    NetworkRequest::new(
        "request-1",
        Arc::new(parse_canonical_url(url).unwrap()),
        Some(RequestAttribution::module_controlled(
            11,
            1,
            "context-1",
            "target-1",
            class,
        )),
        class,
        decision.map(str::to_string),
    )
}

#[test]
fn one_parse_is_reused_by_each_retry_target() {
    let mut cache = TransitionTargetCache::new();
    let first = cache.parsed_target("HTTPS://Example.COM:443/path").unwrap();
    let retry = first.retry();
    let later = cache.parsed_target("HTTPS://Example.COM:443/path").unwrap();
    assert!(first.same_parsed_object(&retry));
    assert!(first.same_parsed_object(&later));
    assert_eq!(cache.parse_count(), 1);
}

#[test]
fn mixed_resolution_answers_select_only_the_allowed_exact_peer() {
    let (mut connector, _) = connector();
    let committed = connector
        .commit_request(&request(
            "https://public.example/",
            RequestClass::TopLevelNavigation,
            Some("decision-1"),
        ))
        .unwrap();
    assert_eq!(committed.peer.to_string(), "93.184.216.34");
    assert_eq!(committed.kind, CommitmentKind::DestinationRequest);
    assert_eq!(connector.destination_request_commits(), 1);

    let mapped = request("https://[::ffff:93.184.216.34]/", RequestClass::Image, None);
    let mapped_peer = connector.commit_request(&mapped).unwrap();
    assert_eq!(mapped_peer.peer.to_string(), "93.184.216.34");
}

#[test]
fn every_precommit_failure_commits_no_request_or_stream_bytes() {
    let (mut connector, resolver) = connector();
    let unattributed = NetworkRequest::new(
        "u",
        Arc::new(parse_canonical_url("https://public.example/").unwrap()),
        None,
        RequestClass::Image,
        None,
    );
    assert_eq!(
        connector.commit_request(&unattributed),
        Err(ConnectorError::Unattributed)
    );
    let unauthorized = request(
        "https://other.example/",
        RequestClass::TopLevelNavigation,
        Some("decision-1"),
    );
    assert!(matches!(
        connector.commit_request(&unauthorized),
        Err(ConnectorError::OriginScope { .. })
    ));
    resolver.set("public.example", vec!["127.0.0.1".into()]);
    assert_eq!(
        connector.commit_stream(&request(
            "https://public.example/",
            RequestClass::WebSocketHandshake,
            None,
        )),
        Err(ConnectorError::AddressNotAllowed {
            address_class: cerebellum::network::AddressClass::Loopback
        })
    );
    assert_eq!(connector.total_committed_bytes(), 0);
}

#[test]
fn direct_fallback_and_page_asserted_attribution_are_fail_closed() {
    let (mut connector, _) = connector();
    assert_eq!(
        connector.direct_socket_attempt(),
        Err(ConnectorError::DirectFallbackBlocked)
    );
    let page_asserted = NetworkRequest::new(
        "p",
        Arc::new(parse_canonical_url("https://public.example/").unwrap()),
        Some(RequestAttribution::page_supplied(RequestClass::FetchXhr)),
        RequestClass::FetchXhr,
        None,
    );
    assert_eq!(
        connector.commit_request(&page_asserted),
        Err(ConnectorError::PageSuppliedAttribution)
    );
    assert_eq!(connector.total_committed_bytes(), 0);
}

#[test]
fn non_http_scheme_is_refused_before_resolution_or_commit() {
    let (connector, _) = connector();
    let target = parse_canonical_url("ftp://public.example/").unwrap();

    assert_eq!(
        connector.resolve_allowed(&target),
        Err(ConnectorError::SchemeNotAllowed {
            scheme: "ftp".to_string()
        })
    );
    assert_eq!(connector.transport_count(), 0);
}

#[test]
fn http_scheme_reaches_the_same_resolution_path() {
    let (connector, _) = connector();
    let target = parse_canonical_url("http://public.example/").unwrap();

    let peer = connector
        .resolve_allowed(&target)
        .expect("an allowed HTTP scheme should resolve");
    assert_eq!(peer.address.to_string(), "93.184.216.34");
}

#[test]
fn missing_transport_is_refused_before_any_commit() {
    let (mut connector, _) = connector();
    let request = request(
        "https://public.example/",
        RequestClass::Retry,
        Some("decision-1"),
    )
    .reuse_transport("transport-missing");

    assert_eq!(
        connector.commit_request(&request),
        Err(ConnectorError::TransportNotFound)
    );
    assert_eq!(connector.total_committed_bytes(), 0);
    assert_eq!(connector.transport_count(), 0);
}

#[test]
fn transport_reuse_keeps_the_validated_peer_and_rejects_coalescing_widening() {
    let (mut connector, _) = connector();
    let first = connector
        .commit_request(&request(
            "https://public.example/",
            RequestClass::TopLevelNavigation,
            Some("decision-1"),
        ))
        .unwrap();
    let retry = request(
        "https://public.example/retry",
        RequestClass::Retry,
        Some("decision-1"),
    )
    .reuse_transport(first.transport_id.clone());
    assert_eq!(connector.commit_request(&retry).unwrap().peer, first.peer);
    let coalesced = request(
        "https://other.example/",
        RequestClass::FrameNavigation,
        None,
    )
    .coalesce_transport(first.transport_id);
    assert_eq!(
        connector.commit_request(&coalesced),
        Err(ConnectorError::CertificateCoalescingDenied)
    );
    assert_eq!(connector.destination_request_commits(), 2);
}
