//! The copied `consent-requester-v2` vectors: their integrity, and this
//! client's requests and reply parsing held to their bytes.

use serde_json::Value;

use super::double::{vector, vector_result, VECTORS};
use super::wire::{self, CardState, Record, Refusal, RefusalCode};

/// The SHA-256 of the copied `SHA256SUMS`. The manifest covers every other
/// file but cannot cover itself, so its own hash is pinned here.
const MANIFEST_SHA256: &str = "d276eaed5330b95923166d006b2f1b5d83a9a95e050cfe99446d685b22c2e568";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn raw(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(VECTORS).join(name)).unwrap()
}

/// The vectors are trusted only as the exact bytes Cingulate published: an
/// edited body could agree with this client and disagree with Cingulate.
#[test]
fn the_requester_vectors_are_the_ones_cingulate_published() {
    let manifest = raw("SHA256SUMS");
    assert_eq!(
        sha256_hex(&manifest),
        MANIFEST_SHA256,
        "SHA256SUMS is not the manifest Cingulate published"
    );
    let mut listed = Vec::new();
    for line in String::from_utf8(manifest).unwrap().lines() {
        let (expected, name) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("SHA256SUMS line is not `<hash>  <name>`: {line}"));
        assert_eq!(
            sha256_hex(&raw(name)),
            expected,
            "{name} does not match SHA256SUMS"
        );
        listed.push(name.to_string());
    }
    let mut present: Vec<String> = std::fs::read_dir(VECTORS)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "SHA256SUMS")
        .collect();
    present.sort();
    listed.sort();
    assert_eq!(present, listed, "the directory and SHA256SUMS disagree");
}

/// The request bodies this client sends are byte for byte the ones Cingulate
/// served its replies to.
#[test]
fn request_envelopes_are_the_vector_bytes() {
    let request = vector("cerebellum-ref-request.json");
    for (file, method, params) in [
        (
            "cerebellum-ref-request.json",
            wire::CONSENT_REQUEST,
            request["params"].clone(),
        ),
        (
            "cerebellum-await-request.json",
            wire::CONSENT_AWAIT,
            wire::await_params("el_1", 0),
        ),
        (
            "cerebellum-get-request.json",
            wire::CONSENT_GET,
            wire::id_params("el_1"),
        ),
        (
            "cerebellum-answers-request.json",
            wire::CONSENT_ANSWERS,
            wire::answers_params(0),
        ),
    ] {
        assert_eq!(
            String::from_utf8(wire::envelope(method, params)).unwrap(),
            String::from_utf8(raw(file)).unwrap(),
            "{file}"
        );
    }
}

/// Records parse from Cingulate's served replies, with `requester_ref`
/// carried through unchanged and absent when the card had none.
#[test]
fn requester_records_parse_from_the_served_replies() {
    let with_ref = Record::parse(vector_result("cerebellum-ref-get-reply.json")).unwrap();
    assert_eq!(with_ref.elicitation_id, "el_1");
    assert_eq!(with_ref.state, CardState::Pending);
    assert_eq!(with_ref.requester_ref.as_deref(), Some("tool-call-42"));
    assert_eq!(with_ref.answered_choice_id, None);
    assert!(!with_ref.detached);

    let without = Record::parse(vector_result("cerebellum-await-reply.json")).unwrap();
    assert_eq!(without.requester_ref, None);

    let page =
        wire::AnswersPage::parse(&vector_result("cerebellum-ref-answers-reply.json")).unwrap();
    assert_eq!(page.cursor, 1);
    assert_eq!(page.continuation, None);
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].state, CardState::Answered);
    assert_eq!(
        page.records[0].answered_choice_id.as_deref(),
        Some("allow_once")
    );
    assert_eq!(
        page.records[0].requester_ref.as_deref(),
        Some("tool-call-42")
    );

    let created = vector_result("cerebellum-ref-reply.json");
    assert_eq!(created, serde_json::json!({"elicitation_id": "el_1"}));
}

/// Cingulate's refusal of a non-consent kind from cerebellum parses to the
/// requester-refused code.
#[test]
fn the_non_consent_refusal_parses() {
    let refusal = Refusal::from_error_body(&raw("cerebellum-non-consent-refusal.json")).unwrap();
    assert_eq!(refusal.code, RefusalCode::RequesterRefused);
    let request: Value = vector("cerebellum-non-consent-request.json");
    assert_ne!(request["params"]["kind"], wire::KIND_CONSENT);
}

#[test]
fn requester_refs_follow_the_contract_bounds() {
    assert!(wire::is_requester_ref("tool-call-42"));
    assert!(wire::is_requester_ref(&"x".repeat(128)));
    assert!(!wire::is_requester_ref(""));
    assert!(!wire::is_requester_ref(&"x".repeat(129)));
    assert!(!wire::is_requester_ref("tab\there"));
    assert!(!wire::is_requester_ref("caf\u{e9}"));
}
