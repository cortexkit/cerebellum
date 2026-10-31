//! The handle store `image.resolve` reads: what a capture mints, what resolves,
//! and what has to end before a handle stops resolving.
//!
//! The conversation-end drop and the shared authorization union are checked
//! where they live, on `Planes` and in `private_content`, because they need the
//! route table and the mark store.

use crate::image_handles::{
    Capture, ImageHandles, IMAGE_HANDLE_MAX_BYTES, LIFETIME, MAX_RESOLVE_BODY_BYTES,
    PER_SCOPE_LIMIT,
};
use crate::{wall_clock_ms, Planes};
use serde_json::{json, Value};
use std::sync::Arc;

fn png(seed: u8, length: usize) -> (Value, Vec<u8>) {
    let bytes: Vec<u8> = (0..length)
        .map(|index| seed.wrapping_add(index as u8))
        .collect();
    let reply = json!({"image": {"mime": "image/png", "data_b64": cerebellum_core::serde_base64::encode(&bytes)}});
    (reply, bytes)
}

fn capture(scope: &str, now_ms: u64) -> Capture {
    Capture {
        scope_ref: scope.to_owned(),
        conversation_key: "conversation".to_owned(),
        now_ms,
    }
}

/// The head a resolve body starts with: its big-endian length, then the JSON.
/// Returns the head's parsed value and the image bytes after it.
fn split_resolve(body: &[u8]) -> (Value, &[u8]) {
    let length = u32::from_be_bytes(body[..4].try_into().expect("a four-byte head length"));
    let head: Value = serde_json::from_slice(&body[4..4 + length as usize]).expect("head JSON");
    (head, &body[4 + length as usize..])
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn a_minted_handle_is_ih_and_32_lowercase_hex() {
    let store = ImageHandles::default();
    let (reply, _) = png(1, 16);
    let mut handles = Vec::new();
    for _ in 0..4 {
        handles.push(store.mint(&reply, &capture("scope", 0)).unwrap());
    }
    for handle in &handles {
        assert_eq!(handle.len(), 34, "{handle}");
        assert!(handle.starts_with("ih"), "{handle}");
        assert!(
            handle[2..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{handle}"
        );
    }
    let unique: std::collections::BTreeSet<_> = handles.iter().collect();
    assert_eq!(unique.len(), handles.len(), "two captures shared a handle");
}

#[test]
fn a_resolved_handle_returns_exactly_the_reply_bytes_and_their_digest() {
    let store = ImageHandles::default();
    let (reply, bytes) = png(9, 300);
    let handle = store.mint(&reply, &capture("scope", 1_000)).unwrap();
    let answer = store.resolve(&handle, &["scope"], 1_000).unwrap();
    let (head, image) = split_resolve(&answer.body);
    assert_eq!(
        head,
        json!({"content_type": "image/png", "sha256": sha256(&bytes), "length": bytes.len()})
    );
    assert_eq!(image, bytes.as_slice());
}

#[test]
fn a_handle_resolves_for_fifteen_minutes_and_not_a_millisecond_longer() {
    let store = ImageHandles::default();
    let (reply, _) = png(2, 8);
    let handle = store.mint(&reply, &capture("scope", 5_000)).unwrap();
    let lifetime = LIFETIME.as_millis() as u64;
    assert!(store
        .resolve(&handle, &["scope"], 5_000 + lifetime - 1)
        .is_some());
    assert!(store
        .resolve(&handle, &["scope"], 5_000 + lifetime)
        .is_none());
}

#[test]
fn resolving_never_extends_a_handle() {
    let store = ImageHandles::default();
    let (reply, _) = png(3, 8);
    // Captured at 1 ms: a capture stamped 0 would already be at its boundary
    // when asked at 0, and this test is about the far end of the 15 minutes.
    let handle = store.mint(&reply, &capture("scope", 1)).unwrap();
    let lifetime = LIFETIME.as_millis() as u64;
    for elapsed in [1 + lifetime / 4, 1 + lifetime / 2, lifetime] {
        assert!(
            store.resolve(&handle, &["scope"], elapsed).is_some(),
            "at {elapsed}"
        );
    }
    assert!(store.resolve(&handle, &["scope"], lifetime + 1).is_none());
}

#[test]
fn a_scope_keeps_its_eight_newest_handles() {
    let store = ImageHandles::default();
    let mut handles = Vec::new();
    for index in 0..(PER_SCOPE_LIMIT + 2) {
        let (reply, _) = png(index as u8, 8);
        handles.push(store.mint(&reply, &capture("scope", 0)).unwrap());
    }
    for (index, handle) in handles.iter().enumerate() {
        let resolved = store.resolve(handle, &["scope"], 0).is_some();
        assert_eq!(resolved, index >= 2, "handle {index}");
    }
    // The cap counts one scope's handles; other scopes keep their own.
    let (reply, _) = png(7, 8);
    store.mint(&reply, &capture("other-scope", 0));
    for handle in &handles[2..] {
        assert!(store.resolve(handle, &["scope"], 0).is_some());
    }
}

#[test]
fn the_oldest_handles_go_first_when_the_bytes_cap_is_reached() {
    let store = ImageHandles::default();
    // Each handle is just under the mint limit, so it mints; seventeen of them
    // cross the store's 64 MiB byte cap, and each scope's cap of eight is never
    // reached.
    let chunk = IMAGE_HANDLE_MAX_BYTES - 1;
    let mut handles = Vec::new();
    for index in 0..17 {
        let (reply, _) = png(index as u8, chunk);
        let scope = format!("scope-{index}");
        handles.push(
            store
                .mint(&reply, &capture(&scope, 0))
                .expect("an image under the mint limit has a handle"),
        );
    }
    // The store holds what 64 MiB allows, and the oldest are what went.
    let surviving = store.held();
    assert!(
        surviving < handles.len(),
        "the byte cap must have evicted some"
    );
    for (index, handle) in handles.iter().enumerate() {
        let scope = format!("scope-{index}");
        let resolved = store.resolve(handle, &[scope.as_str()], 0).is_some();
        assert_eq!(
            resolved,
            index >= handles.len() - surviving,
            "handle {index} must survive exactly when it is among the newest"
        );
    }
    // The newest handle always survives, so eviction never empties the store.
    let newest = format!("scope-{}", handles.len() - 1);
    assert!(store
        .resolve(handles.last().unwrap(), &[newest.as_str()], 0)
        .is_some());
}

#[test]
fn unknown_expired_and_other_scope_handles_are_one_answer() {
    let store = ImageHandles::default();
    let (reply, _) = png(4, 8);
    let handle = store.mint(&reply, &capture("scope", 0)).unwrap();
    let lifetime = LIFETIME.as_millis() as u64;
    let other: String = format!("ih{}", "0".repeat(32));
    assert!(other != handle);
    for candidate in [
        // Never minted.
        store.resolve(&other, &["scope"], 0),
        // Minted, but this union does not name its scope.
        store.resolve(&handle, &["elsewhere"], 0),
        // Minted and in scope, but past its 15 minutes.
        store.resolve(&handle, &["scope"], lifetime),
        // Not a handle this module could have minted.
        store.resolve("ihnot-a-handle", &["scope"], 0),
        store.resolve("", &["scope"], 0),
    ] {
        assert!(candidate.is_none(), "a refusal must not resolve");
    }
}

#[test]
fn a_reply_without_usable_image_bytes_mints_nothing() {
    let store = ImageHandles::default();
    let scope = capture("scope", 0);
    for reply in [
        json!({"outcome": "completed"}),
        json!({"image": {"mime": "image/png"}}),
        json!({"image": {"mime": "image/png", "data_b64": ""}}),
        json!({"image": {"mime": "image/webp", "data_b64": "AAAA"}}),
        json!({"image": {"mime": "image/png", "data_b64": "%%%not base64%%%"}}),
        json!({"image": "not an object"}),
    ] {
        assert_eq!(store.mint(&reply, &scope), None, "{reply}");
    }
}

#[test]
fn a_jpeg_read_state_image_mints_a_jpeg_handle() {
    let store = ImageHandles::default();
    let reply = json!({"outcome": "completed", "image": {"image_id": "image-1", "mime": "image/jpeg", "data_b64": "AAECAw=="}});
    let handle = store.mint(&reply, &capture("scope", 0)).unwrap();
    let answer = store.resolve(&handle, &["scope"], 0).unwrap();
    let (head, image) = split_resolve(&answer.body);
    assert_eq!(head["content_type"], "image/jpeg");
    assert_eq!(image, [0u8, 1, 2, 3]);
}

/// A capture made on a route with a scope stamp leaves the handle beside the
/// image. The store is the same one `image.resolve` reads.
#[test]
fn a_capture_reply_carries_a_handle_its_bytes_resolve_by() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    let facts = crate::AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", "conversation".to_string()),
        Some(subc_protocol::Principal::Reserved {
            module_id: "cerebellum".to_owned(),
        }),
        None,
        None,
        &subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".to_owned(),
        },
    )
    .with_scope(Some(
        subc_protocol::scope::ScopeStamp::new(
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".to_owned(),
            },
            "head-scope",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_owner_authorized(true),
    ));
    let (mut reply, bytes) = png(5, 32);
    crate::mint_image_handle(&planes, &facts, &mut reply);
    let handle = reply["image_handle"].as_str().unwrap().to_owned();
    let answer = planes
        .image_handles
        .resolve(&handle, &["head-scope"], wall_clock_ms());
    let answer = answer.unwrap();
    let (_, image) = split_resolve(&answer.body);
    assert_eq!(image, bytes.as_slice());
}

/// Without a scope stamp nothing could ever resolve the bytes, so the reply
/// omits the field and the store holds nothing.
#[test]
fn a_capture_on_an_unstamped_route_mints_no_handle() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    let facts = crate::AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", "conversation".to_string()),
        Some(subc_protocol::Principal::Reserved {
            module_id: "cerebellum".to_owned(),
        }),
        None,
        None,
        &subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".to_owned(),
        },
    );
    assert!(crate::private_content::capture_scope(&facts).is_none());
    let mut reply = json!({"image": {"mime": "image/png", "data_b64": "AAECAw=="}});
    let before = reply.clone();
    crate::mint_image_handle(&planes, &facts, &mut reply);
    assert_eq!(reply, before);
    assert_eq!(planes.image_handles.held(), 0);
}

/// A conversation's handles go when its last route closes, however long their
/// 15 minutes would have lasted: the bytes were for that conversation's work.
#[test]
fn ending_a_conversation_drops_its_handles() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    let (reply, _) = png(6, 8);
    let kept = planes
        .image_handles
        .mint(
            &reply,
            &Capture {
                scope_ref: "scope".to_owned(),
                conversation_key: "another-conversation".to_owned(),
                now_ms: wall_clock_ms(),
            },
        )
        .unwrap();
    let dropped = planes
        .image_handles
        .mint(
            &reply,
            &Capture {
                scope_ref: "scope".to_owned(),
                conversation_key: "conversation".to_owned(),
                now_ms: wall_clock_ms(),
            },
        )
        .unwrap();
    planes.image_handles.end_conversation("conversation");
    assert!(planes
        .image_handles
        .resolve(&dropped, &["scope"], wall_clock_ms())
        .is_none());
    assert!(planes
        .image_handles
        .resolve(&kept, &["scope"], wall_clock_ms())
        .is_some());
    assert_eq!(planes.image_handles.held(), 1);
}

/// The published limit: 4 MiB minus a 64 KiB allowance, which is BROCA's own
/// `MAX_REFERENCE_IMAGE_BYTES`. A change here changes what BROCA's guard
/// accepts, so it is pinned to the number, not to the arithmetic.
#[test]
fn the_mint_limit_is_the_published_number() {
    assert_eq!(IMAGE_HANDLE_MAX_BYTES, 4_128_768);
    assert_eq!(IMAGE_HANDLE_MAX_BYTES, 4 * 1024 * 1024 - 64 * 1024);
}

/// The largest image a handle is minted for resolves in a reply the daemon
/// will carry, head and frame header included; one byte more mints nothing.
#[test]
fn the_largest_resolvable_image_fits_one_reply_frame() {
    let store = ImageHandles::default();
    let (reply, bytes) = png(1, IMAGE_HANDLE_MAX_BYTES);
    assert_eq!(bytes.len(), IMAGE_HANDLE_MAX_BYTES);
    let handle = store
        .mint(&reply, &capture("scope", 100))
        .expect("the largest allowed image mints");
    let answer = store.resolve(&handle, &["scope"], 100).unwrap();
    assert!(
        answer.body.len() <= MAX_RESOLVE_BODY_BYTES,
        "a resolve body of {} bytes leaves no room for the frame header",
        answer.body.len()
    );
    // The whole delivered frame, header included, is what the daemon counts.
    let frame = subc_protocol::Frame::build(
        subc_protocol::FrameType::Response,
        subc_protocol::Flags::new(true, subc_protocol::Priority::Interactive, false),
        9,
        1,
        11,
        answer.body,
    )
    .unwrap();
    let mut wire = frame.header.encode().to_vec();
    wire.extend_from_slice(&frame.body);
    assert!(
        wire.len() <= 4 * 1024 * 1024,
        "a {}-byte frame exceeds the daemon's 4 MiB cap",
        wire.len()
    );
    let body = frame.body.clone();
    let (_, image) = split_resolve(&body);
    assert_eq!(image.len(), IMAGE_HANDLE_MAX_BYTES);
}

#[test]
fn an_image_one_byte_over_the_limit_gets_no_handle() {
    let store = ImageHandles::default();
    let (reply, _) = png(1, IMAGE_HANDLE_MAX_BYTES + 1);
    assert_eq!(store.mint(&reply, &capture("scope", 0)), None);
    assert_eq!(store.held(), 0);
}

/// The contract document quotes the mint limit, and BROCA's guard is built on
/// the same number, so the doc's number and the code's must not drift apart.
#[test]
fn the_contract_document_quotes_the_mint_limit() {
    let doc = include_str!("../../../../docs/contracts/image-resolve-v1.md");
    // The document bolds the limit as `**4,128,768 bytes**`; every bolded
    // pass that ends in "bytes" must name the constant.
    let quoted: Vec<usize> = doc
        .split("**")
        .filter(|part| part.trim_end().ends_with(" bytes"))
        .map(|part| {
            part.chars()
                .filter(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .expect("a bolded byte count is a number")
        })
        .collect();
    assert!(
        quoted.contains(&IMAGE_HANDLE_MAX_BYTES),
        "the document must quote {IMAGE_HANDLE_MAX_BYTES} bytes: {quoted:?}"
    );
    // The derivation it spells out must also hold, and it must name the value
    // BROCA keeps so a reader can see the two agree.
    assert!(doc.contains("4,194,304") && doc.contains("65,536"));
    assert!(doc.contains("MAX_REFERENCE_IMAGE_BYTES"));
}
