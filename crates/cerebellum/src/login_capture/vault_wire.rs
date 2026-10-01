//! Every shape the capture's vault deposit puts on the wire, in one place.
//!
//! Two exchanges, both opened by this module on a consumer connection of its
//! own:
//!
//! - `route.open` on the daemon's control channel, which opens a route from
//!   this module to claustrum, the vault module. The body is subc-control's
//!   `ClientControlRequest::RouteOpen` and the answer its
//!   `ClientControlResponse::RouteOpen`; a refusal is an Error frame carrying
//!   subc-protocol's `ErrorBody`.
//! - `credential.deposit_cookie` on that route, whose contract claustrum's
//!   owner pinned. Claustrum's request envelope is `{"method", "params"}` and
//!   every reply is `{"result": ...}`, with a refusal as
//!   `{"result": {"error": {"class", "code"}}}` inside an ordinary response
//!   (the envelope ck-bus reads for `credential.sign`). The four deposit keys
//!   are the `params`.
//!
//! The deposit shapes follow claustrum's published wire contract for the op
//! (its `docs/wire-contract-v1.md`, "Cookie deposit", at claustrum f3f968a).
//! Its producer-pinned fixture is copied byte for byte to
//! `crates/cerebellum/tests/fixtures/deposit_cookie_wire_contract.json`, and
//! this file's tests run every reply body in it through
//! [`parse_deposit_reply`] and check the request built for the documented
//! example against the doc's bytes.
//!
//! Malformed requests (an unknown, missing or mistyped field) are not answered
//! with a refusal body: the vault answers them with a transport Error frame
//! whose code is [`INVALID_PARAMS`].

use serde::{Deserialize, Serialize};
use subc_protocol::{BindIdentity, ErrorBody, RouteTarget};

use super::CookieHeader;

/// The vault module's id, which the route is opened to.
pub const VAULT_MODULE_ID: &str = "claustrum";
/// The one vault operation this module calls.
pub const DEPOSIT_METHOD: &str = "credential.deposit_cookie";
/// The longest `consent_ref` the vault accepts.
pub const MAX_CONSENT_REF_BYTES: usize = 128;
/// The longest cookie header the vault stores, in bytes.
pub const MAX_COOKIE_BYTES: usize = 16_384;
/// The Error frame code the vault answers a request it cannot decode with.
/// Only a bug in this module's request can cause it.
pub const INVALID_PARAMS: &str = "invalid_params";
/// The longest vault or daemon code passed on in a reply. Codes are short
/// snake_case words; anything longer or shaped otherwise is not one.
const MAX_CODE_BYTES: usize = 64;

/// Whether the vault accepts `cookie` as a deposit's cookie: 1 to
/// [`MAX_COOKIE_BYTES`] bytes, each a horizontal tab, printable ASCII
/// (0x20 to 0x7E), or a byte of 0x80 and above (UTF-8). Every other control
/// byte and DEL are refused. Checked before anything is sent, so a header the
/// vault would refuse as `invalid_payload` is answered here by name.
pub fn cookie_storable(cookie: &[u8]) -> bool {
    (1..=MAX_COOKIE_BYTES).contains(&cookie.len())
        && cookie
            .iter()
            .all(|&byte| byte == b'\t' || (0x20..=0x7e).contains(&byte) || byte >= 0x80)
}

/// Claustrum registers its operations as a management surface, not a tool
/// provider, and the daemon routes by role.
pub fn vault_route_target() -> RouteTarget {
    RouteTarget::ManagementSurface {
        module_id: VAULT_MODULE_ID.to_string(),
    }
}

/// Overwrite bytes that held a secret.
///
/// `black_box` keeps the compiler from dropping the writes as dead stores to
/// memory about to be freed, which is exactly what a wipe before a drop is.
pub(super) fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(&*bytes);
}

/// Bytes that carry a secret on their way to the socket: the deposit request
/// (the cookie) or the route.open request (the launch nonce). No `Clone`, a
/// `Debug` that prints only the length, and wiped on drop.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Serialize `value` into a buffer reserved up front, so the buffer never
    /// grows. A growing `Vec` copies itself and frees the old allocation
    /// unwiped, which would leave a copy of the secret nobody can reach to
    /// erase. `bound` must cover the whole encoding.
    fn encode<T: Serialize>(value: &T, bound: usize) -> Result<Self, RequestBuildError> {
        let mut bytes = Self(Vec::with_capacity(bound));
        serde_json::to_writer(&mut bytes.0, value).map_err(|_| RequestBuildError::Unencodable)?;
        if bytes.0.capacity() != bound {
            // The buffer reallocated, so an unwiped copy of the secret was
            // freed. The callers' bounds (see `encoded_bound`) rule this out;
            // if one is ever wrong, the request is refused rather than sent
            // as if no copy had been left behind.
            return Err(RequestBuildError::Unencodable);
        }
        Ok(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SecretBytes(<{} bytes withheld>)", self.0.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// The most bytes JSON encoding can turn `text` into: every character as a
/// six-byte `\uXXXX` escape, plus its quotes. serde_json writes non-ASCII
/// characters as they are, so no character grows past six bytes.
fn encoded_bound(text: &str) -> usize {
    text.len().saturating_mul(6).saturating_add(2)
}

/// Why a request could not be built. Names no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBuildError {
    /// The cookie header is not UTF-8 text, which a JSON string must be.
    CookieNotText,
    /// The cookie header breaks the vault's cookie rules (see
    /// [`cookie_storable`]).
    CookieNotStorable,
    /// The consent reference is empty, too long or not printable ASCII.
    ConsentRefOutOfShape,
    /// The encoder failed, or the encoding outgrew its reserved buffer.
    Unencodable,
    /// The request is larger than one frame may carry.
    TooLarge,
}

// --- route.open ------------------------------------------------------------

#[derive(Serialize)]
struct RouteOpenRequest<'a> {
    op: &'static str,
    target: RouteTarget,
    identity: &'a BindIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_identity: Option<ConsumerIdentity<'a>>,
}

/// The daemon's proof that the route comes from the process it spawned as
/// `module_id`. Without it the daemon stamps the route `Direct`, and the vault
/// answers `not_found` to a direct caller.
#[derive(Serialize)]
pub struct ConsumerIdentity<'a> {
    pub module_id: &'a str,
    pub launch_nonce: &'a str,
}

/// The channel-0 request that opens the route to the vault.
pub fn route_open_request(
    identity: &BindIdentity,
    consumer_identity: Option<ConsumerIdentity<'_>>,
) -> Result<SecretBytes, RequestBuildError> {
    let request = RouteOpenRequest {
        op: "route.open",
        target: vault_route_target(),
        identity,
        consumer_identity,
    };
    let identity_bound = encoded_bound(&identity.project_root.to_string_lossy())
        + encoded_bound(&identity.harness)
        + encoded_bound(&identity.session)
        + identity.project_id.as_deref().map_or(0, encoded_bound);
    let consumer_bound = request.consumer_identity.as_ref().map_or(0, |consumer| {
        encoded_bound(consumer.module_id) + encoded_bound(consumer.launch_nonce)
    });
    SecretBytes::encode(&request, identity_bound + consumer_bound + 256)
}

/// The daemon's answer to an accepted `route.open`: the channel and epoch the
/// deposit is sent on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct RouteOpened {
    pub route_channel: u16,
    pub route_epoch: u32,
}

pub fn parse_route_opened(body: &[u8]) -> Option<RouteOpened> {
    serde_json::from_slice(body).ok()
}

/// The code of an Error frame, when it is shaped like one. Used for both a
/// refused `route.open` and a failed call on the route.
pub fn error_frame_code(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<ErrorBody>(body)
        .ok()
        .map(|error| error.code)
        .filter(|code| is_code(code))
}

/// Whether `text` reads as a code (`not_found`, `capability_forbidden`, …):
/// lowercase ASCII letters, digits and underscores, at most
/// [`MAX_CODE_BYTES`]. Codes are passed on to the caller verbatim, so anything
/// else is treated as no code rather than repeated.
fn is_code(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_CODE_BYTES
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

// --- credential.deposit_cookie ----------------------------------------------

#[derive(Serialize)]
struct DepositEnvelope<'a> {
    method: &'static str,
    params: DepositParams<'a>,
}

/// Exactly the four keys the vault accepts. Any other key is refused with
/// `invalid_params`, so this struct is the whole request.
#[derive(Serialize)]
struct DepositParams<'a> {
    id: &'a str,
    cookie: &'a str,
    consent_ref: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
}

/// The `credential.deposit_cookie` request body.
///
/// Takes the header by value and drops it before returning, so the header is
/// wiped as soon as the request bytes exist, on every path. The returned bytes
/// are then the only copy, and are wiped when dropped.
pub fn deposit_request(
    credential_id: &str,
    cookie: CookieHeader,
    consent_ref: &str,
    email: Option<&str>,
) -> Result<SecretBytes, RequestBuildError> {
    if consent_ref.is_empty()
        || consent_ref.len() > MAX_CONSENT_REF_BYTES
        || !consent_ref.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(RequestBuildError::ConsentRefOutOfShape);
    }
    if !cookie_storable(cookie.bytes()) {
        return Err(RequestBuildError::CookieNotStorable);
    }
    let cookie_text =
        std::str::from_utf8(cookie.bytes()).map_err(|_| RequestBuildError::CookieNotText)?;
    let bound = encoded_bound(credential_id)
        + encoded_bound(cookie_text)
        + encoded_bound(consent_ref)
        + email.map_or(0, encoded_bound)
        + 128;
    let request = SecretBytes::encode(
        &DepositEnvelope {
            method: DEPOSIT_METHOD,
            params: DepositParams {
                id: credential_id,
                cookie: cookie_text,
                consent_ref,
                email,
            },
        },
        bound,
    )?;
    drop(cookie);
    if request.len() > subc_protocol::MAX_FRAME_BODY_LEN as usize {
        return Err(RequestBuildError::TooLarge);
    }
    Ok(request)
}

/// What the vault did with a stored login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultOutcome {
    Created,
    Replaced,
}

impl VaultOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Replaced => "replaced",
        }
    }
}

/// A stored login, as the vault reports it. Never carries the cookie.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Deposited {
    pub id: String,
    pub outcome: VaultOutcome,
    pub record_version: u64,
}

/// A vault refusal. Branch on the class, never the code: the class says
/// whether trying again can help, and new codes can join either class.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VaultRefusal {
    pub class: String,
    pub code: String,
}

impl VaultRefusal {
    pub fn is_transient(&self) -> bool {
        self.class == "transient"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositReply {
    Deposited(Deposited),
    Refused(VaultRefusal),
}

/// The reply was not in the contract's shape. Carries nothing from the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedReply;

#[derive(Deserialize)]
struct ReplyEnvelope {
    result: ReplyResult,
}

// Untagged, refusal first: a refusal is the only result with an `error` key,
// and the stored shape has none, so the order decides nothing ambiguous.
#[derive(Deserialize)]
#[serde(untagged)]
enum ReplyResult {
    Refused { error: VaultRefusal },
    Deposited(Deposited),
}

pub fn parse_deposit_reply(body: &[u8]) -> Result<DepositReply, MalformedReply> {
    let envelope: ReplyEnvelope = serde_json::from_slice(body).map_err(|_| MalformedReply)?;
    match envelope.result {
        ReplyResult::Refused { error } if is_code(&error.code) && is_code(&error.class) => {
            Ok(DepositReply::Refused(error))
        }
        ReplyResult::Refused { .. } => Err(MalformedReply),
        ReplyResult::Deposited(deposited) => Ok(DepositReply::Deposited(deposited)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reply(value: serde_json::Value) -> Result<DepositReply, MalformedReply> {
        parse_deposit_reply(&serde_json::to_vec(&value).unwrap())
    }

    use crate::login_capture::test_support::{contract_reply, DEPOSIT_CONTRACT};
    use sha2::{Digest, Sha256};

    /// The copy is the file claustrum published at f3f968a, unedited.
    #[test]
    fn the_fixture_is_the_one_claustrum_published() {
        let digest = Sha256::digest(DEPOSIT_CONTRACT.as_bytes());
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "1eb8e1360d4a1267fa4f5a760634a2a16fbeedb58b0184f297b1cb20d3f64430"
        );
    }

    /// Every reply body in claustrum's fixture parses to the typed result it
    /// stands for, and the fixture holds no reply this test does not name.
    #[test]
    fn every_fixture_reply_parses_to_its_typed_result() {
        let fixture: serde_json::Value = serde_json::from_str(DEPOSIT_CONTRACT).unwrap();
        let mut cases = fixture
            .as_object()
            .unwrap()
            .keys()
            .filter(|key| key.as_str() != "payload_hash")
            .cloned()
            .collect::<Vec<_>>();
        cases.sort();
        assert_eq!(
            cases,
            [
                "created",
                "invalid_id",
                "invalid_payload",
                "not_found",
                "not_permitted",
                "replaced",
                "store_error"
            ]
        );
        let stored = |outcome, record_version| {
            Ok(DepositReply::Deposited(Deposited {
                id: "cookie:ollama.com:ufuk".to_string(),
                outcome,
                record_version,
            }))
        };
        assert_eq!(
            parse_deposit_reply(&contract_reply("created")),
            stored(VaultOutcome::Created, 1)
        );
        assert_eq!(
            parse_deposit_reply(&contract_reply("replaced")),
            stored(VaultOutcome::Replaced, 2)
        );
        for (code, class, transient) in [
            ("invalid_id", "permanent", false),
            ("invalid_payload", "permanent", false),
            ("not_found", "permanent", false),
            ("not_permitted", "permanent", false),
            ("store_error", "transient", true),
        ] {
            let parsed = parse_deposit_reply(&contract_reply(code));
            assert_eq!(
                parsed,
                Ok(DepositReply::Refused(VaultRefusal {
                    class: class.to_string(),
                    code: code.to_string(),
                })),
                "{code}"
            );
            let Ok(DepositReply::Refused(refusal)) = parsed else {
                unreachable!()
            };
            assert_eq!(refusal.is_transient(), transient, "{code}");
        }
    }

    /// Shapes the fixture does not carry, because the vault never sends them:
    /// each must be refused as malformed rather than read as a result.
    #[test]
    fn replies_outside_the_contract_are_malformed() {
        for malformed in [
            json!({"id": "x", "outcome": "created", "record_version": 1}),
            json!({"result": {"id": "x", "outcome": "kept", "record_version": 1}}),
            json!({"result": {"id": "x", "outcome": "created"}}),
            json!({"result": {"id": "x", "outcome": "created", "record_version": "1"}}),
            json!({"result": {"error": {"code": "not_found"}}}),
            json!({"result": {"error": {"class": "permanent", "code": "Not Found!"}}}),
        ] {
            assert_eq!(reply(malformed.clone()), Err(MalformedReply), "{malformed}");
        }
        assert_eq!(parse_deposit_reply(b"not json"), Err(MalformedReply));
    }

    /// The class decides, not the code: a code the fixture does not list is
    /// still transient when its class says so.
    #[test]
    fn an_unlisted_code_is_read_by_its_class() {
        let parsed =
            reply(json!({"result": {"error": {"class": "transient", "code": "store_busy"}}}));
        let Ok(DepositReply::Refused(refusal)) = parsed else {
            panic!("{parsed:?}");
        };
        assert!(refusal.is_transient());
    }

    /// The request built for the contract's documented example is, byte for
    /// byte, the request the doc shows. serde_json writes struct fields in
    /// declaration order, which is the doc's order (`method`, then `params`
    /// with `id`, `cookie`, `consent_ref`, `email`), so no reordering is
    /// needed. The fixture's `payload_hash`, the vault's audit commitment over
    /// id, consent_ref and the cookie's SHA-256, also matches what was sent.
    #[test]
    fn the_example_request_is_built_byte_for_byte() {
        let header = CookieHeader::from_pairs([("session", "abc")]).unwrap();
        let request = deposit_request(
            "cookie:ollama.com:ufuk",
            header,
            "consent-123",
            Some("me@example.com"),
        )
        .unwrap();
        assert_eq!(
            std::str::from_utf8(request.as_bytes()).unwrap(),
            r#"{"method":"credential.deposit_cookie","params":{"id":"cookie:ollama.com:ufuk","cookie":"session=abc","consent_ref":"consent-123","email":"me@example.com"}}"#
        );

        let sent: serde_json::Value = serde_json::from_slice(request.as_bytes()).unwrap();
        let field = |name: &str| sent["params"][name].as_str().unwrap().as_bytes().to_vec();
        let mut committed = b"ck-deposit-cookie/v1".to_vec();
        for part in [field("id"), field("consent_ref")] {
            committed.extend_from_slice(&(part.len() as u32).to_be_bytes());
            committed.extend_from_slice(&part);
        }
        committed.extend_from_slice(&Sha256::digest(field("cookie")));
        let hex = Sha256::digest(&committed)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let fixture: serde_json::Value = serde_json::from_str(DEPOSIT_CONTRACT).unwrap();
        assert_eq!(fixture["payload_hash"], hex);
    }

    /// A header the vault would refuse is refused before any request exists.
    /// Built directly: the browser's header builder already refuses control
    /// bytes, and this is the check behind it.
    #[test]
    fn a_header_breaking_the_cookie_rules_builds_no_request() {
        for cookie in [
            b"a=\x01b".to_vec(),
            b"a=\x7fb".to_vec(),
            vec![b'a'; MAX_COOKIE_BYTES + 1],
        ] {
            assert_eq!(
                deposit_request("cookie:x.com:a", CookieHeader(cookie), "ref", None).unwrap_err(),
                RequestBuildError::CookieNotStorable
            );
        }
        assert!(deposit_request(
            "cookie:x.com:a",
            CookieHeader(vec![b'a'; MAX_COOKIE_BYTES]),
            "ref",
            None
        )
        .is_ok());
    }

    /// The contract's cookie rules, at each boundary.
    #[test]
    fn cookie_bytes_follow_the_contract() {
        assert!(!cookie_storable(b""));
        assert!(cookie_storable(b"a"));
        assert!(cookie_storable(&[b'a'; MAX_COOKIE_BYTES]));
        assert!(!cookie_storable(&[b'a'; MAX_COOKIE_BYTES + 1]));
        assert!(cookie_storable(b"a=b;\tc=d e"));
        assert!(cookie_storable(&[0x20, 0x7e, 0x80, 0xff]));
        assert!(cookie_storable("a=éè".as_bytes()));
        for byte in (0x00..0x20u8).filter(|&byte| byte != b'\t').chain([0x7f]) {
            assert!(!cookie_storable(&[b'a', byte, b'b']), "{byte:#04x}");
        }
    }

    /// The worst case for the reserved buffer: every cookie byte a character
    /// JSON escapes. The buffer must not have grown, or a copy of the cookie
    /// was freed without being wiped.
    #[test]
    fn a_request_is_encoded_without_regrowing_its_buffer() {
        let quotes = "\"\\".repeat(2_000);
        let header = CookieHeader::from_pairs([("session", quotes.as_str())]).unwrap();
        let request = deposit_request(
            "cookie:ollama.com:work",
            header,
            "capture-login-1",
            Some("me@example.com"),
        )
        .unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(request.as_bytes()).unwrap();
        assert_eq!(
            decoded["params"]["cookie"].as_str().unwrap(),
            format!("session={quotes}")
        );
    }

    #[test]
    fn a_consent_ref_out_of_shape_is_refused_before_encoding() {
        for consent_ref in ["", "has space", &"x".repeat(129), "tab\there"] {
            let header = CookieHeader::from_pairs([("a", "b")]).unwrap();
            assert_eq!(
                deposit_request("cookie:x.com:a", header, consent_ref, None).unwrap_err(),
                RequestBuildError::ConsentRefOutOfShape,
                "{consent_ref:?}"
            );
        }
    }

    #[test]
    fn secret_bytes_format_as_their_length_only() {
        let header = CookieHeader::from_pairs([("a", "planted-secret")]).unwrap();
        let request = deposit_request("cookie:x.com:a", header, "ref", None).unwrap();
        let debug = format!("{request:?}");
        assert!(!debug.contains("planted-secret"), "{debug}");
    }

    #[test]
    fn the_route_open_names_the_vault_and_carries_the_consumer_identity() {
        let identity = BindIdentity::new("/tmp", "cerebellum", "browser.capture_login");
        let body = route_open_request(
            &identity,
            Some(ConsumerIdentity {
                module_id: "cerebellum",
                launch_nonce: "n0nce",
            }),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(body.as_bytes()).unwrap();
        assert_eq!(body["op"], "route.open");
        assert_eq!(
            body["target"],
            json!({"kind": "management_surface", "module_id": "claustrum"})
        );
        assert_eq!(
            body["consumer_identity"],
            json!({"module_id": "cerebellum", "launch_nonce": "n0nce"})
        );
        assert_eq!(body["identity"]["harness"], "cerebellum");

        let without = route_open_request(&identity, None).unwrap();
        let without: serde_json::Value = serde_json::from_slice(without.as_bytes()).unwrap();
        assert!(without.get("consumer_identity").is_none(), "{without}");
    }

    #[test]
    fn route_answers_and_error_codes_parse() {
        assert_eq!(
            parse_route_opened(br#"{"op":"route.open","route_channel":3,"route_epoch":9}"#),
            Some(RouteOpened {
                route_channel: 3,
                route_epoch: 9
            })
        );
        assert_eq!(parse_route_opened(br#"{"op":"route.open"}"#), None);
        assert_eq!(
            error_frame_code(br#"{"code":"capability_forbidden","message":"m"}"#).as_deref(),
            Some("capability_forbidden")
        );
        assert_eq!(
            error_frame_code(br#"{"code":"Free text here","message":"m"}"#),
            None
        );
    }
}
