//! One deadline-bounded `secret.use` on a fresh supervised claustrum route.
//!
//! Unlike cookie deposit, the response contains material. JSON strings are
//! decoded by the small closed-shape reader below: even escaped strings are
//! built directly in zeroizing storage, not in serde's ordinary scratch buffer.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use zeroize::Zeroizing;

use super::vault::{ClaustrumVault, CookieVault, VaultReachError};
use crate::browser::fill::{
    Approval, LoginMaterial, LoginMaterialSource, SecretUseAnswer, SecretUseRequest, SourceFuture,
    SourceUnavailable,
};

/// Includes connection, authentication, route opening, and the single reply.
pub const SECRET_USE_DEADLINE: Duration = Duration::from_secs(15);

pub struct VaultLoginSource {
    vault: Arc<dyn CookieVault>,
    deadline: Duration,
    production: bool,
}

impl VaultLoginSource {
    pub fn new(vault: Arc<dyn CookieVault>, deadline: Duration) -> Self {
        Self {
            vault,
            deadline,
            production: false,
        }
    }
}

pub fn production_source(path: PathBuf, module_id: String) -> Arc<dyn LoginMaterialSource> {
    Arc::new(VaultLoginSource {
        vault: Arc::new(ClaustrumVault::supervised(path, module_id)),
        deadline: SECRET_USE_DEADLINE,
        production: true,
    })
}

impl LoginMaterialSource for VaultLoginSource {
    fn enabled(&self) -> bool {
        !self.production || crate::browser::fill::FILL_LOGIN_ENABLED
    }

    fn secret_use(&self, request: &SecretUseRequest) -> SourceFuture<'_> {
        let body = encode_request(request);
        Box::pin(async move {
            if !self.enabled() {
                return Ok(SecretUseAnswer::Refused);
            }
            tokio::time::timeout(self.deadline, async {
                let mut route = match self.vault.open().await {
                    Ok(route) => route,
                    Err(error) if unavailable(&error) => return Err(SourceUnavailable),
                    Err(_) => return Ok(SecretUseAnswer::Refused),
                };
                match route.call(&body).await {
                    Ok(reply) => Ok(SecretUseAnswer::from_wire(Zeroizing::new(reply))),
                    Err(error) if unavailable(&error) => Err(SourceUnavailable),
                    Err(_) => Ok(SecretUseAnswer::Refused),
                }
                // Dropping the route closes its connection, also on cancellation.
            })
            .await
            .unwrap_or(Err(SourceUnavailable))
        })
    }
}

fn unavailable(error: &VaultReachError) -> bool {
    match error {
        VaultReachError::Unreachable | VaultReachError::Claim(_) => true,
        VaultReachError::RouteRefused { code } | VaultReachError::CallFailed { code } => {
            code.as_deref().is_none_or(|code| {
                matches!(
                    code,
                    "unknown_module"
                        | "module_warming"
                        | "module_reloading"
                        | "target_unavailable"
                        | "module_timeout"
                        | "route_closed"
                        | "unknown_channel"
                        | "stale_route_epoch"
                )
            })
        }
    }
}

#[derive(Serialize)]
struct Params<'a> {
    name: &'a str,
    coverage: &'static str,
    stamp: &'a serde_json::Value,
    target: Target<'a>,
}

#[derive(Serialize)]
struct Target<'a> {
    origin: &'a str,
}

/// Closed params, in contract order. The stamp is relayed without reconstruction.
pub fn encode_params(request: &SecretUseRequest) -> Vec<u8> {
    serde_json::to_vec(&Params {
        name: &request.name,
        coverage: SecretUseRequest::COVERAGE,
        stamp: &request.stamp,
        target: Target {
            origin: &request.origin,
        },
    })
    .expect("JSON values and strings serialize")
}

fn encode_request(request: &SecretUseRequest) -> Vec<u8> {
    let mut body = b"{\"method\":\"secret.use\",\"params\":".to_vec();
    body.extend(encode_params(request));
    body.push(b'}');
    body
}

/// No material is deserialized through serde: its escape decoder uses an
/// ordinary Vec. The input is owned by a Zeroizing buffer at the caller, and
/// every decoded string (including unknown keys) starts in Zeroizing storage.
pub(crate) fn decode_reply(bytes: &[u8]) -> SecretUseAnswer {
    let mut reader = Reader { bytes, at: 0 };
    reader
        .reply()
        .filter(|_| reader.end())
        .unwrap_or(SecretUseAnswer::Refused)
}

enum Atom {
    Text(Zeroizing<String>),
    Number(u64),
    Error,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn space(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|b| b" \n\r\t".contains(b))
        {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        self.space();
        if self.bytes.get(self.at) != Some(&byte) {
            return None;
        }
        self.at += 1;
        Some(())
    }

    fn end(&mut self) -> bool {
        self.space();
        self.at == self.bytes.len()
    }

    fn hex(&mut self) -> Option<u16> {
        let mut n = 0;
        for _ in 0..4 {
            let digit = (*self.bytes.get(self.at)? as char).to_digit(16)?;
            n = n * 16 + digit as u16;
            self.at += 1;
        }
        Some(n)
    }

    fn text(&mut self) -> Option<Zeroizing<String>> {
        self.eat(b'"')?;
        // Decoded UTF-8 cannot exceed the remaining encoded bytes. Reserving
        // that bound once prevents reallocations leaving old secret allocations.
        let mut out = Zeroizing::new(String::with_capacity(self.bytes.len() - self.at));
        loop {
            let byte = *self.bytes.get(self.at)?;
            self.at += 1;
            match byte {
                b'"' => return Some(out),
                b'\\' => {
                    let escape = *self.bytes.get(self.at)?;
                    self.at += 1;
                    out.push(match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let first = self.hex()?;
                            let code = if (0xd800..=0xdbff).contains(&first) {
                                if self.bytes.get(self.at..self.at + 2)? != b"\\u" {
                                    return None;
                                }
                                self.at += 2;
                                let second = self.hex()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return None;
                                }
                                0x10000 + ((first as u32 - 0xd800) << 10) + (second as u32 - 0xdc00)
                            } else {
                                first as u32
                            };
                            char::from_u32(code)?
                        }
                        _ => return None,
                    });
                }
                0..=0x1f => return None,
                0x20..=0x7f => out.push(byte as char),
                _ => {
                    let start = self.at - 1;
                    let len = match byte {
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => return None,
                    };
                    let raw = std::str::from_utf8(self.bytes.get(start..start + len)?).ok()?;
                    out.push_str(raw);
                    self.at = start + len;
                }
            }
        }
    }

    fn number(&mut self) -> Option<u64> {
        self.space();
        let start = self.at;
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
        let raw = self.bytes.get(start..self.at)?;
        if raw.is_empty() || (raw.len() > 1 && raw[0] == b'0') {
            return None;
        }
        std::str::from_utf8(raw).ok()?.parse().ok()
    }

    fn object<T>(
        &mut self,
        mut value: impl FnMut(&mut Self, &str) -> Option<T>,
    ) -> Option<Vec<(Zeroizing<String>, T)>> {
        self.eat(b'{')?;
        let mut fields = Vec::new();
        self.space();
        if self.bytes.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Some(fields);
        }
        loop {
            let key = self.text()?;
            if fields.iter().any(|(previous, _)| previous == &key) {
                return None;
            }
            self.eat(b':')?;
            let item = value(self, &key)?;
            fields.push((key, item));
            self.space();
            match self.bytes.get(self.at)? {
                b'}' => {
                    self.at += 1;
                    return Some(fields);
                }
                b',' => self.at += 1,
                _ => return None,
            }
        }
    }

    fn reply(&mut self) -> Option<SecretUseAnswer> {
        let mut wrapper =
            self.object(|reader, key| (key == "result").then(|| reader.result()).flatten())?;
        (wrapper.len() == 1).then(|| wrapper.remove(0).1)
    }

    fn result(&mut self) -> Option<SecretUseAnswer> {
        let mut fields = self.object(|reader, key| match key {
            "status" | "kind" | "username" | "password" | "totp" | "request_id"
            | "statement_b64url" => reader.text().map(Atom::Text),
            "expires_at_ms" => reader.number().map(Atom::Number),
            "error" => {
                let error = reader.object(|reader, key| match key {
                    "code" | "class" => reader.text(),
                    _ => None,
                })?;
                (error.len() == 2).then_some(Atom::Error)
            }
            _ => None,
        })?;
        if fields.len() == 1 && fields[0].0.as_str() == "error" {
            return Some(SecretUseAnswer::Refused);
        }
        let take = |fields: &mut Vec<(Zeroizing<String>, Atom)>, name: &str| {
            let i = fields.iter().position(|(key, _)| key.as_str() == name)?;
            Some(fields.remove(i).1)
        };
        let text = |fields: &mut Vec<(Zeroizing<String>, Atom)>, name| match take(fields, name)? {
            Atom::Text(value) => Some(value),
            _ => None,
        };
        match text(&mut fields, "status")?.as_str() {
            "released" => {
                if text(&mut fields, "kind")?.as_str() != "site_login" {
                    return None;
                }
                let username = text(&mut fields, "username")?;
                let password = text(&mut fields, "password")?;
                let totp = if fields.iter().any(|(key, _)| key.as_str() == "totp") {
                    Some(text(&mut fields, "totp")?)
                } else {
                    None
                };
                fields
                    .is_empty()
                    .then_some(SecretUseAnswer::Released(LoginMaterial {
                        username,
                        password,
                        totp,
                    }))
            }
            "approval_required" => {
                let request_id = text(&mut fields, "request_id")?;
                let statement = text(&mut fields, "statement_b64url")?;
                let Atom::Number(expires_at_ms) = take(&mut fields, "expires_at_ms")? else {
                    return None;
                };
                (fields.is_empty() && !request_id.is_empty() && !statement.is_empty()).then(|| {
                    SecretUseAnswer::ApprovalRequired(Approval {
                        request_id: request_id.to_string(),
                        statement_b64url: statement.to_string(),
                        expires_at_ms,
                    })
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const REQUEST: &[u8] =
        include_bytes!("../../tests/vectors/secret-use-v1/use.request.site_login.json");
    const EXPLICIT: &[u8] = include_bytes!(
        "../../tests/vectors/secret-use-v1/use.request.site_login.explicit_scope.json"
    );
    const RELEASED: &[u8] =
        include_bytes!("../../tests/vectors/secret-use-v1/use.result.released.site_login.json");
    const APPROVAL: &[u8] =
        include_bytes!("../../tests/vectors/secret-use-v1/use.result.approval_required.json");
    const ERROR: &[u8] = include_bytes!("../../tests/vectors/secret-use-v1/error.result.json");

    fn reply(result: &[u8]) -> SecretUseAnswer {
        let mut bytes = Zeroizing::new(b"{\"result\":".to_vec());
        bytes.extend_from_slice(result);
        bytes.push(b'}');
        SecretUseAnswer::from_wire(bytes)
    }

    #[test]
    fn tagged_goldens_are_byte_pinned_and_request_encoding_is_exact() {
        for (bytes, hash) in [
            (
                REQUEST,
                "13939f01aa00751599cab852bc546701dd6d69c1ff76fec3f6b614d1a95662d7",
            ),
            (
                RELEASED,
                "a1bb04d56aedb6545cc3c9fbc11a74155355a46fb290b7b0244ce07f66715d0f",
            ),
            (
                APPROVAL,
                "c227bd0d37abaff792b2e8efba14ecdf0238fc2b0269c3cce7a5d3f4a0f7abf9",
            ),
            (
                ERROR,
                "1ce8024a92bdadd867448f905e5cbae002d60327776bfdb01875a87f2711b99e",
            ),
        ] {
            assert_eq!(format!("{:x}", Sha256::digest(bytes)), hash);
        }
        let original: serde_json::Value = serde_json::from_slice(REQUEST).unwrap();
        let request = SecretUseRequest {
            name: original["name"].as_str().unwrap().into(),
            stamp: original["stamp"].clone(),
            origin: original["target"]["origin"].as_str().unwrap().into(),
        };
        assert_eq!(encode_params(&request), EXPLICIT);
        let mut encoded: serde_json::Value =
            serde_json::from_slice(&encode_params(&request)).unwrap();
        assert_eq!(
            encoded.as_object_mut().unwrap().remove("coverage"),
            Some("scope".into())
        );
        assert_eq!(encoded, original);
        let mut expected = b"{\"method\":\"secret.use\",\"params\":".to_vec();
        expected.extend_from_slice(EXPLICIT);
        expected.push(b'}');
        assert_eq!(encode_request(&request), expected);
    }

    #[test]
    fn tagged_replies_decode_without_plaintext_json_values() {
        let SecretUseAnswer::Released(material) = reply(RELEASED) else {
            panic!("released golden")
        };
        assert_eq!(material.username.as_str(), "alice");
        assert_eq!(material.password.as_str(), "correct horse");
        assert_eq!(material.totp.as_ref().unwrap().as_str(), "123456");
        assert!(!format!("{material:?}").contains("correct horse"));
        let SecretUseAnswer::ApprovalRequired(approval) = reply(APPROVAL) else {
            panic!("approval golden")
        };
        assert_eq!(approval.request_id, "01HF7YAT000000000000000001");
        assert_eq!(approval.expires_at_ms, 1700000600000);
        let parsed: serde_json::Value = serde_json::from_slice(APPROVAL).unwrap();
        assert_eq!(approval.statement_b64url, parsed["statement_b64url"]);
        assert!(matches!(reply(ERROR), SecretUseAnswer::Refused));
        for (code, class) in [
            ("not_found", "permanent"),
            ("limit_exceeded", "context_overflow"),
            ("approval_invalid", "permanent"),
            ("phone_not_registered", "permanent"),
            ("phone_key_conflict", "permanent"),
            ("deposit_conflict", "permanent"),
            ("name_exists", "permanent"),
            ("secret_setup_incomplete", "permanent"),
            ("pairing_unavailable", "transient"),
            ("pending_limit", "transient"),
            ("store_error", "transient"),
            ("future_code", "future_class"),
        ] {
            let result = format!(r#"{{"error":{{"code":"{code}","class":"{class}"}}}}"#);
            assert!(matches!(reply(result.as_bytes()), SecretUseAnswer::Refused));
        }
    }

    #[test]
    fn closed_shapes_refuse_duplicates_unknowns_wrong_types_and_wrong_kinds() {
        for invalid in [
            br#"{"status":"released","kind":"site_login","username":"u","password":"p","extra":"secret"}"#.as_slice(),
            br#"{"status":"released","kind":"site_login","username":"u","password":"p","password":"p"}"#,
            br#"{"status":"released","kind":"site_login","username":"u","password":"p","totp":null}"#,
            br#"{"status":"released","kind":"agent_api_key","username":"u","password":"p"}"#,
            br#"{"status":"released","kind":"site_login","username":"u"}"#,
            br#"{"status":"approval_required","request_id":"r","statement_b64url":"s","expires_at_ms":01}"#,
            br#"{"status":"approval_required","request_id":"r","statement_b64url":"s","expires_at_ms":1.0}"#,
            br#"{"error":{"code":"not_found","class":"permanent"},"status":"released","kind":"site_login","username":"u","password":"p"}"#,
            br#"{"status":"released","kind":"site_login","username":"u","password":"\ud800"}"#,
            br#"{"status":"released","kind":"site_login","username":"u","password":"\q"}"#,
            br#"{"status":"released","kind":"site_login","username":"u","password":"p",}"#,
        ] {
            assert!(matches!(reply(invalid), SecretUseAnswer::Refused));
        }
        for invalid in [
            br#"{"result":{}} trailing"#.as_slice(),
            br#"{"result":{},"result":{}}"#,
            br#"{"result":{},"extra":"p"}"#,
        ] {
            assert!(matches!(decode_reply(invalid), SecretUseAnswer::Refused));
        }
    }

    #[test]
    fn escaped_and_utf8_material_decode_directly_and_optional_totp_is_absent() {
        let SecretUseAnswer::Released(material) = reply(r#"{"password":"p\u00e9\ud83d\ude00\n\"\\\/\b\f\r\t","username":"ü","kind":"site_login","status":"released"}"#.as_bytes()) else { panic!("escaped login") };
        assert_eq!(material.username.as_str(), "ü");
        assert_eq!(material.password.as_str(), "pé😀\n\"\\/\u{8}\u{c}\r\t");
        assert!(material.totp.is_none());
    }

    struct ScriptVault {
        reply: Option<Result<Vec<u8>, VaultReachError>>,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }

    struct Route {
        reply: Option<Result<Vec<u8>, VaultReachError>>,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Route {
        fn drop(&mut self) {
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl CookieVault for ScriptVault {
        fn open(
            &self,
        ) -> super::super::vault::BoxFuture<
            '_,
            Result<Box<dyn super::super::vault::VaultRoute>, VaultReachError>,
        > {
            let route: Box<dyn super::super::vault::VaultRoute> = Box::new(Route {
                reply: self.reply.clone(),
                closed: self.closed.clone(),
            });
            Box::pin(async { Ok(route) })
        }
    }

    impl super::super::vault::VaultRoute for Route {
        fn call<'a>(
            &'a mut self,
            _: &'a [u8],
        ) -> super::super::vault::BoxFuture<'a, Result<Vec<u8>, VaultReachError>> {
            let answer = self.reply.take();
            Box::pin(async move {
                match answer {
                    Some(reply) => reply,
                    None => std::future::pending().await,
                }
            })
        }
    }

    #[tokio::test]
    async fn transport_refusals_are_uniform_but_loss_and_timeout_are_unavailable() {
        let request = SecretUseRequest {
            name: "login".into(),
            stamp: serde_json::json!({}),
            origin: "https://x.test".into(),
        };
        for (response, unavailable) in [
            (
                Some(Err(VaultReachError::CallFailed {
                    code: Some("invalid_params".into()),
                })),
                false,
            ),
            (
                Some(Err(VaultReachError::CallFailed {
                    code: Some("new_refusal".into()),
                })),
                false,
            ),
            (
                Some(Err(VaultReachError::CallFailed {
                    code: Some("module_timeout".into()),
                })),
                true,
            ),
            (Some(Err(VaultReachError::Unreachable)), true),
            (None, true),
        ] {
            let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let source = VaultLoginSource::new(
                Arc::new(ScriptVault {
                    reply: response,
                    closed: closed.clone(),
                }),
                Duration::from_millis(10),
            );
            let answer = source.secret_use(&request).await;
            assert_eq!(answer.is_err(), unavailable);
            if let Ok(answer) = answer {
                assert!(matches!(answer, SecretUseAnswer::Refused));
            }
            assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
        }
    }
}
