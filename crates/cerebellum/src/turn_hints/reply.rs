use serde_json::Value;

pub(super) fn decode_reply(response: &[u8]) -> Result<Value, String> {
    let envelope: Value =
        serde_json::from_slice(response).map_err(|_| "invalid ckbus reply".to_owned())?;
    if let Some(error) = envelope.get("error") {
        let refusal: subc_protocol::ErrorBody = serde_json::from_value(error.clone())
            .map_err(|_| "invalid ckbus refusal".to_owned())?;
        return Err(refusal.code);
    }
    envelope
        .get("result")
        .filter(|result| result.is_object())
        .cloned()
        .ok_or_else(|| "missing ckbus result".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_replies_unwrap_the_result_envelope() {
        let credential = decode_reply(br#"{"result":{"jwt":"token","exp":123}}"#).unwrap();
        assert_eq!(credential["jwt"], "token");
        let signature = decode_reply(br#"{"result":{"signature_b64":"signature"}}"#).unwrap();
        assert_eq!(signature["signature_b64"], "signature");
    }

    #[test]
    fn missing_or_malformed_management_results_are_rejected() {
        for reply in [
            br#"{"jwt":"token"}"#.as_slice(),
            br#"{"result":null}"#,
            b"not json",
        ] {
            assert!(decode_reply(reply).is_err());
        }
    }

    #[test]
    fn management_refusals_take_precedence_and_preserve_the_code() {
        let reply = br#"{"error":{"code":"ckbus_credential_revoked","message":"revoked"},"result":{"jwt":"not accepted"}}"#;
        assert_eq!(decode_reply(reply).unwrap_err(), "ckbus_credential_revoked");
        assert!(decode_reply(br#"{"error":null,"result":{}}"#).is_err());
    }
}
