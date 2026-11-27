use ed25519_dalek::VerifyingKey;

const CI_REVISION: &str = "ci-unreviewed";

/// Return the peer verification key only when the caller's compile-time review
/// revision and public key enable the bridge on its platform.
pub fn classify_bridge_gate(
    revision: Option<&str>,
    public_key_hex: Option<&str>,
) -> Option<VerifyingKey> {
    let revision = revision?;
    if revision.is_empty() || (revision == CI_REVISION) != cfg!(feature = "bridge-test-identities")
    {
        return None;
    }

    let hex = public_key_hex?.as_bytes();
    let mut key_bytes = [0; 32];
    if hex.len() != key_bytes.len() * 2 {
        return None;
    }
    for (pair, byte) in hex.as_chunks::<2>().0.iter().zip(&mut key_bytes) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = ((high << 4) | low) as u8;
    }

    let key = VerifyingKey::from_bytes(&key_bytes).ok()?;
    // Weak Ed25519 keys can decode, but they do not securely verify a peer.
    (!key.is_weak()).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032's first Ed25519 test vector public key, not a bridge release key.
    const VALID_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    // Compressed y = 2 has no corresponding x on the Ed25519 curve.
    const OFF_CURVE: &str = "0200000000000000000000000000000000000000000000000000000000000000";
    const IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const REVIEWED: &str = "reviewed-revision";

    #[test]
    fn gate_opens_only_for_the_feature_matching_revision_and_valid_key() {
        let upper_key = VALID_KEY.to_ascii_uppercase();
        let long_key = format!("{VALID_KEY}00");
        let non_hex = VALID_KEY.replacen('d', "g", 1);
        let signed_hex = VALID_KEY.replacen('d', "+", 1);
        for revision in [None, Some(""), Some(CI_REVISION), Some(REVIEWED)] {
            for (key, valid_key) in [
                (None, false),
                (Some(""), false),
                (Some(&VALID_KEY[..63]), false),
                (Some(long_key.as_str()), false),
                (Some(non_hex.as_str()), false),
                (Some(signed_hex.as_str()), false),
                (Some(OFF_CURVE), false),
                (Some(IDENTITY), false),
                (Some(VALID_KEY), true),
                (Some(upper_key.as_str()), true),
            ] {
                let expected_revision = if cfg!(feature = "bridge-test-identities") {
                    CI_REVISION
                } else {
                    REVIEWED
                };
                let gate = classify_bridge_gate(revision, key);
                assert_eq!(
                    gate.is_some(),
                    revision == Some(expected_revision) && valid_key,
                    "revision={revision:?}, key={key:?}"
                );
                if let Some(key) = gate {
                    let bytes = key.to_bytes();
                    let encoded: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                    assert_eq!(encoded, VALID_KEY);
                }
            }
        }
    }
}
