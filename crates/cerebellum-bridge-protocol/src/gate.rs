use crate::peer_trailer::parse_public_key;
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

    parse_public_key(public_key_hex?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_trailer::TEST_PEER_PUBLIC_KEY_HEX as VALID_KEY;

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
