use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

/// RFC 8032's first test-vector key. Only test builds use this as a peer key.
pub const TEST_PEER_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Decode a 32-byte public key from 64 hex characters, accepting either case.
pub fn parse_public_key(encoded: &str) -> Option<VerifyingKey> {
    let key = VerifyingKey::from_bytes(&decode_hex_32(encoded)?).ok()?;
    // Weak Ed25519 keys can decode, but they do not securely verify a peer.
    (!key.is_weak()).then_some(key)
}

/// Return the lowercase SHA-256 fingerprint of the decoded public key bytes.
pub fn public_key_fingerprint(key: &VerifyingKey) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))
}

pub fn is_test_peer_key(key: &VerifyingKey) -> bool {
    key.to_bytes() == decode_hex_32(TEST_PEER_PUBLIC_KEY_HEX).expect("valid test key hex")
}

fn decode_hex_32(encoded: &str) -> Option<[u8; 32]> {
    let hex = encoded.as_bytes();
    let mut bytes = [0; 32];
    if hex.len() != bytes.len() * 2 {
        return None;
    }
    for (pair, byte) in hex.as_chunks::<2>().0.iter().zip(&mut bytes) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = ((high << 4) | low) as u8;
    }
    Some(bytes)
}
