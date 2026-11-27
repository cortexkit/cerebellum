//! Signed executable trailers for Linux and Windows bridge peers.
//!
//! Peer discovery, liveness, and deadlines are the caller's responsibility. The
//! verifier performs blocking I/O on the image handle the caller already opened.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};

mod key;

pub use key::{
    is_test_peer_key, parse_public_key, public_key_fingerprint, TEST_PEER_PUBLIC_KEY_HEX,
};

const MAGIC: &[u8; 8] = b"CKPEER01";
const DOMAIN: &[u8] = b"cortexkit-peer-v1\0";
const SIGNATURE_LEN: usize = 64;
const FOOTER_LEN: usize = 4 + MAGIC.len();
const OVERHEAD: usize = SIGNATURE_LEN + FOOTER_LEN;
const DIGEST_LEN: usize = 32;
const MAX_FIELD_LEN: usize = 64;
const MIN_PAYLOAD_LEN: usize = 3 * (1 + 1) + DIGEST_LEN;
const MAX_PAYLOAD_LEN: usize = 3 * (1 + MAX_FIELD_LEN) + DIGEST_LEN;
const HASH_CHUNK_LEN: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    Cerebellum,
    Host,
    TestParent,
}

impl PeerRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cerebellum => "cerebellum",
            Self::Host => "host",
            Self::TestParent => "test-parent",
        }
    }
}

impl std::str::FromStr for PeerRole {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "cerebellum" => Ok(Self::Cerebellum),
            "host" => Ok(Self::Host),
            "test-parent" => Ok(Self::TestParent),
            _ => Err(invalid_input("unknown peer role")),
        }
    }
}

/// Verify a trailer and all preceding image bytes using the same open handle.
/// The role and target must match exactly; any authenticated version is admitted.
pub fn verify(
    image: &mut (impl Read + Seek),
    key: &VerifyingKey,
    role: PeerRole,
    target: &str,
) -> io::Result<()> {
    let file_len = image.seek(SeekFrom::End(0))?;
    if file_len < (OVERHEAD + MIN_PAYLOAD_LEN) as u64 {
        return Err(invalid_data("missing or truncated peer trailer"));
    }
    image.seek(SeekFrom::Start(file_len - FOOTER_LEN as u64))?;
    let mut footer = [0; FOOTER_LEN];
    image.read_exact(&mut footer)?;
    if &footer[4..] != MAGIC {
        return Err(invalid_data("missing peer trailer magic"));
    }
    let payload_len = u32::from_le_bytes(footer[..4].try_into().unwrap()) as usize;
    if !(MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN).contains(&payload_len) {
        return Err(invalid_data("peer trailer payload length out of bounds"));
    }
    let image_len = file_len
        .checked_sub((payload_len + OVERHEAD) as u64)
        .ok_or_else(|| invalid_data("peer trailer extends beyond the image"))?;

    image.seek(SeekFrom::Start(image_len))?;
    let mut payload_buf = [0; MAX_PAYLOAD_LEN];
    let payload = &mut payload_buf[..payload_len];
    image.read_exact(payload)?;
    let mut signature = [0; SIGNATURE_LEN];
    image.read_exact(&mut signature)?;
    let fields = Payload::decode(payload)?;

    if fields.role != role.as_str().as_bytes() || fields.target != target.as_bytes() {
        return Err(invalid_data("peer trailer role or target does not match"));
    }
    key.verify_strict(&signed_message(payload), &Signature::from_bytes(&signature))
        .map_err(|_| invalid_data("invalid peer trailer signature"))?;
    if digest_image(image, image_len)? != fields.digest {
        return Err(invalid_data("peer image digest does not match"));
    }
    Ok(())
}

/// Append a trailer to a writable image after all other modifications are complete.
/// An existing trailer marker is an error, even if that trailer is malformed.
pub fn append(
    image: &mut (impl Read + Write + Seek),
    key: &SigningKey,
    role: PeerRole,
    target: &str,
    version: &str,
) -> io::Result<()> {
    let mut payload = Payload {
        role: role.as_str().as_bytes(),
        target: target.as_bytes(),
        version: version.as_bytes(),
        digest: [0; DIGEST_LEN],
    };
    if ![payload.role, payload.target, payload.version]
        .into_iter()
        .all(valid_field)
    {
        return Err(invalid_input(
            "peer trailer fields must be 1–64 ASCII bytes",
        ));
    }
    let image_len = image.seek(SeekFrom::End(0))?;
    if ends_in_magic(image, image_len)? {
        return Err(invalid_data("image already ends in peer trailer magic"));
    }
    payload.digest = digest_image(image, image_len)?;
    let payload = payload.encode();
    let signature = key.sign(&signed_message(&payload));
    image.write_all(&payload)?;
    image.write_all(&signature.to_bytes())?;
    image.write_all(&(payload.len() as u32).to_le_bytes())?;
    image.write_all(MAGIC)?;
    image.flush()
}

/// Detect the trailer marker even when the length or payload is malformed.
pub fn has_trailer_marker(image: &mut (impl Read + Seek)) -> io::Result<bool> {
    let file_len = image.seek(SeekFrom::End(0))?;
    ends_in_magic(image, file_len)
}

fn ends_in_magic(image: &mut (impl Read + Seek), file_len: u64) -> io::Result<bool> {
    let Some(offset) = file_len.checked_sub(MAGIC.len() as u64) else {
        return Ok(false);
    };
    image.seek(SeekFrom::Start(offset))?;
    let mut magic = [0; MAGIC.len()];
    image.read_exact(&mut magic)?;
    Ok(&magic == MAGIC)
}

fn digest_image(
    image: &mut (impl Read + Seek),
    mut remaining: u64,
) -> io::Result<[u8; DIGEST_LEN]> {
    image.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut chunk = [0; HASH_CHUNK_LEN];
    while remaining != 0 {
        let len = remaining.min(HASH_CHUNK_LEN as u64) as usize;
        image.read_exact(&mut chunk[..len])?;
        hasher.update(&chunk[..len]);
        remaining -= len as u64;
    }
    Ok(hasher.finalize().into())
}

struct Payload<'a> {
    role: &'a [u8],
    target: &'a [u8],
    version: &'a [u8],
    digest: [u8; DIGEST_LEN],
}

impl<'a> Payload<'a> {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_PAYLOAD_LEN);
        for field in [self.role, self.target, self.version] {
            bytes.push(field.len() as u8);
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn decode(mut bytes: &'a [u8]) -> io::Result<Self> {
        let role = take_field(&mut bytes)?;
        let target = take_field(&mut bytes)?;
        let version = take_field(&mut bytes)?;
        let digest = bytes
            .try_into()
            .map_err(|_| invalid_data("peer trailer must end with exactly one SHA-256 digest"))?;
        Ok(Self {
            role,
            target,
            version,
            digest,
        })
    }
}

fn take_field<'a>(bytes: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let (&len, rest) = bytes
        .split_first()
        .ok_or_else(|| invalid_data("missing peer trailer field"))?;
    let (field, rest) = rest
        .split_at_checked(len.into())
        .filter(|(field, _)| valid_field(field))
        .ok_or_else(|| invalid_data("peer trailer fields must be 1–64 ASCII bytes"))?;
    *bytes = rest;
    Ok(field)
}

fn valid_field(field: &[u8]) -> bool {
    (1..=MAX_FIELD_LEN).contains(&field.len()) && field.is_ascii()
}

fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(payload);
    message
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
