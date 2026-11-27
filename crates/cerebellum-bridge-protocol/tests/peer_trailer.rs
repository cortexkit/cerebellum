use cerebellum_bridge_protocol::peer_trailer::{
    self, is_test_peer_key, parse_public_key, public_key_fingerprint, PeerRole,
    TEST_PEER_PUBLIC_KEY_HEX,
};
use ed25519_dalek::{pkcs8::EncodePrivateKey, Signer, SigningKey, VerifyingKey};
use serde::Deserialize;
use std::{
    fs,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

const PUBLIC_KEY_ENV: &str = "CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY";
const FINGERPRINT_ENV: &str = "BRIDGE_PEER_SIGNING_FINGERPRINT";
const LINUX_X64: &str = "x86_64-unknown-linux-gnu";
const WINDOWS_ARM64: &str = "aarch64-pc-windows-msvc";

#[derive(Deserialize)]
struct Golden {
    public_key_hex: String,
    public_key_fingerprint: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    image_hex: String,
    role: String,
    target: String,
    version: String,
    trailer_hex: String,
}

fn golden() -> Golden {
    serde_json::from_str(include_str!("fixtures/peer-trailer-v1.json")).unwrap()
}

impl Vector {
    fn image(&self) -> Vec<u8> {
        unhex(&self.image_hex)
    }

    fn signed_image(&self) -> Vec<u8> {
        let mut image = self.image();
        image.extend(unhex(&self.trailer_hex));
        image
    }

    fn role(&self) -> PeerRole {
        self.role.parse().unwrap()
    }
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn verifier_accepts_independent_golden_vectors_and_raw_key_fingerprint() {
    let golden = golden();
    assert_eq!(golden.public_key_hex, TEST_PEER_PUBLIC_KEY_HEX);
    let key = parse_public_key(&golden.public_key_hex.to_ascii_uppercase()).unwrap();
    assert!(is_test_peer_key(&key));
    assert_eq!(public_key_fingerprint(&key), golden.public_key_fingerprint);
    for vector in golden.vectors {
        peer_trailer::verify(
            &mut Cursor::new(vector.signed_image()),
            &key,
            vector.role(),
            &vector.target,
        )
        .unwrap();
    }
}

#[test]
fn invalid_length_and_truncated_images_are_refused() {
    let golden = golden();
    let key = parse_public_key(&golden.public_key_hex).unwrap();
    let vector = &golden.vectors[0];
    let signed = vector.signed_image();
    assert!(signed.len() < 227 + 76);

    for (len, message) in [
        (0, "peer trailer payload length out of bounds"),
        (37, "peer trailer payload length out of bounds"),
        (228, "peer trailer payload length out of bounds"),
        (u32::MAX, "peer trailer payload length out of bounds"),
        (227, "peer trailer extends beyond the image"),
    ] {
        let mut bad = signed.clone();
        let end = bad.len();
        bad[end - 12..end - 8].copy_from_slice(&len.to_le_bytes());
        assert_refusal(&bad, &key, vector.role(), &vector.target, message);
    }
    for bad in [&signed[..signed.len() - 1], &signed[..113], b"no trailer"] {
        assert!(
            peer_trailer::verify(&mut Cursor::new(bad), &key, vector.role(), &vector.target,)
                .is_err()
        );
    }
}

#[test]
fn payload_bounds_are_inclusive() {
    let key = SigningKey::from_bytes(&[17; 32]);
    for (len, field) in [(38, "a".to_owned()), (227, "a".repeat(64))] {
        let payload = payload(&field, &field, &field);
        assert_eq!(payload.len(), len);
        assert_refusal(
            &sign_payload(&payload, &key),
            &key.verifying_key(),
            PeerRole::Host,
            &field,
            "peer trailer role or target does not match",
        );
    }
}

#[test]
fn signed_prefixes_mixed_architectures_roles_and_trailing_payload_are_refused() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let arch_mismatch = signed_fields("cerebellum", "x86_64-pc-windows-msvc", "2.0", &key);
    assert_refusal(
        &arch_mismatch,
        &key.verifying_key(),
        PeerRole::Cerebellum,
        WINDOWS_ARM64,
        "peer trailer role or target does not match",
    );

    for (role, target) in [
        ("hos", LINUX_X64),
        ("cerebellum", LINUX_X64),
        ("host", "x86_64-unknown-linux"),
        ("host", "aarch64-unknown-linux-gnu"),
    ] {
        assert_refusal(
            &signed_fields(role, target, "2.0", &key),
            &key.verifying_key(),
            PeerRole::Host,
            LINUX_X64,
            "peer trailer role or target does not match",
        );
    }

    let mut trailing = payload("host", LINUX_X64, "2.0");
    trailing.push(0);
    assert_refusal(
        &sign_payload(&trailing, &key),
        &key.verifying_key(),
        PeerRole::Host,
        LINUX_X64,
        "peer trailer must end with exactly one SHA-256 digest",
    );
}

#[test]
fn invalid_field_lengths_and_non_ascii_are_refused_by_both_sides() {
    let key = SigningKey::from_bytes(&[17; 32]);
    for bad in ["", &"v".repeat(65), "café"] {
        let mut image = Cursor::new(b"unchanged".to_vec());
        assert!(peer_trailer::append(&mut image, &key, PeerRole::Host, LINUX_X64, bad).is_err());
        assert_eq!(image.into_inner(), b"unchanged");
        assert_refusal(
            &signed_fields("host", LINUX_X64, bad, &key),
            &key.verifying_key(),
            PeerRole::Host,
            LINUX_X64,
            "peer trailer fields must be 1–64 ASCII bytes",
        );
    }
}

#[test]
fn bad_signature_and_authentic_trailer_with_wrong_digest_are_refused() {
    let golden = golden();
    let key = parse_public_key(&golden.public_key_hex).unwrap();
    let vector = &golden.vectors[0];
    let signed = vector.signed_image();
    let signature_pos = signed.len() - 76;
    let mut wrong_signature = signed.clone();
    wrong_signature[signature_pos] ^= 1;
    assert_refusal(
        &wrong_signature,
        &key,
        vector.role(),
        &vector.target,
        "invalid peer trailer signature",
    );

    let mut wrong_image = signed;
    wrong_image[0] ^= 1;
    assert_refusal(
        &wrong_image,
        &key,
        vector.role(),
        &vector.target,
        "peer image digest does not match",
    );
}

fn assert_refusal(bytes: &[u8], key: &VerifyingKey, role: PeerRole, target: &str, message: &str) {
    let error = peer_trailer::verify(&mut Cursor::new(bytes), key, role, target).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), message);
}

const IMAGE: &[u8] = b"image for malformed trailer tests";

fn payload(role: &str, target: &str, version: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut bytes = Vec::new();
    for field in [role, target, version] {
        bytes.push(field.len() as u8);
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes.extend_from_slice(&Sha256::digest(IMAGE));
    bytes
}

fn sign_payload(payload: &[u8], key: &SigningKey) -> Vec<u8> {
    let mut message = b"cortexkit-peer-v1\0".to_vec();
    message.extend_from_slice(payload);
    let mut image = IMAGE.to_vec();
    image.extend_from_slice(payload);
    image.extend(key.sign(&message).to_bytes());
    image.extend((payload.len() as u32).to_le_bytes());
    image.extend(b"CKPEER01");
    image
}

fn signed_fields(role: &str, target: &str, version: &str, key: &SigningKey) -> Vec<u8> {
    sign_payload(&payload(role, target, version), key)
}

#[test]
fn verifier_streams_the_entire_image_in_bounded_chunks() {
    struct Chunked(Cursor<Vec<u8>>);

    impl Read for Chunked {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(buf.len() <= 64 * 1024, "unbounded read: {}", buf.len());
            let len = buf.len().min(997);
            self.0.read(&mut buf[..len])
        }
    }

    impl Seek for Chunked {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    let image_len = 3 * 64 * 1024 + 19;
    let mut image = Cursor::new(vec![0x9a; image_len]);
    let key = SigningKey::from_bytes(&[17; 32]);
    peer_trailer::append(&mut image, &key, PeerRole::Host, LINUX_X64, "0.1").unwrap();
    let mut image = Chunked(image);
    let verify = |image: &mut Chunked| {
        peer_trailer::verify(image, &key.verifying_key(), PeerRole::Host, LINUX_X64)
    };
    verify(&mut image).unwrap();
    image.0.get_mut()[image_len - 1] ^= 1;
    assert_eq!(
        verify(&mut image).unwrap_err().to_string(),
        "peer image digest does not match"
    );
}

#[test]
fn signing_tool_reproduces_the_independent_golden_vectors_byte_for_byte() {
    let golden = golden();
    for vector in golden.vectors {
        let image = TempImage::new(&vector.image());
        let mut signer = tool("sign")
            .arg("--test-key")
            .env(PUBLIC_KEY_ENV, golden.public_key_hex.to_ascii_uppercase())
            .arg(image.path())
            .args([&vector.role, &vector.target, &vector.version])
            .output()
            .unwrap();
        assert_success(&signer);
        assert_eq!(image.bytes(), vector.signed_image());
        signer = tool("sign")
            .arg("--test-key")
            .env(PUBLIC_KEY_ENV, &golden.public_key_hex)
            .arg(image.path())
            .args([&vector.role, &vector.target, &vector.version])
            .output()
            .unwrap();
        assert_failure(&signer, "image already ends in peer trailer magic");
        assert_eq!(image.bytes(), vector.signed_image());
    }
}

#[test]
fn release_signing_reads_pkcs8_pem_from_stdin_and_verifies_the_pinned_image() {
    let image = TempImage::new(IMAGE);
    let key = SigningKey::from_bytes(&[17; 32]);
    let public_key = key.verifying_key();
    let pin = public_key_fingerprint(&public_key);
    let pem = key.to_pkcs8_pem(Default::default()).unwrap();
    let public_key_hex = hex(public_key.as_bytes()).to_ascii_uppercase();
    let signer = sign_command(image.path(), &public_key_hex, &pin);
    assert_success(&with_stdin(signer, pem.as_bytes()));

    assert_success(
        &tool("verify")
            .arg(image.path())
            .args(["host", LINUX_X64])
            .env(PUBLIC_KEY_ENV, &public_key_hex)
            .env(FINGERPRINT_ENV, &pin)
            .output()
            .unwrap(),
    );
    assert_failure(
        &tool("verify")
            .arg(image.path())
            .args(["host", WINDOWS_ARM64])
            .env(PUBLIC_KEY_ENV, &public_key_hex)
            .env(FINGERPRINT_ENV, &pin)
            .output()
            .unwrap(),
        "peer trailer role or target does not match",
    );
}

#[test]
fn release_preflight_refuses_test_key_in_either_case_and_invalid_keys() {
    assert_failure(
        &tool("preflight").output().unwrap(),
        "missing CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY",
    );
    for invalid in ["", "bad hex", &"0".repeat(64)] {
        assert_failure(
            &tool("preflight")
                .env(PUBLIC_KEY_ENV, invalid)
                .output()
                .unwrap(),
            "invalid CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY",
        );
    }
    for encoded in [
        TEST_PEER_PUBLIC_KEY_HEX,
        &TEST_PEER_PUBLIC_KEY_HEX.to_ascii_uppercase(),
    ] {
        assert_failure(
            &tool("preflight")
                .env(PUBLIC_KEY_ENV, encoded)
                .output()
                .unwrap(),
            "repository test key is forbidden for releases",
        );
    }
    let key = SigningKey::from_bytes(&[17; 32]).verifying_key();
    assert_success(
        &tool("preflight")
            .env(PUBLIC_KEY_ENV, hex(key.as_bytes()))
            .output()
            .unwrap(),
    );
}

#[test]
fn release_signing_refuses_without_output_on_bad_pin_or_private_key() {
    let image = TempImage::new(IMAGE);
    let key = SigningKey::from_bytes(&[17; 32]).verifying_key();
    let public_key_hex = hex(key.as_bytes());
    let pin = public_key_fingerprint(&key);
    for (bad_pin, message) in [
        ("", "missing BRIDGE_PEER_SIGNING_FINGERPRINT"),
        (
            &"0".repeat(64),
            "public key fingerprint does not match the pin",
        ),
    ] {
        let output = sign_command(image.path(), &public_key_hex, bad_pin)
            .output()
            .unwrap();
        assert_failure(&output, message);
        assert_eq!(image.bytes(), IMAGE);
    }

    let wrong_key = SigningKey::from_bytes(&[18; 32]);
    let wrong_pem = wrong_key.to_pkcs8_pem(Default::default()).unwrap();
    let output = with_stdin(
        sign_command(image.path(), &public_key_hex, &pin),
        wrong_pem.as_bytes(),
    );
    assert_failure(&output, "private key does not match the bound public key");
    assert_eq!(image.bytes(), IMAGE);

    for invalid in [
        b"".as_slice(),
        b"not PEM",
        b"1111111111111111111111111111111111111111111111111111111111111111",
        &[b'x'; 4097],
    ] {
        let output = with_stdin(sign_command(image.path(), &public_key_hex, &pin), invalid);
        assert_failure(
            &output,
            "expected a PKCS#8 Ed25519 private key in PEM on stdin",
        );
        assert_eq!(image.bytes(), IMAGE);
    }
    let output = sign_command(image.path(), TEST_PEER_PUBLIC_KEY_HEX, &pin)
        .output()
        .unwrap();
    assert_failure(&output, "repository test key is forbidden for releases");
    assert_eq!(image.bytes(), IMAGE);
}

#[test]
fn assert_unsigned_refuses_even_a_malformed_trailer_marker() {
    let image = TempImage::new(b"MZ");
    assert_success(&tool("assert-unsigned").arg(image.path()).output().unwrap());
    let image = TempImage::new(b"MZCKPEER01");
    assert_failure(
        &tool("assert-unsigned").arg(image.path()).output().unwrap(),
        "image ends in peer trailer magic",
    );
}

fn tool(action: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_peer-trailer"));
    command
        .arg(action)
        .env_remove(PUBLIC_KEY_ENV)
        .env_remove(FINGERPRINT_ENV)
        .stdin(Stdio::null());
    command
}

fn sign_command(path: &Path, public_key: &str, pin: &str) -> Command {
    let mut command = tool("sign");
    command
        .arg(path)
        .args(["host", LINUX_X64, "0.1"])
        .env(PUBLIC_KEY_ENV, public_key)
        .env(FINGERPRINT_ENV, pin);
    command
}

fn with_stdin(mut command: Command, bytes: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "unexpected failure: {output:?}");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn assert_failure(output: &Output, message: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("peer-trailer: {message}\n").as_bytes()
    );
}

struct TempImage(PathBuf);

impl TempImage {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "peer-trailer-{}-{}.image",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::File::create_new(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.path()).unwrap()
    }
}

impl Drop for TempImage {
    fn drop(&mut self) {
        fs::remove_file(self.path()).unwrap();
    }
}
