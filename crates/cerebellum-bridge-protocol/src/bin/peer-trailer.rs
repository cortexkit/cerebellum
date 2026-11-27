#![forbid(unsafe_code)]

use cerebellum_bridge_protocol::peer_trailer::{
    self, is_test_peer_key, parse_public_key, public_key_fingerprint, PeerRole,
};
use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey, VerifyingKey};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    process::ExitCode,
};
use zeroize::Zeroizing;

const PUBLIC_KEY_ENV: &str = "CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY";
const FINGERPRINT_ENV: &str = "BRIDGE_PEER_SIGNING_FINGERPRINT";
const MAX_PEM_LEN: usize = 4096;
const USAGE: &str = "usage: peer-trailer preflight | sign [--test-key] PATH ROLE TRIPLE VERSION | verify PATH ROLE TRIPLE | assert-unsigned PATH";

// RFC 8032's public test seed. Never used without the explicit test-key flag.
const TEST_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("peer-trailer: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[OsString]) -> io::Result<()> {
    match args {
        [cmd] if cmd == "preflight" => release_public_key().map(|_| ()),
        [cmd, path, role, target, version] if cmd == "sign" => {
            let role = parse_release_role(role)?;
            let public_key = pinned_release_key()?;
            let signing_key = read_private_key(io::stdin().lock())?;
            sign(path, role, target, version, &public_key, &signing_key)
        }
        [cmd, flag, path, role, target, version] if cmd == "sign" && flag == "--test-key" => {
            let public_key = bound_public_key()?;
            if !is_test_peer_key(&public_key) {
                return Err(input_error(
                    "--test-key requires the repository test public key",
                ));
            }
            let signing_key = SigningKey::from_bytes(&TEST_SEED);
            sign(
                path,
                field(role)?.parse()?,
                target,
                version,
                &public_key,
                &signing_key,
            )
        }
        [cmd, path, role, target] if cmd == "verify" => {
            let role = parse_release_role(role)?;
            let key = pinned_release_key()?;
            peer_trailer::verify(&mut File::open(path)?, &key, role, field(target)?)
        }
        [cmd, path] if cmd == "assert-unsigned" => {
            if peer_trailer::has_trailer_marker(&mut File::open(path)?)? {
                return Err(input_error("image ends in peer trailer magic"));
            }
            Ok(())
        }
        _ => Err(input_error(USAGE)),
    }
}

fn sign(
    path: &OsStr,
    role: PeerRole,
    target: &OsStr,
    version: &OsStr,
    public_key: &VerifyingKey,
    signing_key: &SigningKey,
) -> io::Result<()> {
    if signing_key.verifying_key().as_bytes() != public_key.as_bytes() {
        return Err(input_error(
            "private key does not match the bound public key",
        ));
    }
    let mut image = File::options().read(true).write(true).open(path)?;
    peer_trailer::append(
        &mut image,
        signing_key,
        role,
        field(target)?,
        field(version)?,
    )
}

fn bound_public_key() -> io::Result<VerifyingKey> {
    let encoded = env::var(PUBLIC_KEY_ENV)
        .map_err(|_| input_error("missing CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"))?;
    parse_public_key(&encoded)
        .ok_or_else(|| input_error("invalid CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"))
}

fn release_public_key() -> io::Result<VerifyingKey> {
    let key = bound_public_key()?;
    if is_test_peer_key(&key) {
        return Err(input_error("repository test key is forbidden for releases"));
    }
    Ok(key)
}

fn pinned_release_key() -> io::Result<VerifyingKey> {
    let key = release_public_key()?;
    let pin = env::var(FINGERPRINT_ENV)
        .map_err(|_| input_error("missing BRIDGE_PEER_SIGNING_FINGERPRINT"))?;
    if pin.is_empty() {
        return Err(input_error("missing BRIDGE_PEER_SIGNING_FINGERPRINT"));
    }
    if public_key_fingerprint(&key) != pin {
        return Err(input_error("public key fingerprint does not match the pin"));
    }
    Ok(key)
}

fn read_private_key(mut stdin: impl Read) -> io::Result<SigningKey> {
    let mut pem = Zeroizing::new([0; MAX_PEM_LEN + 1]);
    let mut len = 0;
    while len < pem.len() {
        let read = stdin.read(&mut pem[len..])?;
        if read == 0 {
            break;
        }
        len += read;
    }
    let invalid_key = || input_error("expected a PKCS#8 Ed25519 private key in PEM on stdin");
    if len > MAX_PEM_LEN {
        return Err(invalid_key());
    }
    let text = std::str::from_utf8(&pem[..len]).map_err(|_| invalid_key())?;
    SigningKey::from_pkcs8_pem(text).map_err(|_| invalid_key())
}

fn parse_release_role(value: &OsStr) -> io::Result<PeerRole> {
    let role = field(value)?.parse()?;
    if role == PeerRole::TestParent {
        return Err(input_error("test-parent is forbidden for releases"));
    }
    Ok(role)
}

fn field(value: &OsStr) -> io::Result<&str> {
    value
        .to_str()
        .ok_or_else(|| input_error("non-UTF-8 trailer field"))
}

fn input_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
