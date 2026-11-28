//! Select and attest the Windows Chrome image before taking a launch profile.

use super::writability::{inspect_install, InstallWritability};
use cerebellum_windows::identity::{
    checked_path_forms, native_pe_machine, read_process_image_identity, HeldExecutable,
    OpenExecutableError, SignatureStatus, CERT_E_REVOKED, CERT_TRUST_IS_OFFLINE_REVOCATION,
    CERT_TRUST_IS_REVOKED, CERT_TRUST_REVOCATION_STATUS_UNKNOWN, CRYPT_E_REVOCATION_OFFLINE,
    CRYPT_E_REVOKED, TRUST_E_BAD_DIGEST,
};
use cerebellum_windows::{current_process_token_facts, file_identity, FileIdentity};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::windows::io::BorrowedHandle;
use std::path::{Path, PathBuf};

pub const CHROME_PUBLISHER: &str = "Google LLC";
const CHROME_ROOTS: &[[u8; 32]] = &[
    // DigiCert Assured ID Root CA: Chrome's WinTrust chain on both architectures
    // in GitHub Windows browser workflow run 46107810699.
    [
        0x3e, 0x90, 0x99, 0xb5, 0x01, 0x5e, 0x8f, 0x48, 0x6c, 0x00, 0xbc, 0xea, 0x9d, 0x11, 0x1e,
        0xe7, 0x21, 0xfa, 0xba, 0x35, 0x5a, 0x89, 0xbc, 0xf1, 0xdf, 0x69, 0x56, 0x1e, 0x3d, 0xc6,
        0x32, 0x5c,
    ],
    // Self-signed DigiCert Trusted Root G4: LocalMachine\Root on both architectures
    // in GitHub Windows browser workflow run 46111351938.
    [
        0x55, 0x2f, 0x7b, 0xdc, 0xf1, 0xa7, 0xaf, 0x9e, 0x6c, 0xe6, 0x72, 0x01, 0x7f, 0x4f, 0x12,
        0xab, 0xf7, 0x72, 0x40, 0xc7, 0x8e, 0x76, 0x1a, 0xc2, 0x03, 0xd1, 0xd9, 0xd2, 0x0a, 0xc8,
        0x99, 0x88,
    ],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCheck {
    PathReparse,
    PathUnstable,
    Signature,
    Digest,
    Revoked,
    Chain,
    Publisher,
    Eku,
    Root,
    ImageMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    Checked,
    OfflineOrUnknown,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedSignature {
    pub root_sha256: [u8; 32],
    pub revocation: Revocation,
}

#[derive(Debug)]
pub struct DiscoveryRoots {
    roots: [(RootKind, Option<PathBuf>); 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKind {
    ProgramFiles,
    ProgramFilesX86,
    LocalAppData,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TriedRoot {
    pub kind: RootKind,
    pub path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SkippedCandidate {
    pub path: PathBuf,
    pub reason: SkipReason,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    Missing,
    WrongMachine { found: u16, native: u16 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    ExplicitMissing {
        path: PathBuf,
    },
    ExplicitWrongMachine {
        path: PathBuf,
        found: u16,
        native: u16,
    },
    Refused {
        path: PathBuf,
        check: IdentityCheck,
    },
    Exhausted {
        tried: Vec<TriedRoot>,
        skipped: Vec<SkippedCandidate>,
    },
    NativeMachineUnavailable,
    TokenElevationUnavailable,
}

#[derive(Debug)]
pub struct PreparedExecutable {
    pub held: HeldExecutable,
    pub publisher: String,
    pub signature: VerifiedSignature,
    pub image_sha256: [u8; 32],
    pub image_id: FileIdentity,
    pub token_elevated: bool,
    pub install_writable_by_user: InstallWritability,
    pub skipped: Vec<SkippedCandidate>,
}

impl PreparedExecutable {
    /// Read the suspended child's image identity without reopening it by process ID.
    /// Keep `held` alive through the subsequent ResumeThread call.
    pub fn compare_spawn_image(
        &self,
        process: BorrowedHandle<'_>,
    ) -> Result<FileIdentity, IdentityCheck> {
        compare_file_id(self.image_id, read_process_image_identity(process))
    }
}

fn compare_file_id(
    expected: FileIdentity,
    actual: io::Result<FileIdentity>,
) -> Result<FileIdentity, IdentityCheck> {
    let actual = actual.map_err(|_| IdentityCheck::ImageMismatch)?;
    if actual != expected {
        return Err(IdentityCheck::ImageMismatch);
    }
    Ok(actual)
}

impl DiscoveryRoots {
    pub fn new(
        program_files: Option<PathBuf>,
        program_files_x86: Option<PathBuf>,
        local_app_data: Option<PathBuf>,
    ) -> Self {
        Self {
            roots: [
                (RootKind::ProgramFiles, program_files),
                (RootKind::ProgramFilesX86, program_files_x86),
                (RootKind::LocalAppData, local_app_data),
            ],
        }
    }

    /// Take this snapshot when constructing the launch service, not on launch.
    pub fn from_environment() -> Self {
        let root = |name| {
            std::env::var_os(name)
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
        };
        Self::new(
            root("ProgramFiles"),
            root("ProgramFiles(x86)"),
            root("LOCALAPPDATA"),
        )
    }

    pub fn prepare(
        &self,
        config: &crate::browser_config::BrowserConfig,
    ) -> Result<PreparedExecutable, DiscoveryError> {
        let native = native_pe_machine().map_err(|_| DiscoveryError::NativeMachineUnavailable)?;
        let publisher = config
            .expected_identity
            .as_deref()
            .unwrap_or(CHROME_PUBLISHER);
        let (candidate, skipped) =
            self.select(config.executable_path.as_deref(), native, |held| {
                let signature = check_signature(held.read_signature_status(), publisher)?;
                let image_id =
                    file_identity(held.image()).map_err(|_| IdentityCheck::PathUnstable)?;
                let image_sha256 = image_sha256(held.image()).map_err(|_| IdentityCheck::Digest)?;
                Ok((held, signature, image_id, image_sha256))
            })?;
        let (held, signature, image_id, image_sha256) = candidate;
        let token_elevated = current_process_token_facts()
            .ok_or(DiscoveryError::TokenElevationUnavailable)?
            .elevated;
        let install_writable_by_user = inspect_install(&held);
        Ok(PreparedExecutable {
            held,
            publisher: publisher.to_owned(),
            signature,
            image_sha256,
            image_id,
            token_elevated,
            install_writable_by_user,
            skipped,
        })
    }

    fn select<T>(
        &self,
        explicit: Option<&Path>,
        native: u16,
        mut read: impl FnMut(HeldExecutable) -> Result<T, IdentityCheck>,
    ) -> Result<(T, Vec<SkippedCandidate>), DiscoveryError> {
        let open = |path: &Path| open_candidate(path, native);
        let refusal = |path: PathBuf, check| DiscoveryError::Refused { path, check };
        if let Some(path) = explicit {
            return match open(path) {
                Ok(held) => read(held)
                    .map(|selected| (selected, Vec::new()))
                    .map_err(|check| refusal(path.to_owned(), check)),
                Err(CandidateError::Skip(SkipReason::Missing)) => {
                    Err(DiscoveryError::ExplicitMissing {
                        path: path.to_owned(),
                    })
                }
                Err(CandidateError::Skip(SkipReason::WrongMachine { found, native })) => {
                    Err(DiscoveryError::ExplicitWrongMachine {
                        path: path.to_owned(),
                        found,
                        native,
                    })
                }
                Err(CandidateError::Refused(check)) => Err(refusal(path.to_owned(), check)),
            };
        }

        let mut tried = Vec::new();
        let mut skipped = Vec::new();
        for (kind, root) in &self.roots {
            let Some(root) = root else { continue };
            tried.push(TriedRoot {
                kind: *kind,
                path: root.clone(),
            });
            // Joining a verbatim path can erase dot components; reject ambiguous roots first.
            checked_path_forms(root.as_os_str())
                .map_err(|_| refusal(root.clone(), IdentityCheck::PathUnstable))?;
            let path = root.join(r"Google\Chrome\Application\chrome.exe");
            match open(&path) {
                Ok(held) => {
                    return read(held)
                        .map(|selected| (selected, skipped))
                        .map_err(|check| refusal(path, check))
                }
                Err(CandidateError::Skip(reason)) => {
                    skipped.push(SkippedCandidate { path, reason })
                }
                Err(CandidateError::Refused(check)) => return Err(refusal(path, check)),
            }
        }
        Err(DiscoveryError::Exhausted { tried, skipped })
    }
}

enum CandidateError {
    Skip(SkipReason),
    Refused(IdentityCheck),
}

fn open_candidate(path: &Path, native: u16) -> Result<HeldExecutable, CandidateError> {
    let held = HeldExecutable::open(path).map_err(|err| match err {
        OpenExecutableError::Missing => CandidateError::Skip(SkipReason::Missing),
        OpenExecutableError::UnstablePath => CandidateError::Refused(IdentityCheck::PathUnstable),
        OpenExecutableError::ReparsePoint => CandidateError::Refused(IdentityCheck::PathReparse),
    })?;
    let found = pe_machine(held.image())
        .map_err(|_| CandidateError::Refused(IdentityCheck::PathUnstable))?;
    if found != native {
        return Err(CandidateError::Skip(SkipReason::WrongMachine {
            found,
            native,
        }));
    }
    Ok(held)
}

fn pe_machine(mut image: &File) -> io::Result<u16> {
    let mut dos = [0; 64];
    image.seek(SeekFrom::Start(0))?;
    image.read_exact(&mut dos)?;
    let offset = u32::from_le_bytes(dos[60..64].try_into().expect("four offset bytes"));
    if &dos[..2] != b"MZ" || offset < dos.len() as u32 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut pe = [0; 6];
    image.seek(SeekFrom::Start(offset.into()))?;
    image.read_exact(&mut pe)?;
    if &pe[..4] != b"PE\0\0" {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(u16::from_le_bytes([pe[4], pe[5]]))
}

fn image_sha256(mut image: &File) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    image.seek(SeekFrom::Start(0))?;
    io::copy(&mut image, &mut hasher)?;
    Ok(hasher.finalize().into())
}

const OFFLINE_BITS: u32 = CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION;

pub fn check_signature(
    reading: SignatureStatus,
    publisher: &str,
) -> Result<VerifiedSignature, IdentityCheck> {
    let SignatureStatus {
        provider_status,
        chain_errors,
        signer,
    } = reading;
    if matches!(provider_status, CERT_E_REVOKED | CRYPT_E_REVOKED)
        || chain_errors.is_some_and(|status| status & CERT_TRUST_IS_REVOKED != 0)
    {
        return Err(IdentityCheck::Revoked);
    }
    let provider_offline = match provider_status {
        0 => false,
        CRYPT_E_REVOCATION_OFFLINE => true,
        TRUST_E_BAD_DIGEST => return Err(IdentityCheck::Digest),
        _ => return Err(IdentityCheck::Signature),
    };
    let chain = chain_errors.ok_or(IdentityCheck::Chain)?;
    if chain & !OFFLINE_BITS != 0 {
        return Err(IdentityCheck::Chain);
    }
    let signer = signer.ok_or(IdentityCheck::Chain)?;
    if signer.common_name.as_deref() != Some(publisher)
        || signer.organization.as_deref() != Some(publisher)
    {
        return Err(IdentityCheck::Publisher);
    }
    if !signer.code_signing_eku {
        return Err(IdentityCheck::Eku);
    }
    let root_sha256 = signer.root_sha256.ok_or(IdentityCheck::Root)?;
    if !CHROME_ROOTS.contains(&root_sha256) {
        return Err(IdentityCheck::Root);
    }
    let revocation = if provider_offline || chain != 0 {
        Revocation::OfflineOrUnknown
    } else {
        Revocation::Checked
    };
    Ok(VerifiedSignature {
        root_sha256,
        revocation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_windows::identity::SignatureSigner;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ASSURED_ID_DER: &str = "3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c";
    const G4_DER: &str = "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988";

    fn thumbprint(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
    }

    fn good_reading() -> SignatureStatus {
        SignatureStatus {
            provider_status: 0,
            chain_errors: Some(0),
            signer: Some(SignatureSigner {
                common_name: Some("Google LLC".into()),
                organization: Some("Google LLC".into()),
                code_signing_eku: true,
                root_sha256: Some(thumbprint(ASSURED_ID_DER)),
            }),
        }
    }

    #[test]
    fn windows_chrome_signature_is_checked_against_root_table() {
        let Some(path) = std::env::var_os("CK_WINDOWS_BROWSER_CHROME") else {
            return;
        };
        let fixture = Scratch::new();
        let roots = fixture.roots();
        let per_user = chrome_path(&fixture.0.join("user"));
        ensure_parent(&per_user);
        fs::copy(path, &per_user).expect("copy installed Chrome into the test-owned root");
        let config = crate::browser_config::BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 1000,
            termination_grace_period_ms: 1000,
            browser_idle_timeout_ms: 1000,
            browser_exit_observation_deadline_ms: 1000,
            navigation_settle_deadline_ms: 1000,
        };
        let image = roots
            .prepare(&config)
            .expect("prepare the installed native Chrome image");
        assert_eq!(Path::new(image.held.paths().stored()), per_user);
        assert_eq!(image.signature.root_sha256, thumbprint(ASSURED_ID_DER));
        assert_eq!(image.publisher, "Google LLC");
        assert_eq!(
            image.skipped,
            [
                SkippedCandidate {
                    path: chrome_path(&fixture.0.join("program")),
                    reason: SkipReason::Missing
                },
                SkippedCandidate {
                    path: chrome_path(&fixture.0.join("program32")),
                    reason: SkipReason::Missing
                },
            ]
        );
        let bytes = fs::read(per_user).expect("read fixture independently by path");
        assert_eq!(image.image_sha256, <[u8; 32]>::from(Sha256::digest(bytes)));
    }

    #[test]
    fn windows_signer_pins_both_subject_attributes() {
        for corrupt in [
            |signer: &mut SignatureSigner| signer.common_name = Some("Different".into()),
            |signer: &mut SignatureSigner| signer.organization = Some("Different".into()),
        ] {
            let mut reading = good_reading();
            corrupt(reading.signer.as_mut().unwrap());
            assert_eq!(
                check_signature(reading, CHROME_PUBLISHER),
                Err(IdentityCheck::Publisher)
            );
        }
    }

    #[test]
    fn windows_signer_requires_code_signing_eku() {
        let mut reading = good_reading();
        reading.signer.as_mut().unwrap().code_signing_eku = false;
        assert_eq!(
            check_signature(reading, CHROME_PUBLISHER),
            Err(IdentityCheck::Eku)
        );
    }

    #[test]
    fn windows_signer_only_accepts_the_two_observed_root_certificates() {
        for (root, accepted) in [
            (thumbprint(ASSURED_ID_DER), true),
            (thumbprint(G4_DER), true),
            (
                thumbprint("33846b545a49c9be4903c60e01713c1bd4e4ef31ea65cd95d69e62794f30b941"),
                false,
            ),
            ([11; 32], false),
        ] {
            let mut reading = good_reading();
            reading.signer.as_mut().unwrap().root_sha256 = Some(root);
            let result = check_signature(reading, CHROME_PUBLISHER);
            if accepted {
                assert_eq!(result.unwrap().root_sha256, root);
            } else {
                assert_eq!(result, Err(IdentityCheck::Root));
            }
        }
    }

    #[test]
    fn windows_digest_failure_is_not_excused_by_offline_revocation() {
        for chain in [0, OFFLINE_BITS] {
            let mut reading = good_reading();
            reading.provider_status = TRUST_E_BAD_DIGEST;
            reading.chain_errors = Some(chain);
            assert_eq!(
                check_signature(reading, CHROME_PUBLISHER),
                Err(IdentityCheck::Digest)
            );
        }
    }

    #[test]
    fn windows_revoked_from_either_reading_takes_precedence() {
        for (provider_status, bits) in [
            (CERT_E_REVOKED, 0),
            (CRYPT_E_REVOKED, OFFLINE_BITS),
            (0, CERT_TRUST_IS_REVOKED),
            (
                CRYPT_E_REVOCATION_OFFLINE,
                CERT_TRUST_IS_REVOKED | OFFLINE_BITS,
            ),
            (TRUST_E_BAD_DIGEST, CERT_TRUST_IS_REVOKED | OFFLINE_BITS),
        ] {
            let mut reading = good_reading();
            reading.provider_status = provider_status;
            reading.chain_errors = Some(bits);
            assert_eq!(
                check_signature(reading, CHROME_PUBLISHER),
                Err(IdentityCheck::Revoked)
            );
        }
    }

    #[test]
    fn windows_chain_only_tolerates_offline_or_unknown_revocation() {
        const CERT_TRUST_IS_UNTRUSTED_ROOT: u32 = 0x20;
        for bits in [
            CERT_TRUST_IS_UNTRUSTED_ROOT,
            CERT_TRUST_IS_UNTRUSTED_ROOT | OFFLINE_BITS,
        ] {
            let mut reading = good_reading();
            reading.chain_errors = Some(bits);
            assert_eq!(
                check_signature(reading, CHROME_PUBLISHER),
                Err(IdentityCheck::Chain)
            );
        }
        for (status, bits) in [
            (CRYPT_E_REVOCATION_OFFLINE, 0),
            (0, CERT_TRUST_IS_OFFLINE_REVOCATION),
            (0, CERT_TRUST_REVOCATION_STATUS_UNKNOWN),
            (0, OFFLINE_BITS),
        ] {
            let mut reading = good_reading();
            reading.provider_status = status;
            reading.chain_errors = Some(bits);
            assert_eq!(
                check_signature(reading, CHROME_PUBLISHER)
                    .unwrap()
                    .revocation,
                Revocation::OfflineOrUnknown
            );
        }
        assert_eq!(
            check_signature(good_reading(), CHROME_PUBLISHER)
                .unwrap()
                .revocation,
            Revocation::Checked
        );
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "ck-identity-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create test-owned directory");
            Self(fs::canonicalize(path).expect("resolve fixture directory"))
        }

        fn roots(&self) -> DiscoveryRoots {
            let roots = ["program", "program32", "user"].map(|name| {
                let path = self.0.join(name);
                fs::create_dir(&path).expect("create synthetic discovery root");
                Some(path)
            });
            let [program, program32, user] = roots;
            DiscoveryRoots::new(program, program32, user)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn chrome_path(root: &Path) -> PathBuf {
        root.join(r"Google\Chrome\Application\chrome.exe")
    }
    fn ensure_parent(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).expect("create candidate parent");
    }
    fn fixture_pe(path: &Path, machine: u16) {
        ensure_parent(path);
        let mut bytes = [0u8; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60] = 64;
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&machine.to_le_bytes());
        fs::write(path, bytes).expect("write non-executable test PE header");
    }

    #[test]
    fn windows_discovery_skips_only_missing_and_wrong_machine_in_order() {
        let fixture = Scratch::new();
        let roots = fixture.roots();
        let first = chrome_path(&fixture.0.join("program"));
        let second = chrome_path(&fixture.0.join("program32"));
        let third = chrome_path(&fixture.0.join("user"));
        fixture_pe(&first, 0x014c);
        fixture_pe(&third, 0x8664);
        let (selected, skipped) = roots
            .select(None, 0x8664, |held| {
                Ok(PathBuf::from(held.paths().stored()))
            })
            .unwrap();
        assert_eq!(selected, third);
        assert_eq!(
            skipped,
            [
                SkippedCandidate {
                    path: first,
                    reason: SkipReason::WrongMachine {
                        found: 0x014c,
                        native: 0x8664
                    }
                },
                SkippedCandidate {
                    path: second,
                    reason: SkipReason::Missing
                }
            ]
        );
    }

    #[test]
    fn windows_discovery_stops_at_a_present_refused_candidate() {
        let fixture = Scratch::new();
        let roots = fixture.roots();
        let first = chrome_path(&fixture.0.join("program"));
        fixture_pe(&first, 0x8664);
        fixture_pe(&chrome_path(&fixture.0.join("program32")), 0x8664);
        let mut calls = 0;
        let result = roots.select(None, 0x8664, |held| {
            calls += 1;
            check_signature(held.read_signature_status(), CHROME_PUBLISHER)
        });
        assert_eq!(
            result,
            Err(DiscoveryError::Refused {
                path: first,
                check: IdentityCheck::Signature
            })
        );
        assert_eq!(calls, 1, "an unsigned candidate stops discovery");
    }

    #[test]
    fn windows_discovery_never_falls_back_from_an_explicit_path() {
        let fixture = Scratch::new();
        let roots = fixture.roots();
        fixture_pe(&chrome_path(&fixture.0.join("program")), 0x8664);
        let explicit = fixture.0.join("explicit.exe");
        let run = || roots.select(Some(&explicit), 0x8664, |_| Ok(()));
        assert_eq!(
            run(),
            Err(DiscoveryError::ExplicitMissing {
                path: explicit.clone()
            })
        );
        fixture_pe(&explicit, 0xaa64);
        assert_eq!(
            run(),
            Err(DiscoveryError::ExplicitWrongMachine {
                path: explicit.clone(),
                found: 0xaa64,
                native: 0x8664
            })
        );
        fixture_pe(&explicit, 0x8664);
        assert_eq!(
            roots.select(Some(&explicit), 0x8664, |_| Err::<(), _>(
                IdentityCheck::Root
            )),
            Err(DiscoveryError::Refused {
                path: explicit,
                check: IdentityCheck::Root
            })
        );
    }

    #[test]
    fn windows_discovery_exhaustion_reports_roots_and_skips() {
        let fixture = Scratch::new();
        let roots = fixture.roots();
        let wrong = chrome_path(&fixture.0.join("program32"));
        fixture_pe(&wrong, 0x014c);
        assert_eq!(
            roots.select(None, 0x8664, |_| Ok(())),
            Err(DiscoveryError::Exhausted {
                tried: [
                    (RootKind::ProgramFiles, "program"),
                    (RootKind::ProgramFilesX86, "program32"),
                    (RootKind::LocalAppData, "user")
                ]
                .into_iter()
                .map(|(kind, name)| TriedRoot {
                    kind,
                    path: fixture.0.join(name)
                })
                .collect(),
                skipped: vec![
                    SkippedCandidate {
                        path: chrome_path(&fixture.0.join("program")),
                        reason: SkipReason::Missing
                    },
                    SkippedCandidate {
                        path: wrong,
                        reason: SkipReason::WrongMachine {
                            found: 0x014c,
                            native: 0x8664
                        }
                    },
                    SkippedCandidate {
                        path: chrome_path(&fixture.0.join("user")),
                        reason: SkipReason::Missing
                    }
                ],
            })
        );
    }

    #[test]
    fn windows_barred_file_id_mismatch_is_independent_of_sharing() {
        let fixture = Scratch::new();
        let first = fixture.0.join("first.exe");
        let second = fixture.0.join("second.exe");
        fixture_pe(&first, 0x8664);
        fixture_pe(&second, 0x8664);
        let expected = file_identity(HeldExecutable::open(&first).unwrap().image()).unwrap();
        let observed = file_identity(HeldExecutable::open(&second).unwrap().image()).unwrap();
        assert_eq!(compare_file_id(expected, Ok(expected)), Ok(expected));
        assert_eq!(
            compare_file_id(expected, Ok(observed)),
            Err(IdentityCheck::ImageMismatch)
        );
    }
}
