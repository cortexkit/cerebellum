//! Select and attest the Windows Chrome image before taking a launch profile.

use cerebellum_windows::identity::{
    SignatureStatus, CERT_E_REVOKED, CERT_TRUST_IS_OFFLINE_REVOCATION, CERT_TRUST_IS_REVOKED,
    CERT_TRUST_REVOCATION_STATUS_UNKNOWN, CRYPT_E_REVOCATION_OFFLINE, CRYPT_E_REVOKED,
    TRUST_E_BAD_DIGEST,
};

pub const CHROME_PUBLISHER: &str = "Google LLC";
const CHROME_ROOTS: &[[u8; 32]] = &[];

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
    use cerebellum_windows::identity::HeldExecutable;
    use std::path::Path;

    #[test]
    fn windows_chrome_signature_is_checked_against_root_table() {
        let Some(path) = std::env::var_os("CK_WINDOWS_BROWSER_CHROME") else {
            return;
        };
        let held = HeldExecutable::open(Path::new(&path)).expect("open installed Chrome");
        let reading = held.read_signature_status();
        assert_eq!(
            check_signature(reading, CHROME_PUBLISHER),
            Err(IdentityCheck::Root)
        );
    }
}
