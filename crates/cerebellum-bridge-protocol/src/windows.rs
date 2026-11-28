//! Windows native-messaging image, peer and launch-chain predicates.
//!
//! Readings can block. The caller owns the deadline and retained process handles.

use std::fmt;

use cerebellum_windows::image_status::{
    CERT_E_REVOCATION_FAILURE, CERT_TRUST_IS_OFFLINE_REVOCATION,
    CERT_TRUST_REVOCATION_STATUS_UNKNOWN, CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE,
    ERROR_SERVICE_NOT_ACTIVE,
};
use cerebellum_windows::{
    measure_image_check, read_authenticode, read_catalog_signer, read_product_names,
    read_program_files_directory, read_system_directory, OpenedMachineDirectory,
    ProgramFilesDirectory, SignatureReading, SignerSubject,
};
pub use cerebellum_windows::{
    retain_process_handle_for_image, ImageReadError, OpenedProcessImage, ProcessHandleError,
    RetainedProcessHandle,
};
pub use ed25519_dalek::VerifyingKey;

mod identity;
pub use identity::{
    attest_parent, current_user_sid, observe_client_peer, observe_server_peer, ParentEvidence,
    PeerIdentity, PeerObservationError, VerifiedHost,
};

#[cfg(test)]
mod tests;

const CHROME_RELATIVE: &str = r"Google\Chrome\Application\chrome.exe";
const OFFLINE_BITS: u32 = CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION;

#[derive(Debug)]
pub enum ImageRefusal {
    Reading(ImageReadError),
    UnexpectedPath,
    CatalogServiceInactive,
    Trust { status: i32, chain_errors: u32 },
    MicrosoftRootPolicy(u32),
    SignerSubject,
    ProductName,
}

impl fmt::Display for ImageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CatalogServiceInactive => {
                f.write_str("Windows' Cryptographic Services is not running")
            }
            other => write!(f, "Windows image verification refused: {other:?}"),
        }
    }
}

impl std::error::Error for ImageRefusal {}

impl From<ImageReadError> for ImageRefusal {
    fn from(error: ImageReadError) -> Self {
        match error {
            ImageReadError::CatalogOpen(ERROR_SERVICE_NOT_ACTIVE)
            | ImageReadError::CatalogHash(ERROR_SERVICE_NOT_ACTIVE)
            | ImageReadError::CatalogNotFound(ERROR_SERVICE_NOT_ACTIVE)
            | ImageReadError::CatalogInfo(ERROR_SERVICE_NOT_ACTIVE) => Self::CatalogServiceInactive,
            other => Self::Reading(other),
        }
    }
}

/// Require the system-directory cmd.exe and its Microsoft-rooted SHA-256 catalog.
pub fn verify_system_cmd(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    measure_image_check("cmd path identity", || -> Result<(), ImageRefusal> {
        let root = read_system_directory()?;
        if !path_matches(image, &root, "cmd.exe") {
            return Err(ImageRefusal::UnexpectedPath);
        }
        Ok(())
    })?;
    verify_cmd_signer(image)
}

/// Require a machine-installed Chrome Stable image and its Google signature.
pub fn verify_installed_chrome(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    measure_image_check("Chrome path identity", || -> Result<(), ImageRefusal> {
        let native = read_program_files_directory(ProgramFilesDirectory::Native)?;
        // A native install does not depend on the x86 registry value being present.
        if !path_matches(image, &native, CHROME_RELATIVE) {
            let x86 = read_program_files_directory(ProgramFilesDirectory::X86)?;
            if !path_matches(image, &x86, CHROME_RELATIVE) {
                return Err(ImageRefusal::UnexpectedPath);
            }
        }
        Ok(())
    })?;
    verify_chrome_signer(image)
}

fn path_matches(image: &OpenedProcessImage, root: &OpenedMachineDirectory, relative: &str) -> bool {
    // Compare exact normalized names, including in case-sensitive directories.
    measure_image_check("normalized image path comparison", || {
        image.final_path().as_os_str() == root.final_path().join(relative).as_os_str()
    })
}

fn verify_cmd_signer(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    require_catalog(read_catalog_signer(image))
}

fn require_catalog(
    reading: Result<cerebellum_windows::MicrosoftRootReading, ImageReadError>,
) -> Result<(), ImageRefusal> {
    let reading = reading?;
    require_signature(reading.signature)?;
    let status = reading.policy_status?;
    if status != 0 {
        return Err(ImageRefusal::MicrosoftRootPolicy(status));
    }
    Ok(())
}

fn verify_chrome_signer(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    let reading = read_authenticode(image)?;
    require_signature(reading.signature)?;
    measure_image_check("Chrome signer identity", || {
        require_google_subject(&reading.subject?)
    })?;
    measure_image_check("Chrome product identity", || {
        require_product(read_product_names(image), "Google Chrome")
    })
}

fn require_google_subject(subject: &SignerSubject) -> Result<(), ImageRefusal> {
    if subject.organizations != ["Google LLC"] || subject.common_names != ["Google LLC"] {
        return Err(ImageRefusal::SignerSubject);
    }
    Ok(())
}

fn require_product(products: Option<Vec<String>>, expected: &str) -> Result<(), ImageRefusal> {
    if products.is_some_and(|names| !names.is_empty() && names.iter().all(|name| name == expected))
    {
        Ok(())
    } else {
        Err(ImageRefusal::ProductName)
    }
}

fn require_signature(reading: SignatureReading) -> Result<(), ImageRefusal> {
    measure_image_check("signature and chain status policy", || {
        if !trust_status_ok(reading.status, reading.chain_errors) {
            return Err(ImageRefusal::Trust {
                status: reading.status,
                chain_errors: reading.chain_errors,
            });
        }
        // Both cmd and Chrome require a readable root thumbprint, but neither pins its value.
        reading.root_thumbprint?;
        Ok(())
    })
}

fn trust_status_ok(status: i32, chain_errors: u32) -> bool {
    matches!(
        status,
        0 | CERT_E_REVOCATION_FAILURE | CRYPT_E_REVOCATION_OFFLINE | CRYPT_E_NO_REVOCATION_CHECK
    ) && chain_errors & !OFFLINE_BITS == 0
}
