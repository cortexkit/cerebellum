use super::*;
use cerebellum_windows::image_status::{
    CERT_E_UNTRUSTEDROOT, CERT_TRUST_IS_NOT_SIGNATURE_VALID, CERT_TRUST_IS_NOT_TIME_VALID,
    CERT_TRUST_IS_REVOKED, CERT_TRUST_IS_UNTRUSTED_ROOT, TRUST_E_BAD_DIGEST,
};
use cerebellum_windows::{read_embedded_root_status, MicrosoftRootReading};

#[test]
fn inactive_catalog_service_has_an_actionable_refusal() {
    let error = ImageRefusal::from(ImageReadError::CatalogNotFound(ERROR_SERVICE_NOT_ACTIVE));
    assert!(matches!(error, ImageRefusal::CatalogServiceInactive));
    assert_eq!(
        error.to_string(),
        "Windows' Cryptographic Services is not running"
    );
}

#[test]
fn trust_classifier_tolerates_only_cached_revocation_errors() {
    for status in [
        0,
        CERT_E_REVOCATION_FAILURE,
        CRYPT_E_REVOCATION_OFFLINE,
        CRYPT_E_NO_REVOCATION_CHECK,
    ] {
        assert!(trust_status_ok(status, OFFLINE_BITS));
    }
    assert!(trust_status_ok(0, 0));
    assert!(!trust_status_ok(0, CERT_TRUST_IS_REVOKED));
    assert!(!trust_status_ok(
        0,
        CERT_TRUST_IS_REVOKED | CERT_TRUST_REVOCATION_STATUS_UNKNOWN
    ));
    for fatal in [
        CERT_TRUST_IS_UNTRUSTED_ROOT,
        CERT_TRUST_IS_NOT_TIME_VALID,
        CERT_TRUST_IS_NOT_SIGNATURE_VALID,
    ] {
        assert!(!trust_status_ok(
            CRYPT_E_REVOCATION_OFFLINE,
            OFFLINE_BITS | fatal
        ));
    }
    assert!(!trust_status_ok(TRUST_E_BAD_DIGEST, 0));
}

#[test]
fn offline_chain_still_requires_catalog_and_microsoft_root() {
    assert!(matches!(
        require_catalog(Err(ImageReadError::CatalogNotFound(0))),
        Err(ImageRefusal::Reading(ImageReadError::CatalogNotFound(_)))
    ));
    assert!(matches!(
        require_catalog(Ok(MicrosoftRootReading {
            signature: SignatureReading {
                status: CRYPT_E_REVOCATION_OFFLINE,
                chain_errors: OFFLINE_BITS,
                root_thumbprint: Ok([1; 20]),
            },
            policy_status: Ok(CERT_E_UNTRUSTEDROOT as u32),
        })),
        Err(ImageRefusal::MicrosoftRootPolicy(_))
    ));
}

#[test]
fn chrome_identity_requires_exact_subject_attributes_and_product() {
    let mut subject = SignerSubject {
        organizations: vec!["Google LLC".into()],
        common_names: vec!["Google LLC".into()],
    };
    require_google_subject(&subject).unwrap();
    subject.common_names[0] = "google LLC".into();
    assert!(matches!(
        require_google_subject(&subject),
        Err(ImageRefusal::SignerSubject)
    ));
    subject.common_names.clear();
    assert!(matches!(
        require_google_subject(&subject),
        Err(ImageRefusal::SignerSubject)
    ));
    subject.common_names = vec!["Google LLC".into(), "Google LLC".into()];
    assert!(matches!(
        require_google_subject(&subject),
        Err(ImageRefusal::SignerSubject)
    ));

    let expected = "Google Chrome";
    require_product(Some(vec![expected.into()]), expected).unwrap();
    for product in [
        "Google Chrome Beta",
        "google chrome",
        "Google Chrome\0extra",
        "",
    ] {
        assert!(matches!(
            require_product(Some(vec![expected.into(), product.into()]), expected),
            Err(ImageRefusal::ProductName)
        ));
    }
}

#[test]
#[ignore = "requires the disposable GitHub-hosted Windows signer fixtures"]
fn native_fixture_chain() {
    let path = std::path::PathBuf::from(std::env::var_os("CK_TEST_SIGNED_PE").unwrap());
    let image = OpenedProcessImage::open_path(&path).unwrap();
    require_product(read_product_names(&image), "Google Chrome")
        .expect("fixture has the exact signed ProductName");
    let trusted = std::env::var("CK_TEST_SIGNED_PE_TRUSTED").unwrap() == "1";
    if trusted {
        verify_chrome_signer(&image).expect("installed fixture root is a positive trust control");
        assert!(matches!(
            require_catalog(read_embedded_root_status(&image)),
            Err(ImageRefusal::MicrosoftRootPolicy(code)) if code == CERT_E_UNTRUSTEDROOT as u32
        ));
        assert!(matches!(
            verify_cmd_signer(&image),
            Err(ImageRefusal::Reading(ImageReadError::CatalogNotFound(_)))
        ));
    } else {
        // Inspect the refusing chain too, so an unsigned, wrong-name or
        // absent fixture cannot pass the untrusted-root negative.
        assert!(matches!(
            verify_chrome_signer(&image),
            Err(ImageRefusal::Trust { chain_errors, .. }) if chain_errors & CERT_TRUST_IS_UNTRUSTED_ROOT != 0
        ));
        let subject = read_authenticode(&image).unwrap().subject.unwrap();
        require_google_subject(&subject).expect("fixture subject exactly matches O and CN");
    }
}

#[test]
#[ignore = "requires an installed Google-signed non-Chrome product on the Windows runner"]
fn native_google_signer_does_not_override_product_name() {
    let candidates = std::env::var_os("CK_TEST_GOOGLE_PRODUCTS").unwrap();
    let products = std::env::var("CK_TEST_GOOGLE_PRODUCT_NAMES").unwrap();
    let candidates: Vec<_> = std::env::split_paths(&candidates).collect();
    assert_eq!(candidates.len(), products.lines().count());
    let mut seen = Vec::new();
    for (path, product) in candidates.into_iter().zip(products.lines()) {
        let candidate = match OpenedProcessImage::open_path(&path) {
            Ok(candidate) => candidate,
            Err(error) => {
                seen.push((path, error.into()));
                continue;
            }
        };
        match verify_chrome_signer(&candidate) {
            Err(ImageRefusal::ProductName)
                if require_product(read_product_names(&candidate), product).is_ok() =>
            {
                return
            }
            Err(error) => seen.push((path, error)),
            Ok(()) => panic!("alternate product matches Chrome: {path:?}"),
        }
    }
    panic!("no alternate product had a trusted Google LLC O and CN: {seen:?}");
}

#[test]
#[ignore = "requires a Windows runner where the catalog service is already inactive"]
fn native_cmd_refuses_inactive_catalog_service() {
    let cmd_path = read_system_directory()
        .unwrap()
        .final_path()
        .join("cmd.exe");
    let cmd = OpenedProcessImage::open_path(&cmd_path).unwrap();
    let error = verify_system_cmd(&cmd).unwrap_err();
    assert!(matches!(error, ImageRefusal::CatalogServiceInactive));
    assert_eq!(
        error.to_string(),
        "Windows' Cryptographic Services is not running"
    );
}

#[test]
#[ignore = "requires the real Chrome Stable installation on the GitHub-hosted Windows runner"]
fn native_system_and_chrome_signers_are_isolated() {
    let cmd_path = read_system_directory()
        .unwrap()
        .final_path()
        .join("cmd.exe");
    let cmd = OpenedProcessImage::open_path(&cmd_path).unwrap();
    verify_system_cmd(&cmd).expect("System32 cmd.exe has a Microsoft-rooted catalog signature");

    let chrome_path = [ProgramFilesDirectory::Native, ProgramFilesDirectory::X86]
        .into_iter()
        .filter_map(|which| read_program_files_directory(which).ok())
        .map(|root| root.final_path().join(CHROME_RELATIVE))
        .find(|candidate| candidate.is_file())
        .expect("Chrome Stable is installed in Program Files");
    let chrome = OpenedProcessImage::open_path(&chrome_path).unwrap();
    verify_installed_chrome(&chrome).expect("installed Chrome Stable satisfies its predicate");

    assert!(matches!(
        verify_system_cmd(&chrome),
        Err(ImageRefusal::UnexpectedPath)
    ));
    assert!(matches!(
        verify_installed_chrome(&cmd),
        Err(ImageRefusal::UnexpectedPath)
    ));
    // Bypass only the path gate. Both must still refuse the other's signer.
    assert!(matches!(
        verify_cmd_signer(&chrome),
        Err(ImageRefusal::Reading(ImageReadError::CatalogNotFound(_)))
    ));
    assert!(matches!(
        verify_chrome_signer(&cmd),
        Err(ImageRefusal::Reading(ImageReadError::TrustStateMissing(_))
            | ImageRefusal::Trust { .. }
            | ImageRefusal::SignerSubject)
    ));
}
