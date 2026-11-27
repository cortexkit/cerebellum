use super::*;
use windows_sys::Win32::Foundation::{CERT_E_UNTRUSTEDROOT, TRUST_E_BAD_DIGEST};
use windows_sys::Win32::Security::Cryptography::{
    CERT_TRUST_IS_NOT_SIGNATURE_VALID, CERT_TRUST_IS_NOT_TIME_VALID, CERT_TRUST_IS_REVOKED,
    CERT_TRUST_IS_UNTRUSTED_ROOT,
};

#[test]
fn inactive_catalog_service_has_an_actionable_refusal() {
    let error = catalog_refusal(ERROR_SERVICE_NOT_ACTIVE, ImageRefusal::CatalogNotFound);
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
        authorize(CRYPT_E_REVOCATION_OFFLINE, OFFLINE_BITS, || Err(
            ImageRefusal::CatalogNotFound(0)
        )),
        Err(ImageRefusal::CatalogNotFound(_))
    ));
    assert!(matches!(
        authorize(CRYPT_E_REVOCATION_OFFLINE, OFFLINE_BITS, || Err(
            ImageRefusal::MicrosoftRootPolicy(CERT_E_UNTRUSTEDROOT as u32)
        )),
        Err(ImageRefusal::MicrosoftRootPolicy(_))
    ));
}

#[test]
fn crypt32_requires_both_exact_subject_attributes() {
    // X.509 Name with the common name in UTF8String and organization in PrintableString.
    let matching = b"\x30\x2a\x31\x13\x30\x11\x06\x03\x55\x04\x03\x0c\x0aGoogle LLC\x31\x13\x30\x11\x06\x03\x55\x04\x0a\x13\x0aGoogle LLC";
    google_distinguished_name(matching).unwrap();
    let mut mismatching = *matching;
    mismatching[13] = b'g';
    assert!(matches!(
        google_distinguished_name(&mismatching),
        Err(ImageRefusal::SignerSubject)
    ));
    let mut missing = *matching;
    missing[31] = 0x0b; // Change organization to organizational unit, keeping the value.
    assert!(matches!(
        google_distinguished_name(&missing),
        Err(ImageRefusal::SignerSubject)
    ));
    assert!(matches!(
        google_distinguished_name(&matching[1..]),
        Err(ImageRefusal::SignerSubject)
    ));
}

#[test]
#[ignore = "requires the disposable GitHub-hosted Windows signer fixtures"]
fn native_fixture_chain() {
    let path = std::path::PathBuf::from(std::env::var_os("CK_TEST_SIGNED_PE").unwrap());
    let image = OpenedProcessImage::open_path(&path).unwrap();
    require_chrome_product(&image).expect("fixture has the exact signed ProductName");
    let trusted = std::env::var("CK_TEST_SIGNED_PE_TRUSTED").unwrap() == "1";
    if trusted {
        verify_chrome(&image).expect("installed fixture root is a positive trust control");
        assert!(matches!(
            with_embedded_trust(&image, |_, chain| microsoft_root(chain)),
            Err(ImageRefusal::MicrosoftRootPolicy(code)) if code == CERT_E_UNTRUSTEDROOT as u32
        ));
        assert!(matches!(
            verify_catalog(&image),
            Err(ImageRefusal::CatalogNotFound(_))
        ));
    } else {
        // Inspect the refusing chain too, so an unsigned, wrong-name or
        // absent fixture cannot pass the untrusted-root negative.
        assert!(matches!(
            verify_chrome(&image),
            Err(ImageRefusal::Trust { chain_errors, .. }) if chain_errors & CERT_TRUST_IS_UNTRUSTED_ROOT != 0
        ));
        inspect_fixture_subject(&image);
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
                seen.push((path, error));
                continue;
            }
        };
        match verify_chrome(&candidate) {
            Err(ImageRefusal::ProductName) if product_matches(&candidate, product) => return,
            Err(error) => seen.push((path, error)),
            Ok(()) => panic!("alternate product matches Chrome: {path:?}"),
        }
    }
    panic!("no alternate product had a trusted Google LLC O and CN: {seen:?}");
}

fn inspect_fixture_subject(image: &OpenedProcessImage) {
    let path = wide_z(image.final_path.as_os_str());
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: image.file.as_raw_handle(),
        ..Default::default()
    };
    let mut session = TrustSession {
        action: WINTRUST_ACTION_GENERIC_VERIFY_V2,
        data: WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        },
    };
    // SAFETY: info, path and file outlive both trust calls, including on panic.
    unsafe {
        session.run();
        let provider = WTHelperProvDataFromStateData(session.data.hWVTStateData);
        assert!(!provider.is_null(), "fixture trust state is missing");
        let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
            .as_ref()
            .unwrap();
        google_subject(signer_certificate(signer).unwrap())
            .expect("fixture subject exactly matches O and CN");
    }
    session.close().unwrap();
}
