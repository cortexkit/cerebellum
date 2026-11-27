use std::ffi::CStr;
use std::mem::size_of;
use std::os::windows::fs::FileExt;
use std::os::windows::io::AsRawHandle;
use std::ptr::{null, null_mut};

use windows_sys::core::{w, GUID};
use windows_sys::Win32::Foundation::{
    LocalFree, CERT_E_REVOCATION_FAILURE, CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE,
    ERROR_SERVICE_NOT_ACTIVE,
};
use windows_sys::Win32::Security::Cryptography::{
    szOID_COMMON_NAME, szOID_ORGANIZATION_NAME, Catalog::*, CertVerifyCertificateChainPolicy,
    CryptDecodeObjectEx, CERT_CHAIN_CONTEXT, CERT_CHAIN_POLICY_MICROSOFT_ROOT,
    CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT, CERT_NAME_INFO,
    CERT_RDN_ENCODED_BLOB, CERT_RDN_OCTET_STRING, CERT_TRUST_IS_OFFLINE_REVOCATION,
    CERT_TRUST_REVOCATION_STATUS_UNKNOWN, CRYPT_DECODE_ALLOC_FLAG, X509_ASN_ENCODING,
    X509_UNICODE_NAME,
};
use windows_sys::Win32::Security::WinTrust::*;

use super::{last_error, wide_z, ImageRefusal, OpenedProcessImage};

const OFFLINE_BITS: u32 = CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION;

fn trust_status_ok(status: i32, chain_errors: u32) -> bool {
    matches!(
        status,
        0 | CERT_E_REVOCATION_FAILURE | CRYPT_E_REVOCATION_OFFLINE | CRYPT_E_NO_REVOCATION_CHECK
    ) && chain_errors & !OFFLINE_BITS == 0
}

pub(super) fn verify_catalog(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    let admin = CatalogAdmin::open()?;
    let mut hash = [0; 32]; // SHA-256, selected by the admin context.
    let mut bytes = hash.len() as u32;
    let file = image.file.as_raw_handle();
    // SAFETY: the context and file handle remain live; the hash buffer is writable.
    let ok = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin.0, file, &mut bytes, hash.as_mut_ptr(), 0)
    };
    if ok == 0 {
        return Err(catalog_refusal(last_error(), ImageRefusal::CatalogHash));
    }
    if bytes != hash.len() as u32 {
        return Err(ImageRefusal::CatalogHash(0));
    }

    let catalog = admin.lookup(&hash)?;
    let mut info = CATALOG_INFO {
        cbStruct: size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };
    // SAFETY: catalog is retained and info is writable for its declared size.
    if unsafe { CryptCATCatalogInfoFromContext(catalog.context, &mut info, 0) } == 0 {
        return Err(catalog_refusal(last_error(), ImageRefusal::CatalogInfo));
    }
    if info.wszCatalogFile[0] == 0 || !info.wszCatalogFile.contains(&0) {
        return Err(ImageRefusal::CatalogInfo(0));
    }

    // A catalog member tag is the uppercase hexadecimal catalog hash.
    let member: Vec<u16> = hash
        .iter()
        .flat_map(|&byte| {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            [
                u16::from(HEX[(byte >> 4) as usize]),
                u16::from(HEX[(byte & 0xf) as usize]),
            ]
        })
        .chain([0])
        .collect();
    let path = wide_z(image.final_path.as_os_str());
    let mut catalog_info = WINTRUST_CATALOG_INFO {
        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
        pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
        pcwszMemberTag: member.as_ptr(),
        pcwszMemberFilePath: path.as_ptr(),
        hMemberFile: file,
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: bytes,
        hCatAdmin: admin.0,
        ..Default::default()
    };
    // SAFETY: the union points to catalog_info, and all referenced buffers and
    // handles remain live until both VERIFY and CLOSE return.
    unsafe {
        with_trust(
            WTD_CHOICE_CATALOG,
            WINTRUST_DATA_0 {
                pCatalog: &mut catalog_info,
            },
            |_, chain| microsoft_root(chain),
        )
    }
}

pub(super) fn verify_chrome(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    with_embedded_trust(image, |signer, _| {
        google_subject(signer_certificate(signer)?)
    })?;
    require_chrome_product(image)
}

fn with_embedded_trust(
    image: &OpenedProcessImage,
    check_signer: impl FnOnce(&CRYPT_PROVIDER_SGNR, &CERT_CHAIN_CONTEXT) -> Result<(), ImageRefusal>,
) -> Result<(), ImageRefusal> {
    let path = wide_z(image.final_path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: image.file.as_raw_handle(),
        ..Default::default()
    };
    // SAFETY: the union points to file_info, and the path and the same image
    // handle remain live until both VERIFY and CLOSE return.
    unsafe {
        with_trust(
            WTD_CHOICE_FILE,
            WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            check_signer,
        )
    }
}

fn require_chrome_product(image: &OpenedProcessImage) -> Result<(), ImageRefusal> {
    product_matches(image, "Google Chrome")
        .then_some(())
        .ok_or(ImageRefusal::ProductName)
}

fn product_matches(image: &OpenedProcessImage, expected: &str) -> bool {
    let read_at = |mut offset, mut buf: &mut [u8]| {
        while !buf.is_empty() {
            let n = image.file.seek_read(buf, offset)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            offset += n as u64;
            buf = &mut buf[n..];
        }
        Ok(())
    };
    crate::pe_product::matches(read_at, expected)
}

struct CatalogAdmin(isize);

impl CatalogAdmin {
    fn open() -> Result<Self, ImageRefusal> {
        let mut admin = 0;
        // SAFETY: the output handle is writable. The GUID and SHA-256 name
        // select the system component catalog database and hash algorithm.
        let ok = unsafe {
            CryptCATAdminAcquireContext2(&mut admin, &DRIVER_ACTION_VERIFY, w!("SHA256"), null(), 0)
        };
        if ok == 0 || admin == 0 {
            return Err(catalog_refusal(last_error(), ImageRefusal::CatalogOpen));
        }
        Ok(Self(admin))
    }

    fn lookup(&self, hash: &[u8; 32]) -> Result<CatalogMatch<'_>, ImageRefusal> {
        // SAFETY: the admin handle and hash remain live. Null starts lookup
        // at the first catalog; never fall back to a different hash or signer.
        let context = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                self.0,
                hash.as_ptr(),
                hash.len() as u32,
                0,
                null_mut(),
            )
        };
        if context == 0 {
            return Err(catalog_refusal(last_error(), ImageRefusal::CatalogNotFound));
        }
        Ok(CatalogMatch {
            admin: self,
            context,
        })
    }
}

fn catalog_refusal(code: u32, otherwise: fn(u32) -> ImageRefusal) -> ImageRefusal {
    if code == ERROR_SERVICE_NOT_ACTIVE {
        ImageRefusal::CatalogServiceInactive
    } else {
        otherwise(code)
    }
}

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        // SAFETY: this is the successful acquisition's only owner.
        unsafe { CryptCATAdminReleaseContext(self.0, 0) };
    }
}

struct CatalogMatch<'a> {
    admin: &'a CatalogAdmin,
    context: isize,
}

impl Drop for CatalogMatch<'_> {
    fn drop(&mut self) {
        // SAFETY: context belongs to the retained admin and is released once.
        unsafe { CryptCATAdminReleaseCatalogContext(self.admin.0, self.context, 0) };
    }
}

/// `subject` must carry the pointer for `choice`; all data reachable through
/// it must outlive both WinVerifyTrust calls, including the guard's unwind path.
unsafe fn with_trust(
    choice: u32,
    subject: WINTRUST_DATA_0,
    check_signer: impl FnOnce(&CRYPT_PROVIDER_SGNR, &CERT_CHAIN_CONTEXT) -> Result<(), ImageRefusal>,
) -> Result<(), ImageRefusal> {
    let mut session = TrustSession {
        action: WINTRUST_ACTION_GENERIC_VERIFY_V2,
        data: WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: choice,
            Anonymous: subject,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            ..Default::default()
        },
    };
    // SAFETY: session is writable, and subject's pointers satisfy the contract above.
    let status = unsafe { session.run() };
    let result = session.inspect(status, check_signer);
    let close = session.close();
    result.and(close)
}

struct TrustSession {
    action: GUID,
    data: WINTRUST_DATA,
}

impl TrustSession {
    unsafe fn run(&mut self) -> i32 {
        // SAFETY: the caller keeps the union member and its dependencies alive.
        unsafe {
            WinVerifyTrust(
                null_mut(),
                &mut self.action,
                (&mut self.data as *mut WINTRUST_DATA).cast(),
            )
        }
    }

    fn inspect(
        &self,
        status: i32,
        check_signer: impl FnOnce(&CRYPT_PROVIDER_SGNR, &CERT_CHAIN_CONTEXT) -> Result<(), ImageRefusal>,
    ) -> Result<(), ImageRefusal> {
        if self.data.hWVTStateData.is_null() {
            return Err(ImageRefusal::TrustStateMissing(status));
        }
        // SAFETY: the provider state from VERIFY remains live until CLOSE.
        let (signer, chain) = unsafe {
            let provider = WTHelperProvDataFromStateData(self.data.hWVTStateData);
            if provider.is_null() {
                return Err(ImageRefusal::TrustStateMissing(status));
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
                .as_ref()
                .ok_or(ImageRefusal::TrustStateMissing(status))?;
            let chain = signer
                .pChainContext
                .as_ref()
                .ok_or(ImageRefusal::TrustStateMissing(status))?;
            (signer, chain)
        };
        authorize(status, chain.TrustStatus.dwErrorStatus, || {
            check_signer(signer, chain)
        })
    }

    fn close(&mut self) -> Result<(), ImageRefusal> {
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: the guard lives within with_trust, which retains subject data.
        let status = unsafe { self.run() };
        self.data.dwStateAction = WTD_STATEACTION_IGNORE;
        if status == 0 {
            Ok(())
        } else {
            Err(ImageRefusal::TrustClose(status))
        }
    }
}

fn authorize(
    status: i32,
    chain_errors: u32,
    require_signer: impl FnOnce() -> Result<(), ImageRefusal>,
) -> Result<(), ImageRefusal> {
    if !trust_status_ok(status, chain_errors) {
        return Err(ImageRefusal::Trust {
            status,
            chain_errors,
        });
    }
    require_signer()
}

impl Drop for TrustSession {
    fn drop(&mut self) {
        if self.data.dwStateAction == WTD_STATEACTION_VERIFY {
            let _ = self.close();
        }
    }
}

fn microsoft_root(chain: &CERT_CHAIN_CONTEXT) -> Result<(), ImageRefusal> {
    let params = CERT_CHAIN_POLICY_PARA {
        cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        ..Default::default()
    };
    let mut status = CERT_CHAIN_POLICY_STATUS {
        cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        ..Default::default()
    };
    // SAFETY: the chain belongs to the live trust session, the policy selector
    // is the system constant, and the parameter and status structs are sized.
    let ok = unsafe {
        CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_MICROSOFT_ROOT,
            chain,
            &params,
            &mut status,
        )
    };
    if ok == 0 {
        Err(ImageRefusal::MicrosoftRootApi(last_error()))
    } else if status.dwError != 0 {
        Err(ImageRefusal::MicrosoftRootPolicy(status.dwError))
    } else {
        Ok(())
    }
}

fn signer_certificate(signer: &CRYPT_PROVIDER_SGNR) -> Result<&CERT_CONTEXT, ImageRefusal> {
    // SAFETY: the signer and its first certificate context are retained by
    // WinVerifyTrust state. The accessor's API takes a mutable pointer but
    // only reads the signer; the returned references do not outlive it.
    unsafe {
        let cert = WTHelperGetProvCertFromChain(std::ptr::from_ref(signer).cast_mut(), 0)
            .as_ref()
            .ok_or(ImageRefusal::SignerSubject)?;
        cert.pCert.as_ref().ok_or(ImageRefusal::SignerSubject)
    }
}

fn google_subject(cert: &CERT_CONTEXT) -> Result<(), ImageRefusal> {
    // Decode the Subject itself. Display-name helpers can fall back to the
    // Subject Alternative Name and do not detect duplicate attributes.
    // SAFETY: the certificate and its Subject BLOB belong to the live state.
    let subject = unsafe {
        &cert
            .pCertInfo
            .as_ref()
            .ok_or(ImageRefusal::SignerSubject)?
            .Subject
    };
    // SAFETY: the certificate's subject buffer is valid for the reported size.
    let encoded = unsafe {
        if subject.pbData.is_null() || subject.cbData == 0 {
            return Err(ImageRefusal::SignerSubject);
        }
        std::slice::from_raw_parts(subject.pbData, subject.cbData as usize)
    };
    google_distinguished_name(encoded)
}

fn google_distinguished_name(encoded: &[u8]) -> Result<(), ImageRefusal> {
    let mut decoded: *mut CERT_NAME_INFO = null_mut();
    let mut size = 0;
    // SAFETY: subject is a live encoded name; ALLOC writes a pointer to decoded.
    let ok = unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_UNICODE_NAME,
            encoded.as_ptr(),
            u32::try_from(encoded.len()).map_err(|_| ImageRefusal::SignerSubject)?,
            CRYPT_DECODE_ALLOC_FLAG,
            null(),
            (&mut decoded as *mut *mut CERT_NAME_INFO).cast(),
            &mut size,
        )
    };
    if ok == 0 || decoded.is_null() {
        return Err(ImageRefusal::SignerSubject);
    }
    let name = DecodedName(decoded);
    name.require_google()
}

struct DecodedName(*mut CERT_NAME_INFO);

impl DecodedName {
    fn require_google(&self) -> Result<(), ImageRefusal> {
        // SAFETY: Crypt32 allocated and decoded the CERT_NAME_INFO and each
        // nested array and string; all remain live while self owns the block.
        unsafe {
            let name = &*self.0;
            let mut seen_org = false;
            let mut seen_cn = false;
            for i in 0..name.cRDN as usize {
                let rdn = &*name.rgRDN.add(i);
                for j in 0..rdn.cRDNAttr as usize {
                    let attr = &*rdn.rgRDNAttr.add(j);
                    let oid = CStr::from_ptr(attr.pszObjId.cast());
                    let seen = if oid == CStr::from_ptr(szOID_ORGANIZATION_NAME.cast()) {
                        &mut seen_org
                    } else if oid == CStr::from_ptr(szOID_COMMON_NAME.cast()) {
                        &mut seen_cn
                    } else {
                        continue;
                    };
                    // X509_UNICODE_NAME returns UTF-16 values whose byte counts
                    // exclude the trailing zero; require the entire exact value.
                    const GOOGLE: &str = "Google LLC";
                    let expected = GOOGLE.encode_utf16().flat_map(u16::to_le_bytes);
                    let value = &attr.Value;
                    if *seen
                        || matches!(
                            attr.dwValueType as i32,
                            CERT_RDN_ENCODED_BLOB | CERT_RDN_OCTET_STRING
                        )
                        || value.cbData as usize != 2 * GOOGLE.len()
                        || value.pbData.is_null()
                        || !std::slice::from_raw_parts(value.pbData, value.cbData as usize)
                            .iter()
                            .copied()
                            .eq(expected)
                    {
                        return Err(ImageRefusal::SignerSubject);
                    }
                    *seen = true;
                }
            }
            if seen_org && seen_cn {
                Ok(())
            } else {
                Err(ImageRefusal::SignerSubject)
            }
        }
    }
}

impl Drop for DecodedName {
    fn drop(&mut self) {
        // SAFETY: default CRYPT_DECODE_ALLOC_FLAG allocation uses LocalAlloc.
        unsafe { LocalFree(self.0.cast()) };
    }
}

#[cfg(test)]
mod tests;
