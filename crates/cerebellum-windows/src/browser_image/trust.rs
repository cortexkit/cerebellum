use std::ffi::CStr;
use std::mem::size_of;
use std::os::windows::fs::FileExt;
use std::os::windows::io::AsRawHandle;
use std::ptr::{null, null_mut};

use windows_sys::core::{w, GUID};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    szOID_COMMON_NAME, szOID_ORGANIZATION_NAME, Catalog::*, CertGetCertificateContextProperty,
    CertVerifyCertificateChainPolicy, CryptDecodeObjectEx, CERT_CHAIN_CONTEXT,
    CERT_CHAIN_POLICY_MICROSOFT_ROOT, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
    CERT_CONTEXT, CERT_NAME_INFO, CERT_RDN_ENCODED_BLOB, CERT_RDN_OCTET_STRING,
    CERT_SHA1_HASH_PROP_ID, CRYPT_DECODE_ALLOC_FLAG, X509_ASN_ENCODING, X509_UNICODE_NAME,
};
use windows_sys::Win32::Security::WinTrust::*;

use super::timing::measure_image_check;
use super::{last_error, wide_z, ImageReadError, OpenedProcessImage};

#[derive(Debug)]
pub struct SignatureReading {
    pub status: i32,
    pub chain_errors: u32,
    pub root_thumbprint: Result<[u8; 20], ImageReadError>,
}

#[derive(Debug)]
pub struct AuthenticodeReading {
    pub signature: SignatureReading,
    pub subject: Result<SignerSubject, ImageReadError>,
}

#[derive(Debug)]
pub struct MicrosoftRootReading {
    pub signature: SignatureReading,
    pub policy_status: Result<u32, ImageReadError>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SignerSubject {
    pub organizations: Vec<String>,
    pub common_names: Vec<String>,
}

/// Read the first SHA-256 system catalog entry for this handle and its signer.
pub fn read_catalog_signer(
    image: &OpenedProcessImage,
) -> Result<MicrosoftRootReading, ImageReadError> {
    let admin = measure_image_check("cmd catalog acquire", CatalogAdmin::open)?;
    let mut hash = [0; 32]; // SHA-256, selected by the admin context.
    let mut bytes = hash.len() as u32;
    let file = image.file.as_raw_handle();
    measure_image_check("cmd catalog signature hash", || {
        // SAFETY: the context and file handle remain live; the hash buffer is writable.
        let ok = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin.0, file, &mut bytes, hash.as_mut_ptr(), 0)
        };
        if ok == 0 {
            return Err(ImageReadError::CatalogHash(last_error()));
        }
        if bytes != hash.len() as u32 {
            return Err(ImageReadError::CatalogHash(0));
        }
        Ok(())
    })?;

    let catalog = measure_image_check("cmd catalog lookup", || admin.lookup(&hash))?;
    let mut info = CATALOG_INFO {
        cbStruct: size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };
    measure_image_check("cmd catalog info", || {
        // SAFETY: catalog is retained and info is writable for its declared size.
        if unsafe { CryptCATCatalogInfoFromContext(catalog.context, &mut info, 0) } == 0 {
            return Err(ImageReadError::CatalogInfo(last_error()));
        }
        if info.wszCatalogFile[0] == 0 || !info.wszCatalogFile.contains(&0) {
            return Err(ImageReadError::CatalogInfo(0));
        }
        Ok(())
    })?;

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
        read_from_provider(
            WTD_CHOICE_CATALOG,
            WINTRUST_DATA_0 {
                pCatalog: &mut catalog_info,
            },
            |signature, _, chain| MicrosoftRootReading {
                signature,
                policy_status: measure_image_check("cmd Microsoft root chain policy", || {
                    microsoft_root_status(chain)
                }),
            },
        )
    }
}

/// Read the embedded Authenticode signer, with no catalog fallback.
pub fn read_authenticode(
    image: &OpenedProcessImage,
) -> Result<AuthenticodeReading, ImageReadError> {
    read_embedded(image, |signature, signer, _| AuthenticodeReading {
        signature,
        subject: signer_certificate(signer, 0).and_then(read_subject),
    })
}

/// Read the Microsoft-root policy result for the embedded signer's chain.
pub fn read_embedded_root_status(
    image: &OpenedProcessImage,
) -> Result<MicrosoftRootReading, ImageReadError> {
    read_embedded(image, |signature, _, chain| MicrosoftRootReading {
        signature,
        policy_status: microsoft_root_status(chain),
    })
}

fn read_embedded<T>(
    image: &OpenedProcessImage,
    read_signer: impl FnOnce(SignatureReading, &CRYPT_PROVIDER_SGNR, &CERT_CHAIN_CONTEXT) -> T,
) -> Result<T, ImageReadError> {
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
        read_from_provider(
            WTD_CHOICE_FILE,
            WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            read_signer,
        )
    }
}

/// Read the PE's embedded ProductName values from the open file.
pub fn read_product_names(image: &OpenedProcessImage) -> Option<Vec<String>> {
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
    crate::pe_product::read_product_names(read_at)
}

struct CatalogAdmin(isize);

impl CatalogAdmin {
    fn open() -> Result<Self, ImageReadError> {
        let mut admin = 0;
        // SAFETY: the output handle is writable. The GUID and SHA-256 name
        // select the system component catalog database and hash algorithm.
        let ok = unsafe {
            CryptCATAdminAcquireContext2(&mut admin, &DRIVER_ACTION_VERIFY, w!("SHA256"), null(), 0)
        };
        if ok == 0 || admin == 0 {
            return Err(ImageReadError::CatalogOpen(last_error()));
        }
        Ok(Self(admin))
    }

    fn lookup(&self, hash: &[u8; 32]) -> Result<CatalogMatch<'_>, ImageReadError> {
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
            return Err(ImageReadError::CatalogNotFound(last_error()));
        }
        Ok(CatalogMatch {
            admin: self,
            context,
        })
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
unsafe fn read_from_provider<T>(
    choice: u32,
    subject: WINTRUST_DATA_0,
    read_signer: impl FnOnce(SignatureReading, &CRYPT_PROVIDER_SGNR, &CERT_CHAIN_CONTEXT) -> T,
) -> Result<T, ImageReadError> {
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
    // WinVerifyTrust verifies the signature and builds/checks the chain in one call.
    let status = measure_image_check(
        "WinVerifyTrust signature + chain/revocation (cache-only)",
        || {
            // SAFETY: session is writable, and subject's pointers satisfy the contract above.
            unsafe { session.run() }
        },
    );
    let result = measure_image_check("WinVerifyTrust chain and signer readout", || {
        session.read(status, read_signer)
    });
    let close = measure_image_check("WinVerifyTrust close", || session.close());
    let reading = result?;
    close?;
    Ok(reading)
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

    fn read<T>(
        &self,
        status: i32,
        read_signer: impl FnOnce(SignatureReading, &CRYPT_PROVIDER_SGNR, &CERT_CHAIN_CONTEXT) -> T,
    ) -> Result<T, ImageReadError> {
        if self.data.hWVTStateData.is_null() {
            return Err(ImageReadError::TrustStateMissing(status));
        }
        // SAFETY: the provider state from VERIFY remains live until CLOSE.
        let (signer, chain) = unsafe {
            let provider = WTHelperProvDataFromStateData(self.data.hWVTStateData);
            if provider.is_null() {
                return Err(ImageReadError::TrustStateMissing(status));
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
                .as_ref()
                .ok_or(ImageReadError::TrustStateMissing(status))?;
            let chain = signer
                .pChainContext
                .as_ref()
                .ok_or(ImageReadError::TrustStateMissing(status))?;
            (signer, chain)
        };
        let signature = SignatureReading {
            status,
            chain_errors: chain.TrustStatus.dwErrorStatus,
            root_thumbprint: root_thumbprint(signer),
        };
        #[cfg(feature = "bridge-test-identities")]
        super::timing::record_trust_status(signature.status, signature.chain_errors);
        Ok(read_signer(signature, signer, chain))
    }

    fn close(&mut self) -> Result<(), ImageReadError> {
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: the provider's input buffers and handles remain live here.
        let status = unsafe { self.run() };
        self.data.dwStateAction = WTD_STATEACTION_IGNORE;
        if status == 0 {
            Ok(())
        } else {
            Err(ImageReadError::TrustClose(status))
        }
    }
}

impl Drop for TrustSession {
    fn drop(&mut self) {
        if self.data.dwStateAction == WTD_STATEACTION_VERIFY {
            let _ = self.close();
        }
    }
}

fn microsoft_root_status(chain: &CERT_CHAIN_CONTEXT) -> Result<u32, ImageReadError> {
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
        Err(ImageReadError::MicrosoftRootApi(last_error()))
    } else {
        Ok(status.dwError)
    }
}

fn signer_certificate(
    signer: &CRYPT_PROVIDER_SGNR,
    index: u32,
) -> Result<&CERT_CONTEXT, ImageReadError> {
    // SAFETY: the signer and its certificate context are retained by
    // WinVerifyTrust state. The accessor's API takes a mutable pointer but
    // only reads the signer; the returned references do not outlive it.
    unsafe {
        let cert = WTHelperGetProvCertFromChain(std::ptr::from_ref(signer).cast_mut(), index)
            .as_ref()
            .ok_or(ImageReadError::MissingCertificate)?;
        cert.pCert
            .as_ref()
            .ok_or(ImageReadError::MissingCertificate)
    }
}

fn root_thumbprint(signer: &CRYPT_PROVIDER_SGNR) -> Result<[u8; 20], ImageReadError> {
    let last = signer
        .csCertChain
        .checked_sub(1)
        .ok_or(ImageReadError::MissingCertificate)?;
    let root = signer_certificate(signer, last)?;
    let mut thumbprint = [0u8; 20];
    let mut bytes = thumbprint.len() as u32;
    // SAFETY: the certificate is retained; the output buffer holds the SHA-1 thumbprint.
    let ok = unsafe {
        CertGetCertificateContextProperty(
            root,
            CERT_SHA1_HASH_PROP_ID,
            thumbprint.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if ok == 0 {
        return Err(ImageReadError::CertificateProperty(last_error()));
    }
    if bytes != thumbprint.len() as u32 {
        return Err(ImageReadError::CertificateProperty(0));
    }
    Ok(thumbprint)
}

fn read_subject(cert: &CERT_CONTEXT) -> Result<SignerSubject, ImageReadError> {
    // Decode the Subject itself. Display-name helpers can fall back to the
    // Subject Alternative Name and do not detect duplicate attributes.
    // SAFETY: the certificate and its Subject BLOB belong to the live state.
    let subject = unsafe {
        &cert
            .pCertInfo
            .as_ref()
            .ok_or(ImageReadError::MissingCertificate)?
            .Subject
    };
    // SAFETY: the certificate's subject buffer is valid for the reported size.
    let encoded = unsafe {
        if subject.pbData.is_null() || subject.cbData == 0 {
            return Err(ImageReadError::SubjectEncoding);
        }
        std::slice::from_raw_parts(subject.pbData, subject.cbData as usize)
    };
    read_distinguished_name(encoded)
}

fn read_distinguished_name(encoded: &[u8]) -> Result<SignerSubject, ImageReadError> {
    let mut decoded: *mut CERT_NAME_INFO = null_mut();
    let mut size = 0;
    // SAFETY: subject is a live encoded name; ALLOC writes a pointer to decoded.
    let ok = unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_UNICODE_NAME,
            encoded.as_ptr(),
            u32::try_from(encoded.len()).map_err(|_| ImageReadError::SubjectEncoding)?,
            CRYPT_DECODE_ALLOC_FLAG,
            null(),
            (&mut decoded as *mut *mut CERT_NAME_INFO).cast(),
            &mut size,
        )
    };
    if ok == 0 || decoded.is_null() {
        return Err(ImageReadError::SubjectDecode(last_error()));
    }
    let name = DecodedName(decoded);
    name.read_fields()
}

struct DecodedName(*mut CERT_NAME_INFO);

impl DecodedName {
    fn read_fields(&self) -> Result<SignerSubject, ImageReadError> {
        // SAFETY: Crypt32 allocated and decoded the CERT_NAME_INFO and each
        // nested array and string; all remain live while self owns the block.
        unsafe {
            let name = &*self.0;
            let mut subject = SignerSubject::default();
            for i in 0..name.cRDN as usize {
                let rdn = &*name.rgRDN.add(i);
                for j in 0..rdn.cRDNAttr as usize {
                    let attr = &*rdn.rgRDNAttr.add(j);
                    let oid = CStr::from_ptr(attr.pszObjId.cast());
                    let fields = if oid == CStr::from_ptr(szOID_ORGANIZATION_NAME.cast()) {
                        &mut subject.organizations
                    } else if oid == CStr::from_ptr(szOID_COMMON_NAME.cast()) {
                        &mut subject.common_names
                    } else {
                        continue;
                    };
                    // X509_UNICODE_NAME returns UTF-16 values whose byte counts
                    // exclude the trailing zero. Preserve all values, including duplicates.
                    let value = &attr.Value;
                    if matches!(
                        attr.dwValueType as i32,
                        CERT_RDN_ENCODED_BLOB | CERT_RDN_OCTET_STRING
                    ) || !value.cbData.is_multiple_of(2)
                        || (value.cbData != 0 && value.pbData.is_null())
                    {
                        return Err(ImageReadError::SubjectEncoding);
                    }
                    let bytes = if value.cbData == 0 {
                        &[]
                    } else {
                        std::slice::from_raw_parts(value.pbData, value.cbData as usize)
                    };
                    let units: Vec<u16> = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .copied()
                        .map(u16::from_le_bytes)
                        .collect();
                    fields.push(
                        String::from_utf16(&units).map_err(|_| ImageReadError::SubjectEncoding)?,
                    );
                }
            }
            Ok(subject)
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
