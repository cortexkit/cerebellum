use crate::LockedImageFile;
use std::io;
use std::mem::size_of;
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError, ERROR_NOT_FOUND, TRUST_E_NOSIGNATURE},
    Security::{
        Cryptography::{
            Catalog::{
                CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
                CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
                CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
            },
            CertGetNameStringW, CERT_CONTEXT, CERT_NAME_ATTR_TYPE,
        },
        WinTrust::*,
    },
};

#[derive(Debug)]
pub struct SignerFields {
    pub common_name: String,
    pub organization: String,
    pub root_der: Vec<u8>,
}

#[derive(Debug)]
pub enum AuthenticodeFacts {
    Signer(SignerFields),
    EmbeddedAndCatalogAbsent,
    Status(i32),
    SignerUnavailable,
}

impl LockedImageFile {
    /// The Windows Authenticode provider's status and signer fields for this
    /// handle. The provider is noninteractive, with cache-only revocation.
    pub fn authenticode_facts(&self, path: &Path) -> io::Result<AuthenticodeFacts> {
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        if path[..path.len() - 1].contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut embedded = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: self.file().as_raw_handle(),
            pgKnownSubject: null_mut(),
        };
        let state = ProviderState::new(
            WTD_CHOICE_FILE,
            WINTRUST_DATA_0 {
                pFile: &mut embedded,
            },
        );
        match state.reading() {
            AuthenticodeFacts::Status(TRUST_E_NOSIGNATURE) => {}
            reading => return Ok(reading),
        }
        for algorithm in ["SHA256", "SHA1"] {
            let admin = CatalogAdmin::open(algorithm)?;
            if let Some(reading) = admin.member(self, &path)? {
                return Ok(reading);
            }
        }
        Ok(AuthenticodeFacts::EmbeddedAndCatalogAbsent)
    }
}

struct ProviderState(WINTRUST_DATA);

impl ProviderState {
    fn new(choice: u32, target: WINTRUST_DATA_0) -> Self {
        Self(WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: choice,
            Anonymous: target,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            ..Default::default()
        })
    }

    fn reading(mut self) -> AuthenticodeFacts {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // The union and choice correspond, and caller-owned data (including
        // the retained file and strings) remains live until this state closes.
        let status = unsafe {
            WinVerifyTrust(
                null_mut(),
                &mut action,
                (&mut self.0 as *mut WINTRUST_DATA).cast(),
            )
        };
        if status != 0 {
            return AuthenticodeFacts::Status(status);
        }
        read_signer(&self.0).map_or(
            AuthenticodeFacts::SignerUnavailable,
            AuthenticodeFacts::Signer,
        )
    }
}

impl Drop for ProviderState {
    fn drop(&mut self) {
        if !self.0.hWVTStateData.is_null() {
            self.0.dwStateAction = WTD_STATEACTION_CLOSE;
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            // Close the state from the same action, still borrowing its input.
            unsafe {
                WinVerifyTrust(
                    null_mut(),
                    &mut action,
                    (&mut self.0 as *mut WINTRUST_DATA).cast(),
                )
            };
        }
    }
}

fn read_signer(state: &WINTRUST_DATA) -> Option<SignerFields> {
    // These objects are owned by WinTrust, and all data is copied before the
    // provider state closes. Index zero is the actual signer, not a timestamp.
    unsafe {
        let data = WTHelperProvDataFromStateData(state.hWVTStateData);
        if data.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(data, 0, 0, 0);
        let leaf = WTHelperGetProvCertFromChain(signer, 0)
            .as_ref()?
            .pCert
            .as_ref()?;
        let last = signer.as_ref()?.csCertChain.checked_sub(1)?;
        let root = WTHelperGetProvCertFromChain(signer, last).as_ref()?;
        if root.fTrustedRoot == 0 {
            return None;
        }
        let root = root.pCert.as_ref()?;
        if root.pbCertEncoded.is_null() || root.cbCertEncoded == 0 {
            return None;
        }
        Some(SignerFields {
            common_name: name(leaf, c"2.5.4.3")?,
            organization: name(leaf, c"2.5.4.10")?,
            root_der: std::slice::from_raw_parts(root.pbCertEncoded, root.cbCertEncoded as usize)
                .to_vec(),
        })
    }
}

fn name(cert: &CERT_CONTEXT, oid: &std::ffi::CStr) -> Option<String> {
    // CERT_NAME_ATTR_TYPE takes a terminated ANSI OID and emits UTF-16.
    let oid = oid.as_ptr().cast_mut().cast();
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, oid, null_mut(), 0) };
    if len == 0 || len > 32768 {
        return None;
    }
    let mut value = vec![0; len as usize];
    let read =
        unsafe { CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, oid, value.as_mut_ptr(), len) };
    if read != len || value.pop() != Some(0) || value.contains(&0) {
        return None;
    }
    String::from_utf16(&value).ok()
}

struct CatalogAdmin(isize);

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        // This owns the catalog admin context returned by AcquireContext2.
        unsafe { CryptCATAdminReleaseContext(self.0, 0) };
    }
}

struct Catalog<'a>(&'a CatalogAdmin, isize);

impl Drop for Catalog<'_> {
    fn drop(&mut self) {
        // Release the catalog before the borrowing administrator context.
        unsafe { CryptCATAdminReleaseCatalogContext(self.0 .0, self.1, 0) };
    }
}

impl CatalogAdmin {
    fn open(algorithm: &str) -> io::Result<Self> {
        let algorithm: Vec<u16> = algorithm.encode_utf16().chain([0]).collect();
        let mut handle = 0;
        // A null subsystem selects the system catalog; a null policy leaves
        // the explicit hash algorithm in effect.
        if unsafe {
            CryptCATAdminAcquireContext2(&mut handle, null(), algorithm.as_ptr(), null(), 0)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    fn member(
        &self,
        image: &LockedImageFile,
        path: &[u16],
    ) -> io::Result<Option<AuthenticodeFacts>> {
        let file = image.file().as_raw_handle();
        let mut len = 0;
        // First ask the same provider for the required digest size.
        let sized =
            unsafe { CryptCATAdminCalcHashFromFileHandle2(self.0, file, &mut len, null_mut(), 0) };
        if sized == 0 || !matches!(len, 20 | 32) {
            return Err(io::Error::other("catalog digest size unavailable"));
        }
        let mut hash = vec![0; len as usize];
        // The buffer has the required size and the image is still locked.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(self.0, file, &mut len, hash.as_mut_ptr(), 0)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if len as usize != hash.len() {
            return Err(io::Error::other("catalog digest size changed"));
        }
        // Ask for the first containing catalog. A failed lookup other than the
        // system's not-found status is not evidence of an unsigned image.
        let entry = unsafe {
            SetLastError(0);
            CryptCATAdminEnumCatalogFromHash(self.0, hash.as_ptr(), len, 0, null_mut())
        };
        if entry == 0 {
            let error = unsafe { GetLastError() };
            return if error == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(error as i32))
            };
        }
        let entry = Catalog(self, entry);
        let mut info = CATALOG_INFO {
            cbStruct: size_of::<CATALOG_INFO>() as u32,
            wszCatalogFile: [0; 260],
        };
        // The catalog context supplies a terminated catalog filename.
        if unsafe { CryptCATCatalogInfoFromContext(entry.1, &mut info, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let tag: Vec<u16> = hash
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
            .encode_utf16()
            .chain([0])
            .collect();
        let mut member = WINTRUST_CATALOG_INFO {
            cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
            pcwszMemberTag: tag.as_ptr(),
            pcwszMemberFilePath: path.as_ptr(),
            hMemberFile: file,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: len,
            hCatAdmin: self.0,
            ..Default::default()
        };
        Ok(Some(
            ProviderState::new(
                WTD_CHOICE_CATALOG,
                WINTRUST_DATA_0 {
                    pCatalog: &mut member,
                },
            )
            .reading(),
        ))
    }
}
