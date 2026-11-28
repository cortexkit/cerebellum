//! Retain the executable and its ancestors across verification and process creation.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        NtCreateFile, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    },
};
use windows_sys::Win32::{
    Foundation::{
        RtlNtStatusToDosError, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE,
        MAX_PATH, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    },
    Globalization::{CompareStringOrdinal, CSTR_EQUAL},
    Storage::FileSystem::*,
    System::IO::IO_STATUS_BLOCK,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenExecutableError {
    Missing,
    ReparsePoint,
    UnstablePath,
}

impl OpenExecutableError {
    fn from_open(error: io::Error) -> Self {
        match error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => Self::Missing,
            _ => OpenExecutableError::UnstablePath,
        }
    }
}

const VERBATIM: &str = "\\\\?\\";
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const DIRECTORY_ACCESS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
// NtCreateFile requires SYNCHRONIZE for a synchronous handle, which WinTrust reads.
const IMAGE_ACCESS: u32 = FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

#[derive(Debug)]
pub struct PathForms {
    stored: String,
    spawn: String,
}

impl PathForms {
    pub fn stored(&self) -> &str {
        &self.stored
    }

    pub fn spawn(&self) -> &str {
        &self.spawn
    }
}

/// A local DOS path exactly representable with and without the verbatim prefix.
pub fn checked_path_forms(path: &OsStr) -> Result<PathForms, OpenExecutableError> {
    let refuse = OpenExecutableError::UnstablePath;
    let path = path.to_str().ok_or(refuse)?;
    let spawn = path.strip_prefix(VERBATIM).unwrap_or(path);
    let wide: Vec<u16> = spawn.encode_utf16().chain([0]).collect();
    if !matches!(spawn.as_bytes(), [drive, b':', b'\\', ..] if drive.is_ascii_alphabetic())
        || wide.len() > MAX_PATH as usize
        || (!spawn[3..].is_empty() && spawn[3..].split('\\').any(ambiguous_component))
    {
        return Err(refuse);
    }
    let mut full = [0; MAX_PATH as usize];
    // Absolute, NUL-terminated input and a fixed-size writable output buffer.
    let len = unsafe { GetFullPathNameW(wide.as_ptr(), MAX_PATH, full.as_mut_ptr(), null_mut()) }
        as usize;
    if full.get(..len) != Some(&wide[..wide.len() - 1]) {
        return Err(refuse);
    }
    Ok(PathForms {
        stored: format!("{VERBATIM}{spawn}"),
        spawn: spawn.to_owned(),
    })
}

fn ambiguous_component(name: &str) -> bool {
    if name.is_empty()
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|ch| ch <= '\u{1f}' || matches!(ch, '/' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return true;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    // The Win32 device namespace still recognizes these names with extensions.
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

#[derive(Debug)]
pub struct HeldExecutable {
    image: File,
    paths: PathForms,
    _ancestors: Vec<File>,
}

impl HeldExecutable {
    pub fn open(path: &Path) -> Result<Self, OpenExecutableError> {
        Self::walk(path, |_| {})
    }

    pub fn paths(&self) -> &PathForms {
        &self.paths
    }

    pub fn image(&self) -> &File {
        &self.image
    }

    fn walk(
        path: &Path,
        mut after_open_directory: impl FnMut(usize),
    ) -> Result<Self, OpenExecutableError> {
        let refuse = OpenExecutableError::UnstablePath;
        let requested = checked_path_forms(path.as_os_str())?;
        let (drive, rest) = requested.spawn.split_at(3);
        if rest.is_empty() {
            return Err(refuse);
        }
        let root_name: Vec<u16> = VERBATIM
            .encode_utf16()
            .chain(drive.encode_utf16())
            .chain([0])
            .collect();
        // This is only the drive root. No unchecked ancestor is traversed by name.
        let root = unsafe {
            CreateFileW(
                root_name.as_ptr(),
                DIRECTORY_ACCESS,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if root == INVALID_HANDLE_VALUE {
            return Err(OpenExecutableError::from_open(io::Error::last_os_error()));
        }
        // CreateFileW returned an owned handle, not INVALID_HANDLE_VALUE.
        let root = unsafe { File::from_raw_handle(root) };
        check_attributes(&root, true)?;
        check_volume(&root)?;
        let mut ancestors = vec![root];
        after_open_directory(0);
        let mut names = rest.split('\\').peekable();
        while let Some(name) = names.next() {
            let is_dir = names.peek().is_some();
            let parent = ancestors.last().expect("drive root is retained");
            let file =
                open_component(parent, name, is_dir).map_err(OpenExecutableError::from_open)?;
            check_attributes(&file, is_dir)?;
            if is_dir {
                ancestors.push(file);
                after_open_directory(ancestors.len() - 1);
                continue;
            }
            let actual = final_path(&file, VOLUME_NAME_DOS).map_err(|_| refuse)?;
            if !ordinal_eq_ignore_case(&requested.stored, &actual) {
                return Err(refuse);
            }
            let paths = checked_path_forms(OsStr::new(&actual))?;
            return Ok(Self {
                image: file,
                paths,
                _ancestors: ancestors,
            });
        }
        Err(refuse)
    }
}

fn open_component(parent: &File, component: &str, directory: bool) -> io::Result<File> {
    let mut wide: Vec<u16> = component.encode_utf16().collect();
    let bytes = (wide.len() * size_of::<u16>()) as u16; // bounded by MAX_PATH
    let name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        ..Default::default()
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    let (access, share) = if directory {
        (DIRECTORY_ACCESS, SHARE_ALL)
    } else {
        (IMAGE_ACCESS, FILE_SHARE_READ)
    };
    // The root handle is live and the name is one component. The kernel must
    // return a reparse point itself rather than follow its target.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status,
            null(),
            0,
            share,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 {
        // Translate an NTSTATUS, not the thread's unrelated Win32 last error.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    // The successful open transfers this handle to the caller.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn check_attributes(file: &File, directory: bool) -> Result<(), OpenExecutableError> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // FileAttributeTagInfo writes a FILE_ATTRIBUTE_TAG_INFO into the buffer.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(OpenExecutableError::UnstablePath);
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OpenExecutableError::ReparsePoint);
    }
    if (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        return Err(OpenExecutableError::UnstablePath);
    }
    Ok(())
}

fn check_volume(root: &File) -> Result<(), OpenExecutableError> {
    let refuse = OpenExecutableError::UnstablePath;
    // Remote shares have no mount-manager volume GUID. Check the held object,
    // not the drive letter, which can be remapped between two by-name queries.
    if !final_path(root, VOLUME_NAME_GUID)
        .map_err(|_| refuse)?
        .starts_with("\\\\?\\Volume{")
    {
        return Err(refuse);
    }
    let mut fs = [0; 32];
    // Only the filesystem name is requested; all optional outputs are null.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            root.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    };
    let len = fs.iter().position(|&ch| ch == 0).ok_or(refuse)?;
    if ok == 0
        || !matches!(
            String::from_utf16(&fs[..len]).as_deref(),
            Ok("NTFS" | "ReFS")
        )
    {
        return Err(refuse);
    }
    Ok(())
}

fn final_path(file: &File, volume_mode: u32) -> io::Result<String> {
    let mut wide = [0; 32768];
    // The file is held and Windows gets a writable UTF-16 buffer.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            wide.as_mut_ptr(),
            wide.len() as u32,
            volume_mode,
        )
    } as usize;
    match len {
        0 => Err(io::Error::last_os_error()),
        len if len >= wide.len() => Err(io::ErrorKind::InvalidData.into()),
        len => String::from_utf16(&wide[..len]).map_err(io::Error::other),
    }
}

fn ordinal_eq_ignore_case(a: &str, b: &str) -> bool {
    let a: Vec<u16> = a.encode_utf16().collect();
    let b: Vec<u16> = b.encode_utf16().collect();
    // NT's ordinal case comparison doesn't use the operator's locale.
    unsafe {
        CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1)
            == CSTR_EQUAL
    }
}

use std::ffi::CStr;
use std::marker::PhantomData;
use windows_sys::Win32::Security::{Cryptography::*, WinTrust::*};

pub use windows_sys::Win32::{
    Foundation::{CERT_E_REVOKED, CRYPT_E_REVOCATION_OFFLINE, CRYPT_E_REVOKED, TRUST_E_BAD_DIGEST},
    Security::Cryptography::{
        CERT_TRUST_IS_OFFLINE_REVOCATION, CERT_TRUST_IS_REVOKED,
        CERT_TRUST_REVOCATION_STATUS_UNKNOWN,
    },
};

#[derive(Debug)]
pub struct SignatureStatus {
    pub provider_status: i32,
    pub chain_errors: Option<u32>,
    pub signer: Option<SignatureSigner>,
}

#[derive(Debug)]
pub struct SignatureSigner {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub code_signing_eku: bool,
    pub root_sha256: Option<[u8; 32]>,
}

impl HeldExecutable {
    /// Read the provider status, the selected chain's status, and signer facts.
    /// The provider state closes before this owned snapshot leaves the call.
    pub fn read_signature_status(&self) -> SignatureStatus {
        self.with_signature_state(|state, provider_status| {
            let chain = state.chain();
            let signer = chain.and_then(chain_certificates).and_then(|certificates| {
                let leaf = certificates.first()?;
                Some(SignatureSigner {
                    common_name: cert_name(leaf, c"2.5.4.3"),
                    organization: cert_name(leaf, c"2.5.4.10"),
                    code_signing_eku: code_signing_eku(leaf),
                    root_sha256: certificates.last().and_then(|root| cert_hash(root)),
                })
            });
            SignatureStatus {
                provider_status,
                chain_errors: chain.map(|c| c.TrustStatus.dwErrorStatus),
                signer,
            }
        })
    }

    fn with_signature_state<T>(&self, read: impl FnOnce(&TrustState<'_>, i32) -> T) -> T {
        let path: Vec<u16> = self.paths.stored.encode_utf16().chain([0]).collect();
        let mut target = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: self.image.as_raw_handle(),
            pgKnownSubject: null_mut(),
        };
        let (state, provider) = TrustState::verify(&mut target);
        read(&state, provider)
    }
}

struct TrustState<'a>(WINTRUST_DATA, PhantomData<&'a mut WINTRUST_FILE_INFO>);

impl<'a> TrustState<'a> {
    fn verify(target: &'a mut WINTRUST_FILE_INFO) -> (Self, i32) {
        let mut state = Self(
            WINTRUST_DATA {
                cbStruct: size_of::<WINTRUST_DATA>() as u32,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: WINTRUST_DATA_0 { pFile: target },
                dwStateAction: WTD_STATEACTION_VERIFY,
                dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                ..Default::default()
            },
            PhantomData,
        );
        let result = state.call();
        (state, result)
    }

    fn call(&mut self) -> i32 {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // The data's FILE union member remains valid for both VERIFY and CLOSE.
        unsafe {
            WinVerifyTrust(
                null_mut(),
                &mut action,
                (&mut self.0 as *mut WINTRUST_DATA).cast(),
            )
        }
    }

    fn chain(&self) -> Option<&CERT_CHAIN_CONTEXT> {
        if self.0.hWVTStateData.is_null() {
            return None;
        }
        // Provider state owns the chain; select the primary signer, not a timestamp.
        unsafe {
            let data = WTHelperProvDataFromStateData(self.0.hWVTStateData);
            if data.is_null() {
                return None;
            }
            WTHelperGetProvSignerFromChain(data, 0, 0, 0)
                .as_ref()?
                .pChainContext
                .as_ref()
        }
    }
}

impl Drop for TrustState<'_> {
    fn drop(&mut self) {
        self.0.dwStateAction = WTD_STATEACTION_CLOSE;
        self.call();
    }
}

fn chain_certificates(chain: &CERT_CHAIN_CONTEXT) -> Option<Vec<&CERT_CONTEXT>> {
    // A single simple chain directly ties the signing leaf to the pinned root.
    // Do not pin the root of a second simple chain belonging to a trust list.
    if chain.cChain != 1 || chain.rgpChain.is_null() {
        return None;
    }
    // WinTrust still owns these arrays and the certificate contexts they point to.
    unsafe {
        let path = (*chain.rgpChain).as_ref()?;
        if path.cElement < 2 || path.rgpElement.is_null() {
            return None;
        }
        std::slice::from_raw_parts(path.rgpElement, path.cElement as usize)
            .iter()
            .map(|node| (*node).as_ref()?.pCertContext.as_ref())
            .collect()
    }
}

fn cert_name(cert: &CERT_CONTEXT, oid: &CStr) -> Option<String> {
    let attr = oid.as_ptr().cast_mut().cast();
    // CERT_NAME_ATTR_TYPE takes a NUL-terminated ANSI object identifier in pvTypePara.
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, attr, null_mut(), 0) };
    if len == 0 {
        return None;
    }
    let mut name = vec![0; len as usize];
    // The buffer has the length (including NUL) just returned by Crypt32.
    let written =
        unsafe { CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, attr, name.as_mut_ptr(), len) };
    read_wide_string(name, written, len)
}

fn read_wide_string(mut wide: Vec<u16>, written: u32, expected: u32) -> Option<String> {
    if written != expected || wide.pop() != Some(0) || wide.contains(&0) {
        return None;
    }
    String::from_utf16(&wide).ok()
}

fn code_signing_eku(cert: &CERT_CONTEXT) -> bool {
    let flags = CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG;
    let mut len = 0;
    // Read the signed certificate extension, not usage overrides on the store entry.
    if unsafe { CertGetEnhancedKeyUsage(cert, flags, null_mut(), &mut len) } == 0
        || (len as usize) < size_of::<CTL_USAGE>()
    {
        return false;
    }
    let mut buffer = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
    let usage = buffer.as_mut_ptr().cast::<CTL_USAGE>();
    // Crypt32 initializes the aligned buffer and its array of terminated OIDs.
    unsafe {
        if CertGetEnhancedKeyUsage(cert, flags, usage, &mut len) == 0 {
            return false;
        }
        let usage = &*usage;
        if usage.cUsageIdentifier == 0 || usage.rgpszUsageIdentifier.is_null() {
            return false;
        }
        std::slice::from_raw_parts(usage.rgpszUsageIdentifier, usage.cUsageIdentifier as usize)
            .iter()
            .any(|&oid| !oid.is_null() && CStr::from_ptr(oid.cast()) == c"1.3.6.1.5.5.7.3.3")
    }
}

fn cert_hash(cert: &CERT_CONTEXT) -> Option<[u8; 32]> {
    if cert.pbCertEncoded.is_null() || cert.cbCertEncoded == 0 {
        return None;
    }
    // The context keeps its complete encoded certificate alive for this call.
    hash_der(unsafe { std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize) })
}

fn hash_der(der: &[u8]) -> Option<[u8; 32]> {
    let mut hash = [0; 32];
    let mut len = hash.len() as u32;
    // The input is live and the writable output can accommodate a SHA-256 digest.
    let ok = unsafe {
        CryptHashCertificate2(
            BCRYPT_SHA256_ALGORITHM,
            0,
            null(),
            der.as_ptr(),
            der.len().try_into().ok()?,
            hash.as_mut_ptr(),
            &mut len,
        )
    };
    (ok != 0 && len as usize == hash.len()).then_some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileAccessInformation, NtQueryInformationFile, FILE_ACCESS_INFORMATION,
    };

    #[test]
    fn windows_installed_chrome_chain() {
        let path = match std::env::var_os("CK_WINDOWS_BROWSER_CHROME") {
            Some(path) => path,
            // The standard test workflow has no installed-Chrome prerequisite.
            // The browser workflow checks and exports the path before running cargo.
            None => return,
        };
        let held = HeldExecutable::open(Path::new(&path)).expect("open installed Chrome");
        held.with_signature_state(|state, provider| {
            let chain = state.chain().expect("provider did not supply its chain");
            let certs =
                chain_certificates(chain).expect("provider did not supply its certificates");
            let mut log = io::stderr().lock();
            writeln!(
                log,
                "Chrome Authenticode: {:?}; provider={provider:#010x}; chain={:#010x}",
                held.paths().stored(),
                chain.TrustStatus.dwErrorStatus
            )
            .unwrap();
            for (index, cert) in certs.iter().enumerate() {
                let info = certificate_info(cert).expect("certificate info");
                let subject = distinguished_name(cert, &info.Subject).expect("subject");
                let issuer = distinguished_name(cert, &info.Issuer).expect("issuer");
                let thumbprint = cert_hash(cert).expect("certificate SHA-256");
                writeln!(
                    log,
                    "Chrome certificate {index}: subject={subject:?}; issuer={issuer:?}; SHA256={}",
                    hex(&thumbprint)
                )
                .unwrap();
            }
            let spki = spki_hash(certs.last().unwrap()).expect("root SPKI SHA-256");
            writeln!(log, "Chrome root SPKI SHA256={}", hex(&spki)).unwrap();
        });
    }

    #[test]
    fn windows_machine_root_store_reports_self_signed_g4() {
        if std::env::var_os("CK_WINDOWS_BROWSER_CHROME").is_none() {
            return;
        }
        let root: Vec<u16> = "Root".encode_utf16().chain([0]).collect();
        // Open the machine's existing Root store read-only, with no user store or network lookup.
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                CERT_SYSTEM_STORE_LOCAL_MACHINE
                    | CERT_STORE_OPEN_EXISTING_FLAG
                    | CERT_STORE_READONLY_FLAG,
                root.as_ptr().cast(),
            )
        };
        assert!(
            !handle.is_null(),
            "open LocalMachine\\Root: {}",
            io::Error::last_os_error()
        );
        struct Store(HCERTSTORE);
        impl Drop for Store {
            fn drop(&mut self) {
                // This guard owns the open store.
                unsafe { CertCloseStore(self.0, 0) };
            }
        }
        let store = Store(handle);
        let mut last = null_mut();
        let mut roots = Vec::new();
        loop {
            // The store is open. Each enumeration call releases its preceding context.
            last = unsafe { CertEnumCertificatesInStore(store.0, last) };
            // Copy the matching facts inside this iteration, before advancing.
            let Some(cert) = (unsafe { last.as_ref() }) else {
                break;
            };
            if cert_name(cert, c"2.5.4.3").as_deref() != Some("DigiCert Trusted Root G4") {
                continue;
            }
            let info = certificate_info(cert).expect("certificate info");
            let subject = distinguished_name(cert, &info.Subject).expect("subject");
            let issuer = distinguished_name(cert, &info.Issuer).expect("issuer");
            if subject != issuer {
                continue;
            }
            // A self-issued name alone does not establish a self-signed certificate.
            let self_signed = unsafe {
                CryptVerifyCertificateSignatureEx(
                    0,
                    X509_ASN_ENCODING,
                    CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
                    last.cast(),
                    CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
                    last.cast(),
                    0,
                    null_mut(),
                )
            } != 0;
            if self_signed {
                roots.push((
                    subject,
                    cert_hash(cert).expect("certificate SHA-256"),
                    spki_hash(cert).expect("root SPKI SHA-256"),
                ));
            }
        }
        assert_eq!(
            roots.len(),
            1,
            "unique self-signed Trusted Root G4: {roots:?}"
        );
        let (subject, der, spki) = &roots[0];
        writeln!(io::stderr().lock(), "LocalMachine\\Root self-signed certificate: subject={subject:?}; DER SHA256={}; SPKI SHA256={}", hex(der), hex(spki)).unwrap();
    }

    #[test]
    fn windows_chrome_handle_has_exact_access() {
        let Some(path) = std::env::var_os("CK_WINDOWS_BROWSER_CHROME") else {
            return;
        };
        let held = HeldExecutable::open(Path::new(&path)).expect("open installed Chrome");
        let mut io = IO_STATUS_BLOCK::default();
        let mut info = FILE_ACCESS_INFORMATION::default();
        // The held file stays open and the buffer matches FileAccessInformation.
        let status = unsafe {
            NtQueryInformationFile(
                held.image().as_raw_handle(),
                &mut io,
                (&mut info as *mut FILE_ACCESS_INFORMATION).cast(),
                size_of::<FILE_ACCESS_INFORMATION>() as u32,
                FileAccessInformation,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(
            info.AccessFlags,
            FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        );
    }

    fn certificate_info(cert: &CERT_CONTEXT) -> Option<&CERT_INFO> {
        // The decoded certificate information belongs to the live context.
        unsafe { cert.pCertInfo.as_ref() }
    }

    fn distinguished_name(cert: &CERT_CONTEXT, blob: &CRYPT_INTEGER_BLOB) -> Option<String> {
        // Query length before providing a buffer for the decoded X.500 name.
        let len = unsafe {
            CertNameToStrW(
                cert.dwCertEncodingType,
                blob,
                CERT_X500_NAME_STR,
                null_mut(),
                0,
            )
        };
        if len <= 1 {
            return None;
        }
        let mut text = vec![0; len as usize];
        // The buffer has the reported size including the terminating NUL.
        let written = unsafe {
            CertNameToStrW(
                cert.dwCertEncodingType,
                blob,
                CERT_X500_NAME_STR,
                text.as_mut_ptr(),
                len,
            )
        };
        read_wide_string(text, written, len)
    }

    fn spki_hash(cert: &CERT_CONTEXT) -> Option<[u8; 32]> {
        let key = &certificate_info(cert)?.SubjectPublicKeyInfo;
        let key = (key as *const CERT_PUBLIC_KEY_INFO).cast();
        let mut len = 0;
        // Encode the key algorithm and key bits together as a DER SubjectPublicKeyInfo.
        let ok = unsafe {
            CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                key,
                0,
                null(),
                null_mut(),
                &mut len,
            )
        };
        if ok == 0 || len == 0 {
            return None;
        }
        let mut der = vec![0; len as usize];
        // The key is still live; the buffer has the requested number of bytes.
        let ok = unsafe {
            CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                key,
                0,
                null(),
                der.as_mut_ptr().cast(),
                &mut len,
            )
        };
        (ok != 0)
            .then(|| der.get(..len as usize))
            .flatten()
            .and_then(hash_der)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
