//! Raw code-signing readings for a running process.
//!
//! An application's bundle identifier is a claim the application makes about
//! itself: any program can put any identifier in its Info.plist. Its code
//! signature is not, because only the holder of the signing key can produce
//! one that validates. These readings let a caller record which signer a
//! person approved, and later ask whether the process in front of it is still
//! signed by that signer. Whether a reading admits anything is decided by the
//! platform-neutral caller, never here.
//!
//! Every call is an in-process Security.framework call, not a subprocess. Both
//! entry points still run on a helper thread with an explicit wait bound: the
//! framework reads the executable from disk to validate it, and a process
//! whose image sits on a stalled network volume would otherwise hold the
//! caller for as long as the volume stays stalled. When the bound passes, the
//! caller is answered with [`CodeSigningError::TimedOut`] and the helper thread
//! is left to finish and discard its result on its own.

use std::ffi::c_void;
use std::sync::mpsc;
use std::time::Duration;

use objc2_core_foundation::{CFNumber, CFNumberType, CFRetained, CFString};
use objc2_foundation::{NSString, NSURL};

type CfTypeRef = *const c_void;
type CfDictionaryRef = *const c_void;
type CfStringRef = *const c_void;
type SecCodeRef = *const c_void;
type SecRequirementRef = *const c_void;

/// `kSecCSInternalInformation`: adds the signature flags to the dictionary.
const SEC_CS_INTERNAL_INFORMATION: u32 = 1 << 0;
/// `kSecCSSigningInformation`: adds the Team ID to the dictionary.
const SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;
/// `kSecCodeSignatureAdhoc`: signed without a certificate, so the signature
/// names the exact code (its cdhash) and no signer.
const SEC_CODE_SIGNATURE_ADHOC: u32 = 0x0002;
/// `errSecCSUnsigned`: the code carries no signature at all.
const ERR_SEC_CS_UNSIGNED: i32 = -67062;
/// `errSecCSNoSuchCode`: no running code answers to the pid, normally because
/// the process exited between being resolved and being read.
const ERR_SEC_CS_NO_SUCH_CODE: i32 = -67065;

#[repr(C)]
struct CfDictionaryKeyCallbacks {
    version: isize,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
    hash: *const c_void,
}

#[repr(C)]
struct CfDictionaryValueCallbacks {
    version: isize,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecGuestAttributePid: CfStringRef;
    #[cfg(feature = "desk-probe")]
    static kSecGuestAttributeAudit: CfStringRef;
    static kSecCodeInfoIdentifier: CfStringRef;
    static kSecCodeInfoTeamIdentifier: CfStringRef;
    static kSecCodeInfoFlags: CfStringRef;

    fn SecStaticCodeCreateWithPath(path: CfTypeRef, flags: u32, code: *mut SecCodeRef) -> i32;
    fn SecStaticCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: SecRequirementRef,
    ) -> i32;
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CfDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> i32;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CfDictionaryRef,
    ) -> i32;
    fn SecCodeCopyDesignatedRequirement(
        code: SecCodeRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> i32;
    fn SecRequirementCopyString(
        requirement: SecRequirementRef,
        flags: u32,
        text: *mut CfStringRef,
    ) -> i32;
    fn SecRequirementCreateWithString(
        text: CfStringRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> i32;
    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: SecRequirementRef) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CfDictionaryKeyCallbacks;
    static kCFTypeDictionaryValueCallBacks: CfDictionaryValueCallbacks;

    fn CFDictionaryCreate(
        allocator: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        count: isize,
        key_callbacks: *const CfDictionaryKeyCallbacks,
        value_callbacks: *const CfDictionaryValueCallbacks,
    ) -> CfDictionaryRef;
    fn CFDictionaryGetValue(dictionary: CfDictionaryRef, key: *const c_void) -> CfTypeRef;
    fn CFRelease(value: CfTypeRef);
    #[cfg(feature = "desk-probe")]
    fn CFDataCreate(allocator: *const c_void, bytes: *const u8, length: isize) -> CfTypeRef;
}

/// A framework object this module owns one reference to, released on drop so
/// that no early return can leak it.
struct Owned(CfTypeRef);

impl Owned {
    /// Take ownership of a reference a Create or Copy call returned, or `None`
    /// when the call returned nothing.
    fn adopt(value: CfTypeRef) -> Option<Self> {
        // Lazily, so that a null is never wrapped: dropping a wrapped null
        // would release it.
        (!value.is_null()).then(|| Self(value))
    }

    fn get(&self) -> CfTypeRef {
        self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the pointer is non-null and this value holds exactly one
        // reference to it, taken from a Create or Copy call.
        unsafe { CFRelease(self.0) };
    }
}

/// What the running code's signature says about who produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSigningIdentity {
    /// Whether the code carries a signature at all.
    pub signed: bool,
    /// Whether the signature is ad hoc: made without a certificate, so it
    /// names this exact build and no signer.
    pub ad_hoc: bool,
    /// The Apple Developer Team ID of the signing certificate. Absent for
    /// unsigned and ad-hoc code, and for Apple's own platform binaries, which
    /// are signed by Apple rather than by a team.
    pub team_id: Option<String>,
    /// The designated requirement in its text form: the rule any later build
    /// must satisfy to count as the same program. Absent only for unsigned
    /// code, which has no signature to state one.
    pub designated_requirement: Option<String>,
}

/// Why a signature could not be read or checked. Each carries the framework
/// status, so a failure can be looked up rather than guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSigningError {
    /// No running code answers to the pid; normally the process exited.
    NoSuchCode(i32),
    /// The code was found and its signing information could not be read.
    SigningInformation(i32),
    /// The designated requirement could not be derived.
    DesignatedRequirement(i32),
    /// A requirement could not be converted to or from its text form.
    RequirementText(i32),
    /// The framework did not answer within the caller's bound.
    TimedOut,
    /// The helper thread that bounds the call could not be started.
    ThreadUnavailable,
}

/// Whether a running process satisfies a requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementCheck {
    /// The code validated and satisfies the requirement.
    Satisfied,
    /// The code was read and does not validate against the requirement. The
    /// status says why: most often `errSecCSReqFailed` (-67050), a different
    /// signer; `errSecCSUnsigned` (-67062) when the code is unsigned; others
    /// when the code on disk no longer matches its signature.
    NotSatisfied(i32),
}

/// Read the code-signing identity of the process `pid`.
///
/// The code is looked up through the kernel by pid
/// (`SecCodeCopyGuestWithAttributes`), so the reading is of the image the
/// process is actually running, not of a file that may have been replaced
/// since it started. The pid names whoever holds it at the moment of the
/// call; a caller that must know the reading is about a particular process
/// checks that process's start time after the call.
pub fn code_signing_identity(
    pid: u32,
    timeout: Duration,
) -> Result<CodeSigningIdentity, CodeSigningError> {
    bounded(timeout, move || read_identity(pid))
}

/// Check the running code of `pid` against a requirement given in its text
/// form, typically one [`code_signing_identity`] returned earlier.
///
/// `SecCodeCheckValidity` validates the running code's signature and then
/// evaluates the requirement against it, so a process signed by anyone other
/// than the signer the requirement names does not satisfy it, whatever
/// bundle identifier it declares.
pub fn code_satisfies_requirement(
    pid: u32,
    requirement: &str,
    timeout: Duration,
) -> Result<RequirementCheck, CodeSigningError> {
    let requirement = requirement.to_string();
    bounded(timeout, move || check_requirement(pid, &requirement))
}

/// Run `read` on a helper thread and wait at most `timeout` for it.
fn bounded<T: Send + 'static>(
    timeout: Duration,
    read: impl FnOnce() -> Result<T, CodeSigningError> + Send + 'static,
) -> Result<T, CodeSigningError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("code-signing-read".to_string())
        .spawn(move || {
            // The receiver is gone when the caller stopped waiting; the
            // result is then simply discarded.
            let _ = sender.send(read());
        })
        .map_err(|_| CodeSigningError::ThreadUnavailable)?;
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(CodeSigningError::TimedOut),
    }
}

/// The running code object for `pid`.
fn guest_for_pid(pid: u32) -> Result<Owned, CodeSigningError> {
    let pid =
        i32::try_from(pid).map_err(|_| CodeSigningError::NoSuchCode(ERR_SEC_CS_NO_SUCH_CODE))?;
    let number = CFNumber::new_i32(pid);
    // SAFETY: the key is the framework's own constant, read once.
    let key = unsafe { kSecGuestAttributePid };
    let keys = [key];
    let values = [(&*number as *const CFNumber).cast::<c_void>()];
    // SAFETY: both arrays hold one live CF object each; the standard callbacks
    // retain them into the dictionary, which is owned below.
    let attributes = Owned::adopt(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
    .ok_or(CodeSigningError::NoSuchCode(ERR_SEC_CS_NO_SUCH_CODE))?;
    let mut code: SecCodeRef = std::ptr::null();
    // SAFETY: a null host asks the kernel; the attributes dictionary is live
    // and the output slot receives one owned reference.
    let status =
        unsafe { SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes.get(), 0, &mut code) };
    match Owned::adopt(code) {
        Some(code) if status == 0 => Ok(code),
        _ => Err(CodeSigningError::NoSuchCode(status)),
    }
}

/// A CFString borrowed from a dictionary, as an owned Rust string.
///
/// # Safety
///
/// `value` must be null or a live CFString.
unsafe fn string_value(value: CfTypeRef) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `value` is a live CFString.
    Some(unsafe { &*value.cast::<CFString>() }.to_string())
}

fn read_identity(pid: u32) -> Result<CodeSigningIdentity, CodeSigningError> {
    identity_of_code(guest_for_pid(pid)?)
}

fn identity_of_code(code: Owned) -> Result<CodeSigningIdentity, CodeSigningError> {
    let mut information: CfDictionaryRef = std::ptr::null();
    // SAFETY: `code` is live; the output slot receives one owned dictionary.
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.get(),
            SEC_CS_SIGNING_INFORMATION | SEC_CS_INTERNAL_INFORMATION,
            &mut information,
        )
    };
    let information = match Owned::adopt(information) {
        Some(information) if status == 0 => information,
        _ => return Err(CodeSigningError::SigningInformation(status)),
    };
    // SAFETY: the keys are the framework's constants; values are borrowed from
    // the dictionary, which outlives every use below, and have the types the
    // framework documents for them.
    let (identifier, team_id, flags) = unsafe {
        let identifier = CFDictionaryGetValue(information.get(), kSecCodeInfoIdentifier);
        let team = CFDictionaryGetValue(information.get(), kSecCodeInfoTeamIdentifier);
        let flags = CFDictionaryGetValue(information.get(), kSecCodeInfoFlags);
        (identifier, string_value(team), flags)
    };
    // Unsigned code has no signing identifier; everything signed, ad hoc
    // included, has one.
    let signed = !identifier.is_null();
    let mut flag_bits: u32 = 0;
    if !flags.is_null() {
        // SAFETY: the flags value is a CFNumber, and the out-pointer is a
        // writable u32.
        let read = unsafe {
            (*flags.cast::<CFNumber>()).value(
                CFNumberType::SInt32Type,
                (&mut flag_bits as *mut u32).cast::<c_void>(),
            )
        };
        if !read {
            return Err(CodeSigningError::SigningInformation(0));
        }
    }
    let ad_hoc = signed && flag_bits & SEC_CODE_SIGNATURE_ADHOC != 0;

    let mut requirement: SecRequirementRef = std::ptr::null();
    // SAFETY: `code` is live; the output slot receives one owned requirement.
    let status = unsafe { SecCodeCopyDesignatedRequirement(code.get(), 0, &mut requirement) };
    let designated_requirement = match Owned::adopt(requirement) {
        Some(requirement) if status == 0 => Some(requirement_text(&requirement)?),
        // Unsigned code states no requirement; that is a reading, not a failure.
        _ if status == ERR_SEC_CS_UNSIGNED || !signed => None,
        _ => return Err(CodeSigningError::DesignatedRequirement(status)),
    };

    Ok(CodeSigningIdentity {
        signed,
        ad_hoc,
        team_id: team_id.filter(|team| !team.is_empty()),
        designated_requirement,
    })
}

fn requirement_text(requirement: &Owned) -> Result<String, CodeSigningError> {
    let mut text: CfStringRef = std::ptr::null();
    // SAFETY: `requirement` is live; the output slot receives one owned string.
    let status = unsafe { SecRequirementCopyString(requirement.get(), 0, &mut text) };
    let text = match Owned::adopt(text) {
        Some(text) if status == 0 => text,
        _ => return Err(CodeSigningError::RequirementText(status)),
    };
    // SAFETY: SecRequirementCopyString returns a CFString, owned by `text`.
    unsafe { string_value(text.get()) }.ok_or(CodeSigningError::RequirementText(status))
}

fn check_requirement(pid: u32, requirement: &str) -> Result<RequirementCheck, CodeSigningError> {
    let code = guest_for_pid(pid)?;
    let compiled = compiled_requirement(requirement)?;
    // SAFETY: both objects are live for the duration of the call.
    let status = unsafe { SecCodeCheckValidity(code.get(), 0, compiled.get()) };
    match status {
        0 => Ok(RequirementCheck::Satisfied),
        ERR_SEC_CS_NO_SUCH_CODE => Err(CodeSigningError::NoSuchCode(status)),
        other => Ok(RequirementCheck::NotSatisfied(other)),
    }
}

/// The candidate intentionally uses the entire kernel token, including pidversion,
/// rather than converting it to a pid and losing its identity across an exec.
#[cfg(feature = "desk-probe")]
pub(crate) fn audit_token_satisfies_requirement(
    token: [u32; 8],
    requirement: &str,
) -> Result<RequirementCheck, CodeSigningError> {
    // SAFETY: audit_token_t is eight native-endian u32s; CFData copies the bytes.
    let data = Owned::adopt(unsafe { CFDataCreate(std::ptr::null(), token.as_ptr().cast(), 32) })
        .ok_or(CodeSigningError::NoSuchCode(-1))?;
    let keys = [unsafe { kSecGuestAttributeAudit }];
    let values = [data.get()];
    // SAFETY: one live key and one live data value; the dictionary retains both.
    let attributes = Owned::adopt(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
    .ok_or(CodeSigningError::NoSuchCode(-1))?;
    let mut code = std::ptr::null();
    // SAFETY: the kernel code host receives the full audit token as CFData.
    let status =
        unsafe { SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes.get(), 0, &mut code) };
    let code = match Owned::adopt(code) {
        Some(code) if status == 0 => code,
        _ => return Err(CodeSigningError::NoSuchCode(status)),
    };
    let compiled = compiled_requirement(requirement)?;
    // SAFETY: both owned Security.framework objects remain live during validation.
    let status = unsafe { SecCodeCheckValidity(code.get(), 0, compiled.get()) };
    Ok(if status == 0 {
        RequirementCheck::Satisfied
    } else {
        RequirementCheck::NotSatisfied(status)
    })
}

fn compiled_requirement(requirement: &str) -> Result<Owned, CodeSigningError> {
    let text: CFRetained<CFString> = CFString::from_str(requirement);
    let mut compiled: SecRequirementRef = std::ptr::null();
    // SAFETY: `text` is a live CFString; the output slot receives one owned
    // requirement.
    let status = unsafe {
        SecRequirementCreateWithString(
            (&*text as *const CFString).cast::<c_void>(),
            0,
            &mut compiled,
        )
    };
    let compiled = match Owned::adopt(compiled) {
        Some(compiled) if status == 0 => compiled,
        _ => return Err(CodeSigningError::RequirementText(status)),
    };
    Ok(compiled)
}

/// Validate the signature on disk before describing its signer. An invalid
/// seal must not become an approved application merely by carrying metadata.
pub fn bundle_code_signing_identity(
    path: &std::path::Path,
    timeout: Duration,
) -> Result<CodeSigningIdentity, CodeSigningError> {
    let path = path.to_owned();
    bounded(timeout, move || {
        let code = static_code(&path)?;
        // SAFETY: the static code is live; a null requirement validates its seal.
        let status = unsafe { SecStaticCodeCheckValidity(code.get(), 0, std::ptr::null()) };
        if status != 0 {
            return Err(CodeSigningError::SigningInformation(status));
        }
        identity_of_code(code)
    })
}

pub fn bundle_code_satisfies_requirement(
    path: &std::path::Path,
    requirement: &str,
    timeout: Duration,
) -> Result<RequirementCheck, CodeSigningError> {
    let path = path.to_owned();
    let requirement = requirement.to_owned();
    bounded(timeout, move || {
        let code = static_code(&path)?;
        let requirement = compiled_requirement(&requirement)?;
        // SAFETY: both owned framework objects are live.
        let status = unsafe { SecStaticCodeCheckValidity(code.get(), 0, requirement.get()) };
        Ok(if status == 0 {
            RequirementCheck::Satisfied
        } else {
            RequirementCheck::NotSatisfied(status)
        })
    })
}

fn static_code(path: &std::path::Path) -> Result<Owned, CodeSigningError> {
    let text = NSString::from_str(path.to_str().ok_or(CodeSigningError::NoSuchCode(0))?);
    let url = NSURL::fileURLWithPath(&text);
    let mut code = std::ptr::null();
    // SAFETY: NSURL is toll-free bridged to CFURL and lives through the call;
    // the Create function returns an owned static-code reference.
    let status =
        unsafe { SecStaticCodeCreateWithPath((&*url as *const NSURL).cast(), 0, &mut code) };
    match Owned::adopt(code) {
        Some(code) if status == 0 => Ok(code),
        _ => Err(CodeSigningError::NoSuchCode(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUND: Duration = Duration::from_secs(10);

    /// The pid of the first running process whose executable path ends with
    /// `suffix`, read from the process table.
    fn running(suffix: &str) -> Option<u32> {
        crate::all_process_ids().ok()?.into_iter().find(|pid| {
            crate::process_executable_path(*pid)
                .ok()
                .flatten()
                .is_some_and(|path| path.to_string_lossy().ends_with(suffix))
        })
    }

    /// Finder is signed by Apple, so its designated requirement is anchored in
    /// Apple's own root and names no team. A requirement naming some other
    /// signer fails against it; its own requirement passes.
    #[test]
    fn finder_reads_as_apple_signed_and_fails_a_foreign_requirement() {
        let Some(finder) = running("/Finder.app/Contents/MacOS/Finder") else {
            eprintln!("SKIPPED: Finder is not running in this session");
            return;
        };
        let identity = code_signing_identity(finder, BOUND).expect("Finder's signature reads");
        assert!(identity.signed);
        assert!(!identity.ad_hoc);
        let requirement = identity
            .designated_requirement
            .clone()
            .expect("signed code states a designated requirement");
        assert!(
            requirement.contains("anchor apple"),
            "Finder's requirement is not Apple-anchored: {requirement}"
        );
        assert!(
            requirement.contains("\"com.apple.finder\""),
            "{requirement}"
        );

        assert_eq!(
            code_satisfies_requirement(finder, &requirement, BOUND),
            Ok(RequirementCheck::Satisfied)
        );
        let foreign = "identifier \"com.apple.finder\" and anchor apple generic and \
                       certificate leaf[subject.OU] = \"ABCDE12345\"";
        assert!(matches!(
            code_satisfies_requirement(finder, foreign, BOUND),
            Ok(RequirementCheck::NotSatisfied(_))
        ));
    }

    /// A binary cargo just built is signed ad hoc by the linker on Apple
    /// silicon: no team, and a requirement that names the exact build by its
    /// cdhash. That requirement is what binds a grant for such an application.
    #[test]
    #[cfg(target_arch = "aarch64")]
    fn a_linker_signed_test_binary_reads_as_ad_hoc_bound_to_its_cdhash() {
        let identity = code_signing_identity(std::process::id(), BOUND)
            .expect("this binary's signature reads");
        assert!(identity.signed);
        assert!(identity.ad_hoc);
        assert_eq!(identity.team_id, None);
        let requirement = identity
            .designated_requirement
            .expect("ad-hoc code states one");
        assert!(requirement.starts_with("cdhash H\""), "{requirement}");
        assert_eq!(
            code_satisfies_requirement(std::process::id(), &requirement, BOUND),
            Ok(RequirementCheck::Satisfied)
        );
    }

    /// A pid nothing holds is reported as no such code, never as a reading.
    #[test]
    fn a_pid_nobody_holds_reads_as_no_such_code() {
        // Pids are bounded well below this on macOS.
        let unused = 999_999;
        assert!(matches!(
            code_signing_identity(unused, BOUND),
            Err(CodeSigningError::NoSuchCode(_))
        ));
        assert!(matches!(
            code_satisfies_requirement(unused, "anchor apple", BOUND),
            Err(CodeSigningError::NoSuchCode(_))
        ));
    }

    /// Text that is not a requirement is refused as such, not treated as a
    /// requirement nobody satisfies.
    #[test]
    fn malformed_requirement_text_is_refused() {
        assert!(matches!(
            code_satisfies_requirement(std::process::id(), "this is not a requirement (", BOUND),
            Err(CodeSigningError::RequirementText(_))
        ));
    }

    /// Measures both calls against a system application and a third-party
    /// one. Run with `--ignored --nocapture` to see the numbers; it asserts
    /// only that each call answers inside the bound.
    #[test]
    #[ignore = "measurement; prints latencies"]
    fn measure_latency() {
        for suffix in [
            "/Finder.app/Contents/MacOS/Finder",
            "/TextEdit.app/Contents/MacOS/TextEdit",
            "/Discord.app/Contents/MacOS/Discord",
        ] {
            let Some(pid) = running(suffix) else {
                eprintln!("{suffix}: not running");
                continue;
            };
            let started = std::time::Instant::now();
            let identity = code_signing_identity(pid, BOUND).expect("identity reads");
            let read = started.elapsed();
            let requirement = identity.designated_requirement.clone().unwrap_or_default();
            let mut checks = Vec::new();
            for _ in 0..5 {
                let started = std::time::Instant::now();
                let _ = code_satisfies_requirement(pid, &requirement, BOUND);
                checks.push(started.elapsed());
            }
            eprintln!(
                "{suffix}: team={:?} ad_hoc={} identity_read={read:?} checks={checks:?}",
                identity.team_id, identity.ad_hoc
            );
        }
    }
}
