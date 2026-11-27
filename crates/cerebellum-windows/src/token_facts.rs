//! Facts from the current process's primary access token.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, TokenElevation,
    TokenElevationType as TOKEN_ELEVATION_TYPE_CLASS, TokenElevationTypeDefault,
    TokenElevationTypeFull, TokenElevationTypeLimited, TokenIntegrityLevel, TOKEN_ELEVATION,
    TOKEN_ELEVATION_TYPE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenFacts {
    pub elevated: bool,
    /// The final subauthority of the mandatory label SID.
    pub integrity_rid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenElevationType {
    Default,
    Full,
    Limited,
}

struct Token(HANDLE);

impl Token {
    fn current_process() -> Option<Self> {
        let mut token = null_mut();
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle, and `token`
        // receives an independently owned handle on success.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        (opened != 0).then(|| Self(token))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the live handle and closes it exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Read the elevation flag and mandatory integrity RID, or no reading if either
/// query fails.
pub fn current_process_token_facts() -> Option<TokenFacts> {
    let token = Token::current_process()?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut written = 0;
    // SAFETY: The token is live; the supplied buffer matches TokenElevation's
    // fixed-size output and the size output points to a writable u32.
    let read = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut written,
        )
    };
    if read == 0 || written as usize != size_of::<TOKEN_ELEVATION>() {
        return None;
    }
    Some(TokenFacts {
        elevated: elevation.TokenIsElevated != 0,
        integrity_rid: integrity_rid(&token)?,
    })
}

/// Read whether Windows reports a default, full or limited primary token.
pub fn current_process_token_elevation_type() -> Option<TokenElevationType> {
    let token = Token::current_process()?;
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut written = 0;
    // SAFETY: The token is live and both outputs have the types and lengths
    // required for TokenElevationType.
    let read = unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_ELEVATION_TYPE_CLASS,
            (&mut kind as *mut TOKEN_ELEVATION_TYPE).cast(),
            size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut written,
        )
    };
    if read == 0 || written as usize != size_of::<TOKEN_ELEVATION_TYPE>() {
        return None;
    }
    if kind == TokenElevationTypeDefault {
        Some(TokenElevationType::Default)
    } else if kind == TokenElevationTypeFull {
        Some(TokenElevationType::Full)
    } else if kind == TokenElevationTypeLimited {
        Some(TokenElevationType::Limited)
    } else {
        None
    }
}

fn integrity_rid(token: &Token) -> Option<u32> {
    let mut needed = 0;
    // SAFETY: A null buffer and zero length asks Windows for the required size
    // without passing any token information buffer for it to write.
    unsafe { GetTokenInformation(token.0, TokenIntegrityLevel, null_mut(), 0, &mut needed) };
    if (needed as usize) < size_of::<TOKEN_MANDATORY_LABEL>() {
        return None;
    }
    // TOKEN_MANDATORY_LABEL contains a pointer; pointer-aligned storage also
    // holds its variable-length SID without making a second allocation.
    let mut label = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let buffer: *mut c_void = label.as_mut_ptr().cast();
    let mut written = 0;
    // SAFETY: `buffer` points to at least `needed` writable bytes, aligned for
    // TOKEN_MANDATORY_LABEL. The token and size output are live.
    let read =
        unsafe { GetTokenInformation(token.0, TokenIntegrityLevel, buffer, needed, &mut written) };
    if read == 0 || (written as usize) < size_of::<TOKEN_MANDATORY_LABEL>() {
        return None;
    }
    // SAFETY: A successful read initialized the header and returned a SID
    // pointer into the still-live buffer. Its last subauthority is the RID.
    unsafe {
        let sid = (*buffer.cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        if sid.is_null() || IsValidSid(sid) == 0 {
            return None;
        }
        let count = *GetSidSubAuthorityCount(sid);
        let last = count.checked_sub(1)?;
        Some(*GetSidSubAuthority(sid, u32::from(last)))
    }
}
