//! Facts from a process's primary access token.

use crate::RetainedProcessHandle;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, TokenElevation,
    TokenElevationType as TOKEN_ELEVATION_TYPE_CLASS, TokenElevationTypeDefault,
    TokenElevationTypeFull, TokenElevationTypeLimited, TokenIntegrityLevel, TokenUser,
    TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
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
        // SAFETY: GetCurrentProcess returns the live process pseudo-handle.
        Self::from_process(unsafe { GetCurrentProcess() })
    }

    fn from_process(process: HANDLE) -> Option<Self> {
        Self::open(process).ok()
    }

    fn open(process: HANDLE) -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: The caller supplies a live process handle, and `token`
        // receives an independently owned handle on success.
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        if opened == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(token))
        }
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
    token_facts(Token::current_process()?)
}

impl RetainedProcessHandle {
    pub fn token_facts(&self) -> Option<TokenFacts> {
        token_facts(Token::from_process(self.raw_handle())?)
    }

    pub fn token_user_sid(&self) -> io::Result<String> {
        token_user_sid(Token::open(self.raw_handle())?)
    }
}

pub fn current_process_token_user_sid() -> io::Result<String> {
    // SAFETY: GetCurrentProcess returns the live process pseudo-handle.
    token_user_sid(Token::open(unsafe { GetCurrentProcess() })?)
}

fn token_user_sid(token: Token) -> io::Result<String> {
    let mut needed = 0;
    // SAFETY: The token is live; the null output asks for the buffer length.
    let ok = unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(error);
        }
    }
    if (needed as usize) < size_of::<TOKEN_USER>() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut data = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut written = 0;
    // SAFETY: data has enough space, is pointer-aligned, and stays alive until
    // the SID pointer from TOKEN_USER is no longer needed.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            data.as_mut_ptr().cast(),
            needed,
            &mut written,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if (written as usize) < size_of::<TOKEN_USER>() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut text = null_mut();
    // SAFETY: A successful TokenUser query initialized the header and SID;
    // text is writable and receives a system-allocated NUL-terminated string.
    if unsafe { ConvertSidToStringSidW((*data.as_ptr().cast::<TOKEN_USER>()).User.Sid, &mut text) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: text is the live, NUL-terminated allocation returned above.
    let sid = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sid = String::from_utf16(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        sid
    };
    sid.map_err(io::Error::other)
}

fn token_facts(token: Token) -> Option<TokenFacts> {
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
