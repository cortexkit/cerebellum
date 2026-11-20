use std::ffi::{c_int, c_void};

/// `struct kevent` as the macOS kernel defines it.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct KernelEvent {
    pub(crate) ident: usize,
    pub(crate) filter: i16,
    pub(crate) flags: u16,
    pub(crate) fflags: u32,
    pub(crate) data: isize,
    pub(crate) udata: *mut c_void,
}

#[repr(C)]
pub(crate) struct Timespec {
    pub(crate) seconds: isize,
    pub(crate) nanoseconds: isize,
}

pub(crate) const EVFILT_PROC: i16 = -5;
pub(crate) const EV_ADD: u16 = 0x0001;
pub(crate) const EV_DELETE: u16 = 0x0002;
pub(crate) const EV_ONESHOT: u16 = 0x0010;
pub(crate) const NOTE_EXIT: u32 = 0x8000_0000;

extern "C" {
    pub(crate) fn kqueue() -> c_int;
    pub(crate) fn kevent(
        queue: c_int,
        changes: *const KernelEvent,
        change_count: c_int,
        events: *mut KernelEvent,
        event_count: c_int,
        timeout: *const Timespec,
    ) -> c_int;
}
