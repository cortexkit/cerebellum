//! Per-process keyboard delivery through the private window-server posting call.
//!
//! The public per-process post reaches Cocoa targets but is dropped by
//! web-content targets when they are not frontmost. A private posting entry
//! point takes the same event down a route the window server accepts for those
//! targets, and on recent systems that route also wants an authentication
//! object attached to the event before it will honour a synthetic keystroke.
//!
//! This module owns the raw pointer work for both: it builds the events, finds
//! the internal record the authentication object is built from, attaches that
//! object, and posts. The private symbols are resolved by name once; a symbol
//! that does not resolve marks its capability unavailable rather than aborting,
//! so the same binary runs where the route exists and where it does not.
//!
//! Nothing here decides whether posting is allowed. It reports what the system
//! provides and forwards one event; the caller holds the grant and the policy.

use std::ffi::c_void;

/// Pick the first probed record pointer that is non-null.
///
/// The record the authentication object is built from lives at a fixed byte
/// offset inside the event object, but the offset differs across layouts, so
/// several candidates are probed and the first that reads back non-null is the
/// one used. Split out from the pointer read so the selection rule can be
/// exercised on any host without touching a real event.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn first_non_null_record(candidates: &[*mut c_void]) -> Option<*mut c_void> {
    candidates
        .iter()
        .copied()
        .find(|candidate| !candidate.is_null())
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{c_void, CStr};
    use std::os::raw::{c_char, c_int};
    use std::sync::OnceLock;

    use objc2_core_foundation::CFRetained;
    use objc2_core_graphics::{CGEvent, CGEventFlags, CGEventSource, CGEventSourceStateID};

    use super::first_non_null_record;
    use crate::KeyModifiers;

    extern "C" {
        fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn class_respondsToSelector(cls: *mut c_void, sel: *mut c_void) -> bool;
        fn objc_msgSend();
    }

    const RTLD_LAZY: c_int = 0x1;
    const RTLD_GLOBAL: c_int = 0x8;

    /// The byte offsets inside the event object where the internal record
    /// pointer has been observed to sit on 64-bit layouts. The first is the
    /// current layout (a Core Foundation header of 16 bytes, a 4-byte field,
    /// then the pointer aligned to 24); the others cover older and padded
    /// variants. Probed in this order, first non-null wins.
    const RECORD_OFFSETS: [usize; 3] = [24, 32, 16];

    /// The version argument the authentication factory expects.
    const AUTH_MESSAGE_VERSION: u32 = 0;

    /// Addresses of the private symbols, resolved once by name.
    ///
    /// Held as raw addresses rather than typed pointers so the whole set is
    /// trivially shareable; each is typed back to its C signature at the call
    /// site. `None` means the symbol did not resolve, which is how a missing
    /// capability is reported without a crash.
    struct Symbols {
        /// The per-process posting entry point.
        post_to_pid: Option<usize>,
        /// The setter that attaches an authentication object to an event.
        set_auth_message: Option<usize>,
        /// The class that builds an authentication object from a record.
        auth_class: Option<usize>,
        /// The factory selector on that class, present only where it responds.
        auth_selector: Option<usize>,
    }

    fn symbols() -> &'static Symbols {
        static SYMS: OnceLock<Symbols> = OnceLock::new();
        SYMS.get_or_init(resolve)
    }

    fn resolve() -> Symbols {
        // SAFETY: every call takes NUL-terminated C string literals and returns
        // either a valid handle/address or null; nothing is dereferenced here.
        unsafe {
            // Loading the framework makes its symbols visible to the default
            // search below. Its handle is not needed afterwards: the process
            // keeps the framework mapped for its lifetime.
            let path = c"/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight";
            dlopen(path.as_ptr(), RTLD_LAZY | RTLD_GLOBAL);

            let post_to_pid = resolve_symbol(c"SLEventPostToPid");
            let set_auth_message = resolve_symbol(c"SLEventSetAuthenticationMessage");

            let cls = objc_getClass(c"SLSEventAuthenticationMessage".as_ptr());
            let auth_class = (!cls.is_null()).then_some(cls as usize);
            // The factory selector exists only on newer systems. Interning a
            // name always succeeds, so the class must be asked whether it
            // actually responds before the selector is treated as present:
            // sending an absent selector would raise instead of returning.
            let auth_selector = auth_class.and_then(|_| {
                let sel = sel_registerName(c"messageWithEventRecord:pid:version:".as_ptr());
                (!sel.is_null() && class_respondsToSelector(cls, sel)).then_some(sel as usize)
            });

            Symbols {
                post_to_pid,
                set_auth_message,
                auth_class,
                auth_selector,
            }
        }
    }

    /// Look one symbol up in the default search order, or `None` if absent.
    ///
    /// # Safety
    ///
    /// `name` must be a valid NUL-terminated C string for the call.
    unsafe fn resolve_symbol(name: &CStr) -> Option<usize> {
        // The default-search handle, `RTLD_DEFAULT`, is the constant (void*)-2.
        let rtld_default = (-2isize) as *mut c_void;
        let address = dlsym(rtld_default, name.as_ptr());
        (!address.is_null()).then_some(address as usize)
    }

    /// Whether the private per-process posting entry point resolved.
    pub fn skylight_available() -> bool {
        symbols().post_to_pid.is_some()
    }

    /// Whether the keyboard authentication path is fully present: the class,
    /// its factory selector, and the setter that attaches the result.
    pub fn keyboard_auth_available() -> bool {
        let symbols = symbols();
        symbols.auth_class.is_some()
            && symbols.auth_selector.is_some()
            && symbols.set_auth_message.is_some()
    }

    /// What one posting attempt did.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PostResult {
        /// The event pair was posted; `auth_attached` records whether an
        /// authentication object was attached first.
        Posted { auth_attached: bool },
        /// The private posting entry point did not resolve, so nothing private
        /// could be posted at all.
        SpiUnavailable,
        /// An authentication object was asked for but could not be produced or
        /// attached, so nothing was posted.
        AuthUnavailable,
        /// The event pair could not be constructed, so nothing was posted.
        EventBuildFailed,
    }

    fn flags_for(modifiers: KeyModifiers) -> CGEventFlags {
        let mut flags = CGEventFlags::empty();
        if modifiers.command {
            flags.insert(CGEventFlags::MaskCommand);
        }
        if modifiers.shift {
            flags.insert(CGEventFlags::MaskShift);
        }
        if modifiers.option {
            flags.insert(CGEventFlags::MaskAlternate);
        }
        if modifiers.control {
            flags.insert(CGEventFlags::MaskControl);
        }
        flags
    }

    fn keyboard_event(
        source: &CGEventSource,
        key_code: u16,
        key_down: bool,
        flags: CGEventFlags,
        unicode: Option<&[u16]>,
    ) -> Option<CFRetained<CGEvent>> {
        let event = CGEvent::new_keyboard_event(Some(source), key_code, key_down)?;
        // The full flag set is written on every event. A source may carry the
        // physical modifier state, so omitting flags would not mean "no
        // modifiers" and could turn a later plain key into a shortcut.
        CGEvent::set_flags(Some(&event), flags);
        if let Some(unicode) = unicode {
            // SAFETY: `unicode` is a live slice for the length passed, and the
            // call copies exactly that many UTF-16 values before returning.
            unsafe {
                CGEvent::keyboard_set_unicode_string(
                    Some(&event),
                    unicode.len() as _,
                    unicode.as_ptr(),
                );
            }
        }
        Some(event)
    }

    /// One key-down/key-up pair this module owns and releases.
    ///
    /// The events are retained Core Foundation objects released when this drops.
    /// No raw event pointer leaves the module: callers build one of these and
    /// hand it back to [`post_key_to_pid`].
    pub struct OwnedKeyEvent {
        down: Option<CFRetained<CGEvent>>,
        up: Option<CFRetained<CGEvent>>,
    }

    impl OwnedKeyEvent {
        /// Build a pair carrying one character as a UTF-16 string, so its
        /// meaning does not depend on a keyboard layout or a key table.
        pub fn for_character(character: char) -> Self {
            let Some(source) = CGEventSource::new(CGEventSourceStateID::HIDSystemState) else {
                return Self {
                    down: None,
                    up: None,
                };
            };
            let mut buffer = [0u16; 2];
            let unicode = character.encode_utf16(&mut buffer);
            Self {
                down: keyboard_event(&source, 0, true, CGEventFlags::empty(), Some(unicode)),
                up: keyboard_event(&source, 0, false, CGEventFlags::empty(), Some(unicode)),
            }
        }

        /// Build a pair carrying one macOS virtual keycode and modifier chord,
        /// for keys such as delete or a select-all shortcut that a character
        /// string cannot express.
        pub fn for_key_code(key_code: u16, modifiers: KeyModifiers) -> Self {
            let Some(source) = CGEventSource::new(CGEventSourceStateID::HIDSystemState) else {
                return Self {
                    down: None,
                    up: None,
                };
            };
            let flags = flags_for(modifiers);
            Self {
                down: keyboard_event(&source, key_code, true, flags, None),
                up: keyboard_event(&source, key_code, false, flags, None),
            }
        }

        fn pair(&self) -> Option<(&CGEvent, &CGEvent)> {
            Some((self.down.as_deref()?, self.up.as_deref()?))
        }
    }

    /// Read the internal record pointer out of the event object.
    ///
    /// # Safety
    ///
    /// `event` must point to a live event object; each probed offset is read as
    /// a pointer-sized value.
    unsafe fn record_pointer(event: *mut c_void) -> Option<*mut c_void> {
        let probed = RECORD_OFFSETS.map(|offset| {
            let slot = (event as *const u8).add(offset).cast::<*mut c_void>();
            slot.read()
        });
        first_non_null_record(&probed)
    }

    /// Build the authentication object for `event`, targeted at `pid`.
    ///
    /// # Safety
    ///
    /// The class and selector addresses must be the resolved ones, and `event`
    /// must be a live event object.
    unsafe fn authentication_message(
        symbols: &Symbols,
        event: *mut c_void,
        pid: i32,
    ) -> Option<*mut c_void> {
        let class = symbols.auth_class? as *mut c_void;
        let selector = symbols.auth_selector? as *mut c_void;
        let record = record_pointer(event)?;
        // objc_msgSend has no single Rust signature, so its address is retyped
        // to this factory's call shape. Coercing to a plain function pointer
        // first gives transmute two same-sized pointer types to convert.
        let base = objc_msgSend as unsafe extern "C" fn();
        let factory: unsafe extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            i32,
            u32,
        ) -> *mut c_void = std::mem::transmute(base);
        let message = factory(class, selector, record, pid, AUTH_MESSAGE_VERSION);
        (!message.is_null()).then_some(message)
    }

    /// Post one key-down/key-up pair to `pid` through the private entry point.
    ///
    /// With `attach_auth`, an authentication object is built from each event and
    /// attached before posting; the whole pair is posted only if both objects
    /// were produced, so a failure leaves nothing half-sent. Returns which of
    /// the outcomes occurred; it is not evidence the target acted on the keys.
    pub fn post_key_to_pid(pid: i32, event: &OwnedKeyEvent, attach_auth: bool) -> PostResult {
        let symbols = symbols();
        let Some(post_address) = symbols.post_to_pid else {
            return PostResult::SpiUnavailable;
        };
        let Some((down, up)) = event.pair() else {
            return PostResult::EventBuildFailed;
        };
        if attach_auth && !keyboard_auth_available() {
            return PostResult::AuthUnavailable;
        }
        let Some(set_address) = symbols.set_auth_message else {
            // Only reachable with attach_auth false; without the setter there is
            // no auth path, and the plain post below still runs.
            return post_pair(post_address, pid, down, up);
        };

        // SAFETY: the addresses are the resolved private symbols retyped to
        // their C signatures; the events are live for the duration of the call.
        // The autorelease pool drains the authentication objects, which the
        // factory returns autoreleased and this module does not own.
        objc2::rc::autoreleasepool(|_| unsafe {
            let down_ptr = (down as *const CGEvent).cast_mut().cast::<c_void>();
            let up_ptr = (up as *const CGEvent).cast_mut().cast::<c_void>();
            if attach_auth {
                let set_auth: unsafe extern "C" fn(*mut c_void, *mut c_void) =
                    std::mem::transmute(set_address);
                for raw in [down_ptr, up_ptr] {
                    let Some(message) = authentication_message(symbols, raw, pid) else {
                        return PostResult::AuthUnavailable;
                    };
                    set_auth(raw, message);
                }
            }
            let post: unsafe extern "C" fn(i32, *mut c_void) = std::mem::transmute(post_address);
            post(pid, down_ptr);
            post(pid, up_ptr);
            PostResult::Posted {
                auth_attached: attach_auth,
            }
        })
    }

    fn post_pair(post_address: usize, pid: i32, down: &CGEvent, up: &CGEvent) -> PostResult {
        // SAFETY: `post_address` is the resolved posting symbol retyped to its C
        // signature, and both events are live for the call.
        unsafe {
            let post: unsafe extern "C" fn(i32, *mut c_void) = std::mem::transmute(post_address);
            post(pid, (down as *const CGEvent).cast_mut().cast::<c_void>());
            post(pid, (up as *const CGEvent).cast_mut().cast::<c_void>());
        }
        PostResult::Posted {
            auth_attached: false,
        }
    }
}

#[cfg(target_os = "macos")]
pub use imp::{
    keyboard_auth_available, post_key_to_pid, skylight_available, OwnedKeyEvent, PostResult,
};

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use super::first_non_null_record;

    #[test]
    fn the_first_non_null_candidate_is_the_one_chosen() {
        let null = std::ptr::null_mut::<c_void>();
        let first = 0x1000 as *mut c_void;
        let second = 0x2000 as *mut c_void;
        // The first non-null wins even when a later candidate is also non-null,
        // so the probe order in the caller decides which offset is trusted.
        assert_eq!(first_non_null_record(&[null, first, second]), Some(first));
    }

    #[test]
    fn a_leading_non_null_is_not_skipped_for_a_later_one() {
        let first = 0x1000 as *mut c_void;
        let second = 0x2000 as *mut c_void;
        // Guards against a rule that returned the last match: with two non-null
        // candidates the answer must be the first, not the second.
        assert_eq!(first_non_null_record(&[first, second]), Some(first));
    }

    #[test]
    fn all_null_candidates_have_no_record() {
        let null = std::ptr::null_mut::<c_void>();
        assert_eq!(first_non_null_record(&[null, null, null]), None);
        assert_eq!(first_non_null_record(&[]), None);
    }
}
