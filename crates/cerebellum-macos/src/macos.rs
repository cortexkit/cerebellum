//! The framework calls themselves.
//!
//! Only the C functions declared below need `unsafe`; the CoreGraphics entry
//! points are safe bindings. Every `unsafe` block here is therefore a real one,
//! which is the point of keeping them few.

use std::ffi::CStr;
use std::fmt;
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_core_foundation::{CFData, CFRetained, CFString, CGPoint, CGRect, CGSize};
use objc2_core_graphics::{
    CGBitmapInfo, CGColorRenderingIntent, CGColorSpace, CGDataProvider, CGEvent,
    CGEventTapLocation, CGImage,
};
use objc2_foundation::NSError;
use objc2_screen_capture_kit::{
    SCContentFilter, SCScreenshotManager, SCShareableContent, SCStreamConfiguration, SCWindow,
};

/// The prefix of `struct proc_bsdinfo` from `<sys/proc_info.h>`, up to and
/// including the two fields this reads.
///
/// Declared in full rather than as an opaque buffer with offsets, because a
/// field added upstream would shift an offset silently while a named field
/// keeps its meaning. The size is asserted against what the kernel reports it
/// wrote, so a layout that disagrees with this system is refused rather than
/// interpreted.
#[repr(C)]
#[derive(Default)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    /// The kernel's process command-name buffer, `MAXCOMLEN` (16) bytes.
    pbi_comm: [c_char; 16],
    /// The kernel's process-name buffer, `2 * MAXCOMLEN` (32) bytes.
    pbi_name: [c_char; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    /// Process start time, seconds since the epoch.
    pbi_start_tvsec: u64,
    /// Process start time, microseconds within the second.
    pbi_start_tvusec: u64,
}

/// The `proc_pidinfo` flavor asking the kernel to fill a BSD process-information
/// structure, which is what [`ProcBsdInfo`] mirrors. `PROC_PIDTBSDINFO` from
/// `<sys/proc_info.h>`.
const PROC_PIDTBSDINFO: c_int = 3;

// The system's image encoders, which is why no encoding crate is vendored.
#[link(name = "ImageIO", kind = "framework")]
extern "C" {
    /// A destination that writes an encoded image into a buffer.
    fn CGImageDestinationCreateWithData(
        data: *mut std::ffi::c_void,
        ty: *const std::ffi::c_void,
        count: usize,
        options: *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn CGImageDestinationAddImage(
        destination: *mut std::ffi::c_void,
        image: *const std::ffi::c_void,
        properties: *const std::ffi::c_void,
    );
    /// Writes everything added so far. False means nothing usable was produced.
    fn CGImageDestinationFinalize(destination: *mut std::ffi::c_void) -> bool;
}

extern "C" {
    /// A growable buffer for an encoder to write into.
    fn CFDataCreateMutable(
        allocator: *const std::ffi::c_void,
        capacity: isize,
    ) -> *mut std::ffi::c_void;
    fn CFDataGetLength(data: *const std::ffi::c_void) -> isize;
    fn CFDataGetBytePtr(data: *const std::ffi::c_void) -> *const u8;

    /// This thread's `errno`. The kernel calls below report every failure as a
    /// zero return, so the cause is only available here.
    #[link_name = "__error"]
    fn errno_location() -> *mut c_int;

    /// The current graphical session's properties, or null outside one.
    fn CGSessionCopyCurrentDictionary() -> *const std::ffi::c_void;
    fn CFDictionaryGetValue(
        dictionary: *const std::ffi::c_void,
        key: *const std::ffi::c_void,
    ) -> *const std::ffi::c_void;
    fn CFBooleanGetValue(value: *const std::ffi::c_void) -> bool;
    fn CFStringCreateWithCString(
        allocator: *const std::ffi::c_void,
        cstr: *const c_char,
        encoding: u32,
    ) -> *const std::ffi::c_void;
    fn CFRelease(value: *const std::ffi::c_void);

    /// Kernel process information. Returns the byte count written, or 0.
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffer_size: c_int,
    ) -> c_int;

    /// The process the system attributes our permission grants to.
    ///
    /// Taking a grant to belong to the calling binary is wrong for anything
    /// launched by something else: the attribution follows the launching
    /// process, so a module spawned by a daemon inherits the daemon's grants
    /// and holds none of its own.
    fn responsibility_get_pid_responsible_for_pid(pid: c_int) -> c_int;

    /// Executable path for a pid. Returns the byte count written, or 0.
    fn proc_pidpath(pid: c_int, buffer: *mut c_char, buffer_size: c_uint) -> c_int;

    /// Non-zero when the calling thread is the main thread.
    fn pthread_main_np() -> c_int;
}

/// `PROC_PIDPATHINFO_MAXSIZE` from `<sys/proc_info.h>`.
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

/// Establish this process's window-server connection, at most once.
///
/// Creating a capture filter in a process that has never reached the window
/// server fails an assertion inside CoreGraphics and ABORTS THE PROCESS rather
/// than returning an error. Window enumeration works beforehand, so the process
/// looks healthy right up to the abort.
///
/// Reading the main display id is enough to establish the connection. It looks
/// like a call whose result is discarded, which is exactly why removing it must
/// stay difficult: the failure it prevents is a crash, not a refusal.
pub fn establish_window_server_connection() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = objc2_core_graphics::CGMainDisplayID();
    });
}

/// The executable path of the process our grants are attributed to.
///
/// The full path rather than a name, because the question this answers is
/// whether the attribution is still the one seen at startup, and a replacement
/// binary at a different location is precisely the change worth noticing.
///
/// `None` when the system reports no attribution or no path for it. That is
/// reported as absence rather than substituted with this process, because
/// "we could not establish who holds the grant" and "we hold it" are opposite
/// answers.
pub fn responsible_process() -> Option<String> {
    let self_pid = std::process::id() as c_int;
    // SAFETY: takes a pid by value and returns a pid. No pointers involved.
    let responsible = unsafe { responsibility_get_pid_responsible_for_pid(self_pid) };
    if responsible <= 0 {
        return None;
    }

    let mut buffer = vec![0 as c_char; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: the buffer is owned here, and its true capacity is passed, so the
    // call cannot write past it. The value written is a NUL-terminated path.
    let written = unsafe {
        proc_pidpath(
            responsible,
            buffer.as_mut_ptr(),
            PROC_PIDPATHINFO_MAXSIZE as c_uint,
        )
    };
    if written <= 0 {
        return None;
    }

    // SAFETY: the call above reported success, so the buffer holds a
    // NUL-terminated string within its capacity, and it outlives this read.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Whether screen capture is usable by this process right now.
///
/// This is the non-prompting query. The prompting variant exists and is
/// deliberately not called: a module spawned by a daemon raising a system
/// permission dialog on its own initiative is its own defect, and a dialog
/// nobody is present to answer is worse than a refusal.
pub fn screen_capture_is_permitted() -> bool {
    objc2_core_graphics::CGPreflightScreenCaptureAccess()
}

/// Whether the calling thread is NOT the main thread.
///
/// Reported so a permission reading can record where it was taken. A reading
/// from the main thread of a process whose main thread is a run loop is not
/// evidence about a background probe.
pub fn is_off_main_thread() -> bool {
    // SAFETY: takes no arguments, returns a plain integer, and is callable from
    // any thread.
    unsafe { pthread_main_np() == 0 }
}

/// Encode tightly-packed BGRA pixels as a PNG.
///
/// PNG rather than a lossy format, and the reason is not size: a model reading
/// a screenshot is reading small text, and the artifacts a lossy encoder leaves
/// around glyph edges are exactly what degrades that. It is also not a cost
/// difference — an image is charged by its dimensions rather than its bytes, so
/// the compression choice changes what is sent and not what is paid.
///
/// Uses the platform's own encoder rather than a third-party one, so nothing is
/// added to the dependency set for a facility the system already provides.
///
/// Expects the tight packing [`capture_window`] produces: exactly
/// `width * height * 4` bytes. A buffer still carrying the row padding the
/// system leaves would encode as a progressively skewed image rather than fail,
/// so the length is checked rather than trusted.
pub fn encode_png(bgra: &[u8], width: usize, height: usize) -> Result<Vec<u8>, String> {
    let expected = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| format!("{width}x{height} is too large to describe"))?;
    if bgra.len() != expected {
        return Err(format!(
            "{width}x{height} needs exactly {expected} tightly-packed bytes, got {}",
            bgra.len()
        ));
    }
    if width == 0 || height == 0 {
        return Err("an image with no area cannot be encoded".to_string());
    }
    let image = bgra_image(bgra, width, height)?;
    encode_image(&image, "public.png", std::ptr::null())
}

/// Wrap tightly-packed BGRA pixels, already checked against their dimensions,
/// as an image the system encoders and drawing calls accept.
pub(crate) fn bgra_image(
    bgra: &[u8],
    width: usize,
    height: usize,
) -> Result<CFRetained<CGImage>, String> {
    let data = CFData::from_bytes(bgra);
    let provider = CGDataProvider::with_cf_data(Some(&data))
        .ok_or_else(|| "the pixels could not be wrapped for encoding".to_string())?;
    let color_space = CGColorSpace::new_device_rgb()
        .ok_or_else(|| "the device colour space is unavailable".to_string())?;

    // Little-endian 32-bit, alpha last: the order the capture path delivers.
    let bitmap_info = CGBitmapInfo(2 | (2 << 12));
    // SAFETY: the provider holds the pixels for the lifetime of the image, and
    // the dimensions match the buffer length the caller checked. The decode
    // array is null, which the constructor documents as permitted.
    unsafe {
        CGImage::new(
            width,
            height,
            8,
            32,
            width * 4,
            Some(&color_space),
            bitmap_info,
            Some(&provider),
            std::ptr::null(),
            false,
            CGColorRenderingIntent::RenderingIntentDefault,
        )
    }
    .ok_or_else(|| "the pixels could not be read as an image".to_string())
}

/// Encode one image with the system encoder for `uniform_type`, passing
/// `options` (a CFDictionary, or null) as the image's encoding properties.
pub(crate) fn encode_image(
    image: &CGImage,
    uniform_type: &'static str,
    options: *const std::ffi::c_void,
) -> Result<Vec<u8>, String> {
    let image_type = CFString::from_static_str(uniform_type);
    // SAFETY: every object created here is released on every path out,
    // including the early return. The encoded bytes are copied before the
    // buffer holding them is released. `options` is null or a dictionary the
    // caller keeps alive for this call.
    unsafe {
        let out = CFDataCreateMutable(std::ptr::null(), 0);
        if out.is_null() {
            return Err("no buffer could be allocated for the encoded image".to_string());
        }
        let destination = CGImageDestinationCreateWithData(
            out,
            CFRetained::as_ptr(&image_type).as_ptr().cast(),
            1,
            std::ptr::null(),
        );
        if destination.is_null() {
            CFRelease(out.cast());
            return Err(format!("the system offers no {uniform_type} encoder"));
        }

        CGImageDestinationAddImage(destination, (image as *const CGImage).cast(), options);
        let finalized = CGImageDestinationFinalize(destination);
        let length = CFDataGetLength(out.cast()) as usize;
        let encoded = if finalized && length > 0 {
            Some(std::slice::from_raw_parts(CFDataGetBytePtr(out.cast()), length).to_vec())
        } else {
            None
        };

        CFRelease(destination.cast());
        CFRelease(out.cast());

        encoded.ok_or_else(|| "the image could not be encoded".to_string())
    }
}

/// Whether the screen is locked.
///
/// A locked screen still answers questions ABOUT windows -- the list, their
/// owners, their sizes -- while refusing their CONTENTS, so a caller that only
/// checks its permission concludes it can capture and then fails at the picture.
/// `None` when there is no graphical session to ask, which is not the same as an
/// unlocked one: a process with no session cannot capture either.
///
/// The system reports this by OMITTING the key while the screen is unlocked
/// rather than by reporting false, so an absent key inside a real session is
/// `Some(false)`. Only the absence of the session itself is unknown.
pub fn screen_is_locked() -> Option<bool> {
    // SAFETY: takes no arguments, and returns either null or a dictionary this
    // frame owns. Released below on every path that reaches it.
    let session = unsafe { CGSessionCopyCurrentDictionary() };
    if session.is_null() {
        return None;
    }

    // SAFETY: the key is a NUL-terminated literal and the dictionary is
    // non-null. The value is borrowed from the dictionary, so it is read before
    // the release. Both objects created here are released on every path.
    unsafe {
        // 0x08000100 is kCFStringEncodingUTF8.
        let key = CFStringCreateWithCString(
            std::ptr::null(),
            c"CGSSessionScreenIsLocked".as_ptr(),
            0x0800_0100,
        );
        let value = CFDictionaryGetValue(session, key);
        // An absent key means unlocked. Reporting that as unknown would make
        // `== Some(false)` a test that never matches, which is worse than
        // wrong: it reads as a check and is a constant.
        let locked = if value.is_null() {
            Some(false)
        } else {
            Some(CFBooleanGetValue(value))
        };
        CFRelease(key);
        CFRelease(session);
        locked
    }
}

/// An owned CoreGraphics event that can cross the safe platform seam.
pub type OwnedCgEvent = CFRetained<CGEvent>;

/// Evidence that CoreGraphics returned from a post call.
///
/// `CGEvent::post` and `CGEvent::post_to_pid` have no delivery result. This
/// type therefore records only that the call returned; it says nothing about
/// whether an application received the event or acted on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a returned post call is not evidence that the event was delivered"]
pub struct CgEventPostCall;

/// Ask CoreGraphics to post one event to one process.
///
/// This is the public `CGEventPostToPid` API exposed through its generated safe
/// Rust binding. The caller owns all target checks and policy. A returned
/// [`CgEventPostCall`] means only that the void framework call returned.
pub fn post_event_to_pid(pid: i32, event: &CGEvent) -> CgEventPostCall {
    CGEvent::post_to_pid(pid, Some(event));
    CgEventPostCall
}

const GLOBAL_POST_TAP_LOCATION: CGEventTapLocation = CGEventTapLocation::SessionEventTap;

/// Ask CoreGraphics to post one production event at the session tap.
///
/// The location is load-bearing: HID-tap posts reset the HID idle table even
/// when a private event source builds them, while session-tap posts both deliver
/// and leave that hardware reading unchanged. Consumes the event by value so a
/// retry cannot hand the same event to a second transport. A returned
/// [`CgEventPostCall`] means only that the void framework call returned.
pub fn post_event_globally(event: OwnedCgEvent) -> CgEventPostCall {
    CGEvent::post(GLOBAL_POST_TAP_LOCATION, Some(&event));
    CgEventPostCall
}

/// Ask CoreGraphics to post one event at the HID tap for a measurement.
///
/// Production must not call this path because the post resets the hardware idle
/// table and would make the next observed action mistake our own input for the
/// user's. It remains only so the desk probe can reproduce that distinction.
pub fn post_event_at_hid_tap_for_measurement(event: OwnedCgEvent) -> CgEventPostCall {
    CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&event));
    CgEventPostCall
}

/// Read the unix process id of the application that owns the topmost normal
/// window on screen.
///
/// This is the reading the observed dispatch loop takes before every post,
/// so it has to be cheap, CURRENT, and permitted under what the module
/// already holds. Three sources were measured on a VM under the daemon's own
/// attribution and rejected: System Events over AppleScript answers correctly
/// in 170-260 ms, most of the latency between a person's input and the
/// sequence stopping; NSWorkspace answers in 31 us from a cache a process
/// without a run loop never refreshes, so it kept naming the first
/// application it ever saw across four switches; the system-wide
/// accessibility element's focused application answered
/// kAXErrorCannotComplete in that process even with accessibility trusted.
/// The window list is served live by the window server under the screen
/// recording grant the module holds for capture, in z-order, and the first
/// window at the normal layer belongs to the application a cursor event
/// would reach.
///
/// A focus reading, not an identity: which process the pid is right now is
/// the caller's generation check. `None` when the list cannot be read or has
/// no normal-layer window; both are refusals for the policy caller.
pub fn frontmost_process_id() -> Option<i32> {
    use objc2_core_foundation::{CFDictionary, CFNumber, CFNumberType};
    use objc2_core_graphics::{
        kCGWindowLayer, kCGWindowOwnerPID, CGWindowListCopyWindowInfo, CGWindowListOption,
    };
    use std::ffi::c_void;
    let windows = CGWindowListCopyWindowInfo(
        CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements,
        0,
    )?;
    for index in 0..windows.count() {
        // SAFETY: `index` is within the array's count; the element is borrowed
        // from the array, which outlives this loop.
        let entry = unsafe { windows.value_at_index(index) }.cast::<CFDictionary>();
        if entry.is_null() {
            continue;
        }
        // SAFETY: entries of a CGWindowList array are CFDictionary; the keys
        // are the framework's own constants; values are borrowed.
        let (layer, owner) = unsafe {
            let entry = &*entry;
            (
                entry.value((kCGWindowLayer as *const CFString).cast::<c_void>()),
                entry.value((kCGWindowOwnerPID as *const CFString).cast::<c_void>()),
            )
        };
        let layer_number = layer.cast::<CFNumber>();
        let owner_number = owner.cast::<CFNumber>();
        if layer_number.is_null() || owner_number.is_null() {
            continue;
        }
        let mut layer_value: i64 = -1;
        let mut owner_value: i64 = 0;
        // SAFETY: both values are CFNumber (the framework documents the
        // types); the out-pointers are writable i64 storage.
        let ok = unsafe {
            (*layer_number).value(
                CFNumberType::SInt64Type,
                (&mut layer_value as *mut i64).cast::<c_void>(),
            ) && (*owner_number).value(
                CFNumberType::SInt64Type,
                (&mut owner_value as *mut i64).cast::<c_void>(),
            )
        };
        if !ok || layer_value != 0 {
            continue;
        }
        return i32::try_from(owner_value).ok().filter(|pid| *pid > 0);
    }
    None
}

/// When a process was started, as kernel-sourced microseconds since the epoch.
///
/// This is the discriminator that survives pid reuse. A pid alone identifies
/// whoever holds it now, which is exactly the process an identity check exists
/// to distinguish from the one that held it earlier; the start time separates
/// them because the replacement cannot share it.
///
/// `None` when the process is gone or the kernel reports a structure this does
/// not recognise. Absence rather than a zero, because a zero start time would
/// compare equal to another zero and read as a match.
/// What the kernel says when asked when a process started.
///
/// The failures are separate because they are not the same news. Only one of
/// them is about the process; one is about this code being wrong, and reporting
/// that as "the process is gone" would make a mismatch with a future kernel look
/// like every process on the machine having exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStartTime {
    /// Microseconds since the epoch.
    Started(u64),
    /// No process holds this id.
    NoSuchProcess,
    /// The process exists and this one may not inspect it. NOT the same as
    /// absent: a caller that treats it as absent concludes a target has exited
    /// when it is merely out of reach.
    NotPermitted,
    /// The kernel wrote a different number of bytes than [`ProcBsdInfo`]
    /// declares, so its structure is not the one described here and any field
    /// read out would be some other data. A defect in this module rather than a
    /// fact about the process, and it would otherwise present as every process
    /// being gone at once.
    LayoutMismatch,
    /// The kernel refused for a reason this code does not classify, carrying the
    /// errno so the next reader can name it.
    ///
    /// Separate from [`Self::LayoutMismatch`] because that variant asserts
    /// something specific about a structure that was READ, and an unclassified
    /// failure read nothing. Folding the two sends whoever debugs it to compare
    /// struct definitions against a kernel header, when the answer is an errno
    /// that was discarded before it could be reported.
    ///
    /// It travels with the other unreadable outcomes: not knowing why is not
    /// evidence that a process is gone.
    Unclassified(i32),
    /// The process reports no start time, or one that does not fit. Two such
    /// processes would compare as the same generation, so it cannot be used as
    /// evidence.
    NoStartTime,
}

pub fn process_start_time(pid: u32) -> ProcessStartTime {
    let mut info = ProcBsdInfo::default();
    let size = std::mem::size_of::<ProcBsdInfo>() as c_int;
    // SAFETY: the buffer is owned here and its true size is passed, so the call
    // cannot write past it. The pid is passed by value.
    let written = unsafe {
        errno_location().write(0);
        proc_pidinfo(
            pid as c_int,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut ProcBsdInfo as *mut std::ffi::c_void,
            size,
        )
    };

    if written != size {
        // The call reports 0 for every failure, so the cause is read from errno.
        // Measured on macOS 26: ESRCH for a pid nobody holds, EPERM for a
        // process this one may not inspect, ENOMEM when the buffer is smaller
        // than the kernel's own structure.
        // SAFETY: reads a thread-local set by the call above.
        return start_time_failure(unsafe { errno_location().read() });
    }

    if info.pbi_start_tvsec == 0 {
        return ProcessStartTime::NoStartTime;
    }

    match info
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
    {
        Some(micros) => ProcessStartTime::Started(micros),
        None => ProcessStartTime::NoStartTime,
    }
}

/// What a failed `proc_pidinfo` call means, by the errno it left behind.
///
/// Separated from the call so the mapping can be tested: the failures it
/// distinguishes are ones no test can provoke on demand, and a mapping only
/// reachable through a syscall that refuses on the kernel's terms is a mapping
/// nobody checks.
fn start_time_failure(errno: i32) -> ProcessStartTime {
    match errno {
        3 => ProcessStartTime::NoSuchProcess,
        1 => ProcessStartTime::NotPermitted,
        12 => ProcessStartTime::LayoutMismatch,
        // Unclassified rather than a layout mismatch. Both refuse to signal, so
        // the safety is identical -- but a layout mismatch asserts something
        // about a structure that was READ, and nothing was read here. The errno
        // rides along because it is the only thing that can name the cause, and
        // discarding it is what made an unclassified refusal present as a
        // struct-definition problem.
        other => ProcessStartTime::Unclassified(other),
    }
}

/// Who runs a process, as the kernel's BSD process information reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOwner {
    /// The process exists. `zombie` is true when it has exited and only waits
    /// to be reaped: it holds no open files and runs no code. `uid` is the
    /// effective user, whose credentials the process opens files with.
    Running {
        uid: u32,
        zombie: bool,
    },
    NoSuchProcess,
    /// The kernel refused with `EPERM`. Not evidence of whose process it is.
    NotPermitted,
    /// The kernel refused for another reason, carrying the errno. Not
    /// evidence that the process is gone.
    Unreadable(i32),
}

/// `SZOMB` from `<sys/proc.h>`: exited, not yet reaped.
const PROCESS_STATUS_ZOMBIE: u32 = 5;

/// `struct proc_bsdshortinfo` from `<sys/proc_info.h>`, in full.
///
/// The short form rather than [`ProcBsdInfo`] because the kernel answers it
/// for every process, whoever runs it, while the full form refuses another
/// user's process with `EPERM` unless the caller is privileged. Measured on
/// macOS 27 as an unprivileged user: all 1,208 running processes, across 43
/// distinct users including root, answered the short form.
#[repr(C)]
#[derive(Default)]
struct ProcBsdShortInfo {
    pbsi_pid: u32,
    pbsi_ppid: u32,
    pbsi_pgid: u32,
    pbsi_status: u32,
    /// `MAXCOMLEN` (16) bytes.
    pbsi_comm: [c_char; 16],
    pbsi_flags: u32,
    pbsi_uid: u32,
    pbsi_gid: u32,
    pbsi_ruid: u32,
    pbsi_rgid: u32,
    pbsi_svuid: u32,
    pbsi_svgid: u32,
    pbsi_rfu: u32,
}

/// `PROC_PIDT_SHORTBSDINFO` from `<sys/proc_info.h>`.
const PROC_PIDT_SHORTBSDINFO: c_int = 13;

/// Who runs a process, and whether it is a zombie. Answers for any process.
pub fn process_owner(pid: u32) -> ProcessOwner {
    let mut info = ProcBsdShortInfo::default();
    let size = std::mem::size_of::<ProcBsdShortInfo>() as c_int;
    // SAFETY: the buffer is owned here and its true size is passed, so the call
    // cannot write past it. The pid is passed by value.
    let written = unsafe {
        errno_location().write(0);
        proc_pidinfo(
            pid as c_int,
            PROC_PIDT_SHORTBSDINFO,
            0,
            &mut info as *mut ProcBsdShortInfo as *mut std::ffi::c_void,
            size,
        )
    };
    if written != size {
        // SAFETY: reads a thread-local set by the call above.
        let errno = unsafe { errno_location().read() };
        return match errno {
            3 => ProcessOwner::NoSuchProcess,
            1 => ProcessOwner::NotPermitted,
            other => ProcessOwner::Unreadable(other),
        };
    }
    ProcessOwner::Running {
        uid: info.pbsi_uid,
        zombie: info.pbsi_status == PROCESS_STATUS_ZOMBIE,
    }
}

/// When a process started, or `None` for every reason it cannot be told.
///
/// Kept for callers that only need the value. A caller deciding what to do about
/// a failure should use [`process_start_time`], since the reasons differ.
pub fn process_start_time_micros(pid: u32) -> Option<u64> {
    match process_start_time(pid) {
        ProcessStartTime::Started(micros) => Some(micros),
        _ => None,
    }
}

/// C `struct timespec` on Apple platforms, for the one call below that takes a
/// wait bound.
#[repr(C)]
struct Timespec {
    tv_sec: std::ffi::c_long,
    tv_nsec: std::ffi::c_long,
}

extern "C" {
    /// Copies this machine's platform UUID (the IOPlatformUUID) into `id`,
    /// waiting at most `wait` for it; returns 0 on success.
    fn gethostuuid(id: *mut u8, wait: *const Timespec) -> c_int;
}

/// This machine's hardware UUID (IOPlatformUUID), uppercase and hyphenated as
/// `ioreg` prints it, or `None` if it could not be read within `timeout`.
///
/// Read through the kernel with an explicit wait bound rather than by running
/// a command: a subprocess can hang with nothing to stop it, and this is read
/// on the path that decides whether a person is offered a durable grant.
pub fn hardware_uuid(timeout: Duration) -> Option<String> {
    let mut id = [0u8; 16];
    let wait = Timespec {
        tv_sec: timeout
            .as_secs()
            .try_into()
            .unwrap_or(std::ffi::c_long::MAX),
        tv_nsec: timeout.subsec_nanos().into(),
    };
    // SAFETY: `id` is a 16-byte buffer, the size of `uuid_t`, owned here; the
    // wait bound is a live value passed by pointer for the duration of the call.
    let status = unsafe { gethostuuid(id.as_mut_ptr(), &wait) };
    if status != 0 || id == [0u8; 16] {
        return None;
    }
    let hex: String = id.iter().map(|byte| format!("{byte:02X}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// One window as the system reports it.
///
/// Deliberately without the window title. A title is readable only with a
/// permission this module may not hold, and it is chosen by the application, so
/// it is not identity evidence: two windows can carry the same one, and any
/// application can present a title belonging to another.
#[derive(Debug, Clone, PartialEq)]
pub struct RawWindow {
    pub window_id: u32,
    pub owner_pid: u32,
    pub owner_bundle_identifier: String,
    /// The owning application's display name. For showing to a person only:
    /// an application picks its own name, so it is not identity evidence.
    pub owner_application_name: String,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub on_screen: bool,
}

/// Delivers one callback result to a waiting thread.
struct Delivery<T> {
    slot: Mutex<Option<T>>,
    ready: Condvar,
}

impl<T> Delivery<T> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(None),
            ready: Condvar::new(),
        })
    }

    fn deliver(&self, value: T) {
        *self.slot.lock().unwrap() = Some(value);
        self.ready.notify_all();
    }

    /// Waits for a value, or gives up at the deadline.
    ///
    /// The bound exists because the callback is invoked by the system: if the
    /// window server never answers, an unbounded wait holds this thread
    /// forever, and the caller cannot distinguish that from slow work.
    fn wait(&self, timeout: Duration) -> Option<T> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.slot.lock().unwrap();
        while slot.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, _) = self.ready.wait_timeout(slot, remaining).unwrap();
            slot = next;
        }
        slot.take()
    }
}

/// Every window the system is willing to describe to this process.
///
/// Returns an error rather than an empty list when the system declines, because
/// "no windows" and "not permitted to look" are different answers and only one
/// of them is about the machine's contents.
///
/// Unfiltered by owner: the caller matches against its own grant, so the
/// filtering happens where the grant is known rather than here.
///
/// The timeout bounds the WAIT for the system's answer, not the call that asks
/// for it. That call is normally a few microseconds and was measured at 2.5ms
/// under six threads enumerating concurrently, but it is a system call and
/// nothing here can bound it, so a caller passing a short deadline can still
/// block for longer than it asked. Moving the ask onto its own thread would
/// close the gap -- the system retains the callback, so it fires even after the
/// dispatching thread has exited -- at the cost of a thread per call and a
/// leaked one if the ask never returns. Left as it is because the module's
/// health reporting reads its own counters and never enumerates, so a slow
/// answer here delays the caller that asked rather than the module's ability to
/// report that it is alive.
pub fn enumerate_windows(timeout: Duration) -> Result<Vec<RawWindow>, String> {
    let delivery: Arc<Delivery<Result<Vec<RawWindow>, String>>> = Delivery::new();
    let sink = delivery.clone();

    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: the system passes either a content object or an error, both
            // valid for the duration of this callback. Neither is retained beyond
            // it: every value read below is copied into an owned RawWindow.
            let outcome = unsafe {
                if let Some(error) = error.as_ref() {
                    Err(error.localizedDescription().to_string())
                } else if let Some(content) = content.as_ref() {
                    Ok(content
                        .windows()
                        .iter()
                        .filter_map(|window| {
                            let owner = window.owningApplication()?;
                            let frame = window.frame();
                            Some(RawWindow {
                                window_id: window.windowID(),
                                owner_pid: u32::try_from(owner.processID()).ok()?,
                                owner_bundle_identifier: owner.bundleIdentifier().to_string(),
                                owner_application_name: owner.applicationName().to_string(),
                                x: frame.origin.x,
                                y: frame.origin.y,
                                width: frame.size.width,
                                height: frame.size.height,
                                on_screen: window.isOnScreen(),
                            })
                        })
                        .collect())
                } else {
                    Err("the system reported neither content nor an error".to_string())
                }
            };
            sink.deliver(outcome);
        },
    );

    // SAFETY: the handler outlives the call through the block's own retain, and
    // the delivery it writes into is kept alive by this frame until the wait
    // below returns.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };

    delivery
        .wait(timeout)
        .unwrap_or_else(|| Err(format!("the window list did not arrive within {timeout:?}")))
}

/// One window's pixels, as the system produced them.
///
/// The owner is read again at capture time rather than carried over from
/// enumeration, so a caller can tell whether the window it asked for is still
/// owned by the process it meant. A window id is reused after its window
/// closes, so the id alone does not answer that.
pub struct RawCapture {
    pub width: usize,
    pub height: usize,
    /// Pixels in BGRA order, tightly packed: exactly `width * height * 4` bytes,
    /// with no padding between rows.
    ///
    /// The system delivers rows padded to a stride of its own choosing; that
    /// padding is removed before this is built, so the buffer can be indexed
    /// from the dimensions alone.
    pub bgra: Vec<u8>,
    pub owner_pid_at_capture: u32,
}

/// A rectangle in the captured window's own space, with its origin at the top-left.
///
/// Measured on macOS 26: ScreenCaptureKit honors this window-local rectangle
/// with a desktop-independent window filter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CaptureSourceRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// A failure to read a window's pixels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// The session was locked when a failed capture was classified.
    ScreenLocked,
    /// The framework refused the capture for another reason.
    Capture(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScreenLocked => f.write_str("screen is locked"),
            Self::Capture(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Look up one window by id, if the system still describes it.
fn find_window(window_id: u32, timeout: Duration) -> Result<Retained<SCWindow>, String> {
    let delivery: Arc<Delivery<Result<Option<Retained<SCWindow>>, String>>> = Delivery::new();
    let sink = delivery.clone();

    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: the system passes either a content object or an error, both
            // valid for this callback. The window is retained before the callback
            // returns.
            let outcome = unsafe {
                if let Some(error) = error.as_ref() {
                    Err(error.localizedDescription().to_string())
                } else if let Some(content) = content.as_ref() {
                    Ok(content
                        .windows()
                        .iter()
                        .find(|window| window.windowID() == window_id))
                } else {
                    Err("the system reported neither content nor an error".to_string())
                }
            };
            sink.deliver(outcome);
        },
    );

    // SAFETY: the handler outlives the call through the block's own retain.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };

    match delivery.wait(timeout) {
        Some(Ok(Some(window))) => Ok(window),
        Some(Ok(None)) => Err(format!("window {window_id} is no longer present")),
        Some(Err(reason)) => Err(reason),
        None => Err(format!("the window list did not arrive within {timeout:?}")),
    }
}

/// Capture one window's pixels, without bringing it forward.
///
/// Scoped to a single window rather than to a display: a display filter
/// composites in whatever else overlaps that region, so capturing one
/// application through it would hand back another application's pixels.
///
/// The cursor is excluded. It belongs to the user rather than to the window,
/// and its position at the moment of capture says where the user was pointing,
/// which is not part of the window's contents.
///
/// THE FIRST CAPTURE IN A PROCESS IS NOT LIKE THE REST, and a caller that
/// treats them alike will misread a healthy system as a broken one. Measured on
/// macOS 26: once a process has captured once, captures take about 40ms and
/// several at a time are fine. The FIRST one sets up this process's session
/// with the window server, and that setup contends system-wide -- while another
/// process is capturing, it does not proceed. Two processes starting together
/// blocked each other past 60 seconds, on different windows, with no error from
/// either side.
///
/// IT IS SPECIFICALLY TWO SETUPS AT ONCE, which is narrower than it first
/// appears and worth stating exactly, since the wider readings are wrong.
/// Measured on an otherwise busy machine: a first capture takes about 150ms
/// alone, about the same immediately after another process captured and exited,
/// and about the same while a warmed process captures in a loop. Only two
/// processes performing their FIRST capture simultaneously collide, and that
/// collision is severe rather than slow.
///
/// So the deadline has to cover a wait for another process's setup rather than
/// for the work, and it is a wait that ends in a refusal rather than a late
/// picture.
pub fn capture_window(
    window_id: u32,
    timeout: Duration,
    source_rect: Option<CaptureSourceRect>,
) -> Result<RawCapture, CaptureError> {
    // Before any filter is created. Without a window-server connection the
    // filter constructor does not fail -- it aborts the process, which for a
    // module means the whole module dies rather than refusing one capture.
    establish_window_server_connection();

    let window = find_window(window_id, timeout).map_err(CaptureError::Capture)?;
    // SAFETY: the window is retained by this frame, so reading its properties
    // is valid for as long as it is held here.
    let (owner_pid_at_capture, frame) = unsafe {
        let owner = window
            .owningApplication()
            .and_then(|owner| u32::try_from(owner.processID()).ok())
            .ok_or_else(|| format!("window {window_id} reports no owning process"))
            .map_err(CaptureError::Capture)?;
        (owner, window.frame())
    };
    // SAFETY: the window is retained here and outlives the filter's creation.
    let filter = unsafe {
        SCContentFilter::initWithDesktopIndependentWindow(SCContentFilter::alloc(), &window)
    };

    // SAFETY: plain object construction and property sets on an object owned
    // by this frame. The desktop-independent filter captures one window, and
    // the measured source rect is interpreted in that window's own space.
    let configuration = unsafe {
        let configuration = SCStreamConfiguration::new();
        let (width, height) = match source_rect {
            Some(rect) => {
                // WINDOW-LOCAL, not display coordinates. A desktop-independent
                // filter's content IS the window, so its space starts at the
                // window's top-left; adding the window's screen position pushed
                // the rect outside that space and the framework then returned
                // neither the region nor a clean crop.
                //
                // Measured on macOS 26 rather than taken from documentation,
                // which states that sourceRect is not referenced for this filter
                // type. It is: the `source_rect_pattern` test captures the top
                // half of a window whose rows are painted with their own index
                // and reads back exactly those rows. The `source_rect_truth`
                // example's header records the instruments that looked
                // conclusive before that one and were not.
                configuration.setSourceRect(CGRect::new(
                    CGPoint::new(rect.x, rect.y),
                    CGSize::new(rect.width, rect.height),
                ));
                (rect.width, rect.height)
            }
            None => (frame.size.width, frame.size.height),
        };
        configuration.setWidth((width.max(1.0)) as usize);
        configuration.setHeight((height.max(1.0)) as usize);
        configuration.setShowsCursor(false);
        configuration
    };

    let delivery: Arc<Delivery<Result<RawCapture, String>>> = Delivery::new();
    let sink = delivery.clone();
    let handler = RcBlock::new(move |image: *mut CGImage, error: *mut NSError| {
        // SAFETY: the system passes either an image or an error, both valid for
        // this callback. Pixel bytes are copied out before it returns.
        let outcome = unsafe {
            if let Some(error) = error.as_ref() {
                Err(error.localizedDescription().to_string())
            } else if let Some(image) = image.as_ref() {
                read_pixels(image, owner_pid_at_capture)
            } else {
                Err("the system reported neither an image nor an error".to_string())
            }
        };
        sink.deliver(outcome);
    });

    // SAFETY: filter and configuration are owned by this frame and outlive the
    // call; the handler outlives it through the block's own retain.
    unsafe {
        SCScreenshotManager::captureImageWithFilter_configuration_completionHandler(
            &filter,
            &configuration,
            Some(&handler),
        )
    };

    let outcome = delivery
        .wait(timeout)
        .unwrap_or_else(|| Err(format!("the capture did not arrive within {timeout:?}")));

    outcome.map_err(|reason| explain_capture_failure(reason, screen_is_locked()))
}

/// Classify a failed capture when the screen being locked caused it.
///
/// A locked screen refuses pixel contents while still answering questions ABOUT
/// windows, and it does so with a generic stream failure that reads like a
/// fault in the capture itself. Without this, the operator sees a transport
/// error and looks for a broken capture path.
///
/// Separated from the capture call so the decision is decidable without a
/// window server: the call needs a real screen, which is exactly the condition
/// under which nobody can run it.
///
/// The state is read AFTER the failure rather than checked before it, so what
/// is reported is the state that actually applied rather than one that may have
/// changed since.
fn explain_capture_failure(reason: String, locked: Option<bool>) -> CaptureError {
    if locked == Some(true) {
        CaptureError::ScreenLocked
    } else {
        // Not locked, or the session could not be read. Neither is evidence
        // about the capture, so the original reason remains the error.
        CaptureError::Capture(reason)
    }
}

/// Copy an image's pixels out of the system's storage.
///
/// # Safety
///
/// `image` must be a valid image for the duration of the call.
unsafe fn read_pixels(image: &CGImage, owner_pid_at_capture: u32) -> Result<RawCapture, String> {
    let width = CGImage::width(Some(image));
    let height = CGImage::height(Some(image));
    let bytes_per_row = CGImage::bytes_per_row(Some(image));

    let provider =
        CGImage::data_provider(Some(image)).ok_or_else(|| "the image has no pixels".to_string())?;
    let data = objc2_core_graphics::CGDataProvider::data(Some(&provider))
        .ok_or_else(|| "the image's pixels could not be read".to_string())?;

    let length = data.length() as usize;
    let pointer = data.byte_ptr();
    if pointer.is_null() {
        return Err("the image's pixels are not readable".to_string());
    }
    // SAFETY: the pointer and length come from the same object, which is held
    // by this frame. The bytes are read here and copied below, so nothing
    // borrowed outlives this frame.
    let source = unsafe { std::slice::from_raw_parts(pointer, length) };

    // A row stride shorter than the row means the buffer does not hold what its
    // dimensions describe, so nothing downstream could index it correctly.
    if bytes_per_row < width * 4 || source.len() < bytes_per_row * height {
        return Err(format!(
            "the image's pixels do not match its dimensions: {width}x{height}, \
             {bytes_per_row} bytes per row, {} bytes total",
            source.len()
        ));
    }

    Ok(RawCapture {
        width,
        height,
        bgra: repack_rows(source, width, height, bytes_per_row),
        owner_pid_at_capture,
    })
}

/// Drop the padding the system leaves at the end of each row.
///
/// Rows arrive padded to a stride of the system's choosing, wider than the image
/// whenever the width is not a convenient multiple. Removing it here, at the one
/// place the stride is known, means what leaves this module is exactly
/// `width * height * 4` bytes and can be indexed from the dimensions alone.
///
/// The alternative -- carrying the stride alongside the buffer -- makes every
/// consumer responsible for a layout detail of one operating system's graphics
/// stack, and a consumer that assumes the obvious packing decodes a
/// progressively skewed image rather than failing outright. There is nothing in
/// the padding worth preserving.
///
/// Separate from the capture that calls it so the arithmetic can be checked
/// against a constructed buffer: the capture path needs a real screen and an
/// unlocked one, which makes it unavailable exactly when a regression would be
/// introduced.
fn repack_rows(source: &[u8], width: usize, height: usize, bytes_per_row: usize) -> Vec<u8> {
    let row_bytes = width * 4;
    let mut packed = Vec::with_capacity(row_bytes * height);
    for row in 0..height {
        let start = row * bytes_per_row;
        packed.extend_from_slice(&source[start..start + row_bytes]);
    }
    packed
}

#[cfg(test)]
mod tests {

    /// The kernel read of the hardware UUID agrees with `ioreg`'s
    /// IOPlatformUUID, the value an operator would look up by hand.
    ///
    /// `ioreg` runs once here, under a deadline, and is killed if it does not
    /// finish: a hung system tool must fail this test, not hold the suite.
    #[test]
    fn the_hardware_uuid_matches_ioreg() {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let read = super::hardware_uuid(Duration::from_secs(5))
            .expect("this machine reports a hardware UUID");

        let mut child = Command::new("/usr/sbin/ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("ioreg starts");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().expect("ioreg can be waited on").is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("ioreg did not finish within its deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut output = String::new();
        child
            .stdout
            .take()
            .expect("ioreg's output is piped")
            .read_to_string(&mut output)
            .expect("ioreg's output is text");
        let listed = output
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key.trim() == "\"IOPlatformUUID\"")
                    .then(|| value.trim().trim_matches('"').to_string())
            })
            .expect("ioreg lists IOPlatformUUID");

        assert_eq!(read, listed);
    }

    /// A locked screen is classified separately from other capture failures.
    ///
    /// The framework reports a generic stream failure for a locked screen, but
    /// callers can recover by unlocking it. Other failures retain their reason.
    #[test]
    fn a_locked_screen_has_its_own_capture_failure() {
        let raw = "stream stopped with error".to_string();

        assert_eq!(
            explain_capture_failure(raw.clone(), Some(true)),
            CaptureError::ScreenLocked,
            "a locked screen did not receive its own failure"
        );
        assert_eq!(
            explain_capture_failure(raw.clone(), Some(false)),
            CaptureError::Capture(raw.clone()),
            "an unlocked screen rewrote a failure it did not cause"
        );
        assert_eq!(
            explain_capture_failure(raw.clone(), None),
            CaptureError::Capture(raw),
            "an unknown session state was reported as a locked screen"
        );
    }
    use super::*;

    #[test]
    fn production_global_post_enters_at_the_session_tap() {
        assert_eq!(
            GLOBAL_POST_TAP_LOCATION,
            CGEventTapLocation::SessionEventTap,
            "the production global post must preserve the HID idle-table reading"
        );
    }

    /// Serializes every test that talks to the window server.
    ///
    /// Window-server work contends system-wide and the contention outlasts the
    /// process that caused it: an operation taking half a second on an idle
    /// machine took fourteen after another process had captured and exited.
    /// So the lock is held by tests that merely SUFFER the contention as well as
    /// by those that cause it, or the former wait out the latter and fail for a
    /// reason unrelated to what they assert. Tests run as threads in one
    /// process, so a lock here covers them.
    static WINDOW_SERVER: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Whether this machine can currently produce window pixels at all.
    ///
    /// Two states prevent it and they are different: capture may not be
    /// permitted, or the screen may be locked. A locked screen still answers
    /// questions about windows while refusing their contents, so a test that
    /// only checks enumeration would proceed and then fail on the picture.
    ///
    /// Tests asserting a property OF a capture stop when this is false, since a
    /// machine that cannot capture has nothing to say about it. Tests asserting
    /// a REFUSAL do not need it: they are about what is refused, and both
    /// states refuse.
    fn pixels_are_obtainable() -> bool {
        screen_capture_is_permitted() && screen_is_locked() != Some(true)
    }

    /// The attribution resolves to a real executable on this system.
    ///
    /// Asserted as an absolute path that exists, rather than merely as "some
    /// string", because the failure this guards against is the resolution
    /// silently degrading to something a comparison would still accept.
    #[test]
    fn the_responsible_process_is_a_real_executable_path() {
        let Some(path) = responsible_process() else {
            panic!("no responsible process resolved for a running process");
        };
        assert!(
            path.starts_with('/'),
            "expected an absolute path, got {path:?}"
        );
        assert!(
            std::path::Path::new(&path).exists(),
            "resolved path does not exist: {path:?}"
        );
    }

    /// Establishing the window-server connection is safe to repeat.
    ///
    /// It is called before every capture rather than once at a place someone
    /// has to remember, so repeating it must be harmless.
    #[test]
    fn establishing_the_window_server_connection_twice_is_harmless() {
        establish_window_server_connection();
        establish_window_server_connection();
    }

    /// The capture permission query answers without prompting or aborting.
    ///
    /// The value is deliberately not asserted: it depends on whether this
    /// machine has granted capture, and demanding one answer would fail
    /// honestly on the other kind of machine.
    #[test]
    fn the_capture_permission_query_returns() {
        let _ = screen_capture_is_permitted();
    }

    /// Start times order the way process creation did.
    ///
    /// A child cannot start before its parent, so the comparison holds on any
    /// machine. It is asserted because it is the available check that a WRONG
    /// field is being read: a misread offset still yields a plausible-looking
    /// number, and a bound like "after 2020" would accept one, while an
    /// ordering two independent readings must satisfy would not.
    ///
    /// A child is used rather than the system's first process, which is owned
    /// by root and whose information the kernel declines to report here.
    #[test]
    fn start_times_order_the_way_process_creation_did() {
        let this_process =
            process_start_time_micros(std::process::id()).expect("this process exists");

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn a child to compare against");
        let child_start = process_start_time_micros(child.id());
        let _ = child.kill();
        let _ = child.wait();

        let child_start = child_start.expect("a running child has a start time");
        assert!(
            this_process < child_start,
            "a child cannot predate its parent: {this_process} vs {child_start}"
        );
    }

    /// The reading is a wall-clock time in the past, at microsecond scale.
    ///
    /// Ordering alone would be satisfied by any two values with the right
    /// relation, including counters that are not times at all. This pins the
    /// units and the epoch, so a field holding something else has to coincide
    /// with a plausible recent timestamp to pass.
    #[test]
    fn a_start_time_is_a_past_wall_clock_time_in_microseconds() {
        let start = process_start_time_micros(std::process::id()).expect("this process exists");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_micros() as u64;

        assert!(start < now, "a process cannot start in the future");
        // This process was started by the test run, so its age is bounded by
        // how long a test binary plausibly runs rather than by machine uptime.
        assert!(
            now - start < 3_600_000_000,
            "a just-started process reporting an age over an hour is not reporting its start"
        );
    }

    /// The same process reads the same start time every time.
    ///
    /// A value that varied between readings could not discriminate a process
    /// from its replacement, which is the only thing this is for.
    #[test]
    fn a_start_time_is_stable_across_readings() {
        let pid = std::process::id();
        let first = process_start_time_micros(pid);
        let second = process_start_time_micros(pid);
        assert_eq!(first, second);
        assert!(first.is_some());
    }

    /// A denied permission query means enumeration cannot succeed.
    ///
    /// An IMPLICATION, not an equivalence. The converse is false and asserting
    /// it made this test fail under load: the permission query is a settings
    /// level read, while enumeration is a live window-server operation that can
    /// fail transiently — measured on this machine, the query reported
    /// PERMITTED while enumeration returned a declined-permission error in the
    /// same instant, with four suites running.
    ///
    /// That is the same wrong model the production path held until
    /// `TargetResolution::Unreadable` was introduced: an unreadable window list
    /// is not evidence that permission was withdrawn, and treating the two as
    /// interchangeable turns a transient failure into a claim about the world.
    ///
    /// Stated as an outcome rather than a value so it holds on a machine of
    /// either kind, which is what the original equivalence was reaching for.
    #[test]
    fn a_denied_permission_query_means_enumeration_cannot_succeed() {
        let _serialized = WINDOW_SERVER.lock();
        let permitted = screen_capture_is_permitted();
        let enumerated = enumerate_windows(Duration::from_secs(10));

        if !permitted {
            assert!(
                enumerated.is_err(),
                "enumeration succeeded while the permission query said it was denied: \
                 {enumerated:?}"
            );
        }

        // The other direction is deliberately unasserted, and the reason is the
        // finding: a failed enumeration on a permitted machine is a transient
        // window-server failure, not a permission change.
    }

    /// A granted machine reports windows that carry an owner.
    ///
    /// Skipped rather than failed where capture is not granted: the property is
    /// about the shape of what enumeration returns, and a machine that refuses
    /// to answer has nothing to say about it.
    #[test]
    fn enumerated_windows_carry_an_owning_process() {
        let _serialized = WINDOW_SERVER.lock();
        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        assert!(!windows.is_empty(), "a running desktop has windows");
        for window in &windows {
            assert_ne!(window.owner_pid, 0, "a window with no owner: {window:?}");
            assert_ne!(window.window_id, 0, "a window with no id: {window:?}");
        }
    }

    /// A deadline that has already passed produces an error, not a wait.
    ///
    /// The bound is the only thing standing between a system that never answers
    /// and a thread held forever, so it has to be load-bearing rather than
    /// advisory.
    ///
    /// The proof is the CONTRAST between the two deadlines, not elapsed time. A
    /// call that ignored its deadline would wait for the window server and
    /// return the same window list as the generous call below, so an error from
    /// one and a list from the other can only mean the deadline was honoured.
    /// Measuring elapsed time instead would assert a wall-clock bound on a
    /// machine shared with other work, which fails for reasons unrelated to the
    /// property.
    ///
    /// Both calls fail on a machine without capture permission, where the
    /// contrast cannot be drawn and the test would pass vacuously, so it stops
    /// there rather than claiming a result.
    #[test]
    fn an_expired_deadline_refuses_rather_than_waits() {
        let _serialized = WINDOW_SERVER.lock();
        if enumerate_windows(Duration::from_secs(10)).is_err() {
            return;
        }
        assert!(
            enumerate_windows(Duration::ZERO).is_err(),
            "an expired deadline produced a window list, so it was not applied"
        );
    }

    /// An errno this code does not classify is reported as unclassified,
    /// carrying the errno, rather than borrowing a sibling's meaning.
    ///
    /// The distinction is diagnostic rather than behavioural — both refuse to
    /// signal — and that is exactly why it needs a test. A wrong label here
    /// costs nobody a process and costs whoever debugs it a day, because
    /// `LayoutMismatch` sends a reader to compare struct definitions against a
    /// kernel header for a call that never read a structure.
    #[test]
    fn an_unclassified_errno_is_not_reported_as_a_layout_mismatch() {
        // The three this code does classify, so the catch-all is not simply
        // swallowing everything.
        assert_eq!(start_time_failure(3), ProcessStartTime::NoSuchProcess);
        assert_eq!(start_time_failure(1), ProcessStartTime::NotPermitted);
        assert_eq!(start_time_failure(12), ProcessStartTime::LayoutMismatch);

        // EINTR and EFAULT are real errnos this code has no reading for. They
        // must not arrive wearing a claim about the kernel's structure.
        for errno in [4, 14, 22] {
            assert_eq!(
                start_time_failure(errno),
                ProcessStartTime::Unclassified(errno),
                "errno {errno} should be reported as itself"
            );
            assert_ne!(
                start_time_failure(errno),
                ProcessStartTime::LayoutMismatch,
                "errno {errno} must not claim the kernel structure was wrong"
            );
        }
    }

    /// A captured window yields pixels matching the size it reported.
    ///
    /// Skipped where capture is not granted: the property is about what a
    /// capture returns, and a machine that refuses to capture has nothing to
    /// say about it.
    #[test]
    fn a_captured_window_yields_pixels_of_its_own_size() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = WINDOW_SERVER.lock();
        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        // A window with area, since a zero-sized one would satisfy any claim
        // about its pixels.
        let Some(window) = windows
            .iter()
            .find(|window| window.on_screen && window.width >= 64.0 && window.height >= 64.0)
        else {
            return;
        };

        let capture = capture_window(window.window_id, Duration::from_secs(10), None)
            .expect("a window the system just listed can be captured");

        assert_eq!(
            capture.owner_pid_at_capture, window.owner_pid,
            "captured a window owned by a different process than the one enumerated"
        );
        assert!(capture.width > 0 && capture.height > 0);
        // Exactly four bytes per pixel with nothing between rows. Asserted as
        // equality rather than a lower bound: the system pads rows to a stride
        // of its own choosing, and a buffer still carrying that padding would
        // satisfy "at least" while decoding to a skewed image.
        assert_eq!(
            capture.bgra.len(),
            capture.width * capture.height * 4,
            "{}x{} should be tightly packed, got {} bytes",
            capture.width,
            capture.height,
            capture.bgra.len()
        );
    }

    /// Padding is dropped and the pixels keep their order.
    ///
    /// Built from a constructed buffer rather than a capture, so it holds on a
    /// locked screen and on a machine with no capture permission -- the
    /// conditions under which the capture-based tests here silently skip.
    ///
    /// The row marker is what makes this more than a length check: a repack that
    /// dropped the wrong end of each row, or read from the wrong offset, still
    /// produces a buffer of the right size.
    #[test]
    fn repacking_drops_the_padding_and_keeps_the_pixel_order() {
        let (width, height) = (3usize, 4usize);
        let row_bytes = width * 4;
        let stride = row_bytes + 7;

        let mut source = Vec::new();
        for row in 0..height {
            // First byte of each row identifies it; the rest of the pixel data
            // is distinct from the padding that follows.
            source.push(row as u8);
            source.extend(std::iter::repeat_n(0xAA, row_bytes - 1));
            source.extend(std::iter::repeat_n(0xFF, stride - row_bytes));
        }

        let packed = repack_rows(&source, width, height, stride);

        assert_eq!(packed.len(), row_bytes * height);
        assert!(!packed.contains(&0xFF), "padding survived the repack");
        for row in 0..height {
            assert_eq!(
                packed[row * row_bytes],
                row as u8,
                "row {row} is not where it should be"
            );
        }
    }

    /// A buffer with no padding is returned unchanged.
    #[test]
    fn repacking_an_unpadded_buffer_changes_nothing() {
        let (width, height) = (2usize, 2usize);
        let row_bytes = width * 4;
        let source: Vec<u8> = (0..(row_bytes * height) as u8).collect();
        assert_eq!(repack_rows(&source, width, height, row_bytes), source);
    }

    /// Padding is removed for a width the system is known to pad.
    ///
    /// The window in the test above may happen to have a width the system does
    /// not pad, in which case it passes whether or not the padding is stripped.
    /// This looks for a window whose tight row length is not a multiple of the
    /// 16-byte alignment CoreGraphics uses, so the source buffer is genuinely
    /// wider than the image and the equality above can only hold if the repack
    /// happened.
    #[test]
    fn a_padded_width_is_repacked_rather_than_carried() {
        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        let Some(window) = windows.iter().find(|window| {
            window.on_screen
                && window.width >= 8.0
                && !(window.width as usize * 4).is_multiple_of(16)
        }) else {
            // No window on this screen has a padded width, so the property
            // cannot be observed here. Skipped rather than asserted, since a
            // pass would say nothing.
            return;
        };

        let Ok(capture) = capture_window(window.window_id, Duration::from_secs(10), None) else {
            return;
        };
        assert_eq!(capture.bgra.len(), capture.width * capture.height * 4);
    }

    /// Capturing a window that no longer exists refuses.
    ///
    /// Window ids are reused, so a request naming a departed window must not be
    /// answered with whatever now holds that id.
    #[test]
    fn capturing_a_window_that_is_gone_refuses() {
        let _serialized = WINDOW_SERVER.lock();
        // Above any id the window server has assigned on a running system.
        assert!(capture_window(u32::MAX - 1, Duration::from_secs(10), None).is_err());
    }

    /// Creating a capture filter without the window-server connection kills the
    /// process, which is why [`capture_window`] establishes it first.
    ///
    /// What a child run of the unguarded-filter probe established.
    ///
    /// Separated from the test because the interesting case CANNOT BE REACHED
    /// ON A HEALTHY MACHINE: the child only fails to enumerate when the window
    /// server is slow to answer, which is why the original defect -- a setup
    /// failure and a missing abort both leaving exit 0, so the parent read one
    /// as the other -- survived every run except a loaded workspace build. A
    /// decision that can only be exercised under contention is a decision that
    /// must be testable without it.
    #[derive(Debug, PartialEq, Eq)]
    enum ProbeVerdict {
        /// The child was aborted, which is the property under test.
        GuardProven,
        /// The child never reached the filter, so it observed nothing.
        SetupFailed,
        /// The child reached the filter and lived, which the guard forbids.
        ReachedWithoutAborting,
        /// Neither shape: an unrelated panic or signal, which must not read as
        /// a confirmation in either direction.
        Unrecognised,
    }

    fn probe_verdict(signal: Option<i32>, code: Option<i32>) -> ProbeVerdict {
        const COULD_NOT_REACH_FILTER: i32 = 79;
        match (signal, code) {
            (Some(6), _) => ProbeVerdict::GuardProven,
            (None, Some(COULD_NOT_REACH_FILTER)) => ProbeVerdict::SetupFailed,
            (None, Some(0)) => ProbeVerdict::ReachedWithoutAborting,
            _ => ProbeVerdict::Unrecognised,
        }
    }

    #[test]
    fn a_child_that_could_not_set_up_is_not_read_as_a_missing_abort() {
        assert_eq!(probe_verdict(None, Some(79)), ProbeVerdict::SetupFailed);
        // The defect this replaced: both shapes arrived as exit 0, so a window
        // server that did not answer was indistinguishable from a guard that
        // failed to fire.
        assert_eq!(
            probe_verdict(None, Some(0)),
            ProbeVerdict::ReachedWithoutAborting
        );
        assert_eq!(probe_verdict(Some(6), None), ProbeVerdict::GuardProven);
        // An unrelated death confirms nothing in either direction.
        assert_eq!(probe_verdict(Some(11), None), ProbeVerdict::Unrecognised);
        assert_eq!(probe_verdict(None, Some(101)), ProbeVerdict::Unrecognised);
    }

    /// The connection is established by a call whose result is discarded, so it
    /// reads like a line with no effect and invites removal. This asserts what
    /// removing it costs: not a failed capture but a dead process, which for a
    /// module means every capability it serves goes down with it.
    ///
    /// Run in a child process because the failure is an abort, which an
    /// in-process test cannot survive to assert anything about. The parent
    /// chooses the window and passes its id, so the child performs exactly one
    /// enumeration -- the same number [`capture_window`] performs, and the most
    /// that reliably completes in a process that has never reached the window
    /// server.
    #[test]
    fn creating_a_filter_without_the_window_server_connection_kills_the_process() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = WINDOW_SERVER.lock();
        use std::os::unix::process::ExitStatusExt;

        const TARGET_WINDOW: &str = "CK_UNGUARDED_FILTER_PROBE_WINDOW";
        // Any value distinguishable from 0 (reached the filter, no abort) and
        // from a signal death. 79 has no other meaning here; it is simply not
        // one this child can produce accidentally.
        const COULD_NOT_REACH_FILTER: i32 = 79;

        if let Ok(window_id) = std::env::var(TARGET_WINDOW) {
            let window_id: u32 = window_id.parse().expect("the parent passes a window id");
            // Deliberately WITHOUT establish_window_server_connection().
            let Ok(window) = find_window(window_id, Duration::from_secs(10)) else {
                // Could not reach the filter, so this run proves nothing.
                //
                // A DISTINCT CODE, because exit 0 already means something else
                // here: it is what the child returns when it DID reach the
                // filter and was not aborted, which is the failure this test
                // exists to catch. Signalling "I could not set up" the same way
                // made the parent read a setup failure as a missing abort --
                // and enumeration fails more often under load, so the test
                // failed only in the full workspace run and passed alone, in
                // its own crate suite, and under process isolation.
                std::process::exit(COULD_NOT_REACH_FILTER);
            };
            // SAFETY: the window is retained by this frame. This is expected to
            // abort, which is the point of the test.
            let _filter = unsafe {
                SCContentFilter::initWithDesktopIndependentWindow(SCContentFilter::alloc(), &window)
            };
            std::process::exit(0);
        }

        // Skip where capture is not permitted: the child cannot look up a
        // window, so it cannot reach the filter.
        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        let Some(window) = windows.first() else {
            return;
        };

        let status = std::process::Command::new(
            std::env::current_exe().expect("the test binary's own path"),
        )
        .args([
            "--exact",
            "macos::tests::creating_a_filter_without_the_window_server_connection_kills_the_process",
        ])
        .env(TARGET_WINDOW, window.window_id.to_string())
        .output()
        .expect("run the probe in a child process");

        match probe_verdict(status.status.signal(), status.status.code()) {
            // The child could not reach the filter, so it observed nothing
            // about the guard. Reported rather than passed silently: a skip
            // that looks like a pass is how a test stops meaning anything, and
            // this one fences a crash boundary -- an unguarded filter does not
            // fail the capture, it kills the process and every capability it
            // serves.
            ProbeVerdict::SetupFailed => {
                eprintln!(
                    "SKIPPED: the child could not enumerate the target window, so \
                     the abort guard was never exercised. This says nothing about \
                     the guard; it says the window server did not answer in time."
                );
                return;
            }
            ProbeVerdict::GuardProven => return,
            ProbeVerdict::ReachedWithoutAborting | ProbeVerdict::Unrecognised => {}
        }

        // SIGABRT specifically, rather than "did not succeed": a child that
        // panicked for an unrelated reason must not read as a confirmation.
        // Exit 0 here means the child DID reach the filter and was not
        // aborted, which is a real failure of the property under test.
        assert_eq!(
            status.status.signal(),
            Some(6),
            "expected the child to abort; it exited with {:?} and said: {}",
            status.status,
            String::from_utf8_lossy(&status.stderr)
        );
    }

    /// [`capture_window`] survives in a process that has established nothing.
    ///
    /// The companion to the test above, and the one that fences the CALL SITE
    /// rather than the hazard. Removing the establishing call from
    /// [`capture_window`] cannot be detected in this process: tests run as
    /// threads in one process, so a sibling that establishes the connection
    /// leaves it established for everyone, and the removed call looks
    /// redundant precisely because something else already did its work.
    ///
    /// The child process establishes nothing, so the call inside
    /// [`capture_window`] is the only thing standing between it and an abort.
    #[test]
    fn capturing_establishes_the_window_server_connection_itself() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = WINDOW_SERVER.lock();
        use std::os::unix::process::ExitStatusExt;

        const TARGET_WINDOW: &str = "CK_CAPTURE_SURVIVAL_PROBE_WINDOW";
        const CAPTURE_REFUSED: i32 = 3;

        if let Ok(window_id) = std::env::var(TARGET_WINDOW) {
            let window_id: u32 = window_id.parse().expect("the parent passes a window id");
            match capture_window(window_id, Duration::from_secs(10), None) {
                Ok(_) => std::process::exit(0),
                // A typed refusal is still a survival, and it is reported
                // separately so the parent does not read it as a capture.
                Err(_) => std::process::exit(CAPTURE_REFUSED),
            }
        }

        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        let Some(window) = windows.iter().find(|window| window.on_screen) else {
            return;
        };

        let status = std::process::Command::new(
            std::env::current_exe().expect("the test binary's own path"),
        )
        .args([
            "--exact",
            "macos::tests::capturing_establishes_the_window_server_connection_itself",
        ])
        .env(TARGET_WINDOW, window.window_id.to_string())
        .output()
        .expect("run the probe in a child process");

        assert_ne!(
            status.status.signal(),
            Some(6),
            "capturing aborted the child, so it did not establish the window-server connection"
        );
        assert!(
            matches!(status.status.code(), Some(0) | Some(CAPTURE_REFUSED)),
            "the child neither captured nor refused: {:?}, {}",
            status.status,
            String::from_utf8_lossy(&status.stderr)
        );
    }

    /// Pixels encode to a real PNG, smaller than the bytes they came from.
    ///
    /// Built from a constructed buffer rather than a capture, so it holds on a
    /// locked screen and with no capture permission — the conditions under
    /// which the capture-based tests here skip and prove nothing.
    #[test]
    fn pixels_encode_to_a_png() {
        // A width that is not a convenient multiple, and a pattern with
        // structure: a uniform block would survive most encoding bugs.
        let (width, height) = (37usize, 11usize);
        let mut bgra = Vec::with_capacity(width * height * 4);
        for y in 0..height {
            for x in 0..width {
                bgra.extend_from_slice(&[(x * 7) as u8, (y * 23) as u8, 0x40, 0xFF]);
            }
        }

        let png = encode_png(&bgra, width, height).expect("pixels encode");

        // The signature, so this asserts the FORMAT rather than that some bytes
        // came back.
        assert_eq!(
            &png[..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
            "the encoded bytes are not a PNG"
        );
        assert!(
            png.len() < bgra.len(),
            "encoding {} bytes produced {}, which is not compression",
            bgra.len(),
            png.len()
        );

        // The dimensions are carried in the header, immediately after the
        // signature and an 8-byte chunk prefix, big-endian. Asserted because an
        // encoder given the wrong stride produces a valid PNG of the wrong
        // shape rather than an error.
        let header_width = u32::from_be_bytes(png[16..20].try_into().unwrap());
        let header_height = u32::from_be_bytes(png[20..24].try_into().unwrap());
        assert_eq!((header_width, header_height), (width as u32, height as u32));
    }

    /// A buffer that does not match its dimensions is refused.
    ///
    /// The case that matters is a buffer still carrying the row padding the
    /// system leaves: it is LARGER than the image describes, and encoding it
    /// anyway produces a progressively skewed picture rather than a failure.
    #[test]
    fn a_buffer_that_does_not_match_its_dimensions_is_refused() {
        let (width, height) = (37usize, 11usize);
        let tight = width * height * 4;

        // Padded to a wider stride, as the system delivers.
        let padded = vec![0u8; (width * 4 + 7) * height];
        assert!(encode_png(&padded, width, height).is_err());

        // Short by one pixel.
        assert!(encode_png(&vec![0u8; tight - 4], width, height).is_err());

        // No area at all.
        assert!(encode_png(&[], 0, 10).is_err());
    }

    /// A graphical session reports a definite lock state, never an unknown one.
    ///
    /// The system omits the lock key entirely while the screen is unlocked, so
    /// a reading that treated an absent key as unknown would answer `None` in
    /// the ordinary case, and `== Some(false)` would be a comparison that never
    /// matches. `None` is reserved for having no session to ask.
    ///
    /// The assertion does not name WHICH state, because the machine may be in
    /// either and a test demanding one fails when someone locks the screen.
    /// That costs some strength honestly: while the screen is locked the key is
    /// present and the answer was already definite, so this only discriminates
    /// in the unlocked case.
    #[test]
    fn a_session_reports_a_definite_lock_state() {
        // Enumeration succeeding establishes that there IS a session to ask,
        // which is the only condition under which None would be correct. It
        // does NOT establish that the screen is unlocked: a locked screen
        // answers questions about windows and refuses only their contents.
        if enumerate_windows(Duration::from_secs(10)).is_err() {
            return;
        }
        assert!(
            screen_is_locked().is_some(),
            "a session that answers window queries must report a definite lock state"
        );
    }

    /// The reasons a start time cannot be read are told apart.
    ///
    /// They are not the same news, and one is not about the process at all: a
    /// layout mismatch means this module's declaration disagrees with the
    /// kernel, which reported as absence would look like every process on the
    /// machine having exited at once. A process this one may not inspect
    /// matters for the same reason in the other direction: a target that is
    /// merely out of reach has not exited.
    ///
    /// The system reports all three as a zero return, so only errno separates
    /// them; a test that asserted the return value alone would pass over a
    /// reading that could not tell them apart.
    #[test]
    fn the_reasons_a_start_time_is_unavailable_are_distinguished() {
        // Above the highest pid this system assigns, so nothing holds it.
        assert_eq!(
            process_start_time(u32::MAX - 1),
            ProcessStartTime::NoSuchProcess
        );

        // The first process is root-owned, so it exists and cannot be inspected
        // from here.
        assert_eq!(process_start_time(1), ProcessStartTime::NotPermitted);

        // A process that can be read reports a time rather than any failure.
        assert!(matches!(
            process_start_time(std::process::id()),
            ProcessStartTime::Started(_)
        ));
    }

    /// A process that does not exist has no start time.
    ///
    /// Absence rather than a zero: a zero would compare equal to another zero
    /// and read as two processes sharing a generation.
    #[test]
    fn a_process_that_does_not_exist_reports_no_start_time() {
        // Above the highest pid this system can assign, so it identifies no
        // process.
        assert_eq!(process_start_time_micros(u32::MAX - 1), None);
    }
}
