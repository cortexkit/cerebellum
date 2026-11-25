//! One window's image for a vision model: which window is in front, and the
//! capture resampled and encoded small enough to read.

use std::ffi::c_void;
use std::ptr::NonNull;

use objc2_core_foundation::{
    CFArray, CFDictionary, CFNumber, CFRetained, CFString, CFType, CGPoint, CGRect, CGSize,
};
use objc2_core_graphics::{
    CGBitmapContextCreateImage, CGColorSpace, CGContext, CGInterpolationQuality,
    CGWindowListCopyWindowInfo, CGWindowListOption,
};

use crate::macos::{bgra_image, encode_image};

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    #[cfg(feature = "desk-probe")]
    fn CGPreflightPostEventAccess() -> bool;
    fn CGGetActiveDisplayList(max_displays: u32, displays: *mut u32, count: *mut u32) -> i32;
    fn CGDisplayBounds(display: u32) -> CGRect;
    fn CGDisplayIsAsleep(display: u32) -> u32;
    /// A drawing context backed by memory the system allocates.
    fn CGBitmapContextCreate(
        data: *mut c_void,
        width: usize,
        height: usize,
        bits_per_component: usize,
        bytes_per_row: usize,
        space: *const c_void,
        bitmap_info: u32,
    ) -> *mut c_void;
}

/// The quality JPEG images are encoded at. High enough that small interface
/// text stays legible to a vision model, which is what the image is for; an
/// image is charged by its dimensions rather than its bytes, so a higher
/// setting costs transfer size and nothing else.
const JPEG_QUALITY: f64 = 0.85;

/// Resample tightly-packed BGRA pixels to `target_width` by `target_height`
/// and encode them as JPEG.
///
/// The caller chooses the target size; this only draws and encodes, with the
/// system's high-quality interpolation so downscaled text stays readable.
pub fn encode_scaled_jpeg(
    bgra: &[u8],
    width: usize,
    height: usize,
    target_width: usize,
    target_height: usize,
) -> Result<Vec<u8>, String> {
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
    if width == 0 || height == 0 || target_width == 0 || target_height == 0 {
        return Err("an image with no area cannot be encoded".to_string());
    }
    let source = bgra_image(bgra, width, height)?;
    let color_space = CGColorSpace::new_device_rgb()
        .ok_or_else(|| "the device colour space is unavailable".to_string())?;

    // Premultiplied alpha first, 32-bit little-endian: the layout bitmap
    // contexts support for four 8-bit channels.
    let bitmap_info = 2 | (2 << 12);
    // SAFETY: a null data pointer asks the system to allocate the context's
    // memory; width, height and row length describe that allocation, and the
    // colour space is retained for the call. The context is owned below.
    let context = unsafe {
        CGBitmapContextCreate(
            std::ptr::null_mut(),
            target_width,
            target_height,
            8,
            target_width * 4,
            CFRetained::as_ptr(&color_space).as_ptr().cast(),
            bitmap_info,
        )
    };
    let context = NonNull::new(context.cast::<CGContext>())
        .ok_or_else(|| "no drawing context could be made for the scaled image".to_string())?;
    // SAFETY: a Create function returned this non-null context with one
    // retain count, which the wrapper now owns and releases on drop.
    let context = unsafe { CFRetained::from_raw(context) };

    CGContext::set_interpolation_quality(Some(&context), CGInterpolationQuality::High);
    CGContext::draw_image(
        Some(&context),
        CGRect::new(
            CGPoint::new(0.0, 0.0),
            CGSize::new(target_width as f64, target_height as f64),
        ),
        Some(&source),
    );
    let scaled = CGBitmapContextCreateImage(Some(&context))
        .ok_or_else(|| "the scaled image could not be read back".to_string())?;

    let key = CFString::from_static_str("kCGImageDestinationLossyCompressionQuality");
    let quality = CFNumber::new_f64(JPEG_QUALITY);
    let options: CFRetained<CFDictionary<CFString, CFNumber>> =
        CFDictionary::from_slices(&[&*key], &[&*quality]);
    encode_image(
        &scaled,
        "public.jpeg",
        CFRetained::as_ptr(&options).as_ptr().cast(),
    )
}

/// The id of the frontmost on-screen window `pid` owns, if it has one.
///
/// Read from the window server's on-screen list, which is ordered front to
/// back, keeping only ordinary windows (layer zero) that are not fully
/// transparent: menus, the menu bar and invisible helper windows are also
/// windows of the process, and none of them is what a person means by the
/// application's window. Reading the list moves nothing and fronts nothing.
pub fn frontmost_window_id(pid: u32) -> Option<u32> {
    visible_window_ids(pid)?.into_iter().next()
}

/// The on-screen ordinary windows a process owns, in front-to-back order.
/// Reads window numbers only, without titles, images or accessibility content.
pub fn visible_window_ids(pid: u32) -> Option<Vec<u32>> {
    let windows = CGWindowListCopyWindowInfo(
        CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements,
        0,
    )?;
    let owner_key = CFString::from_static_str("kCGWindowOwnerPID");
    let layer_key = CFString::from_static_str("kCGWindowLayer");
    let number_key = CFString::from_static_str("kCGWindowNumber");
    let alpha_key = CFString::from_static_str("kCGWindowAlpha");
    // SAFETY: the window list is documented as an array of dictionaries keyed
    // by strings; the cast only names that element type for reading.
    let windows: &CFArray<CFDictionary<CFString, CFType>> = unsafe { windows.cast_unchecked() };
    let mut ids = Vec::new();
    for index in 0..windows.len() {
        let Some(window) = windows.get(index) else {
            continue;
        };
        let number = |key: &CFString| -> Option<f64> {
            window.get(key)?.downcast::<CFNumber>().ok()?.as_f64()
        };
        if number(&owner_key) != Some(f64::from(pid)) {
            continue;
        }
        if number(&layer_key) != Some(0.0) {
            continue;
        }
        if number(&alpha_key).is_some_and(|alpha| alpha <= 0.0) {
            continue;
        }
        if let Some(id) = number(&number_key) {
            ids.push(id as u32);
        }
    }
    Some(ids)
}

/// Active display rectangles in the same top-down coordinates as AX frames.
pub fn display_frames() -> Option<Vec<[f64; 4]>> {
    Some(
        diagnostic_display_bounds()?
            .into_iter()
            .map(|(rect, _)| {
                [
                    rect.origin.x,
                    rect.origin.y,
                    rect.size.width,
                    rect.size.height,
                ]
            })
            .collect(),
    )
}

/// Numeric window-server context for a process that capture could not resolve.
/// Unknown readings stay `None`, rather than looking like zero windows.
#[derive(Debug, Clone, Copy)]
pub struct ProcessWindowCounts {
    pub total_windows: Option<usize>,
    pub on_screen_windows: Option<usize>,
    pub windows_on_active_display: Option<usize>,
    pub windows_on_awake_display: Option<usize>,
}

/// Read counts only: no window names, titles, images or accessibility attributes.
/// All layers are counted, including helper windows. Display intersection uses
/// the all-windows list, so it does not imply that a window is on the current Space.
pub fn process_window_counts(pid: u32) -> ProcessWindowCounts {
    let all = process_window_bounds(pid, CGWindowListOption::OptionAll);
    let on_screen = process_window_bounds(pid, CGWindowListOption::OptionOnScreenOnly);
    let displays = diagnostic_display_bounds();
    let active = displays.as_ref().map(|displays| {
        displays
            .iter()
            .map(|(bounds, _)| *bounds)
            .collect::<Vec<_>>()
    });
    let awake = displays.as_ref().map(|displays| {
        displays
            .iter()
            .filter(|(_, asleep)| !asleep)
            .map(|(bounds, _)| *bounds)
            .collect::<Vec<_>>()
    });
    ProcessWindowCounts {
        total_windows: all.as_ref().map(Vec::len),
        on_screen_windows: on_screen.as_ref().map(Vec::len),
        windows_on_active_display: intersecting_window_count(all.as_deref(), active.as_deref()),
        windows_on_awake_display: intersecting_window_count(all.as_deref(), awake.as_deref()),
    }
}

fn process_window_bounds(pid: u32, options: CGWindowListOption) -> Option<Vec<Option<CGRect>>> {
    let windows = CGWindowListCopyWindowInfo(options, 0)?;
    // SAFETY: CoreGraphics documents this array as string-keyed window dictionaries.
    let windows: &CFArray<CFDictionary<CFString, CFType>> = unsafe { windows.cast_unchecked() };
    let mut bounds = Vec::new();
    for index in 0..windows.len() {
        let window = windows.get(index)?;
        let owner = window
            .get(&CFString::from_static_str("kCGWindowOwnerPID"))?
            .downcast::<CFNumber>()
            .ok()?
            .as_f64()?;
        if owner != f64::from(pid) {
            continue;
        }
        let rect = window
            .get(&CFString::from_static_str("kCGWindowBounds"))
            .and_then(|value| value.downcast::<CFDictionary>().ok())
            .and_then(|dictionary| {
                // SAFETY: CoreGraphics window bounds use numeric X/Y/Width/Height keys.
                let dictionary: &CFDictionary<CFString, CFType> =
                    unsafe { dictionary.cast_unchecked() };
                let value = |key: &str| {
                    dictionary
                        .get(&CFString::from_str(key))?
                        .downcast::<CFNumber>()
                        .ok()?
                        .as_f64()
                };
                Some(CGRect::new(
                    CGPoint::new(value("X")?, value("Y")?),
                    CGSize::new(value("Width")?, value("Height")?),
                ))
            });
        bounds.push(rect);
    }
    Some(bounds)
}

fn diagnostic_display_bounds() -> Option<Vec<(CGRect, bool)>> {
    let mut ids = [0u32; 32];
    let mut count = 0;
    // SAFETY: ids and count are valid output buffers for the supplied capacity.
    let status = unsafe { CGGetActiveDisplayList(ids.len() as u32, ids.as_mut_ptr(), &mut count) };
    if status != 0 || count as usize >= ids.len() {
        return None;
    }
    Some(
        ids[..count as usize]
            .iter()
            .map(|id| {
                // SAFETY: CoreGraphics just returned this display ID; these calls only read it.
                unsafe { (CGDisplayBounds(*id), CGDisplayIsAsleep(*id) != 0) }
            })
            .collect(),
    )
}

fn intersecting_window_count(
    windows: Option<&[Option<CGRect>]>,
    displays: Option<&[CGRect]>,
) -> Option<usize> {
    let displays = displays?;
    let valid = |rect: &CGRect| {
        [
            rect.origin.x,
            rect.origin.y,
            rect.size.width,
            rect.size.height,
            rect.origin.x + rect.size.width,
            rect.origin.y + rect.size.height,
        ]
        .iter()
        .all(|v| v.is_finite())
            && rect.size.width >= 0.0
            && rect.size.height >= 0.0
    };
    if !displays.iter().all(valid) {
        return None;
    }
    let mut count = 0;
    for window in windows? {
        let window = window.as_ref().filter(|rect| valid(rect))?;
        if displays.iter().any(|display| {
            window.origin.x.max(display.origin.x)
                < (window.origin.x + window.size.width).min(display.origin.x + display.size.width)
                && window.origin.y.max(display.origin.y)
                    < (window.origin.y + window.size.height)
                        .min(display.origin.y + display.size.height)
                && window.size.width > 0.0
                && window.size.height > 0.0
        }) {
            count += 1;
        }
    }
    Some(count)
}

/// Whether this exact window is wholly on screen under the image visibility rules.
/// The on-screen list is front-to-back; missing data never proves visibility.
pub fn window_visibility(pid: u32, id: u32) -> crate::WindowVisibility {
    window_visibility_decision(pid, id).0
}

/// Return the rule as well as the visibility; no window titles are retained.
pub fn window_visibility_decision(
    pid: u32,
    id: u32,
) -> (crate::WindowVisibility, crate::VisibilityRule) {
    #[cfg(feature = "desk-probe")]
    if OVERLAP_WITNESS.with_borrow(Option::is_some) {
        let sample = sample_window_overlap_for_probe(pid, id);
        let decision = (sample.visibility, sample.rule);
        OVERLAP_WITNESS.with_borrow_mut(|slot| *slot = Some(Some(sample)));
        return decision;
    }
    let Some(entries) = cursor_window_list() else {
        return (
            crate::WindowVisibility::Unknown,
            crate::VisibilityRule::MissingData,
        );
    };
    window_visibility_with_entries(pid, id, &entries)
}

#[cfg(feature = "desk-probe")]
pub struct WindowOverlapSample {
    pub pid: u32,
    pub window_number: u32,
    pub frontmost_normal_pid: Option<i32>,
    pub started_at: std::time::Instant,
    pub returned_at: std::time::Instant,
    pub visibility: crate::WindowVisibility,
    pub rule: crate::VisibilityRule,
    pub rectangles: Vec<WindowOverlapRectangle>,
}

#[cfg(feature = "desk-probe")]
pub struct WindowOverlapRectangle {
    pub owner_pid: Option<u32>,
    pub owner_name: Option<String>,
    pub window_number: Option<u32>,
    pub layer: i64,
    pub bounds: [f64; 4],
    pub alpha: f64,
    pub sharing_state: Option<i64>,
}

#[cfg(feature = "desk-probe")]
thread_local! {
    // The outer option arms a witness capture on this thread; the inner one
    // is empty if the picture read never queried CoreGraphics for a window ID.
    static OVERLAP_WITNESS: std::cell::RefCell<Option<Option<WindowOverlapSample>>> = const { std::cell::RefCell::new(None) };
}

/// Collect the native visibility query's own evidence, not a second window list.
#[cfg(feature = "desk-probe")]
pub fn observe_window_overlap_for_probe<T>(
    inspect: impl FnOnce() -> T,
) -> (T, Option<WindowOverlapSample>) {
    struct RestoreWitness(Option<Option<WindowOverlapSample>>);
    impl Drop for RestoreWitness {
        fn drop(&mut self) {
            OVERLAP_WITNESS.with_borrow_mut(|slot| *slot = self.0.take());
        }
    }
    let _restore = RestoreWitness(OVERLAP_WITNESS.replace(Some(None)));
    let result = inspect();
    (result, OVERLAP_WITNESS.take().flatten())
}

/// Read visibility and the nonzero-layer cover rectangles from one snapshot.
/// No window title or pixels are fetched.
#[cfg(feature = "desk-probe")]
pub fn sample_window_overlap_for_probe(pid: u32, id: u32) -> WindowOverlapSample {
    let started_at = std::time::Instant::now();
    let snapshot = on_screen_window_dictionaries().and_then(|dictionaries| {
        let entries = cursor_windows_from(&dictionaries)?;
        Some((dictionaries, entries, visibility_displays()?))
    });
    overlap_sample(
        pid,
        id,
        started_at,
        snapshot
            .as_ref()
            .map(|(d, w, s)| (&**d, w.as_slice(), s.as_slice())),
    )
}

#[cfg(feature = "desk-probe")]
fn overlap_sample(
    pid: u32,
    id: u32,
    started_at: std::time::Instant,
    snapshot: Option<(
        &WindowDictionaries,
        &[crate::window_visibility::Window],
        &[crate::window_visibility::Rect],
    )>,
) -> WindowOverlapSample {
    let mut frontmost_normal_pid = None;
    let mut rectangles = Vec::new();
    let (visibility, rule) = snapshot
        .map(|(dictionaries, entries, displays)| {
            frontmost_normal_pid = crate::window_visibility::frontmost_from_windows(entries);
            let mut cover = Vec::new();
            let decision = crate::window_visibility::visibility_with_cover(
                pid, id, entries, displays, &mut cover,
            );
            rectangles.extend(cover.into_iter().filter_map(|slot| {
                let entry = &entries[slot];
                let dictionary = dictionaries.get(slot)?;
                let bounds = entry.bounds?;
                Some(WindowOverlapRectangle {
                    owner_pid: entry.pid,
                    owner_name: dictionary
                        .get(&CFString::from_static_str("kCGWindowOwnerName"))
                        .and_then(|name| name.downcast::<CFString>().ok())
                        .map(|name| name.to_string()),
                    window_number: entry.id,
                    layer: entry.layer?,
                    bounds: [bounds.x, bounds.y, bounds.width, bounds.height],
                    alpha: entry.alpha?,
                    sharing_state: dictionary
                        .get(&CFString::from_static_str("kCGWindowSharingState"))
                        .and_then(|state| state.downcast::<CFNumber>().ok())
                        .and_then(|state| state.as_i64()),
                })
            }));
            decision
        })
        .unwrap_or((
            crate::WindowVisibility::Unknown,
            crate::VisibilityRule::MissingData,
        ));
    WindowOverlapSample {
        pid,
        window_number: id,
        frontmost_normal_pid,
        started_at,
        returned_at: std::time::Instant::now(),
        visibility,
        rule,
        rectangles,
    }
}

pub(super) fn fronted_visibility_snapshot(
    _pid: u32,
    _id: u32,
) -> Option<(
    Vec<crate::window_visibility::Window>,
    Vec<crate::window_visibility::Rect>,
)> {
    #[cfg(feature = "desk-probe")]
    let started = std::time::Instant::now();
    let dictionaries = on_screen_window_dictionaries()?;
    let windows = cursor_windows_from(&dictionaries)?;
    let displays = visibility_displays()?;
    #[cfg(feature = "desk-probe")]
    if OVERLAP_WITNESS.with_borrow(Option::is_some) {
        let sample = overlap_sample(
            _pid,
            _id,
            started,
            Some((&dictionaries, &windows, &displays)),
        );
        OVERLAP_WITNESS.with_borrow_mut(|slot| *slot = Some(Some(sample)));
    }
    Some((windows, displays))
}

static CURSOR_GENERATION: std::sync::Mutex<Option<crate::ProcessGeneration>> =
    std::sync::Mutex::new(None);

/// Register only the kernel generation the barred launcher recorded. A pid
/// reused by another application must not make that application's windows
/// disappear from an occlusion reading.
pub fn register_cursor_generation(generation: Option<crate::ProcessGeneration>) {
    *CURSOR_GENERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = generation;
}

type WindowDictionaries = CFArray<CFDictionary<CFString, CFType>>;

fn on_screen_window_dictionaries() -> Option<CFRetained<WindowDictionaries>> {
    let windows = CGWindowListCopyWindowInfo(
        CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements,
        0,
    )?;
    // SAFETY: CoreGraphics documents this result as an array of string-keyed dictionaries.
    Some(unsafe { CFRetained::cast_unchecked(windows) })
}

pub(super) fn cursor_window_list() -> Option<Vec<crate::window_visibility::Window>> {
    let dictionaries = on_screen_window_dictionaries()?;
    cursor_windows_from(&dictionaries)
}

/// Find the Dock's on-screen layer-20 window filling the display that contains
/// the entire target rectangle. CG window alpha is metadata, not the witness.
pub(super) fn dock_overlay_window(
    dock_pid: u32,
    scratch_rect: [f64; 4],
) -> Result<Option<(u32, [f64; 4])>, String> {
    let [x, y, w, h] = scratch_rect;
    let displays = display_frames().ok_or("active display bounds unavailable")?;
    let mut displays = displays.into_iter().filter(|&[dx, dy, dw, dh]| {
        w > 0.0 && h > 0.0 && x >= dx && y >= dy && x + w <= dx + dw && y + h <= dy + dh
    });
    let Some(display) = displays.next() else {
        return Ok(None);
    };
    if displays.next().is_some() {
        return Ok(None);
    }
    let mut overlays = cursor_window_list()
        .ok_or("CoreGraphics window list unavailable")?
        .into_iter()
        .filter_map(|window| {
            let bounds = window.bounds?;
            (window.pid == Some(dock_pid)
                && window.layer == Some(20)
                && window
                    .alpha
                    .is_some_and(|alpha| alpha.is_finite() && alpha != 0.0)
                && [bounds.x, bounds.y, bounds.width, bounds.height] == display)
                .then_some(window.id)
                .flatten()
        });
    let id = overlays.next();
    if overlays.next().is_some() {
        return Ok(None);
    }
    Ok(id.map(|id| (id, display)))
}

fn cursor_windows_from(
    windows: &WindowDictionaries,
) -> Option<Vec<crate::window_visibility::Window>> {
    use crate::window_visibility::{Rect, Window};
    let mut entries = Vec::new();
    let cursor = *CURSOR_GENERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cursor_pid = cursor
        .filter(|g| {
            crate::process_start_time(g.pid)
                == crate::ProcessStartTime::Started(g.start_time_micros)
        })
        .map(|g| g.pid);
    for index in 0..windows.len() {
        let window = windows.get(index)?;
        let number = |key: &str| -> Option<f64> {
            window
                .get(&CFString::from_str(key))?
                .downcast::<CFNumber>()
                .ok()?
                .as_f64()
        };
        let bounds = window
            .get(&CFString::from_static_str("kCGWindowBounds"))
            .and_then(|value| value.downcast::<CFDictionary>().ok())
            .and_then(|dictionary| {
                // SAFETY: the window bounds dictionary contains numeric X/Y/Width/Height keys.
                let dictionary: &CFDictionary<CFString, CFType> =
                    unsafe { dictionary.cast_unchecked() };
                let value = |key: &str| -> Option<f64> {
                    dictionary
                        .get(&CFString::from_str(key))?
                        .downcast::<CFNumber>()
                        .ok()?
                        .as_f64()
                };
                Some(Rect {
                    x: value("X")?,
                    y: value("Y")?,
                    width: value("Width")?,
                    height: value("Height")?,
                })
            });
        let identifier = |key: &str| {
            number(key)
                .filter(|v| {
                    v.is_finite() && *v >= 0.0 && *v <= f64::from(u32::MAX) && v.fract() == 0.0
                })
                .map(|v| v as u32)
        };
        entries.push(Window {
            cursor_picture: cursor_pid.is_some()
                && identifier("kCGWindowOwnerPID") == cursor_pid
                && number("kCGWindowLayer").is_some_and(|layer| layer != 0.0),
            id: identifier("kCGWindowNumber"),
            pid: identifier("kCGWindowOwnerPID"),
            bounds,
            alpha: number("kCGWindowAlpha"),
            layer: number("kCGWindowLayer")
                .filter(|v| {
                    v.is_finite()
                        && *v >= i64::MIN as f64
                        && *v < i64::MAX as f64
                        && v.fract() == 0.0
                })
                .map(|v| v as i64),
        });
    }
    Some(entries)
}

/// Read the exact on-screen window's frame without reading its pixels or title.
pub fn visible_window_frame(pid: u32, id: u32) -> Option<[f64; 4]> {
    let bounds = cursor_window_list()?
        .into_iter()
        .find(|window| window.id == Some(id) && window.pid == Some(pid))?
        .bounds?;
    Some([bounds.x, bounds.y, bounds.width, bounds.height])
}

pub(super) fn fronted_frame_matches(pid: u32, id: u32, frame: [f64; 4]) -> bool {
    use crate::window_visibility::{fronted_frame_matches, Rect};
    cursor_window_list()
        .is_some_and(|windows| fronted_frame_matches(&windows, pid, id, Rect::from_frame(frame)))
}

/// Uses the same front-to-back list as the image visibility reading. `frame`
/// is the acted-on element's frame, used only when there is no exact point.
pub fn visible_cursor_point(
    pid: u32,
    point: Option<[f64; 2]>,
    frame: Option<[f64; 4]>,
) -> Option<[f64; 2]> {
    crate::window_visibility::cursor_point_from_windows(pid, point, frame, &cursor_window_list()?)
}

pub(crate) fn normal_frontmost_process_id() -> Option<i32> {
    crate::window_visibility::frontmost_from_windows(&cursor_window_list()?)
}

/// The window `frontmost_process_id` reads its answer from, for the manual
/// desk probe only: the first normal-layer window's owner pid and window id
/// (`None` when the list gives none), chosen by the same rule. `None` when the
/// list cannot be read or has no such window.
#[cfg(feature = "desk-probe")]
pub fn normal_frontmost_window_for_probe() -> Option<(i32, Option<u32>)> {
    let windows = cursor_window_list()?;
    let pid = crate::window_visibility::frontmost_from_windows(&windows)?;
    let window = windows
        .iter()
        .find(|window| window.layer == Some(0) && window.pid == u32::try_from(pid).ok())?;
    Some((pid, window.id))
}

/// The window ids of `pid`'s on-screen normal-layer windows, front to back,
/// for the manual desk probe only, so it can tell whether a restore
/// rearranged that application's windows. `None` when the list cannot be read.
#[cfg(feature = "desk-probe")]
pub fn normal_window_order_for_probe(pid: u32) -> Option<Vec<u32>> {
    Some(
        cursor_window_list()?
            .iter()
            .filter(|window| window.layer == Some(0) && window.pid == Some(pid))
            .filter_map(|window| window.id)
            .collect(),
    )
}

/// Legacy rectangular window-list containment; it does not account for
/// click-through overlays. The admitted pointer route uses pointer_window_at.
pub fn topmost_window_at(x: f64, y: f64) -> Option<u32> {
    crate::window_visibility::topmost_window_at([x, y], &cursor_window_list()?)
}

#[cfg(feature = "desk-probe")]
type PointerStartupDiagnosis = (Option<isize>, Option<bool>, Option<isize>);
#[cfg(feature = "desk-probe")]
static POINTER_STARTUP_DIAGNOSIS: std::sync::Mutex<PointerStartupDiagnosis> =
    std::sync::Mutex::new((None, None, None));

/// The window selected by AppKit's mouse-down hit test, which excludes
/// click-through windows and transparency at the point. This is a snapshot,
/// not a prediction of mouse-up tracking or atomic event delivery.
pub fn pointer_window_at(x: f64, y: f64) -> Option<u32> {
    let _main = objc2::MainThreadMarker::new()?;
    // SAFETY: CoreGraphics returns the primary display's value-type bounds.
    let primary = unsafe { CGDisplayBounds(objc2_core_graphics::CGMainDisplayID()) };
    let windows = cursor_window_list()?;
    crate::window_visibility::mouse_down_window_at(
        [x, y],
        primary.size.height,
        &windows,
        |point, below| {
            // SAFETY: MainThreadMarker above ensures this runs on the main thread. The selector's NSInteger return and
            // NSPoint argument match the documented AppKit method signature.
            unsafe {
                objc2::msg_send![objc2::class!(NSWindow), windowNumberAtPoint: objc2_foundation::NSPoint::new(point[0], point[1]), belowWindowWithWindowNumber: below]
            }
        },
    )
}

/// Snapshot the real cursor without moving it or posting an event.
pub fn cursor_position() -> Option<(f64, f64)> {
    let event = objc2_core_graphics::CGEvent::new(None)?;
    let point = objc2_core_graphics::CGEvent::location(Some(&event));
    (point.x.is_finite() && point.y.is_finite()).then_some((point.x, point.y))
}

/// VM-probe-only startup. Production initializes AppKit only in the cursor helper.
/// No launch/run,
/// activation, menu or window creation is performed. Embedders with an already
/// regular application must not silently change their activation policy.
#[cfg(feature = "desk-probe")]
pub fn prepare_pointer_hit_tests() -> bool {
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy, NSRunningApplication};
    let Some(main) = objc2::MainThreadMarker::new() else {
        return false;
    };
    let before = NSRunningApplication::currentApplication().activationPolicy();
    if before == NSApplicationActivationPolicy::Regular {
        *POINTER_STARTUP_DIAGNOSIS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (Some(before.0), None, None);
        return false;
    }
    let app = NSApplication::sharedApplication(main);
    let setter = app.setActivationPolicy(NSApplicationActivationPolicy::Prohibited);
    let after = app.activationPolicy();
    *POINTER_STARTUP_DIAGNOSIS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        (Some(before.0), Some(setter), Some(after.0));
    // The setter reports whether a switch succeeded, not whether the process
    // currently has the required policy. Only the policy read-back admits it.
    pointer_policy_ready(before.0, after.0)
}

/// Non-prompting posting permission preflight for the manual VM probe.
#[cfg(feature = "desk-probe")]
pub fn pointer_probe_posting_permitted() -> bool {
    // SAFETY: the documented preflight takes no arguments and requests no grant.
    unsafe { CGPreflightPostEventAccess() }
}

#[cfg(feature = "desk-probe")]
fn pointer_policy_ready(before: isize, after: isize) -> bool {
    // -1 was observed for a pre-AppKit command-line process in the test VM;
    // Apple does not document it as an activation-policy enum case. Admit that
    // initial unknown only after a concrete Prohibited read-back. Other unknown
    // values, and an initially Regular application, are not admitted.
    matches!(before, -1 | 1 | 2) && after == 2
}

#[cfg(feature = "desk-probe")]
pub fn pointer_hit_test_startup_diagnosis() -> PointerStartupDiagnosis {
    *POINTER_STARTUP_DIAGNOSIS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "desk-probe")]
pub fn current_app_activation_mode_raw() -> isize {
    objc2_app_kit::NSRunningApplication::currentApplication()
        .activationPolicy()
        .0
}

#[cfg(all(test, feature = "desk-probe"))]
#[test]
fn pointer_startup_readiness_requires_nonregular_before_and_prohibited_after() {
    assert!(pointer_policy_ready(-1, 2));
    assert!(!pointer_policy_ready(-1, -1));
    assert!(!pointer_policy_ready(99, 2));
    assert!(pointer_policy_ready(2, 2));
    assert!(pointer_policy_ready(1, 2));
    assert!(!pointer_policy_ready(0, 2));
    assert!(!pointer_policy_ready(2, 0));
    assert!(!pointer_policy_ready(2, 1));
}

fn window_visibility_with_entries(
    pid: u32,
    id: u32,
    entries: &[crate::window_visibility::Window],
) -> (crate::WindowVisibility, crate::VisibilityRule) {
    use crate::window_visibility::visibility_from_windows;
    use crate::WindowVisibility;
    let Some(displays) = visibility_displays() else {
        return (
            WindowVisibility::Unknown,
            crate::VisibilityRule::MissingData,
        );
    };
    visibility_from_windows(pid, id, entries, &displays)
}

pub(super) fn visibility_displays() -> Option<Vec<crate::window_visibility::Rect>> {
    use crate::window_visibility::Rect;
    let mut ids = [0u32; 32];
    let mut count = 0;
    // SAFETY: ids has capacity for 32 display IDs and count is a valid output pointer.
    let status = unsafe { CGGetActiveDisplayList(ids.len() as u32, ids.as_mut_ptr(), &mut count) };
    if status != 0 || count == 0 || count as usize >= ids.len() {
        return None;
    }
    Some(
        ids[..count as usize]
            .iter()
            .map(|id| {
                // SAFETY: the display ID was supplied by CoreGraphics immediately above.
                let bounds = unsafe { CGDisplayBounds(*id) };
                Rect {
                    x: bounds.origin.x,
                    y: bounds.origin.y,
                    width: bounds.size.width,
                    height: bounds.size.height,
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_thread_pointer_query_returns_without_entering_appkit() {
        assert_eq!(
            std::thread::spawn(|| pointer_window_at(10.0, 20.0))
                .join()
                .unwrap(),
            None
        );
    }

    fn rect(x: f64, y: f64, width: f64, height: f64) -> CGRect {
        CGRect::new(CGPoint::new(x, y), CGSize::new(width, height))
    }

    #[test]
    fn diagnostic_display_counts_use_all_windows_and_positive_area_overlap() {
        let displays = [rect(0.0, 0.0, 100.0, 100.0), rect(100.0, 0.0, 100.0, 100.0)];
        let windows = [
            Some(rect(90.0, 0.0, 20.0, 20.0)),
            Some(rect(300.0, 0.0, 20.0, 20.0)),
            Some(rect(10.0, 10.0, 0.0, 20.0)),
            Some(rect(-10.0, 0.0, 10.0, 20.0)),
        ];
        assert_eq!(
            intersecting_window_count(Some(&windows), Some(&displays)),
            Some(1)
        );
        assert_eq!(
            intersecting_window_count(Some(&windows), Some(&[])),
            Some(0)
        );
        assert_eq!(
            intersecting_window_count(Some(&[]), Some(&displays)),
            Some(0)
        );
    }

    #[test]
    fn diagnostic_display_counts_keep_missing_or_invalid_readings_unknown() {
        let display = [rect(0.0, 0.0, 100.0, 100.0)];
        assert_eq!(intersecting_window_count(None, Some(&display)), None);
        assert_eq!(
            intersecting_window_count(Some(&[None]), Some(&display)),
            None
        );
        assert_eq!(intersecting_window_count(Some(&[]), None), None);
        assert_eq!(
            intersecting_window_count(Some(&[Some(rect(f64::NAN, 0.0, 1.0, 1.0))]), Some(&display)),
            None
        );
    }

    /// The frame header's width and height, found by walking the markers.
    fn frame_size(jpeg: &[u8]) -> Option<(u16, u16)> {
        let mut at = 2;
        while at + 9 < jpeg.len() {
            let marker = jpeg[at + 1];
            let length = u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]) as usize;
            if matches!(marker, 0xC0..=0xC2) {
                let height = u16::from_be_bytes([jpeg[at + 5], jpeg[at + 6]]);
                let width = u16::from_be_bytes([jpeg[at + 7], jpeg[at + 8]]);
                return Some((width, height));
            }
            at += 2 + length;
        }
        None
    }

    /// The system encoder produces a JPEG of exactly the requested size, which
    /// is what a reply's stated dimensions are read back from.
    #[test]
    fn a_scaled_jpeg_has_exactly_the_requested_dimensions() {
        let (width, height) = (300, 200);
        let bgra: Vec<u8> = (0..width * height)
            .flat_map(|pixel| [(pixel % 251) as u8, 40, 200, 255])
            .collect();
        let jpeg = encode_scaled_jpeg(&bgra, width, height, 150, 100).unwrap();
        assert_eq!(&jpeg[..2], &[0xFF, 0xD8]);
        assert_eq!(frame_size(&jpeg), Some((150, 100)));
    }

    #[test]
    fn a_buffer_that_does_not_match_its_dimensions_is_refused() {
        assert!(encode_scaled_jpeg(&[0; 12], 2, 2, 1, 1).is_err());
        assert!(encode_scaled_jpeg(&[0; 16], 2, 2, 0, 1).is_err());
    }
}

/// Count only this process's on-screen window-server entries, without capture,
/// ScreenCaptureKit enumeration, or any permission-requesting API.
#[cfg(feature = "desk-probe")]
pub fn pointer_probe_own_window_count() -> Option<usize> {
    let windows = CGWindowListCopyWindowInfo(CGWindowListOption::OptionOnScreenOnly, 0)?;
    // SAFETY: CoreGraphics documents this array as string-keyed dictionaries.
    let windows: &CFArray<CFDictionary<CFString, CFType>> = unsafe { windows.cast_unchecked() };
    let own_pid = f64::from(std::process::id());
    Some(
        (0..windows.len())
            .filter(|index| {
                windows
                    .get(*index)
                    .and_then(|window| window.get(&CFString::from_static_str("kCGWindowOwnerPID")))
                    .and_then(|value| value.downcast::<CFNumber>().ok())
                    .and_then(|value| value.as_f64())
                    == Some(own_pid)
            })
            .count(),
    )
}
