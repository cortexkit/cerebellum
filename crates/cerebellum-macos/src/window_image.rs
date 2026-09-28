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
            return Some(id as u32);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
