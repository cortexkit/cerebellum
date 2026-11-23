//! Alpha-only, single-window witness for the manually operated Dock probe.

use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_core_graphics::{
    CGColor, CGDataProvider, CGImage, CGImageAlphaInfo, CGImageByteOrderInfo,
};
use objc2_foundation::NSError;
use objc2_screen_capture_kit::{SCContentFilter, SCScreenshotManager, SCStreamConfiguration};

use super::{find_window, Delivery};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const DOCK_BUNDLE: &str = "com.apple.dock";

pub type WitnessFence = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Debug)]
pub struct AlphaSample {
    pub requested_at: Instant,
    pub frame_arrived_at: Instant,
    pub returned_at: Instant,
    pub total: usize,
    pub near_opaque: usize,
    pub near_transparent: usize,
}

#[derive(Clone)]
pub struct DockOverlayWitness {
    send: mpsc::Sender<SampleRequest>,
    pub dock_pid: u32,
    pub window_id: u32,
    pub window_rect: [f64; 4],
    dock_generation: u64,
}

struct SampleRequest {
    until: Instant,
    fence: WitnessFence,
    reply: mpsc::Sender<Result<AlphaSample, String>>,
}

impl DockOverlayWitness {
    pub fn prepare(scratch_rect: [f64; 4]) -> Result<Self, String> {
        let mut docks = crate::workspace_running_applications()?
            .into_iter()
            .filter(|app| app.bundle_identifier == DOCK_BUNDLE);
        let dock_pid = docks.next().ok_or("no running com.apple.dock")?.pid;
        if docks.next().is_some() {
            return Err("multiple processes claim com.apple.dock".into());
        }
        let dock_generation = crate::process_start_time_micros(dock_pid)
            .ok_or("cannot identify Dock process generation")?;
        let (window_id, window_rect) =
            crate::window_image::dock_overlay_window(dock_pid, scratch_rect)?;
        let (send, requests) = mpsc::channel::<SampleRequest>();
        let (ready, setup) = mpsc::channel();
        // Keep the Objective-C capture objects on one worker. The fronted
        // callback need not enumerate windows or construct a filter.
        std::thread::Builder::new()
            .name("ck-desk-dock-overlay-witness".into())
            .spawn(move || {
                let prepared = objc2::rc::autoreleasepool(|_| {
                    Prepared::new(dock_pid, window_id, window_rect, scratch_rect)
                });
                let prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                for request in requests {
                    let result = objc2::rc::autoreleasepool(|_| {
                        if crate::process_start_time_micros(dock_pid) != Some(dock_generation) {
                            return Err("Dock process generation changed".into());
                        }
                        prepared.capture(request.until, request.fence)
                    });
                    let _ = request.reply.send(result);
                }
            })
            .map_err(|error| format!("cannot start Dock witness worker: {error}"))?;
        setup
            .recv_timeout(LOOKUP_TIMEOUT + Duration::from_secs(1))
            .map_err(|_| "Dock witness setup did not finish")??;
        Ok(Self {
            send,
            dock_pid,
            window_id,
            window_rect,
            dock_generation,
        })
    }

    /// Stop rather than sample a moved or replaced overlay on another display.
    pub fn verify_window(&self, scratch_rect: [f64; 4]) -> Result<(), String> {
        if crate::process_start_time_micros(self.dock_pid) != Some(self.dock_generation)
            || crate::window_image::dock_overlay_window(self.dock_pid, scratch_rect)?
                != (self.window_id, self.window_rect)
        {
            return Err("Dock overlay identity or geometry changed".into());
        }
        Ok(())
    }

    /// There is no alternate capture path, including when the cutoff wins.
    pub fn sample(&self, until: Instant, fence: WitnessFence) -> Result<AlphaSample, String> {
        let (reply, receive) = mpsc::channel();
        self.send
            .send(SampleRequest {
                until,
                fence,
                reply,
            })
            .map_err(|_| "Dock witness worker stopped")?;
        receive
            .recv_timeout(until.saturating_duration_since(Instant::now()))
            .map_err(|_| "Dock alpha sample did not arrive before the cutoff")?
    }
}

#[derive(Clone, Copy)]
struct Raster {
    width: usize,
    height: usize,
    left: usize,
    top: usize,
    right: usize,
    bottom: usize,
}

impl Raster {
    fn new([x, y, w, h]: [f64; 4], [sx, sy, sw, sh]: [f64; 4]) -> Result<Self, String> {
        // CoreGraphics and ScreenCaptureKit frames are top-down screen points.
        // Request one output pixel per point and count only pixels inside scratch.
        let raster = Self {
            width: w as usize,
            height: h as usize,
            left: (sx - x).ceil() as usize,
            top: (sy - y).ceil() as usize,
            right: (sx + sw - x).floor() as usize,
            bottom: (sy + sh - y).floor() as usize,
        };
        if w.fract() != 0.0
            || h.fract() != 0.0
            || raster.left >= raster.right
            || raster.top >= raster.bottom
            || raster.right > raster.width
            || raster.bottom > raster.height
        {
            return Err("scratch rect cannot be mapped to Dock pixels".into());
        }
        Ok(raster)
    }
}

struct Prepared {
    filter: Retained<SCContentFilter>,
    configuration: Retained<SCStreamConfiguration>,
    raster: Raster,
}

impl Prepared {
    fn new(dock_pid: u32, id: u32, rect: [f64; 4], scratch: [f64; 4]) -> Result<Self, String> {
        let raster = Raster::new(rect, scratch)?;
        crate::establish_window_server_connection();
        let window = find_window(id, LOOKUP_TIMEOUT).map_err(|error| {
            format!("ScreenCaptureKit did not supply Dock window {id}: {error}")
        })?;
        // SAFETY: the retained window and owner live through these property reads.
        unsafe {
            let owner = window
                .owningApplication()
                .ok_or("ScreenCaptureKit Dock window has no owner")?;
            let frame = window.frame();
            if u32::try_from(owner.processID()).ok() != Some(dock_pid)
                || owner.bundleIdentifier().to_string() != DOCK_BUNDLE
                || window.windowLayer() != 20
                || [
                    frame.origin.x,
                    frame.origin.y,
                    frame.size.width,
                    frame.size.height,
                ] != rect
            {
                return Err(
                    "ScreenCaptureKit Dock window identity or frame disagrees with CoreGraphics"
                        .into(),
                );
            }
            let filter = SCContentFilter::initWithDesktopIndependentWindow(
                SCContentFilter::alloc(),
                &window,
            );
            let configuration = SCStreamConfiguration::new();
            let clear = CGColor::new_generic_rgb(0.0, 0.0, 0.0, 0.0);
            configuration.setWidth(raster.width);
            configuration.setHeight(raster.height);
            configuration.setShowsCursor(false);
            configuration.setIgnoreShadowsSingleWindow(true);
            configuration.setShouldBeOpaque(false);
            configuration.setBackgroundColor(&clear);
            Ok(Self {
                filter,
                configuration,
                raster,
            })
        }
    }

    fn capture(&self, until: Instant, fence: WitnessFence) -> Result<AlphaSample, String> {
        let result = Delivery::new();
        let sink = result.clone();
        let raster = self.raster;
        let callback_fence = fence.clone();
        let handler = RcBlock::new(move |image: *mut CGImage, error: *mut NSError| {
            let arrived = Instant::now();
            if arrived >= until || !callback_fence() {
                return;
            }
            // SAFETY: ScreenCaptureKit owns the arguments until this callback
            // returns. No pixel buffer or image leaves the callback.
            let outcome = unsafe {
                if error.as_ref().is_some() {
                    Err("ScreenCaptureKit refused the Dock window capture".into())
                } else if let Some(image) = image.as_ref() {
                    read_alpha(image, raster).map(|counts| (arrived, counts))
                } else {
                    Err("ScreenCaptureKit returned no Dock window image".into())
                }
            };
            sink.deliver(outcome);
        });
        if Instant::now() >= until || !fence() {
            return Err("Dock witness cutoff passed before capture was requested".into());
        }
        let requested_at = Instant::now();
        // SAFETY: the worker owns the single-window filter and configuration;
        // the framework retains the completion block if it calls it later.
        unsafe {
            SCScreenshotManager::captureImageWithFilter_configuration_completionHandler(
                &self.filter,
                &self.configuration,
                Some(&handler),
            );
        }
        let (frame_arrived_at, (total, near_opaque, near_transparent)) = result
            .wait(until.saturating_duration_since(Instant::now()))
            .ok_or("ScreenCaptureKit Dock window image timed out")??;
        let returned_at = Instant::now();
        if returned_at >= until || !fence() {
            return Err("Dock alpha sample returned after the cutoff".into());
        }
        Ok(AlphaSample {
            requested_at,
            frame_arrived_at,
            returned_at,
            total,
            near_opaque,
            near_transparent,
        })
    }
}

fn read_alpha(image: &CGImage, raster: Raster) -> Result<(usize, usize, usize), String> {
    if (CGImage::width(Some(image)), CGImage::height(Some(image))) != (raster.width, raster.height)
    {
        return Err("ScreenCaptureKit returned unexpected Dock image dimensions".into());
    }
    if CGImage::bits_per_component(Some(image)) != 8 || CGImage::bits_per_pixel(Some(image)) != 32 {
        return Err("Dock image is not a four-channel 8-bit raster".into());
    }
    let alpha_first = match CGImage::alpha_info(Some(image)) {
        CGImageAlphaInfo::First | CGImageAlphaInfo::PremultipliedFirst => true,
        CGImageAlphaInfo::Last | CGImageAlphaInfo::PremultipliedLast => false,
        _ => return Err("Dock image has no usable alpha channel".into()),
    };
    let reversed = match CGImage::byte_order_info(Some(image)) {
        CGImageByteOrderInfo::Order32Little => true,
        CGImageByteOrderInfo::Order32Big | CGImageByteOrderInfo::OrderDefault => false,
        _ => return Err("Dock image has unsupported byte order".into()),
    };
    let channel = if alpha_first != reversed { 0 } else { 3 };
    let provider = CGImage::data_provider(Some(image)).ok_or("Dock image has no pixel provider")?;
    let data = CGDataProvider::data(Some(&provider)).ok_or("Dock pixel provider is unreadable")?;
    let byte_ptr = data.byte_ptr();
    let len = usize::try_from(data.length()).map_err(|_| "invalid Dock pixel buffer length")?;
    if byte_ptr.is_null() {
        return Err("Dock image pixels are unreadable".into());
    }
    // SAFETY: the retained CFData owns this pointer and length during the scan.
    let bytes = unsafe { std::slice::from_raw_parts(byte_ptr, len) };
    count_alpha(bytes, CGImage::bytes_per_row(Some(image)), raster, channel)
}

fn count_alpha(
    bytes: &[u8],
    stride: usize,
    raster: Raster,
    channel: usize,
) -> Result<(usize, usize, usize), String> {
    if stride < raster.width.saturating_mul(4) || bytes.len() < stride.saturating_mul(raster.height)
    {
        return Err("Dock pixel buffer is shorter than its raster".into());
    }
    let mut opaque = 0;
    let mut transparent = 0;
    for y in raster.top..raster.bottom {
        for alpha in bytes[y * stride + 4 * raster.left + channel..y * stride + 4 * raster.right]
            .iter()
            .step_by(4)
            .copied()
        {
            opaque += usize::from(alpha >= 250);
            transparent += usize::from(alpha <= 5);
        }
    }
    Ok((
        (raster.right - raster.left) * (raster.bottom - raster.top),
        opaque,
        transparent,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dock_alpha_counts_only_scratch_pixels_at_the_inclusive_thresholds() {
        let raster = Raster::new([-5.0, 10.0, 4.0, 3.0], [-4.0, 11.0, 3.0, 1.0]).unwrap();
        let stride = 20;
        // A non-alpha channel is opaque everywhere; it must not affect counts.
        let mut bytes = [255; 60];
        [5, 249, 250]
            .into_iter()
            .enumerate()
            .for_each(|(i, alpha)| {
                bytes[stride + 4 * (i + 1) + 3] = alpha;
            });
        assert_eq!(count_alpha(&bytes, stride, raster, 3).unwrap(), (3, 1, 1));
        assert!(count_alpha(&bytes[..59], stride, raster, 3).is_err());
    }
}
