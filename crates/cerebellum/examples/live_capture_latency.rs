//! Read-only latency probe for the already-frontmost, uncovered window.
//! It never activates an app, posts input, launches an app, or saves pixels.
//! Build locally with CEREBELLUM_CAPTURE_PROBE_NONCE set to a fresh receipt.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("UNMEASURABLE: this probe requires macOS");
    std::process::exit(2);
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(reason) = probe::run() {
        eprintln!("UNMEASURABLE: {reason}");
        std::process::exit(2);
    }
}

#[cfg(target_os = "macos")]
mod probe {
    use std::time::{Duration, Instant};

    use cerebellum_computer::capture::ScopedCaptureController;
    use cerebellum_computer::platform::native::{grant_for_pid, NativeCaptureBackend};
    use sha2::{Digest, Sha256};

    const SAMPLES: usize = 20;
    const TIMEOUT: Duration = Duration::from_secs(3);

    fn check(pid: u32, window: u32) -> Result<(), String> {
        match cerebellum_macos::screen_is_locked() {
            Some(false) => {}
            Some(true) => return Err("the screen is locked; no capture was attempted".into()),
            None => return Err("screen lock state is unknown".into()),
        }
        if !cerebellum_macos::screen_capture_is_permitted() {
            return Err("Screen Recording is unavailable; this probe never requests it".into());
        }
        if cerebellum_macos::frontmost_process_id().and_then(|v| u32::try_from(v).ok()) != Some(pid)
            || cerebellum_macos::frontmost_window_id(pid) != Some(window)
        {
            return Err(
                "the frontmost app or window changed; stopped without moving anything".into(),
            );
        }
        if cerebellum_macos::window_visibility(pid, window)
            != cerebellum_macos::WindowVisibility::FullyVisible
        {
            return Err("the window is not established to be uncovered".into());
        }
        Ok(())
    }

    fn stats(name: &str, mut samples: Vec<f64>) {
        samples.sort_by(f64::total_cmp);
        println!(
            "{name}: n={} p50_ms={:.3} p95_ms={:.3} max_ms={:.3} (nearest-rank)",
            samples.len(),
            samples[9],
            samples[18],
            samples[19]
        );
    }

    pub fn run() -> Result<(), String> {
        let nonce = option_env!("CEREBELLUM_CAPTURE_PROBE_NONCE")
            .ok_or("build with a fresh CEREBELLUM_CAPTURE_PROBE_NONCE")?;
        println!(
            "fresh_build_nonce={nonce} example_source_sha256={:x}",
            Sha256::digest(include_bytes!("live_capture_latency.rs"))
        );
        // Lock and permission reads precede even window enumeration.
        match cerebellum_macos::screen_is_locked() {
            Some(false) => {}
            Some(true) => return Err("the screen is locked; no capture was attempted".into()),
            None => return Err("screen lock state is unknown".into()),
        }
        if !cerebellum_macos::screen_capture_is_permitted() {
            return Err("Screen Recording is unavailable; this probe never requests it".into());
        }
        let pid = cerebellum_macos::frontmost_process_id()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or("frontmost pid is unknown")?;
        let window = cerebellum_macos::frontmost_window_id(pid)
            .ok_or("the frontmost app has no ordinary on-screen window")?;
        check(pid, window)?;
        let grant =
            grant_for_pid(pid, TIMEOUT).ok_or("the frontmost process cannot be identified")?;
        println!(
            "app={} pid={pid} window_id={window} screen_locked=false",
            grant.bundle_identity
        );
        let mut total = Vec::new();
        let mut visible_work = Vec::new();
        for i in 0..SAMPLES {
            let work = Instant::now();
            check(pid, window)?;
            // A fresh controller per sample matches each served read_state call.
            let mut controller = ScopedCaptureController::with_v1_bounds(
                NativeCaptureBackend::new(TIMEOUT),
                grant.clone(),
            )
            .map_err(|e| e.to_string())?;
            let begun = Instant::now();
            let frame = controller
                .capture_frontmost_window_for_vision(0)
                .map_err(|e| format!("capture failed: {e:?}"))?;
            let elapsed = begun.elapsed().as_secs_f64() * 1000.0;
            check(pid, window)?;
            total.push(elapsed);
            visible_work.push(work.elapsed().as_secs_f64() * 1000.0);
            println!(
                "controller_sample={} total_ms={elapsed:.3} size={}x{}",
                i + 1,
                frame.frame.captured_width_px,
                frame.frame.captured_height_px
            );
        }
        stats("capture_frontmost_window_for_vision", total);
        stats("controller_plus_visibility_checks", visible_work);

        // A second read-only batch separates the same native BGRA capture from
        // its scaling/JPEG encoder, without altering the production backend.
        let mut captures = Vec::new();
        let mut encodes = Vec::new();
        for i in 0..SAMPLES {
            check(pid, window)?;
            let begun = Instant::now();
            let raw = cerebellum_macos::capture_window(window, TIMEOUT, None)
                .map_err(|e| format!("raw capture failed: {e:?}"))?;
            let capture_ms = begun.elapsed().as_secs_f64() * 1000.0;
            check(pid, window)?;
            if raw.owner_pid_at_capture != pid
                || cerebellum_macos::process_start_time_micros(pid).map(|v| v.to_string())
                    != Some(grant.process_generation_evidence.clone())
            {
                return Err("capture owner or process generation changed".into());
            }
            let size = cerebellum_core::vision::fit_within_vision_limits(
                u32::try_from(raw.width).map_err(|_| "width overflow")?,
                u32::try_from(raw.height).map_err(|_| "height overflow")?,
            )
            .ok_or("empty capture")?;
            let begun = Instant::now();
            let _jpeg = cerebellum_macos::encode_scaled_jpeg(
                &raw.bgra,
                raw.width,
                raw.height,
                size.0 as usize,
                size.1 as usize,
            )?;
            let encode_ms = begun.elapsed().as_secs_f64() * 1000.0;
            captures.push(capture_ms);
            encodes.push(encode_ms);
            println!(
                "split_sample={} capture_ms={capture_ms:.3} encode_ms={encode_ms:.3}",
                i + 1
            );
        }
        stats("native_bgra_capture", captures);
        stats("scale_and_jpeg_encode", encodes);
        check(pid, window)?;
        println!("PASS: 20 controller and 20 split captures; no fronting, input, launch, saved pixels or window text");
        Ok(())
    }
}
