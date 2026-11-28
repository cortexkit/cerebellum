//! Windows foreground observations and HWND-bound activation.

use super::app_state::windows;
use super::identity::{frame_proof, frame_target_pid, FrameProof};
use super::picture::common_keys;
use super::*;
use cerebellum_windows::{
    foreground_window_number, last_input_tick, retain_image_process, set_foreground_window,
    window_identity_facts, ProcessStartTime, RetainedProcessHandle,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

mod background;
mod bracket;
mod observer;
mod pieces;
mod takeover;
pub use background::{BackgroundForeground, BackgroundRestore};
use bracket::Observer;
pub(super) use bracket::{query_focus, run_native, FrontedHookSlot, NativeWork};
pub(super) use observer::trial_install;
use observer::NativeObserver;
pub use pieces::chord_supported;
pub use takeover::WINDOWS_DOWN_GESTURE_RECOVERY_MEASURED;
pub(super) use takeover::{dispatch_takeover, physical_pointer_pixel};

pub fn background_restore_admitted(
    inputs: &ImmutableReleaseInputs,
    elevation: WindowsElevation,
) -> bool {
    common_keys(inputs, elevation) && inputs.windows_fronting_review_revision.is_some()
}

// Background cleanup cannot race another Windows foreground write in this process.
fn take_foreground_lane() -> Option<ForegroundLane> {
    static LANE: AtomicBool = AtomicBool::new(false);
    LANE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .ok()
        .map(|_| ForegroundLane(&LANE))
}

struct ForegroundLane(&'static AtomicBool);

impl Drop for ForegroundLane {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let now = crate::fronting_clock::now();
    now.saturating_duration_since(*START.get_or_init(|| now))
        .as_millis() as u64
}

fn generation(process: &RetainedProcessHandle) -> Option<u64> {
    match process.creation_time() {
        ProcessStartTime::Started(start) if process.process_wait_pending() => Some(start),
        _ => None,
    }
}

fn readable_integrity(process: &RetainedProcessHandle) -> bool {
    process
        .token_facts()
        .is_some_and(|token| !token.elevated && token.integrity_rid <= 0x2000)
}

/// An exact HWND and the retained generation the frame represents. Keep the
/// raw owner too: a hosted frame has a different owner from its content.
#[derive(Clone)]
pub(super) struct Binding {
    pub(super) number: u32,
    class: String,
    owner: Arc<RetainedProcessHandle>,
    owner_start: u64,
    target: Arc<RetainedProcessHandle>,
    target_start: u64,
    pub(super) proof: FrameProof,
}

impl Binding {
    fn read(number: u32, target: Option<Arc<RetainedProcessHandle>>) -> Option<Self> {
        let root = window_identity_facts(number).ok()?;
        let target = match target {
            Some(target) => target,
            None => Arc::new(retain_image_process(frame_target_pid(&root).ok()?).ok()?),
        };
        let owner = if root.pid == target.pid() {
            Arc::clone(&target)
        } else {
            Arc::new(retain_image_process(root.pid).ok()?)
        };
        let owner_start = generation(&owner)?;
        let target_start = generation(&target)?;
        let proof = frame_proof(&target, target.pid(), number).ok()??;
        let bound = Self {
            number,
            class: root.class,
            owner,
            owner_start,
            target,
            target_start,
            proof,
        };
        bound.current().then_some(bound)
    }

    fn current(&self) -> bool {
        generation(&self.owner) == Some(self.owner_start)
            && generation(&self.target) == Some(self.target_start)
            && window_identity_facts(self.number)
                .is_ok_and(|root| root.pid == self.owner.pid() && root.class == self.class)
            && frame_proof(&self.target, self.pid(), self.number)
                .ok()
                .flatten()
                .as_ref()
                == Some(&self.proof)
    }

    fn pid(&self) -> u32 {
        self.target.pid()
    }

    fn safe_integrity(&self) -> bool {
        readable_integrity(&self.owner) && readable_integrity(&self.target)
    }

    fn is_shell_desktop(&self) -> bool {
        matches!(self.class.as_str(), "Progman" | "WorkerW" | "Shell_TrayWnd")
    }

    pub(super) fn is_foreground(&self) -> bool {
        foreground_window_number() == Some(self.number)
            && self.current()
            && foreground_window_number() == Some(self.number)
    }
}

fn desktop_safe() -> bool {
    WindowsElevation::read_current_process() == WindowsElevation::Medium
        && windows::is_default_desktop()
}

fn target_process(target: &ProcessGrant) -> Result<Arc<RetainedProcessHandle>, DriverError> {
    target.validate()?;
    let generation = target.process_generation_evidence.parse().map_err(|_| {
        DriverError::InvalidRequest("process generation evidence is not a kernel start time")
    })?;
    windows::retain(target.pid, generation)
        .map(Arc::new)
        .map_err(|_| {
            DriverError::Unsupported("Windows target process or input desktop unavailable")
        })
}

pub(super) fn snapshot(target: &ProcessGrant) -> Result<FrontingSnapshot, DriverError> {
    let started = Instant::now();
    let retained = target_process(target)?;
    let foreground = foreground_window_number();
    let binding = foreground.and_then(|number| Binding::read(number, None));
    let candidates = windows::windows(&retained, target.pid, started + Duration::from_secs(2))
        .map_err(|_| DriverError::Unsupported("Windows window inventory unreadable"))?;
    let stack = cerebellum_windows::desktop_z_order()
        .map_err(|_| DriverError::Unsupported("Windows window order unreadable"))?;
    let target_windows: Vec<_> = stack
        .iter()
        .filter_map(|number| {
            candidates
                .eligible
                .iter()
                .find(|window| window.root.number == *number)
        })
        .enumerate()
        .map(|(rank, window)| FrontingWindow {
            observation_window_id: window.root.number.to_string(),
            owning_process_generation: target.process_generation_evidence.clone(),
            activation_state: if foreground == Some(window.root.number) {
                "foreground"
            } else {
                "background"
            }
            .into(),
            z_order: rank as i32,
        })
        .collect();
    let completeness = candidates.unreadable == 0
        && target_windows.len() == candidates.eligible.len()
        && foreground_window_number() == foreground
        && (foreground.is_none() || binding.as_ref().is_some_and(Binding::is_foreground));
    Ok(FrontingSnapshot {
        captured_at_ms: now_ms(),
        // A process or principal alone cannot distinguish two foreground HWNDs.
        frontmost_application_identity: binding.map(|bound| {
            format!(
                "{}:{}:{}",
                bound.number,
                bound.owner.pid(),
                bound.owner_start
            )
        }),
        target_windows,
        completeness,
    })
}
