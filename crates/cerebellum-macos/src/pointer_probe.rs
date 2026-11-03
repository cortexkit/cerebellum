//! Read-only telemetry for the disposable-VM probe.

use crate::ProcessGeneration;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject};
use objc2::{msg_send, ClassType};
use objc2_app_kit::{NSRunningApplication, NSWorkspace};
use objc2_core_foundation::{CFArray, CFDictionary, CFNumber, CFString, CFType};
use objc2_core_graphics::{CGWindowListCopyWindowInfo, CGWindowListOption};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerHelperState {
    pub pid: u32,
    pub activation_policy: Option<isize>,
    pub on_screen_windows: Option<Vec<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerHelperStartupSample {
    pub frontmost_pid: Option<u32>,
    pub helpers: Vec<PointerHelperState>,
}

/// Sample Workspace focus, per-helper activation policy, and all on-screen
/// window IDs owned by those helper PIDs. No image capture, accessibility
/// queries or permission requests occur.
pub fn pointer_helper_startup_sample(helpers: &[ProcessGeneration]) -> PointerHelperStartupSample {
    objc2::rc::autoreleasepool(|_| {
        let frontmost_pid = NSWorkspace::sharedWorkspace()
            .frontmostApplication()
            .and_then(|app| {
                // SAFETY: documented read-only pid property of the retained app.
                let pid: i32 = unsafe { msg_send![&*app, processIdentifier] };
                u32::try_from(pid).ok()
            });
        let windows = CGWindowListCopyWindowInfo(CGWindowListOption::OptionOnScreenOnly, 0);
        let helpers = helpers
            .iter()
            .map(|helper| {
                let alive =
                    crate::process_start_time_micros(helper.pid) == Some(helper.start_time_micros);
                let policy = alive
                    .then(|| i32::try_from(helper.pid).ok())
                    .flatten()
                    .and_then(|pid| {
                        let class: &AnyClass = NSRunningApplication::class();
                        // SAFETY: documented read-only PID lookup and policy
                        // property; the retained instance lives through the read.
                        let app: Option<Retained<AnyObject>> = unsafe {
                            msg_send![class, runningApplicationWithProcessIdentifier: pid]
                        };
                        app.map(|app| unsafe { msg_send![&*app, activationPolicy] })
                    });
                let own = windows.as_ref().and_then(|windows| {
                    // SAFETY: CoreGraphics documents an array of string-keyed
                    // window dictionaries; only numeric metadata is read.
                    let windows: &CFArray<CFDictionary<CFString, CFType>> =
                        unsafe { windows.cast_unchecked() };
                    let mut own = Vec::new();
                    for index in 0..windows.len() {
                        let window = windows.get(index)?;
                        let number = |key: &str| {
                            window
                                .get(&CFString::from_str(key))?
                                .downcast::<CFNumber>()
                                .ok()?
                                .as_f64()
                        };
                        if number("kCGWindowOwnerPID") != Some(f64::from(helper.pid)) {
                            continue;
                        }
                        let id = number("kCGWindowNumber")?;
                        if !id.is_finite()
                            || id < 1.0
                            || id > f64::from(u32::MAX)
                            || id.fract() != 0.0
                        {
                            return None;
                        }
                        own.push(id as u32);
                    }
                    own.sort_unstable();
                    Some(own)
                });
                PointerHelperState {
                    pid: helper.pid,
                    activation_policy: policy,
                    on_screen_windows: own,
                }
            })
            .collect();
        PointerHelperStartupSample {
            frontmost_pid,
            helpers,
        }
    })
}
