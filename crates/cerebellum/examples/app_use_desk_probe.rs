//! Background app-use desk probe: what the person sees while an agent works
//! in a covered app, and what the module and the agent-cursor helper cost
//! once the agent is idle.
//!
//! Run it only with the person present and their approval, on an unlocked
//! Mac, after building the module binary it uses as the cursor helper:
//!
//! ```text
//! cargo build -p cerebellum --features desk-probe --bin ck-cerebellum --example app_use_desk_probe
//! cargo build -p cerebellum-macos --features desk-probe --example disclaim_launch
//! codesign --force --sign 'Apple Development: YOUR NAME (TEAMID)' --identifier ck-cerebellum target/debug/ck-cerebellum target/debug/examples/app_use_desk_probe
//! target/debug/examples/disclaim_launch target/debug/examples/app_use_desk_probe --approve-desk-probe
//! ```
//!
//! The operator signs the probe and its cursor-helper binary with their Apple
//! Development certificate. The launcher does not pass its own permission
//! grants to the probe: the probe must hold its own grants. Before any desk work
//! or helper exec, the probe prints the executable that macOS holds responsible
//! for its permission grants, then checks Accessibility, Screen Recording and
//! Input Monitoring without prompting. A missing permission exits 2; grant it
//! to the printed executable in System Settings before retrying.
//!
//! The probe is its own scratch module: it builds a computer plane in this
//! process with an isolated journal, never talks to the running daemon, and
//! reads no config file, so `computer_use.app_use` is `background` (the
//! default). Fronting is admitted here as an unreviewed desk build, so the
//! needs-front chord can run. The plane's agent cursor launches its helper by
//! re-running this executable with `--agent-cursor`; that branch replaces
//! itself with the sibling `ck-cerebellum --agent-cursor`, so the helper
//! process (and its pid) is the real one.
//!
//! It launches its own scratch TextEdit (a new instance, never the person's;
//! TextEdit must not already be running), waits until the person's front
//! app covers the scratch window, and then:
//!
//! 1. Active phase, background mode: reads the scratch app, writes a marker
//!    into its document, sends one Command chord (the one needs-front
//!    action), and reads again. A sampler reads the frontmost app every
//!    100 ms. Every sample outside the chord must be the person's front app,
//!    and the samples after the chord show it restored. The chord's reply
//!    must report a needs-front front that was restored, and the helper's
//!    preview window must be on screen after the first actions and again at
//!    the end of the phase.
//! 2. Idle phase: the agent's badge and preview are hidden (the agent's turn
//!    is over) and nothing is in flight. Over 30 s, measured with
//!    `proc_pid_rusage`, the helper's CPU time may grow by at most 10 ms, and
//!    the module's health counters `previewCaptureRequests` and
//!    `previewFramesWritten` must not move. A counter missing from the health
//!    report is a failure that names it, never a zero.
//! 3. Baseline: the same run in a child process with the agent cursor off
//!    (`agent_cursor: false`). The module's idle CPU time in phase 2 must be
//!    no more than 10% above the baseline's.
//!
//! The scratch TextEdit is killed on every exit path: normal return, a failed
//! check, a panic, and Ctrl-C. The helper ends with the plane. Nothing is
//! saved. The process exits 0 when every check passes, 1 when one fails and
//! 2 when the desk cannot be measured (`UNMEASURABLE`).

// Other platforms do not run the desk probe: an unapproved run is refused
// and an approved one reports `UNMEASURABLE: macOS desk required`. The
// verdict functions serve the macOS desk module and the tests alone.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

const APPROVAL_FLAG: &str = "--approve-desk-probe";
/// The flag the agent cursor's transport launches its helper with.
const HELPER_FLAG: &str = "--agent-cursor";
/// Runs the baseline child: the same actions with the agent cursor off.
const BASELINE_FLAG: &str = "--baseline";
/// The line the baseline child reports its idle CPU time on.
const BASELINE_LINE: &str = "BASELINE_MODULE_IDLE_CPU_NS=";
/// The module binary that serves as the cursor helper, beside the
/// `examples/` directory this probe is built into.
const HELPER_BINARY: &str = "ck-cerebellum";
/// Where the helper branch records its pid, beside this executable, so the
/// probe can measure exactly that process.
const HELPER_PID_EXTENSION: &str = "helper-pid";

/// How long the idle window lasts.
const IDLE_WINDOW: Duration = Duration::from_secs(30);
/// The most CPU time the helper may use across the idle window.
const HELPER_IDLE_CPU_LIMIT_NS: u64 = 10_000_000;
/// How far above the baseline the module's idle CPU time may be, in percent.
const MODULE_IDLE_CPU_TOLERANCE_PERCENT: u64 = 10;
/// The health counters that must not move while the agent is idle.
const IDLE_COUNTERS: [&str; 2] = ["previewCaptureRequests", "previewFramesWritten"];
/// The width of a background-mode preview window, in points.
const PREVIEW_WIDTH: f64 = cerebellum_computer::preview_layout::PREVIEW_WIDTH;

/// Whether the person approved this run on the command line.
fn approved(arguments: impl IntoIterator<Item = String>) -> bool {
    arguments
        .into_iter()
        .any(|argument| argument == APPROVAL_FLAG)
}

const TCC_PERMISSIONS: [&str; 3] = ["Accessibility", "Screen Recording", "Input Monitoring"];

/// Decide from non-prompting answers alone, without consulting macOS or
/// attempting to obtain a missing permission.
fn tcc_preflight_verdict(answers: [bool; 3]) -> Result<(), String> {
    let missing = TCC_PERMISSIONS
        .into_iter()
        .zip(answers)
        .filter_map(|(permission, allowed)| (!allowed).then_some(permission))
        .collect::<Vec<_>>()
        .join(", ");
    if !missing.is_empty() {
        return Err(missing);
    }
    Ok(())
}

/// No operation that could request permission may start until every preflight
/// has passed. Keeping the operation behind the decision also protects helper
/// execs and the baseline child, not just the main desk run.
fn with_tcc_preflight<T>(answers: [bool; 3], operation: impl FnOnce() -> T) -> Result<T, String> {
    tcc_preflight_verdict(answers)?;
    Ok(operation())
}

#[cfg(target_os = "macos")]
fn desk_preflight(operation: impl FnOnce() -> i32) -> i32 {
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrusted() -> bool;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGPreflightScreenCaptureAccess() -> bool;
        fn CGPreflightListenEventAccess() -> bool;
    }

    let responsible = cerebellum_macos::responsible_process().unwrap_or_else(|| {
        format!(
            "<unknown responsible process; probe executable: {}>",
            std::env::current_exe()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| "unknown".into())
        )
    });
    println!("TCC responsible executable: {responsible}");
    // These three calls only inspect the current grants; none requests access.
    let answers = unsafe {
        [
            AXIsProcessTrusted(),
            CGPreflightScreenCaptureAccess(),
            CGPreflightListenEventAccess(),
        ]
    };
    for (permission, allowed) in TCC_PERMISSIONS.into_iter().zip(answers) {
        println!("TCC {permission}: {allowed}");
    }
    match with_tcc_preflight(answers, operation) {
        Ok(code) => code,
        Err(missing) => {
            eprintln!(
                "REFUSED: missing {missing}. Grant the missing permissions to {responsible} \
                 in System Settings, then retry with the disclaiming launcher."
            );
            2
        }
    }
}

/// The module binary to run as the cursor helper: `ck-cerebellum` in the
/// build directory that holds this example's `examples/` directory.
fn helper_binary(executable: &Path) -> Option<PathBuf> {
    Some(executable.parent()?.parent()?.join(HELPER_BINARY))
}

/// CPU time in nanoseconds from `proc_pid_rusage` time units. On Apple
/// silicon those are mach absolute-time ticks, not nanoseconds, so they are
/// scaled by the mach timebase (1/1 on Intel).
fn cpu_nanos(ticks: u64, numer: u32, denom: u32) -> u64 {
    if denom == 0 {
        return ticks;
    }
    let nanos = u128::from(ticks) * u128::from(numer) / u128::from(denom);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// The helper's idle CPU time is at most 10 ms across the idle window.
fn helper_idle_verdict(delta_ns: u64) -> Result<(), String> {
    if delta_ns <= HELPER_IDLE_CPU_LIMIT_NS {
        Ok(())
    } else {
        Err(format!(
            "the helper used {:.3} ms of CPU while idle (limit {:.3} ms)",
            delta_ns as f64 / 1e6,
            HELPER_IDLE_CPU_LIMIT_NS as f64 / 1e6
        ))
    }
}

/// The module's idle CPU time is within 10% of the run with the agent
/// cursor off. Using less than the baseline passes.
fn module_idle_verdict(module_ns: u64, baseline_ns: u64) -> Result<(), String> {
    let allowed = u128::from(baseline_ns) * u128::from(100 + MODULE_IDLE_CPU_TOLERANCE_PERCENT);
    if u128::from(module_ns) * 100 <= allowed {
        Ok(())
    } else {
        Err(format!(
            "the module used {:.3} ms of CPU while idle, more than {MODULE_IDLE_CPU_TOLERANCE_PERCENT}% \
             above the {:.3} ms it used with the agent cursor off",
            module_ns as f64 / 1e6,
            baseline_ns as f64 / 1e6
        ))
    }
}

/// The counter `name` did not move between two health reports. A counter
/// absent from either report fails with its name: an unreported counter is
/// not evidence that nothing happened.
fn counter_still_verdict(before: &Value, after: &Value, name: &str) -> Result<(), String> {
    let read = |report: &Value, when: &str| {
        report[name]
            .as_u64()
            .ok_or_else(|| format!("health counter {name} is missing from the report {when}"))
    };
    let (before, after) = (read(before, "before")?, read(after, "after")?);
    if after == before {
        Ok(())
    } else {
        Err(format!(
            "health counter {name} moved from {before} to {after} while idle"
        ))
    }
}

/// The baseline child's idle CPU time, from its output.
fn baseline_from_output(output: &str) -> Option<u64> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(BASELINE_LINE))
        .and_then(|value| value.trim().parse().ok())
}

/// One reading of the frontmost app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrontSample {
    /// Milliseconds since sampling began.
    at_ms: u128,
    /// The frontmost app's pid, if it could be read.
    front: Option<i32>,
    /// Whether the needs-front action was running when the sample was taken.
    needs_front: bool,
}

/// The person's front app was frontmost in every sample except while the
/// one needs-front action ran, and samples after that action show it back.
fn front_app_verdict(samples: &[FrontSample], person: i32) -> Result<(), String> {
    let Some(first) = samples.iter().position(|sample| sample.needs_front) else {
        return Err("no sample was taken while the needs-front action ran".into());
    };
    let last = samples
        .iter()
        .rposition(|sample| sample.needs_front)
        .unwrap_or(first);
    if samples[first..=last]
        .iter()
        .any(|sample| !sample.needs_front)
    {
        return Err("the samples show more than one needs-front action".into());
    }
    if first == 0 {
        return Err("no sample was taken before the needs-front action".into());
    }
    if last + 1 == samples.len() {
        return Err("no sample was taken after the needs-front action".into());
    }
    match samples
        .iter()
        .find(|sample| !sample.needs_front && sample.front != Some(person))
    {
        Some(sample) => Err(format!(
            "at {} ms the frontmost app was {:?}, not the person's (pid {person}), outside the \
             needs-front action",
            sample.at_ms, sample.front
        )),
        None => Ok(()),
    }
}

/// The needs-front chord fronted the app for itself and put the person's
/// app back.
fn needs_front_reply_verdict(reply: &Value) -> Result<(), String> {
    let fronting = &reply["fronting"];
    let expected = [
        ("outcome", &reply["outcome"], Value::from("completed")),
        (
            "fronting.mode",
            &fronting["mode"],
            Value::from("background"),
        ),
        (
            "fronting.purpose",
            &fronting["purpose"],
            Value::from("needs_front"),
        ),
        ("fronting.fronted", &fronting["fronted"], Value::from(true)),
        (
            "fronting.restore",
            &fronting["restore"],
            Value::from("restored"),
        ),
    ];
    match expected.iter().find(|(_, actual, want)| *actual != want) {
        Some((name, actual, want)) => Err(format!(
            "the needs-front chord's {name} was {actual}, expected {want}"
        )),
        None => Ok(()),
    }
}

/// A background-mode action that is not a needs-front action completed
/// without fronting anything.
fn background_reply_verdict(action: &str, reply: &Value) -> Result<(), String> {
    if reply["outcome"] != "completed" {
        return Err(format!("{action} ended {}", reply["outcome"]));
    }
    match reply.get("fronting") {
        None => Ok(()),
        Some(fronting) if fronting["fronted"] == false => Ok(()),
        Some(fronting) => Err(format!("{action} fronted its app: {fronting}")),
    }
}

/// One on-screen window as the window server lists it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ListedWindow {
    owner: i32,
    width: f64,
    height: f64,
    alpha: f64,
}

/// How many of `windows` are the helper's preview windows, drawn so they can
/// be seen. A preview's width is within 1 point of `PREVIEW_WIDTH`; the
/// helper's badge windows are far narrower.
fn visible_previews(windows: &[ListedWindow], helper: i32) -> usize {
    windows
        .iter()
        .filter(|window| {
            window.owner == helper
                && (window.width - PREVIEW_WIDTH).abs() < 1.0
                && window.height > 0.0
                && window.alpha > 0.0
        })
        .count()
}

fn main() {
    // The agent cursor's transport launches its helper as this executable,
    // with no other argument and an empty environment.
    let helper = std::env::args()
        .skip(1)
        .any(|argument| argument == HELPER_FLAG);
    if !helper && !approved(std::env::args().skip(1)) {
        eprintln!(
            "REFUSED: this probe fronts a scratch application on the person's screen and \
             draws the agent cursor. Run it only with the person present and their approval, \
             passing {APPROVAL_FLAG}."
        );
        std::process::exit(2);
    }
    #[cfg(target_os = "macos")]
    std::process::exit(desk_preflight(|| {
        if helper {
            desk::become_helper();
            1
        } else {
            desk::run(
                std::env::args()
                    .skip(1)
                    .any(|argument| argument == BASELINE_FLAG),
            )
        }
    }));
    #[cfg(not(target_os = "macos"))]
    {
        if helper {
            std::process::exit(1);
        }
        eprintln!("UNMEASURABLE: macOS desk required");
        std::process::exit(2);
    }
}

// The probe's Cingulate, which answers each card with the narrowest grant it
// offers. Declared at the file's top level: a `#[path]` on a mod nested in an
// inline module resolves against `examples/<inline-mod-name>/`, which does not
// exist.
#[cfg(target_os = "macos")]
#[path = "support/allowing_cingulate.rs"]
mod allowing_cingulate;

#[cfg(target_os = "macos")]
mod desk {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use cerebellum::cingulate_client::desk::ConsentDesk;
    use cerebellum::cingulate_client::live_call::{LiveCall, NotLive};
    use cerebellum::computer_capability::{
        computer_audit, servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
    };
    use cerebellum::computer_grants::{
        AlwaysOpenRoute, ConsentContext, GrantCaller, QuestionCarrier,
    };
    use cerebellum::management::{ManagementPlane, PlatformResolver};
    use cerebellum::{HealthState, JournalPersistence};
    use cerebellum_computer::platform::native::NativeCaptureBackend;
    use cerebellum_computer::platform::{MacOs26PlatformDriver, TargetResolution};
    use cerebellum_core::clock::SystemClock;
    use cerebellum_core::dispatch::{DispatchTimingState, InFlightGuard};
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::JournalIdentity;
    use serde_json::json;
    use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
    use subc_protocol::session::{ModuleControlRequest, ModuleControlResponse};
    use subc_protocol::{Flags, Frame, FrameType, Principal, Priority, PROTOCOL_VERSION};

    const TEXTEDIT: &str = "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit";
    const TEXTEDIT_BUNDLE: &str = "com.apple.TextEdit";
    /// The agent the probe acts as; its badge and preview carry this name.
    const AGENT: &str = "desk-probe";
    const LAUNCH_WAIT: Duration = Duration::from_secs(15);
    /// How long the person has to cover the scratch window.
    const COVER_WAIT: Duration = Duration::from_secs(30);
    /// How long the preview has to appear after an action.
    const PREVIEW_WAIT: Duration = Duration::from_secs(3);
    /// Quiet time after the agent's turn ends, before the idle window starts,
    /// so a hide or a last frame in flight is not counted as idle work.
    const SETTLE: Duration = Duration::from_secs(2);
    const SAMPLE_EVERY: Duration = Duration::from_millis(100);

    /// Replace this process with the module binary's cursor helper, keeping
    /// the pid and the pipe on stdin the transport launched it with. Returns
    /// only when that fails.
    pub fn become_helper() {
        let Ok(executable) = std::env::current_exe() else {
            return;
        };
        let Some(helper) = helper_binary(&executable) else {
            return;
        };
        // The probe reads this to measure the helper; exec keeps the pid.
        let _ = std::fs::write(
            executable.with_extension(HELPER_PID_EXTENSION),
            std::process::id().to_string(),
        );
        let _ = Command::new(helper).arg(HELPER_FLAG).exec();
    }

    /// The scratch TextEdit, killed when dropped.
    struct Scratch {
        child: Child,
    }

    impl Scratch {
        fn pid(&self) -> u32 {
            self.child.id()
        }
    }

    fn kill(pid: u32) {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            kill(self.child.id());
            let _ = self.child.wait();
            println!("SCRATCH {} killed", self.child.id());
        }
    }

    /// The scratch pid, for the Ctrl-C handler. Zero when none is running.
    static SCRATCH_PID: Mutex<u32> = Mutex::new(0);

    fn install_interrupt_handler() {
        std::thread::spawn(|| {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                if tokio::signal::ctrl_c().await.is_ok() {
                    let pid = *SCRATCH_PID.lock().unwrap();
                    if pid != 0 {
                        kill(pid);
                        println!("SCRATCH {pid} killed after interrupt");
                    }
                    std::process::exit(130);
                }
            });
        });
    }

    /// Answers each card with the first choice it offers in the probe's
    /// order (30 minutes of the app, 30 minutes of the whole computer, one
    /// call), and declines when none is offered: running this probe is the
    /// person's consent to what it does.
    struct Allowing {
        desk: Arc<ConsentDesk>,
        guard: Arc<InFlightGuard>,
        stamp: ScopeStamp,
    }

    impl Allowing {
        fn new() -> Self {
            let clock = SystemClock::new();
            let timing = Arc::new(DispatchTimingState::new(&clock));
            Self {
                desk: Arc::new(ConsentDesk::new(Arc::new(
                    crate::allowing_cingulate::AllowingCingulate::new("el_app_use_probe_"),
                ))),
                guard: Arc::new(timing.enter(&clock)),
                stamp: ScopeStamp::new(
                    Principal::Reserved {
                        module_id: "prefrontal-core".into(),
                    },
                    identity().conversation_key,
                    1,
                    ScopeKind::Ephemeral,
                )
                .with_attributes(
                    ScopeAttributes::new().with_agent_id(Some(identity().agent_project_id)),
                )
                .with_owner_authorized(true),
            }
        }
    }

    impl QuestionCarrier for Allowing {
        fn desk(&self) -> Arc<ConsentDesk> {
            self.desk.clone()
        }
        fn live(&self) -> Result<LiveCall, NotLive> {
            LiveCall::from_inbound(Some(&self.stamp), &self.guard, Arc::new(AlwaysOpenRoute))
        }
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "desk-probe".into(),
            conversation_key: "app-use-desk-probe".into(),
            agent_project_id: AGENT.into(),
            session_kind: SessionKind::Primary,
            origin: Default::default(),
            computer_order: None,
        }
    }

    /// An attended session: the probe's Cingulate carries every question.
    fn consent() -> ConsentContext {
        let (drain_sender, drain) = tokio::sync::watch::channel(false);
        std::mem::forget(drain_sender);
        ConsentContext::new(
            GrantCaller::new(
                identity().conversation_key,
                identity().agent_project_id,
                false,
            ),
            Some(Arc::new(Allowing::new()) as Arc<dyn QuestionCarrier>),
            Arc::new(AlwaysOpenRoute),
            drain,
            None,
        )
    }

    /// Process CPU time and the window list, read straight from the system.
    #[allow(unsafe_code)]
    mod sys {
        use super::super::{cpu_nanos, ListedWindow};
        use std::ffi::{c_void, CString};

        type CfRef = *const c_void;

        /// `struct rusage_info_v0` from `<sys/resource.h>`.
        #[repr(C)]
        #[derive(Default)]
        struct RusageInfoV0 {
            uuid: [u8; 16],
            user_time: u64,
            system_time: u64,
            pkg_idle_wkups: u64,
            interrupt_wkups: u64,
            pageins: u64,
            wired_size: u64,
            resident_size: u64,
            phys_footprint: u64,
            proc_start_abstime: u64,
            proc_exit_abstime: u64,
        }

        #[repr(C)]
        #[derive(Default)]
        struct MachTimebaseInfo {
            numer: u32,
            denom: u32,
        }

        const RUSAGE_INFO_V0: i32 = 0;

        extern "C" {
            fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut *mut c_void) -> i32;
            fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
        }

        /// The CPU time (user plus system) `pid` has used, in nanoseconds.
        pub fn cpu_time_ns(pid: u32) -> Option<u64> {
            let mut info = RusageInfoV0::default();
            // SAFETY: `info` is a live, correctly laid out rusage_info_v0,
            // which is what flavor RUSAGE_INFO_V0 writes.
            let code = unsafe {
                proc_pid_rusage(
                    i32::try_from(pid).ok()?,
                    RUSAGE_INFO_V0,
                    (&mut info as *mut RusageInfoV0).cast(),
                )
            };
            if code != 0 {
                return None;
            }
            let mut timebase = MachTimebaseInfo::default();
            // SAFETY: `timebase` is a live mach_timebase_info_data_t.
            if unsafe { mach_timebase_info(&mut timebase) } != 0 {
                return None;
            }
            Some(cpu_nanos(
                info.user_time.saturating_add(info.system_time),
                timebase.numer,
                timebase.denom,
            ))
        }

        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {
            fn CGWindowListCopyWindowInfo(option: u32, relative_to: u32) -> CfRef;
        }

        #[link(name = "CoreFoundation", kind = "framework")]
        extern "C" {
            fn CFStringCreateWithCString(allocator: CfRef, text: *const i8, encoding: u32)
                -> CfRef;
            fn CFArrayGetCount(array: CfRef) -> isize;
            fn CFArrayGetValueAtIndex(array: CfRef, index: isize) -> CfRef;
            fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
            fn CFNumberGetValue(number: CfRef, kind: isize, value: *mut c_void) -> u8;
            fn CFGetTypeID(value: CfRef) -> usize;
            fn CFNumberGetTypeID() -> usize;
            fn CFDictionaryGetTypeID() -> usize;
            fn CFRelease(value: CfRef);
        }

        const UTF8: u32 = 0x0800_0100;
        const ON_SCREEN_ONLY: u32 = 1 << 0;
        const EXCLUDE_DESKTOP_ELEMENTS: u32 = 1 << 4;
        const FLOAT64: isize = 6;

        /// An owned CoreFoundation reference, released when dropped.
        struct Owned(CfRef);

        impl Drop for Owned {
            fn drop(&mut self) {
                // SAFETY: `Owned` holds exactly one retain count.
                unsafe { CFRelease(self.0) };
            }
        }

        fn string(text: &str) -> Owned {
            let text = CString::new(text).unwrap();
            // SAFETY: a valid NUL-terminated UTF-8 string; returns one retain.
            Owned(unsafe { CFStringCreateWithCString(std::ptr::null(), text.as_ptr(), UTF8) })
        }

        /// The number under `key` in `dictionary`, which is borrowed.
        fn number(dictionary: CfRef, key: &str) -> Option<f64> {
            let key = string(key);
            // SAFETY: a live dictionary and key; the value is borrowed.
            let value = unsafe { CFDictionaryGetValue(dictionary, key.0) };
            // SAFETY: `value` is checked to be a CFNumber before it is read.
            if value.is_null() || unsafe { CFGetTypeID(value) != CFNumberGetTypeID() } {
                return None;
            }
            let mut out = 0.0_f64;
            // SAFETY: a live CFNumber, converted into an f64.
            let converted =
                unsafe { CFNumberGetValue(value, FLOAT64, (&mut out as *mut f64).cast()) };
            (converted != 0).then_some(out)
        }

        /// The owner, size and opacity of each on-screen window whose owner
        /// and size can be read (an unreadable opacity counts as opaque), or
        /// `None` when the window server's list cannot be read.
        pub fn on_screen_windows() -> Option<Vec<ListedWindow>> {
            // SAFETY: returns one retained CFArray, or null.
            let list =
                unsafe { CGWindowListCopyWindowInfo(ON_SCREEN_ONLY | EXCLUDE_DESKTOP_ELEMENTS, 0) };
            if list.is_null() {
                return None;
            }
            let list = Owned(list);
            let bounds_key = string("kCGWindowBounds");
            let mut windows = Vec::new();
            // SAFETY: `list` is a live CFArray of dictionaries.
            for index in 0..unsafe { CFArrayGetCount(list.0) } {
                // SAFETY: the index is in range; the entry is borrowed.
                let entry = unsafe { CFArrayGetValueAtIndex(list.0, index) };
                // SAFETY: a live dictionary and key; the value is borrowed.
                let bounds = unsafe { CFDictionaryGetValue(entry, bounds_key.0) };
                // SAFETY: `bounds` is checked to be a dictionary before use.
                if bounds.is_null() || unsafe { CFGetTypeID(bounds) != CFDictionaryGetTypeID() } {
                    continue;
                }
                let (Some(owner), Some(width), Some(height)) = (
                    number(entry, "kCGWindowOwnerPID"),
                    number(bounds, "Width"),
                    number(bounds, "Height"),
                ) else {
                    continue;
                };
                windows.push(ListedWindow {
                    owner: owner as i32,
                    width,
                    height,
                    alpha: number(entry, "kCGWindowAlpha").unwrap_or(1.0),
                });
            }
            Some(windows)
        }
    }

    /// The frontmost app, sampled every 100 ms until stopped. Each sample
    /// records whether the needs-front action was running.
    struct Sampler {
        samples: Arc<Mutex<Vec<FrontSample>>>,
        needs_front: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Sampler {
        fn start() -> Self {
            let samples = Arc::new(Mutex::new(Vec::new()));
            let needs_front = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let started = Instant::now();
            let thread = {
                let (samples, needs_front, stop) =
                    (samples.clone(), needs_front.clone(), stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        // The flag is read on both sides of the frontmost
                        // read, so a sample taken while the action started
                        // or ended counts as taken during it.
                        let before = needs_front.load(Ordering::SeqCst);
                        let front = cerebellum_macos::frontmost_process_id();
                        let after = needs_front.load(Ordering::SeqCst);
                        samples.lock().unwrap().push(FrontSample {
                            at_ms: started.elapsed().as_millis(),
                            front,
                            needs_front: before || after,
                        });
                        std::thread::sleep(SAMPLE_EVERY);
                    }
                })
            };
            Self {
                samples,
                needs_front,
                stop,
                thread: Some(thread),
            }
        }

        fn finish(mut self) -> Vec<FrontSample> {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let samples = self.samples.lock().unwrap().clone();
            samples
        }
    }

    /// The health report's metrics, as this scratch module answers a health
    /// check.
    async fn health_metrics() -> Option<Value> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let request = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Passive, false),
            0,
            0,
            1,
            serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).ok()?,
        )
        .ok()?;
        cerebellum::handle_control_request_for_test(request, &tx, &Arc::new(HealthState::new()))
            .await
            .ok()?;
        let reply = rx.recv().await?;
        match serde_json::from_slice(&reply.body).ok()? {
            ModuleControlResponse::HealthCheck {
                metrics: Some(metrics),
                ..
            } => Some(metrics),
            _ => None,
        }
    }

    /// The pid the helper branch recorded, once the helper has started.
    fn helper_pid(record: &Path) -> Option<u32> {
        std::fs::read_to_string(record).ok()?.trim().parse().ok()
    }

    /// How many preview windows the helper shows, waiting up to `wait` for
    /// at least one when `want_shown`, or for none otherwise.
    fn previews_after(helper: Option<u32>, want_shown: bool, wait: Duration) -> Option<usize> {
        let started = Instant::now();
        loop {
            let shown = helper.and_then(|helper| {
                let windows = sys::on_screen_windows()?;
                Some(visible_previews(&windows, i32::try_from(helper).ok()?))
            });
            if shown.is_some_and(|shown| (shown > 0) == want_shown) || started.elapsed() >= wait {
                return shown;
            }
            std::thread::sleep(SAMPLE_EVERY);
        }
    }

    struct Report {
        failed: bool,
    }

    impl Report {
        fn check(&mut self, name: &str, verdict: Result<(), String>) {
            match verdict {
                Ok(()) => println!("PASS {name}"),
                Err(reason) => {
                    self.failed = true;
                    println!("FAIL {name}: {reason}");
                }
            }
        }
    }

    pub fn run(baseline: bool) -> i32 {
        if !baseline {
            match cerebellum_macos::probe_overlay_capture_exclusion() {
                Ok(report) => {
                    println!("PASS overlay_single_window_capture_excludes_preview_and_badge_patterns: {report}")
                }
                Err(reason) => {
                    eprintln!("FAIL overlay_single_window_capture_excludes_preview_and_badge_patterns: {reason}");
                    return 1;
                }
            }
        }
        println!(
            "TIME BUDGET: at most about {} s (launch {} s, covering the window up to {} s, \
             actions, two idle windows of {} s, teardown)",
            (2 * (LAUNCH_WAIT + COVER_WAIT + IDLE_WINDOW) + Duration::from_secs(30)).as_secs(),
            LAUNCH_WAIT.as_secs(),
            COVER_WAIT.as_secs(),
            IDLE_WINDOW.as_secs()
        );
        if cerebellum_macos::screen_is_locked() != Some(false) {
            eprintln!("UNMEASURABLE: the screen is locked or its state is unknown");
            return 2;
        }
        if !cerebellum_macos::accessibility_is_permitted() {
            eprintln!("UNMEASURABLE: this process may not use accessibility");
            return 2;
        }
        let Ok(executable) = std::env::current_exe() else {
            eprintln!("UNMEASURABLE: this executable's path cannot be read");
            return 2;
        };
        let helper = helper_binary(&executable).filter(|helper| helper.is_file());
        if !baseline && helper.is_none() {
            eprintln!(
                "UNMEASURABLE: no {HELPER_BINARY} beside this example's build directory; build it \
                 first with: cargo build -p cerebellum --bin {HELPER_BINARY} --example \
                 app_use_desk_probe"
            );
            return 2;
        }
        match cerebellum_computer::platform::native::resolve_target(
            TEXTEDIT_BUNDLE,
            Duration::from_secs(3),
        ) {
            TargetResolution::NotRunning => {}
            other => {
                eprintln!(
                    "UNMEASURABLE: TextEdit must not be running, so the scratch instance is the \
                     only one the plane can address ({other:?})"
                );
                return 2;
            }
        }
        let Some(person) = cerebellum_macos::frontmost_process_id() else {
            eprintln!("UNMEASURABLE: the person's front app cannot be read");
            return 2;
        };
        install_interrupt_handler();
        // A second TextEdit runs under the person's HOME, so without this it
        // would reopen their documents from saved window state.
        let child = match Command::new(TEXTEDIT)
            .args(["-ApplePersistenceIgnoreState", "YES"])
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                eprintln!("UNMEASURABLE: cannot launch scratch TextEdit: {error}");
                return 2;
            }
        };
        let scratch = Scratch { child };
        *SCRATCH_PID.lock().unwrap() = scratch.pid();
        println!(
            "SCRATCH TextEdit pid {}; the person's front app is pid {person}",
            scratch.pid()
        );
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("UNMEASURABLE: no runtime: {error}");
                return 2;
            }
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(measure(&scratch, person, baseline, &executable))
        }));
        *SCRATCH_PID.lock().unwrap() = 0;
        drop(scratch);
        let code = match outcome {
            Ok(code) => code,
            Err(_) => {
                eprintln!("FAIL probe panicked");
                1
            }
        };
        if baseline || code == 2 {
            return code;
        }
        // The baseline needs TextEdit to itself, so it runs after the
        // scratch instance above is gone.
        let baseline_ns = match baseline_run(&executable) {
            Ok(baseline_ns) => baseline_ns,
            Err(reason) => {
                eprintln!("UNMEASURABLE: the baseline run failed: {reason}");
                return 2;
            }
        };
        let Some(module_ns) = *MODULE_IDLE_NS.lock().unwrap() else {
            eprintln!("UNMEASURABLE: the module's idle CPU time was not measured");
            return 2;
        };
        println!(
            "RECORD module idle CPU: {:.3} ms with the agent cursor, {:.3} ms without",
            module_ns as f64 / 1e6,
            baseline_ns as f64 / 1e6
        );
        let mut report = Report { failed: code != 0 };
        report.check(
            "module idle CPU within 10% of the agent_cursor false baseline",
            module_idle_verdict(module_ns, baseline_ns),
        );
        if report.failed {
            println!("FAILED");
            1
        } else {
            println!("PASS");
            0
        }
    }

    /// The module's idle CPU time from this run, for the comparison with
    /// the baseline once the scratch instance is gone.
    static MODULE_IDLE_NS: Mutex<Option<u64>> = Mutex::new(None);

    /// Run this probe again with the agent cursor off and read its idle CPU
    /// time.
    fn baseline_run(executable: &Path) -> Result<u64, String> {
        println!("BASELINE run with the agent cursor off");
        let output = Command::new(executable)
            .args([APPROVAL_FLAG, BASELINE_FLAG])
            .output()
            .map_err(|error| error.to_string())?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            println!("  baseline: {line}");
        }
        if !output.status.success() {
            return Err(format!(
                "exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        baseline_from_output(&stdout).ok_or_else(|| format!("no {BASELINE_LINE} line"))
    }

    /// Every phase against the scratch app. Returns the process exit code.
    async fn measure(scratch: &Scratch, person: i32, baseline: bool, executable: &Path) -> i32 {
        let target_pid = scratch.pid();
        let audit = match computer_audit(JournalPersistence::Isolated) {
            Ok(audit) => audit,
            Err(error) => {
                eprintln!("UNMEASURABLE: no isolated journal: {error}");
                return 2;
            }
        };
        // This scratch plane admits the fronting the needs-front chord uses
        // as an unreviewed desk build. A release build admits it only when
        // both the takeover-dispatch review and the app-use fronting review
        // are bound.
        let review = Some("app-use-desk-probe-unreviewed".to_string());
        let plane = ComputerPlane::<NativeCaptureBackend, _, _, _, _>::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::Withhold,
            move || {
                MacOs26PlatformDriver::default()
                    .without_expected_post_condition()
                    .with_takeover_dispatch_review_revision(review.clone())
            },
        )
        .with_fronting_bracket_admitted(true)
        .with_app_use_fronting_admitted(true);
        // `agent_cursor: true` for the measured run, `false` for the
        // baseline; a plane's cursor starts disabled.
        let cursor = plane.cursor();
        let helper_record = executable.with_extension(HELPER_PID_EXTENSION);
        let _ = std::fs::remove_file(&helper_record);
        if !baseline {
            cursor.enable(true);
        }
        let management = Arc::new(ManagementPlane::new(Arc::new(PlatformResolver::new())));
        let clock = SystemClock::new();
        let serve = |name: &'static str, arguments: Value| {
            let (plane, management, clock) = (&plane, &management, &clock);
            async move {
                plane
                    .serve(
                        servable(name).expect("the capability is served"),
                        &arguments,
                        ServeContext {
                            cancel: cerebellum::CancelHandle::pending(),
                            grantee: "desk-probe",
                            identity: identity(),
                            management,
                            consent: consent(),
                            clock,
                            now_ms: 0,
                        },
                        |_| NativeCaptureBackend::new(Duration::from_secs(10)),
                    )
                    .await
                    .unwrap_or_else(
                        |error| json!({"outcome": "withheld", "error": format!("{error:?}")}),
                    )
            }
        };

        // The scratch window, read through the plane until it answers.
        let started = Instant::now();
        let read = loop {
            let read = serve("computer.read_state", json!({"target": TEXTEDIT_BUNDLE})).await;
            if read["outcome"] == "completed"
                && read["tree"].as_str().is_some_and(|t| !t.is_empty())
            {
                break read;
            }
            if started.elapsed() > LAUNCH_WAIT {
                eprintln!(
                    "UNMEASURABLE: the scratch window never answered a read: {}",
                    read["outcome"]
                );
                return 2;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        // A freshly launched app may have taken the front; give it back.
        if cerebellum_macos::frontmost_process_id() != Some(person) {
            let _ = cerebellum_macos::request_frontmost(person as u32);
        }
        if !baseline {
            println!(
                "WAITING up to {} s for the person's front app to cover the scratch TextEdit \
                 window; move or enlarge its window over it if needed",
                COVER_WAIT.as_secs()
            );
        }
        let started = Instant::now();
        loop {
            let front = cerebellum_macos::frontmost_process_id();
            let covered = cerebellum_macos::frontmost_window_id(target_pid).map(|window| {
                cerebellum_macos::window_visibility(target_pid, window)
                    == cerebellum_macos::WindowVisibility::Covered
            });
            // The baseline measures CPU alone, so the scratch window only
            // has to be behind the person's app there.
            if front == Some(person) && (baseline || covered == Some(true)) {
                break;
            }
            if started.elapsed() > COVER_WAIT {
                eprintln!(
                    "UNMEASURABLE: the person's app (pid {person}) is not in front of a covered \
                     scratch window (front {front:?}, covered {covered:?})"
                );
                return 2;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        // Moving a window is the person's input; the fronting idle gate
        // wants a quiet second before it fronts anything.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut report = Report { failed: false };

        // Active phase, in background mode.
        let sampler = Sampler::start();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let first = serve("computer.read_state", json!({"target": TEXTEDIT_BUNDLE})).await;
        report.check(
            "background read_state fronts nothing",
            background_reply_verdict("read_state", &first),
        );
        let tree = first["tree"]
            .as_str()
            .or(read["tree"].as_str())
            .unwrap_or_default()
            .to_string();
        let text_area = tree
            .lines()
            .find(|line| line.contains(" text area ") && line.contains("settable"))
            .and_then(|line| line.split_whitespace().next())
            .map(str::to_string);
        match text_area {
            Some(element_id) => {
                let write = serve(
                    "computer.write_text",
                    json!({
                        "element_id": element_id,
                        "text": format!("app use desk probe {}", std::process::id()),
                        "write_mode": "replace_value",
                    }),
                )
                .await;
                report.check(
                    "background write_text fronts nothing",
                    background_reply_verdict("write_text", &write),
                );
            }
            None => report.check(
                "background write_text fronts nothing",
                Err("no settable text area in the scratch window".into()),
            ),
        }
        let helper = helper_pid(&helper_record);
        if !baseline {
            report.check(
                "preview visible after the first background actions",
                match previews_after(helper, true, PREVIEW_WAIT) {
                    Some(shown) if shown > 0 => Ok(()),
                    shown => Err(format!(
                        "the helper (pid {helper:?}) shows {shown:?} preview windows"
                    )),
                },
            );
        }
        // The one needs-front action: a Command chord cannot reach an app in
        // the background. Select-all in the scratch document is harmless.
        sampler.needs_front.store(true, Ordering::SeqCst);
        let chord = serve(
            "computer.keys",
            json!({"target": TEXTEDIT_BUNDLE, "keys": ["command", "a"]}),
        )
        .await;
        sampler.needs_front.store(false, Ordering::SeqCst);
        println!(
            "RECORD needs-front chord reply fronting: {}",
            chord["fronting"]
        );
        report.check(
            "needs-front chord fronts, sends and restores",
            needs_front_reply_verdict(&chord),
        );
        let last = serve("computer.read_state", json!({"target": TEXTEDIT_BUNDLE})).await;
        report.check(
            "background read_state after the chord fronts nothing",
            background_reply_verdict("read_state", &last),
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        let samples = sampler.finish();
        if !baseline {
            report.check(
                "preview visible at the end of the active phase",
                match previews_after(helper, true, PREVIEW_WAIT) {
                    Some(shown) if shown > 0 => Ok(()),
                    shown => Err(format!(
                        "the helper (pid {helper:?}) shows {shown:?} preview windows"
                    )),
                },
            );
            println!(
                "RECORD {} frontmost samples, {} during the needs-front chord",
                samples.len(),
                samples.iter().filter(|sample| sample.needs_front).count()
            );
            report.check(
                "the person's front app stays frontmost except during the needs-front action",
                front_app_verdict(&samples, person),
            );
        }

        // Idle phase: the agent's turn is over, so its badge and preview are
        // hidden and nothing is in flight.
        cursor.end(AGENT);
        tokio::time::sleep(SETTLE).await;
        if !baseline {
            report.check(
                "preview hidden before the idle window",
                match previews_after(helper, false, PREVIEW_WAIT) {
                    Some(0) => Ok(()),
                    shown => Err(format!(
                        "the helper (pid {helper:?}) shows {shown:?} preview windows"
                    )),
                },
            );
        }
        let counters_before = health_metrics().await;
        let module_pid = std::process::id();
        let module_before = sys::cpu_time_ns(module_pid);
        let helper_before = helper.and_then(sys::cpu_time_ns);
        tokio::time::sleep(IDLE_WINDOW).await;
        let module_after = sys::cpu_time_ns(module_pid);
        let helper_after = helper.and_then(sys::cpu_time_ns);
        let counters_after = health_metrics().await;
        cursor.shutdown();

        let Some(module_ns) = module_before
            .zip(module_after)
            .map(|(before, after)| after.saturating_sub(before))
        else {
            eprintln!("UNMEASURABLE: proc_pid_rusage could not read this process");
            return 2;
        };
        if baseline {
            println!("{BASELINE_LINE}{module_ns}");
            return i32::from(report.failed);
        }
        *MODULE_IDLE_NS.lock().unwrap() = Some(module_ns);
        report.check(
            "helper CPU over the idle window",
            match helper_before.zip(helper_after) {
                Some((before, after)) => {
                    let delta = after.saturating_sub(before);
                    println!("RECORD helper idle CPU: {:.3} ms", delta as f64 / 1e6);
                    helper_idle_verdict(delta)
                }
                None => Err(format!(
                    "proc_pid_rusage could not read the helper (pid {helper:?})"
                )),
            },
        );
        for name in IDLE_COUNTERS {
            report.check(
                &format!("{name} still while idle"),
                match (&counters_before, &counters_after) {
                    (Some(before), Some(after)) => counter_still_verdict(before, after, name),
                    _ => Err("the module's health report could not be read".into()),
                },
            );
        }
        i32::from(report.failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PERSON: i32 = 100;
    const TARGET: i32 = 200;

    fn sample(at_ms: u128, front: i32, needs_front: bool) -> FrontSample {
        FrontSample {
            at_ms,
            front: Some(front),
            needs_front,
        }
    }

    #[test]
    fn the_probe_runs_only_with_the_explicit_approval_flag() {
        assert!(!approved(Vec::<String>::new()));
        assert!(!approved(["--approve".to_string()]));
        assert!(!approved([HELPER_FLAG.to_string()]));
        assert!(approved(["--approve-desk-probe".to_string()]));
    }

    #[test]
    fn tcc_preflight_refuses_every_missing_permission_before_requesting() {
        for answers in [
            [false, true, true],
            [true, false, true],
            [true, true, false],
            [false, false, true],
            [false, true, false],
            [true, false, false],
            [false, false, false],
        ] {
            let result: Result<(), String> = with_tcc_preflight(answers, || {
                panic!("a requesting operation ran with missing permissions: {answers:?}")
            });
            let missing = result.expect_err("a false preflight must refuse");
            for (permission, allowed) in TCC_PERMISSIONS.into_iter().zip(answers) {
                assert_eq!(missing.contains(permission), !allowed, "{answers:?}");
            }
        }
    }

    #[test]
    fn tcc_preflight_allows_the_operation_only_when_all_three_pass() {
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            with_tcc_preflight([true; 3], || {
                calls.set(calls.get() + 1);
                17
            }),
            Ok(17)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn the_helper_is_the_module_binary_beside_the_examples_directory() {
        assert_eq!(
            helper_binary(Path::new("/w/target/debug/examples/app_use_desk_probe")),
            Some(PathBuf::from("/w/target/debug/ck-cerebellum"))
        );
    }

    #[test]
    fn rusage_ticks_are_scaled_by_the_mach_timebase() {
        // Apple silicon's timebase: 125/3 nanoseconds per tick.
        assert_eq!(cpu_nanos(240_000, 125, 3), 10_000_000);
        assert_eq!(cpu_nanos(10_000_000, 1, 1), 10_000_000);
    }

    #[test]
    fn the_helper_may_use_at_most_ten_milliseconds_while_idle() {
        assert!(helper_idle_verdict(0).is_ok());
        assert!(helper_idle_verdict(10_000_000).is_ok());
        assert!(helper_idle_verdict(10_000_001).is_err());
    }

    #[test]
    fn the_module_may_use_at_most_ten_percent_above_the_baseline_while_idle() {
        assert!(module_idle_verdict(900, 1_000).is_ok());
        assert!(module_idle_verdict(1_100, 1_000).is_ok());
        assert!(module_idle_verdict(1_101, 1_000).is_err());
        assert!(module_idle_verdict(1, 0).is_err());
    }

    #[test]
    fn an_idle_counter_must_be_reported_and_must_not_move() {
        let still = json!({"previewCaptureRequests": 3, "previewFramesWritten": 7});
        assert!(counter_still_verdict(&still, &still, "previewCaptureRequests").is_ok());
        let moved = json!({"previewCaptureRequests": 4, "previewFramesWritten": 7});
        assert!(counter_still_verdict(&still, &moved, "previewCaptureRequests").is_err());
        let missing = json!({"previewFramesWritten": 7});
        let reason = counter_still_verdict(&missing, &missing, "previewCaptureRequests")
            .expect_err("a missing counter is never a zero");
        assert!(reason.contains("previewCaptureRequests"), "{reason}");
    }

    #[test]
    fn the_baseline_child_reports_its_idle_cpu_on_one_line() {
        let output = format!("SCRATCH TextEdit pid 4\n{BASELINE_LINE}12345\n");
        assert_eq!(baseline_from_output(&output), Some(12_345));
        assert_eq!(baseline_from_output("SCRATCH TextEdit pid 4\n"), None);
    }

    #[test]
    fn the_person_keeps_the_front_except_during_the_one_needs_front_action() {
        let restored = [
            sample(0, PERSON, false),
            sample(100, PERSON, true),
            sample(200, TARGET, true),
            sample(300, PERSON, false),
        ];
        assert!(front_app_verdict(&restored, PERSON).is_ok());
        let not_restored = [
            sample(0, PERSON, false),
            sample(100, TARGET, true),
            sample(200, TARGET, false),
        ];
        assert!(front_app_verdict(&not_restored, PERSON).is_err());
        let fronted_outside = [
            sample(0, TARGET, false),
            sample(100, PERSON, true),
            sample(200, PERSON, false),
        ];
        assert!(front_app_verdict(&fronted_outside, PERSON).is_err());
        let unreadable = [
            FrontSample {
                at_ms: 0,
                front: None,
                needs_front: false,
            },
            sample(100, PERSON, true),
            sample(200, PERSON, false),
        ];
        assert!(front_app_verdict(&unreadable, PERSON).is_err());
    }

    #[test]
    fn the_front_check_needs_samples_before_during_and_after_one_action() {
        let none_during = [sample(0, PERSON, false), sample(100, PERSON, false)];
        assert!(front_app_verdict(&none_during, PERSON).is_err());
        let none_after = [sample(0, PERSON, false), sample(100, TARGET, true)];
        assert!(front_app_verdict(&none_after, PERSON).is_err());
        let none_before = [sample(0, TARGET, true), sample(100, PERSON, false)];
        assert!(front_app_verdict(&none_before, PERSON).is_err());
        let two_actions = [
            sample(0, PERSON, false),
            sample(100, TARGET, true),
            sample(200, PERSON, false),
            sample(300, TARGET, true),
            sample(400, PERSON, false),
        ];
        assert!(front_app_verdict(&two_actions, PERSON).is_err());
    }

    #[test]
    fn the_chord_must_report_a_needs_front_front_that_was_restored() {
        let fronting = |restore: &str, purpose: &str| {
            json!({"outcome": "completed", "fronting": {
                "mode": "background", "fronted": true, "purpose": purpose, "restore": restore,
            }})
        };
        assert!(needs_front_reply_verdict(&fronting("restored", "needs_front")).is_ok());
        assert!(needs_front_reply_verdict(&fronting("skipped_person", "needs_front")).is_err());
        assert!(needs_front_reply_verdict(&fronting("restored", "foreground_mode")).is_err());
        assert!(needs_front_reply_verdict(&json!({"outcome": "completed"})).is_err());
        let refused = json!({"outcome": "restore_failed", "fronting": {
            "mode": "background", "fronted": true, "purpose": "needs_front", "restore": "restored",
        }});
        assert!(needs_front_reply_verdict(&refused).is_err());
    }

    #[test]
    fn a_background_action_completes_without_fronting() {
        assert!(background_reply_verdict("read", &json!({"outcome": "completed"})).is_ok());
        let unfronted = json!({"outcome": "completed", "fronting": {"fronted": false}});
        assert!(background_reply_verdict("read", &unfronted).is_ok());
        let fronted = json!({"outcome": "completed", "fronting": {"fronted": true}});
        assert!(background_reply_verdict("read", &fronted).is_err());
        assert!(background_reply_verdict("read", &json!({"outcome": "not_fronted"})).is_err());
    }

    #[test]
    fn only_the_helpers_visible_preview_width_windows_count_as_previews() {
        let window = |owner, width, alpha| ListedWindow {
            owner,
            width,
            height: 200.0,
            alpha,
        };
        let helper = 300;
        let listed = [
            window(helper, PREVIEW_WIDTH, 1.0),
            window(helper, 64.0, 1.0),
            window(helper, PREVIEW_WIDTH, 0.0),
            window(PERSON, PREVIEW_WIDTH, 1.0),
        ];
        assert_eq!(visible_previews(&listed, helper), 1);
        assert_eq!(visible_previews(&listed[1..], helper), 0);
    }
}
