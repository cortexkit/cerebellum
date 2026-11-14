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
//! codesign --force --sign 'Apple Development: YOUR NAME (TEAMID)' --identifier ckdev-cerebellum-desk-probe target/debug/ck-cerebellum target/debug/examples/app_use_desk_probe
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
//! needs-front chord can run. The plane's agent cursor launches a startup-pinned
//! copy of the sibling `ck-cerebellum --agent-cursor`. Its CPU measurements use
//! the helper pid owned by the cursor transport, without a wrapper process.
//!
//! It launches its own scratch TextEdit (a new instance, never the person's;
//! TextEdit must not already be running), waits until the person's front
//! app covers the scratch window, and then:
//!
//! 1. Active phase, background mode: reads the scratch app, writes a marker
//!    into its document, sends at least 20 needs-front Command chords,
//!    and reads again. A sampler reads the frontmost app every
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
//! On normal return, a failed check, a panic, and Ctrl-C, the probe kills the
//! scratch TextEdit only while it is the unique new pid, its start time is
//! unchanged, and its main window's AXDocument identifies the private scratch
//! file. Otherwise it leaves the process running and reports UNMEASURABLE.
//! The scratch directory is removed at exit. The helper ends with the plane.
//! The process exits 0 when every check passes, 1 when one fails and 2 when
//! the desk cannot be measured (`UNMEASURABLE`).

// Other platforms do not run the desk probe: an unapproved run is refused
// and an approved one reports `UNMEASURABLE: macOS desk required`. The
// verdict functions serve the macOS desk module and the tests alone.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

const APPROVAL_FLAG: &str = "--approve-desk-probe";
/// A helper invocation is not permission to run the desk probe.
#[cfg(test)]
const HELPER_FLAG: &str = "--agent-cursor";
/// Runs the baseline child: the same actions with the agent cursor off.
const BASELINE_FLAG: &str = "--baseline";
/// The line the baseline child reports its idle CPU time on.
const BASELINE_LINE: &str = "BASELINE_MODULE_IDLE_CPU_NS=";
/// The module binary that serves as the cursor helper, beside the
/// `examples/` directory this probe is built into.
const HELPER_BINARY: &str = "ck-cerebellum";

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
const NEEDS_FRONT_ATTEMPTS: usize = 20;
const CANDIDATE_BOUNDS_MS: [u64; 5] = [100, 150, 200, 250, 300];

#[derive(Debug, PartialEq)]
struct TimingSummary {
    count: usize,
    min: f64,
    median: f64,
    p90: f64,
    max: f64,
}

/// Median averages the middle pair; p90 uses the nearest-rank convention.
fn timing_summary(values: &[f64]) -> Option<TimingSummary> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let count = sorted.len();
    let middle = count / 2;
    let median = if count.is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    };
    Some(TimingSummary {
        count,
        min: sorted[0],
        median,
        p90: sorted[(count * 9).div_ceil(10) - 1],
        max: sorted[count - 1],
    })
}

#[derive(Default)]
struct AttemptTiming {
    front_ms: Option<f64>,
    /// Present only when the chord actually posted and restore was confirmed.
    bracket_ms: Option<f64>,
    /// Front confirmation through posting and confirmed restore, same attempt.
    post_and_restore_ms: Option<f64>,
    cleanup_only_ms: Option<f64>,
}

#[derive(Debug, PartialEq)]
struct BoundCount {
    bound_ms: u64,
    measured: usize,
    estimated: Option<usize>,
}

/// Candidate bounds are computed, never tried. An estimate combines each
/// observed front latency with the median measured post-and-restore time.
fn bound_counts(attempts: &[AttemptTiming], bounds: &[u64]) -> Vec<BoundCount> {
    let post_and_restore = timing_summary(
        &attempts
            .iter()
            .filter_map(|attempt| attempt.post_and_restore_ms)
            .collect::<Vec<_>>(),
    );
    bounds
        .iter()
        .map(|&bound_ms| BoundCount {
            bound_ms,
            measured: attempts
                .iter()
                .filter_map(|attempt| attempt.bracket_ms)
                .filter(|&ms| ms <= bound_ms as f64)
                .count(),
            estimated: post_and_restore.as_ref().map(|post| {
                attempts
                    .iter()
                    .filter_map(|attempt| attempt.front_ms)
                    .filter(|&ms| ms + post.median <= bound_ms as f64)
                    .count()
            }),
        })
        .collect()
}

fn print_timing_summary(name: &str, values: &[f64]) {
    match timing_summary(values) {
        Some(stats) => println!(
            "SUMMARY {name}: count={} min={:.3} median={:.3} p90={:.3} max={:.3} ms",
            stats.count, stats.min, stats.median, stats.p90, stats.max
        ),
        None => println!("SUMMARY {name}: count=0; no confirmed measurements"),
    }
}

fn print_needs_front_summary(attempts: &[AttemptTiming]) {
    println!("SUMMARY needs-front attempts: {}; production bound unchanged at 100 ms; median averages the middle pair, p90 is nearest-rank", attempts.len());
    for (name, values) in [
        (
            "request→frontmost (in-call or late)",
            attempts
                .iter()
                .filter_map(|a| a.front_ms)
                .collect::<Vec<_>>(),
        ),
        (
            "request→post→confirmed restore (posted brackets only)",
            attempts.iter().filter_map(|a| a.bracket_ms).collect(),
        ),
        (
            "frontmost→post→confirmed restore",
            attempts
                .iter()
                .filter_map(|a| a.post_and_restore_ms)
                .collect(),
        ),
        (
            "request→cleanup restore (no posted chord confirmed)",
            attempts.iter().filter_map(|a| a.cleanup_only_ms).collect(),
        ),
    ] {
        print_timing_summary(name, &values);
    }
    println!("SUMMARY candidate bounds COMPUTED, NOT TRIED: measured counts use only posted+restored brackets; estimates use each front latency + median measured frontmost→post→restore time from a separate distribution (not a replay)");
    for count in bound_counts(attempts, &CANDIDATE_BOUNDS_MS) {
        println!(
            "COMPUTED bound {} ms: measured posted+restored {}/{}; estimated from two measured parts {}/{}",
            count.bound_ms,
            count.measured,
            attempts.len(),
            count.estimated.map_or_else(|| "unavailable (no posted+restored samples)".into(), |n| n.to_string()),
            attempts.len()
        );
    }
}

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

/// Initialize AppKit for both processes. Only the cursor-on run displays colour
/// patterns to check that captures exclude the preview and badge panels.
/// Return whether that optional capture-exclusion check failed.
fn desk_startup(
    baseline: bool,
    bootstrap: impl FnOnce() -> Result<(), String>,
    exclusion_failed: impl FnOnce() -> bool,
) -> Result<bool, String> {
    bootstrap()?;
    Ok(!baseline && exclusion_failed())
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
/// Standalone examples stay in `<profile>/examples/` when Cargo moves test binaries.
fn helper_binary(executable: &Path) -> Option<PathBuf> {
    Some(executable.parent()?.parent()?.join(HELPER_BINARY))
}

/// A unique new pid is only a candidate: its document must also prove ownership.
/// Repeated entries describe the same process, not additional instances.
fn new_scratch_pid(before: &[u32], after: &[u32]) -> Result<u32, usize> {
    let new: std::collections::BTreeSet<_> = after
        .iter()
        .copied()
        .filter(|pid| !before.contains(pid))
        .collect();
    if new.len() == 1 {
        Ok(*new.first().unwrap())
    } else {
        Err(new.len())
    }
}

fn scratch_launch_command(document: &Path) -> std::process::Command {
    // LaunchServices supplies the system-app launch context. Keep the new
    // instance inactive but visible, and do not restore the person's documents.
    let mut command = std::process::Command::new("/usr/bin/open");
    command.args(["-n", "-g", "-a", "TextEdit"]);
    // open(1) opens file operands in the selected new instance. Everything
    // after --args is only argv, not a document for LaunchServices to open.
    command.arg(document);
    command.args(["--args", "-ApplePersistenceIgnoreState", "YES"]);
    command
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ScratchProcess {
    pid: u32,
    start_time: u64,
}

impl ScratchProcess {
    /// Newness alone is not ownership: require the private document as well.
    fn may_kill(
        self,
        before: &[u32],
        after: Option<&[u32]>,
        current_start_time: Option<u64>,
        open_document: Option<&str>,
        scratch_document: &str,
    ) -> bool {
        self.pid != 0
            && after.is_some_and(|after| new_scratch_pid(before, after) == Ok(self.pid))
            && current_start_time == Some(self.start_time)
            && open_document.is_some_and(|document| same_document(document, scratch_document))
    }
}

/// Accept only absolute local file identities, never a title or basename.
fn document_path(value: &str) -> Option<PathBuf> {
    let path = if let Some(url) = value.strip_prefix("file://") {
        if let Some(local) = url.strip_prefix("localhost/") {
            format!("/{local}")
        } else if url.starts_with('/') {
            url.to_owned()
        } else {
            return None;
        }
    } else {
        let path = PathBuf::from(value);
        return path.is_absolute().then_some(path);
    };
    let mut decoded = Vec::new();
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hi = (bytes.next()? as char).to_digit(16)?;
            let lo = (bytes.next()? as char).to_digit(16)?;
            decoded.push((hi * 16 + lo) as u8);
        } else {
            decoded.push(byte);
        }
    }
    let path = PathBuf::from(String::from_utf8(decoded).ok()?);
    path.is_absolute().then_some(path)
}

fn same_document(actual: &str, expected: &str) -> bool {
    let (Some(actual), Some(expected)) = (document_path(actual), document_path(expected)) else {
        return false;
    };
    // Equal normalized paths can be compared without filesystem access.
    // Otherwise resolve symlinks, including macOS's /tmp -> /private/tmp.
    actual == expected
        || actual
            .canonicalize()
            .ok()
            .zip(expected.canonicalize().ok())
            .is_some_and(|(actual, expected)| actual == expected)
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

/// Forward each line as it arrives; retain only the baseline's CPU measurement.
fn stream_baseline(
    reader: impl std::io::BufRead,
    mut emit: impl FnMut(&str),
) -> Result<Option<u64>, String> {
    let mut idle_ns = None;
    for line in reader.lines() {
        let line = line.map_err(|error| format!("reading baseline output: {error}"))?;
        emit(&line);
        idle_ns = idle_ns.or_else(|| baseline_from_output(&line));
    }
    Ok(idle_ns)
}

/// Re-exec the same signed binary, but give the baseline its own responsibility
/// identity just like the cursor-on probe. Never fall back to an ordinary spawn.
fn baseline_launch_command(executable: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(executable.with_file_name("disclaim_launch"));
    command.arg(executable).args([APPROVAL_FLAG, BASELINE_FLAG]);
    command
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
/// needs-front actions ran, and samples after those actions show it back.
fn front_app_verdict(samples: &[FrontSample], person: i32) -> Result<(), String> {
    let Some(first) = samples.iter().position(|sample| sample.needs_front) else {
        return Err("no sample was taken while the needs-front action ran".into());
    };
    let last = samples
        .iter()
        .rposition(|sample| sample.needs_front)
        .unwrap_or(first);
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

/// A posted chord is deliberately unconfirmed: the keys contract does not
/// claim its effect was observed. The fronting bracket must still be held.
fn needs_front_reply_verdict(reply: &Value) -> Result<(), String> {
    let fronting = &reply["fronting"];
    let expected = [
        (
            "outcome",
            &reply["outcome"],
            Value::from("delivery_unconfirmed"),
        ),
        (
            "target_fronted",
            &reply["target_fronted"],
            Value::from(true),
        ),
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
    let mut failures = expected
        .iter()
        .filter(|(_, actual, want)| *actual != want)
        .map(|(name, actual, want)| format!("{name} was {actual}, expected {want}"))
        .collect::<Vec<_>>();
    if let Some(reason) = reply.get("containment_forfeited_because") {
        failures.push(format!(
            "containment_forfeited_because was {reason}, expected absent"
        ));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the needs-front chord's {}; reply: {reply}",
            failures.join("; ")
        ))
    }
}

#[derive(Clone, Copy, Debug)]
struct TextSelection {
    start: usize,
    length: usize,
    text_length: usize,
}

/// AX ranges and CFString lengths both count UTF-16 code units, not bytes.
fn selection_line(
    attempt: usize,
    before: &Result<TextSelection, String>,
    after: &Result<TextSelection, String>,
) -> String {
    let range = |sample: &Result<TextSelection, String>| match sample {
        Ok(sample) => format!("{}:{}", sample.start, sample.length),
        Err(_) => "unreadable".into(),
    };
    let length = |sample: &Result<TextSelection, String>| match sample {
        Ok(sample) => sample.text_length.to_string(),
        Err(_) => "unreadable".into(),
    };
    let mut line = format!(
        "RECORD needs-front attempt {attempt}: selection before={} after={} length={}→{} (UTF-16; start:length)",
        range(before), range(after), length(before), length(after)
    );
    let failures = [("before", before), ("after", after)]
        .into_iter()
        .filter_map(|(when, sample)| {
            sample
                .as_ref()
                .err()
                .map(|reason| format!("{when}: {}", reason.replace(['\r', '\n'], " ")))
        })
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        line.push_str(&format!("; selection unreadable: {}", failures.join("; ")));
    }
    line
}

/// The text the probe types into the scratch document, kept out of the log.
fn redact_typed_text(text: &str, typed: &str) -> String {
    if typed.is_empty() {
        return text.to_string();
    }
    text.replace(typed, "<typed text>")
}

/// Whether resetting the scratch selection to a caret worked before an
/// attempt, and where the caret is.
fn caret_reset_line(attempt: usize, caret: &Result<usize, String>) -> String {
    match caret {
        Ok(at) => format!(
            "RECORD needs-front attempt {attempt}: selection reset to caret at={at} (UTF-16)"
        ),
        Err(reason) => format!(
            "RECORD needs-front attempt {attempt}: selection reset failed: {}",
            reason.replace(['\r', '\n'], " ")
        ),
    }
}

/// What Command-A did to the selection: `selected_all` when a caret became
/// the whole text, `unchanged` when the range stayed the same, `other` for any
/// other range, and `not_judged` when either side was unreadable or the
/// attempt did not start from a caret in non-empty text.
fn select_all_effect(
    before: &Result<TextSelection, String>,
    after: &Result<TextSelection, String>,
) -> &'static str {
    let (Ok(before), Ok(after)) = (before, after) else {
        return "not_judged";
    };
    if before.length != 0 || before.text_length == 0 {
        return "not_judged";
    }
    if after.start == 0 && after.length == after.text_length {
        "selected_all"
    } else if (after.start, after.length) == (before.start, before.length) {
        "unchanged"
    } else {
        "other"
    }
}

fn select_all_line(
    attempt: usize,
    before: &Result<TextSelection, String>,
    after: &Result<TextSelection, String>,
) -> String {
    format!(
        "RECORD needs-front attempt {attempt}: select_all effect={}",
        select_all_effect(before, after)
    )
}

/// Whether the Edit menu title was highlighted right after the chord
/// returned. Recorded apart from the selection: the highlight shows AppKit
/// matched the key equivalent, not that Select All took effect.
fn edit_title_line(attempt: usize, highlighted: &Result<bool, String>) -> String {
    match highlighted {
        Ok(true) => format!("RECORD needs-front attempt {attempt}: edit_title_highlight=seen"),
        Ok(false) => format!("RECORD needs-front attempt {attempt}: edit_title_highlight=not_seen"),
        Err(reason) => format!(
            "RECORD needs-front attempt {attempt}: edit_title_highlight=unreadable ({})",
            reason.replace(['\r', '\n'], " ")
        ),
    }
}

/// The zoomed element's line from a reply's state text, without its value:
/// its id, role and states. `None` when the element is not in the text.
fn zoomed_element_summary<'a>(state_text: &'a str, element_id: &str) -> Option<&'a str> {
    state_text.lines().find_map(|line| {
        let start = line.find(&format!("{element_id} "))?;
        let at_start = line[..start]
            .chars()
            .last()
            .is_none_or(|before| before.is_whitespace());
        if !at_start {
            return None;
        }
        let element = &line[start..];
        Some(
            element
                .split(", Value:")
                .next()
                .unwrap_or(element)
                .trim_end(),
        )
    })
}

fn zoomed_read_line(attempt: usize, reply: &Value, element_id: Option<&str>) -> String {
    let summary = element_id.and_then(|id| {
        zoomed_element_summary(reply["state_text"].as_str().unwrap_or_default(), id)
    });
    format!(
        "RECORD needs-front attempt {attempt}: zoomed read state_report={} focused_element_id={} element={}",
        reply["state_report"],
        reply["focused_element_id"],
        summary.unwrap_or("absent")
    )
}

/// How long the target had been confirmed frontmost when the chord's first
/// keystroke was posted, both in ms from the front request.
fn front_to_post_line(
    attempt: usize,
    confirmed_front: Option<f64>,
    first_post: Option<f64>,
) -> String {
    match (confirmed_front, first_post) {
        (Some(front), Some(post)) => format!(
            "RECORD needs-front attempt {attempt}: frontmost confirmed→first post {:.3} ms (first post at_ms={post:.3})",
            post - front
        ),
        (None, Some(post)) => format!(
            "RECORD needs-front attempt {attempt}: first post at_ms={post:.3} with no in-call frontmost confirmation"
        ),
        (_, None) => format!("RECORD needs-front attempt {attempt}: no post observed"),
    }
}

/// When the scratch text area reported selection changes, in ms from the
/// front request, and how long after the first post the first one came.
fn selection_change_line(attempt: usize, changes_ms: &[f64], first_post: Option<f64>) -> String {
    let Some(first) = changes_ms.iter().copied().reduce(f64::min) else {
        return format!("RECORD needs-front attempt {attempt}: no selection change observed");
    };
    let mut line = format!(
        "RECORD needs-front attempt {attempt}: selection_changed count={} first_at_ms={first:.3}",
        changes_ms.len()
    );
    if let Some(post) = first_post {
        line.push_str(&format!(" (first post→change {:.3} ms)", first - post));
    }
    line
}

/// One ScreenCaptureKit window-list request: where in the probe's startup it
/// ran, on which thread, what came back and how long it took. The baseline
/// process's list requests have timed out while the main run's arrived, and
/// these lines show which threads and stages get an answer.
fn window_list_line(
    stage: &str,
    thread: &str,
    result: &Result<usize, String>,
    elapsed: Duration,
) -> String {
    let outcome = match result {
        Ok(count) => format!("windows={count}"),
        Err(reason) => format!("error={}", reason.replace(['\r', '\n'], " ")),
    };
    format!(
        "RECORD window-list check stage={stage} thread={thread} {outcome} elapsed_ms={:.3}",
        elapsed.as_secs_f64() * 1000.0
    )
}

/// A background-mode action that is not a needs-front action completed
/// without fronting anything.
fn background_reply_verdict(action: &str, reply: &Value) -> Result<(), String> {
    if reply["outcome"] != "completed" {
        return Err(format!("{action} did not complete; reply: {reply}"));
    }
    match reply.get("fronting") {
        None => Ok(()),
        Some(fronting) if fronting["fronted"] == false => Ok(()),
        Some(_) => Err(format!("{action} fronted its app; reply: {reply}")),
    }
}

fn read_state_outline(reply: &Value) -> Option<&str> {
    if reply["outcome"] != "completed" {
        return None;
    }
    reply["state_text"].as_str().filter(|text| !text.is_empty())
}

fn settable_text_area_id(outline: &str) -> Option<&str> {
    outline.lines().find_map(|line| {
        let (id, description) = line.trim_start().split_once(' ')?;
        let states = description.strip_prefix("text area (")?.split_once(')')?.0;
        states
            .split(", ")
            .any(|state| state == "settable")
            .then_some(id)
    })
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
    if !approved(std::env::args().skip(1)) {
        eprintln!(
            "REFUSED: this probe fronts a scratch application on the person's screen and \
             draws the agent cursor. Run it only with the person present and their approval, \
             passing {APPROVAL_FLAG}."
        );
        std::process::exit(2);
    }
    #[cfg(target_os = "macos")]
    std::process::exit(desk_preflight(|| {
        desk::run(
            std::env::args()
                .skip(1)
                .any(|argument| argument == BASELINE_FLAG),
        )
    }));
    #[cfg(not(target_os = "macos"))]
    {
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
    use std::process::Command;
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
    const FRONT_CLEANUP_SPACING: Duration =
        Duration::from_millis(cerebellum::budgets::LATE_ACTIVATION_WATCH_MS + 100);
    /// After the selection is reset to a caret, long enough for its own
    /// selection-change notification to arrive before the chord's are counted.
    const CARET_SETTLE: Duration = Duration::from_millis(300);
    /// Each window-list check waits at most this long for ScreenCaptureKit.
    const WINDOW_LIST_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

    /// The calling thread's name and id, for the window-list checks.
    fn thread_label() -> String {
        let thread = std::thread::current();
        format!("{}/{:?}", thread.name().unwrap_or("unnamed"), thread.id())
    }

    /// Ask ScreenCaptureKit for the window list once from this thread and
    /// say what came back.
    fn window_list_check(stage: &str) -> String {
        let started = Instant::now();
        let result = cerebellum_macos::enumerate_windows(WINDOW_LIST_CHECK_TIMEOUT)
            .map(|windows| windows.len());
        window_list_line(stage, &thread_label(), &result, started.elapsed())
    }

    /// Private files are outside $TMPDIR, where signing can hang on this Mac.
    struct ScratchFiles {
        directory: PathBuf,
        document: PathBuf,
        document_url: String,
    }

    impl ScratchFiles {
        fn create() -> Result<Self, String> {
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random).map_err(|error| error.to_string())?;
            let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let directory = Path::new("/tmp").join(format!("ck-desk-probe-{nonce}"));
            // Atomic creation refuses existing paths, including symlinks.
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|error| error.to_string())?;
            let mut files = Self {
                directory,
                document: PathBuf::new(),
                document_url: String::new(),
            };
            // TextEdit reports the resolved path (/private/tmp on macOS).
            files.directory = files
                .directory
                .canonicalize()
                .map_err(|error| error.to_string())?;
            files.document = files.directory.join(format!("probe-{nonce}.txt"));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&files.document)
                .map_err(|error| error.to_string())?;
            files.document_url = sys::file_url(&files.document)
                .ok_or("cannot encode the scratch document's file URL")?;
            Ok(files)
        }

        fn remove(&self) -> bool {
            match std::fs::remove_dir_all(&self.directory) {
                Ok(()) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(error) => {
                    eprintln!("UNMEASURABLE: cannot remove scratch directory: {error}");
                    false
                }
            }
        }
    }

    impl Drop for ScratchFiles {
        fn drop(&mut self) {
            self.remove();
        }
    }

    #[derive(Clone)]
    struct ScratchIdentity {
        process: ScratchProcess,
        before: Vec<u32>,
        files: Arc<ScratchFiles>,
    }

    /// The scratch TextEdit, signalled only after rechecking ownership.
    struct Scratch {
        identity: ScratchIdentity,
        cleaned_up: bool,
    }

    impl Scratch {
        fn pid(&self) -> u32 {
            self.identity.process.pid
        }

        fn selection(&self) -> Result<TextSelection, String> {
            scratch_ownership(&self.identity)?;
            sys::text_selection(self.pid(), &self.identity.files.document_url)
        }

        fn reset_to_caret(&self) -> Result<usize, String> {
            scratch_ownership(&self.identity)?;
            sys::reset_to_caret(self.pid(), &self.identity.files.document_url)
        }

        fn edit_title_highlighted(&self) -> Result<bool, String> {
            scratch_ownership(&self.identity)?;
            sys::edit_title_highlighted(self.pid())
        }

        fn observe_selection(&self) -> Result<sys::SelectionObserver, String> {
            scratch_ownership(&self.identity)?;
            sys::SelectionObserver::start(self.pid(), &self.identity.files.document_url)
        }

        fn finish(&mut self) -> bool {
            let mut pending = SCRATCH_PID.lock().unwrap();
            let killed = kill(&self.identity);
            let removed = self.identity.files.remove();
            self.cleaned_up = true;
            *pending = None;
            killed && removed
        }
    }

    fn left_running(pid: u32) {
        eprintln!(
            "LEFT RUNNING: pid {pid}, not provably the probe's; AX reads: {:?}",
            sys::window_documents(pid)
        );
    }

    fn scratch_ownership(identity: &ScratchIdentity) -> Result<(), String> {
        let documents = sys::window_documents(identity.process.pid);
        let document = documents
            .as_ref()
            .ok()
            .filter(|docs| docs.len() == 1)
            .and_then(|docs| docs.first());
        let after = textedit_pids().ok();
        let start = cerebellum_macos::process_start_time_micros(identity.process.pid);
        if identity.process.may_kill(
            &identity.before,
            after.as_deref(),
            start,
            document.map(String::as_str),
            &identity.files.document_url,
        ) {
            Ok(())
        } else {
            Err(format!("AXWindows/AXDocument={documents:?}; expected={:?}; before={:?}; now={after:?}; start={start:?}, expected_start={}",
                identity.files.document_url, identity.before, identity.process.start_time))
        }
    }

    fn kill(identity: &ScratchIdentity) -> bool {
        let process = identity.process;
        if let Err(evidence) = scratch_ownership(identity) {
            eprintln!(
                "LEFT RUNNING: pid {}, not provably the probe's; {evidence}",
                process.pid
            );
            return false;
        }
        if !Command::new("/bin/kill")
            .args(["-KILL", &process.pid.to_string()])
            .status()
            .is_ok_and(|status| status.success())
        {
            left_running(process.pid);
            return false;
        }
        // LaunchServices owns the child, so wait by identity rather than waitpid.
        // The baseline must not begin while the first scratch app is still alive.
        let deadline = Instant::now() + LAUNCH_WAIT;
        while Instant::now() < deadline {
            match cerebellum_macos::process_start_time(process.pid) {
                cerebellum_macos::ProcessStartTime::NoSuchProcess => return true,
                cerebellum_macos::ProcessStartTime::Started(start)
                    if start != process.start_time =>
                {
                    return true;
                }
                _ => std::thread::sleep(SAMPLE_EVERY),
            }
        }
        left_running(process.pid);
        false
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if !self.cleaned_up && self.finish() {
                println!("SCRATCH {} killed", self.pid());
            }
        }
    }

    /// Ctrl-C needs the document proof as well as the process identity.
    static SCRATCH_PID: Mutex<Option<ScratchIdentity>> = Mutex::new(None);

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
                    let mut pending = SCRATCH_PID.lock().unwrap();
                    let mut code = 130;
                    if let Some(identity) = pending.take() {
                        let killed = kill(&identity);
                        let removed = identity.files.remove();
                        if killed {
                            println!("SCRATCH {} killed after interrupt", identity.process.pid);
                        }
                        if !killed || !removed {
                            code = 2;
                        }
                    }
                    std::process::exit(code);
                }
            });
        });
    }

    fn textedit_pids() -> Result<Vec<u32>, String> {
        Ok(cerebellum_macos::workspace_running_applications()?
            .into_iter()
            .filter(|app| app.bundle_identifier == TEXTEDIT_BUNDLE)
            .map(|app| app.pid)
            .collect())
    }

    fn launch_scratch(before: &[u32]) -> Result<Scratch, String> {
        let files = Arc::new(ScratchFiles::create()?);
        let status = scratch_launch_command(&files.document)
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!("open exited with {status}"));
        }
        let deadline = Instant::now() + LAUNCH_WAIT;
        loop {
            let after = textedit_pids()?;
            match new_scratch_pid(before, &after) {
                Ok(pid) => {
                    let start_time = match cerebellum_macos::process_start_time(pid) {
                        cerebellum_macos::ProcessStartTime::Started(start) => start,
                        other => {
                            left_running(pid);
                            return Err(format!("cannot identify scratch pid {pid}: {other:?}"));
                        }
                    };
                    let identity = ScratchIdentity {
                        process: ScratchProcess { pid, start_time },
                        before: before.to_vec(),
                        files,
                    };
                    // Verify AXDocument on this pid, not whichever TextEdit the
                    // bundle resolver might find. LaunchServices is asynchronous.
                    while Instant::now() < deadline {
                        if scratch_ownership(&identity).is_ok() {
                            return Ok(Scratch {
                                identity,
                                cleaned_up: false,
                            });
                        }
                        std::thread::sleep(SAMPLE_EVERY);
                    }
                    left_running(pid);
                    return Err("the new TextEdit did not open the scratch document".into());
                }
                Err(0) if Instant::now() < deadline => std::thread::sleep(SAMPLE_EVERY),
                Err(count) => {
                    for pid in after.iter().filter(|pid| !before.contains(pid)) {
                        left_running(*pid);
                    }
                    return Err(format!("expected one new TextEdit pid, found {count}"));
                }
            }
        }
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

    /// The probe's calls stand in for tool requests, so each gets an armed
    /// witness as the tool handler gives every request. A detached witness
    /// would mark the probe's own dispatches as unattributed, and builds
    /// with `test-support` (which examples get) refuse such a commit.
    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::armed(),
            principal: "desk-probe".into(),
            conversation_key: "app-use-desk-probe".into(),
            agent_project_id: AGENT.into(),
            session_kind: SessionKind::Primary,
            origin: Default::default(),
            computer_order: None,
        }
    }

    /// An attended session: the probe's Cingulate carries every question.
    fn consent(carrier: Arc<Allowing>) -> ConsentContext {
        let (drain_sender, drain) = tokio::sync::watch::channel(false);
        std::mem::forget(drain_sender);
        ConsentContext::new(
            GrantCaller::new(
                identity().conversation_key,
                identity().agent_project_id,
                false,
            ),
            Some(carrier as Arc<dyn QuestionCarrier>),
            Arc::new(AlwaysOpenRoute),
            drain,
            None,
        )
    }

    /// Process CPU time, windows and document ownership, read from the system.
    #[allow(unsafe_code)]
    mod sys {
        use super::super::{cpu_nanos, same_document, ListedWindow, TextSelection};
        use std::ffi::{c_void, CStr, CString};
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;

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

        #[link(name = "ApplicationServices", kind = "framework")]
        extern "C" {
            fn AXUIElementCreateApplication(pid: i32) -> CfRef;
            fn AXUIElementGetTypeID() -> usize;
            fn AXUIElementGetPid(element: CfRef, pid: *mut i32) -> i32;
            fn AXUIElementSetMessagingTimeout(element: CfRef, timeout: f32) -> i32;
            fn AXUIElementCopyAttributeValue(
                element: CfRef,
                attribute: CfRef,
                value: *mut CfRef,
            ) -> i32;
            fn AXValueGetTypeID() -> usize;
            fn AXValueGetType(value: CfRef) -> u32;
            fn AXValueGetValue(value: CfRef, kind: u32, output: *mut c_void) -> u8;
            fn AXValueCreate(kind: u32, value: *const c_void) -> CfRef;
            fn AXUIElementSetAttributeValue(element: CfRef, attribute: CfRef, value: CfRef) -> i32;
            fn AXObserverCreate(
                pid: i32,
                callback: extern "C" fn(CfRef, CfRef, CfRef, *mut c_void),
                observer: *mut CfRef,
            ) -> i32;
            fn AXObserverAddNotification(
                observer: CfRef,
                element: CfRef,
                notification: CfRef,
                refcon: *mut c_void,
            ) -> i32;
            fn AXObserverGetRunLoopSource(observer: CfRef) -> CfRef;
        }

        #[link(name = "CoreFoundation", kind = "framework")]
        extern "C" {
            fn CFStringCreateWithCString(allocator: CfRef, text: *const i8, encoding: u32)
                -> CfRef;
            fn CFStringGetTypeID() -> usize;
            fn CFStringGetLength(string: CfRef) -> isize;
            fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
            fn CFStringGetCString(string: CfRef, buffer: *mut i8, size: isize, encoding: u32)
                -> u8;
            fn CFURLCreateFromFileSystemRepresentation(
                allocator: CfRef,
                buffer: *const u8,
                length: isize,
                is_directory: u8,
            ) -> CfRef;
            fn CFURLGetTypeID() -> usize;
            fn CFURLGetString(url: CfRef) -> CfRef;
            fn CFArrayGetCount(array: CfRef) -> isize;
            fn CFArrayGetTypeID() -> usize;
            fn CFArrayGetValueAtIndex(array: CfRef, index: isize) -> CfRef;
            fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
            fn CFNumberGetValue(number: CfRef, kind: isize, value: *mut c_void) -> u8;
            fn CFGetTypeID(value: CfRef) -> usize;
            fn CFNumberGetTypeID() -> usize;
            fn CFDictionaryGetTypeID() -> usize;
            fn CFRelease(value: CfRef);
            fn CFRetain(value: CfRef) -> CfRef;
            fn CFBooleanGetTypeID() -> usize;
            fn CFBooleanGetValue(value: CfRef) -> u8;
            fn CFRunLoopGetMain() -> CfRef;
            fn CFRunLoopAddSource(run_loop: CfRef, source: CfRef, mode: CfRef);
            fn CFRunLoopRemoveSource(run_loop: CfRef, source: CfRef, mode: CfRef);
            static kCFRunLoopDefaultMode: CfRef;
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

        fn string_text(value: CfRef) -> Option<String> {
            // SAFETY: non-null CF values can be type-checked before conversion.
            if value.is_null() || unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
                return None;
            }
            // SAFETY: the type check established a live CFString.
            let length = unsafe { CFStringGetLength(value) };
            if !(0..=16_384).contains(&length) {
                return None;
            }
            // SAFETY: length is a bounded CFString length and UTF8 is valid.
            let capacity = unsafe { CFStringGetMaximumSizeForEncoding(length, UTF8) } + 1;
            let mut buffer = vec![0_u8; usize::try_from(capacity).ok()?];
            // SAFETY: the output buffer has capacity bytes; value is a CFString.
            if unsafe { CFStringGetCString(value, buffer.as_mut_ptr().cast(), capacity, UTF8) } == 0
            {
                return None;
            }
            Some(
                CStr::from_bytes_until_nul(&buffer)
                    .ok()?
                    .to_str()
                    .ok()?
                    .to_owned(),
            )
        }

        pub fn file_url(path: &Path) -> Option<String> {
            let path = path.as_os_str().as_bytes();
            // SAFETY: path is readable for its length; returns one owned CFURL.
            let url = unsafe {
                CFURLCreateFromFileSystemRepresentation(
                    std::ptr::null(),
                    path.as_ptr(),
                    isize::try_from(path.len()).ok()?,
                    0,
                )
            };
            if url.is_null() {
                return None;
            }
            let url = Owned(url);
            // SAFETY: the URL owns the borrowed string until it is copied out.
            string_text(unsafe { CFURLGetString(url.0) })
        }

        fn ax_attribute(element: &Owned, name: &str) -> Result<Owned, String> {
            let attribute = string(name);
            let mut value = std::ptr::null();
            // SAFETY: element and attribute are live; value is an output slot.
            let code = unsafe { AXUIElementCopyAttributeValue(element.0, attribute.0, &mut value) };
            if code == 0 && !value.is_null() {
                Ok(Owned(value))
            } else {
                Err(format!("{name}: AX error {code}, null={}", value.is_null()))
            }
        }

        /// Retain children while traversing only this pid's bounded AX tree.
        fn ax_elements(element: &Owned, name: &str, pid: i32) -> Result<Vec<Owned>, String> {
            let attribute = string(name);
            let mut value = std::ptr::null();
            // SAFETY: element, attribute and output slot are live.
            let code = unsafe { AXUIElementCopyAttributeValue(element.0, attribute.0, &mut value) };
            // Leaf elements need not expose AXChildren.
            if name == "AXChildren" && matches!(code, -25205 | -25212) {
                return Ok(Vec::new());
            }
            if code != 0 || value.is_null() {
                return Err(format!("{name}: AX error {code}, null={}", value.is_null()));
            }
            let array = Owned(value);
            // SAFETY: array is live and checked before CFArray access.
            if unsafe { CFGetTypeID(array.0) != CFArrayGetTypeID() } {
                return Err(format!("{name} is not an array"));
            }
            // SAFETY: array is a live CFArray.
            let count = unsafe { CFArrayGetCount(array.0) };
            if !(0..=128).contains(&count) {
                return Err(format!(
                    "{name} has {count} elements, outside traversal limit"
                ));
            }
            let mut elements = Vec::new();
            for index in 0..count {
                // SAFETY: index is in bounds and array owns each borrowed value.
                let child = unsafe { CFArrayGetValueAtIndex(array.0, index) };
                if child.is_null() || unsafe { CFGetTypeID(child) != AXUIElementGetTypeID() } {
                    return Err(format!("{name}[{index}] is not an AX element"));
                }
                let mut owner = 0;
                // SAFETY: child is a live AX element and owner is an output slot.
                let code = unsafe { AXUIElementGetPid(child, &mut owner) };
                if code != 0 || owner != pid {
                    return Err(format!("{name}[{index}]: owner={owner}, AX error {code}"));
                }
                // SAFETY: child is live; retain it beyond array's lifetime.
                let child = Owned(unsafe { CFRetain(child) });
                // SAFETY: child is a retained AX element; bound each message.
                let code = unsafe { AXUIElementSetMessagingTimeout(child.0, 0.5) };
                if code != 0 {
                    return Err(format!("{name}[{index}]: timeout setup AX error {code}"));
                }
                elements.push(child);
            }
            Ok(elements)
        }

        #[repr(C)]
        #[derive(Default)]
        struct CfRange {
            location: isize,
            length: isize,
        }

        fn selected_range(element: &Owned) -> Result<TextSelection, String> {
            const CF_RANGE: u32 = 4;
            let selection = ax_attribute(element, "AXSelectedTextRange")?;
            // SAFETY: selection is live; validate both its CF and AX value types.
            if unsafe {
                CFGetTypeID(selection.0) != AXValueGetTypeID()
                    || AXValueGetType(selection.0) != CF_RANGE
            } {
                return Err("AXSelectedTextRange is not a CFRange AXValue".into());
            }
            let mut range = CfRange::default();
            // SAFETY: the AXValue holds a CFRange and the output has that layout.
            if unsafe {
                AXValueGetValue(selection.0, CF_RANGE, (&mut range as *mut CfRange).cast())
            } == 0
            {
                return Err("AXSelectedTextRange could not be decoded".into());
            }
            let value = ax_attribute(element, "AXValue")?;
            // SAFETY: value is live and checked before CFString access.
            if unsafe { CFGetTypeID(value.0) != CFStringGetTypeID() } {
                return Err("text area's AXValue is not a string".into());
            }
            // SAFETY: value is a live CFString; its length uses UTF-16 units.
            let text_length = unsafe { CFStringGetLength(value.0) };
            let start = usize::try_from(range.location).map_err(|_| "negative selection start")?;
            let length = usize::try_from(range.length).map_err(|_| "negative selection length")?;
            let text_length = usize::try_from(text_length).map_err(|_| "negative text length")?;
            if start
                .checked_add(length)
                .is_none_or(|end| end > text_length)
            {
                return Err(format!(
                    "selection {start}:{length} exceeds text length {text_length}"
                ));
            }
            Ok(TextSelection {
                start,
                length,
                text_length,
            })
        }

        fn find_text_areas(
            element: &Owned,
            pid: i32,
            depth: usize,
            remaining: &mut usize,
            found: &mut Vec<Owned>,
        ) -> Result<(), String> {
            if depth > 12 || *remaining == 0 {
                return Err("scratch AX tree exceeds depth/node limit".into());
            }
            *remaining -= 1;
            let role = ax_attribute(element, "AXRole")?;
            if string_text(role.0).as_deref() == Some("AXTextArea") {
                // SAFETY: element is a live AX element; keep one more retain.
                found.push(Owned(unsafe { CFRetain(element.0) }));
            } else {
                for child in ax_elements(element, "AXChildren", pid)? {
                    find_text_areas(&child, pid, depth + 1, remaining, found)?;
                }
            }
            Ok(())
        }

        /// The scratch document's one text area, found without focusing,
        /// fronting or changing anything.
        fn scratch_text_area(pid: u32, expected_document: &str) -> Result<Owned, String> {
            let pid = i32::try_from(pid).map_err(|_| "pid out of range")?;
            // SAFETY: creates an owned application reference for the scratch pid.
            let app = unsafe { AXUIElementCreateApplication(pid) };
            if app.is_null() {
                return Err("AX application is null".into());
            }
            let app = Owned(app);
            // SAFETY: app is a live AX element; bound its messages.
            let code = unsafe { AXUIElementSetMessagingTimeout(app.0, 0.5) };
            if code != 0 {
                return Err(format!("app timeout setup: AX error {code}"));
            }
            let windows = ax_elements(&app, "AXWindows", pid)?;
            let [window] = windows.as_slice() else {
                return Err(format!(
                    "expected one scratch window, found {}",
                    windows.len()
                ));
            };
            let document = ax_attribute(window, "AXDocument")?;
            // SAFETY: document is live and checked before CFURL access.
            let document = if unsafe { CFGetTypeID(document.0) == CFURLGetTypeID() } {
                // SAFETY: the URL keeps its borrowed string live during conversion.
                string_text(unsafe { CFURLGetString(document.0) })
            } else {
                string_text(document.0)
            };
            if !document
                .as_deref()
                .is_some_and(|doc| same_document(doc, expected_document))
            {
                return Err(format!(
                    "window AXDocument {document:?} is not the scratch document"
                ));
            }
            let mut found = Vec::new();
            find_text_areas(window, pid, 0, &mut 128, &mut found)?;
            let count = found.len();
            match <[Owned; 1]>::try_from(found) {
                Ok([text_area]) => Ok(text_area),
                Err(_) => Err(format!("expected one scratch AXTextArea, found {count}")),
            }
        }

        /// Read the selection without focusing, fronting or changing any AX value.
        pub fn text_selection(pid: u32, expected_document: &str) -> Result<TextSelection, String> {
            selected_range(&scratch_text_area(pid, expected_document)?)
        }

        /// Put the scratch text area's selection back to a caret at the end
        /// of its text, so the next Command-A has something to select.
        /// Returns the caret position in UTF-16 units. Fronts nothing.
        pub fn reset_to_caret(pid: u32, expected_document: &str) -> Result<usize, String> {
            const CF_RANGE: u32 = 4;
            let text_area = scratch_text_area(pid, expected_document)?;
            let end = selected_range(&text_area)?.text_length;
            let range = CfRange {
                location: isize::try_from(end).map_err(|_| "text too long")?,
                length: 0,
            };
            // SAFETY: range is a live CFRange; returns one owned AXValue or null.
            let value = unsafe { AXValueCreate(CF_RANGE, (&range as *const CfRange).cast()) };
            if value.is_null() {
                return Err("caret AXValue could not be created".into());
            }
            let value = Owned(value);
            let attribute = string("AXSelectedTextRange");
            // SAFETY: element, attribute and value are live for the call.
            let code = unsafe { AXUIElementSetAttributeValue(text_area.0, attribute.0, value.0) };
            if code != 0 {
                return Err(format!("AXSelectedTextRange set: AX error {code}"));
            }
            Ok(end)
        }

        /// Whether the scratch app's Edit menu title is highlighted
        /// (`AXSelected` on its menu bar item), as AppKit shows it while it
        /// handles a key equivalent from that menu.
        pub fn edit_title_highlighted(pid: u32) -> Result<bool, String> {
            let pid = i32::try_from(pid).map_err(|_| "pid out of range")?;
            // SAFETY: creates an owned application reference for the scratch pid.
            let app = unsafe { AXUIElementCreateApplication(pid) };
            if app.is_null() {
                return Err("AX application is null".into());
            }
            let app = Owned(app);
            // SAFETY: app is a live AX element; bound its messages.
            let code = unsafe { AXUIElementSetMessagingTimeout(app.0, 0.5) };
            if code != 0 {
                return Err(format!("app timeout setup: AX error {code}"));
            }
            let menu_bar = ax_attribute(&app, "AXMenuBar")?;
            // SAFETY: menu_bar is a live CF value, checked before AX use.
            if unsafe { CFGetTypeID(menu_bar.0) != AXUIElementGetTypeID() } {
                return Err("AXMenuBar is not an AX element".into());
            }
            for item in ax_elements(&menu_bar, "AXChildren", pid)? {
                let title = ax_attribute(&item, "AXTitle")?;
                if string_text(title.0).as_deref() != Some("Edit") {
                    continue;
                }
                let selected = ax_attribute(&item, "AXSelected")?;
                // SAFETY: selected is live and checked before CFBoolean access.
                if unsafe { CFGetTypeID(selected.0) != CFBooleanGetTypeID() } {
                    return Err("Edit AXSelected is not a boolean".into());
                }
                // SAFETY: selected is a live CFBoolean.
                return Ok(unsafe { CFBooleanGetValue(selected.0) } != 0);
            }
            Err("no Edit menu bar item".into())
        }

        /// When the scratch text area reported a selection change, noted on
        /// the main run loop the probe keeps turning.
        static SELECTION_CHANGES: std::sync::Mutex<Vec<std::time::Instant>> =
            std::sync::Mutex::new(Vec::new());

        extern "C" fn selection_changed(
            _observer: CfRef,
            _element: CfRef,
            _notification: CfRef,
            _refcon: *mut c_void,
        ) {
            SELECTION_CHANGES
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(std::time::Instant::now());
        }

        /// Drain the selection changes noted since the last drain.
        pub fn take_selection_changes() -> Vec<std::time::Instant> {
            std::mem::take(
                &mut *SELECTION_CHANGES
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
        }

        /// An accessibility observer for the scratch text area's
        /// `AXSelectedTextChanged`, delivered on the main run loop. It reads
        /// no text. Removed from the run loop when dropped.
        pub struct SelectionObserver {
            observer: Owned,
            _text_area: Owned,
        }

        impl SelectionObserver {
            pub fn start(pid: u32, expected_document: &str) -> Result<Self, String> {
                let text_area = scratch_text_area(pid, expected_document)?;
                let pid = i32::try_from(pid).map_err(|_| "pid out of range")?;
                let mut observer = std::ptr::null();
                // SAFETY: the callback has AXObserverCallback's signature;
                // observer is an output slot that receives one retain.
                let code = unsafe { AXObserverCreate(pid, selection_changed, &mut observer) };
                if code != 0 || observer.is_null() {
                    return Err(format!("AXObserverCreate: AX error {code}"));
                }
                let observer = Owned(observer);
                let notification = string("AXSelectedTextChanged");
                // SAFETY: observer, element and notification are live.
                let code = unsafe {
                    AXObserverAddNotification(
                        observer.0,
                        text_area.0,
                        notification.0,
                        std::ptr::null_mut(),
                    )
                };
                if code != 0 {
                    return Err(format!("AXObserverAddNotification: AX error {code}"));
                }
                // SAFETY: the observer owns its source; the main run loop
                // retains it while added.
                unsafe {
                    CFRunLoopAddSource(
                        CFRunLoopGetMain(),
                        AXObserverGetRunLoopSource(observer.0),
                        kCFRunLoopDefaultMode,
                    );
                }
                Ok(Self {
                    observer,
                    _text_area: text_area,
                })
            }
        }

        impl Drop for SelectionObserver {
            fn drop(&mut self) {
                // SAFETY: the observer is live and its source was added to the
                // main run loop in this mode.
                unsafe {
                    CFRunLoopRemoveSource(
                        CFRunLoopGetMain(),
                        AXObserverGetRunLoopSource(self.observer.0),
                        kCFRunLoopDefaultMode,
                    );
                }
            }
        }

        /// Read every window of this pid, including a background document that
        /// has no AXMainWindow. Any unreadable window leaves ownership unproven.
        pub fn window_documents(pid: u32) -> Result<Vec<String>, String> {
            let pid = i32::try_from(pid).map_err(|_| "pid out of range")?;
            // SAFETY: creates an owned AX application reference for this pid.
            let app = unsafe { AXUIElementCreateApplication(pid) };
            if app.is_null() {
                return Err("AX application is null".into());
            }
            let app = Owned(app);
            // SAFETY: app is a live AXUIElement; every message is bounded.
            let code = unsafe { AXUIElementSetMessagingTimeout(app.0, 0.5) };
            if code != 0 {
                return Err(format!("app timeout setup: AX error {code}"));
            }
            let windows = ax_attribute(&app, "AXWindows")?;
            // SAFETY: windows is retained; verify its type before array access.
            if unsafe { CFGetTypeID(windows.0) != CFArrayGetTypeID() } {
                return Err("AXWindows is not an array".into());
            }
            let mut documents = Vec::new();
            // SAFETY: windows was verified as a live CFArray.
            let count = unsafe { CFArrayGetCount(windows.0) };
            for index in 0..count {
                // SAFETY: index is within the live array; retain a window via
                // its AXWindows owner for the duration of these reads.
                let window = unsafe { CFArrayGetValueAtIndex(windows.0, index) };
                if window.is_null() || unsafe { CFGetTypeID(window) != AXUIElementGetTypeID() } {
                    return Err(format!(
                        "window {index}: not an AX element; documents={documents:?}"
                    ));
                }
                let mut owner = 0;
                // SAFETY: window was verified; owner is a live output slot.
                let code = unsafe { AXUIElementGetPid(window, &mut owner) };
                if code != 0 || owner != pid {
                    return Err(format!(
                        "window {index}: owner={owner}, AX error {code}; documents={documents:?}"
                    ));
                }
                // SAFETY: the live window is kept alive by the array.
                let code = unsafe { AXUIElementSetMessagingTimeout(window, 0.5) };
                if code != 0 {
                    return Err(format!("window {index}: timeout setup AX error {code}"));
                }
                let name = string("AXDocument");
                let mut value = std::ptr::null();
                // SAFETY: window, attribute and output slot are all live.
                let code = unsafe { AXUIElementCopyAttributeValue(window, name.0, &mut value) };
                if code != 0 || value.is_null() {
                    return Err(format!(
                        "window {index}: AXDocument error {code}, null={}; documents={documents:?}",
                        value.is_null()
                    ));
                }
                let document = Owned(value);
                // SAFETY: document is a live CF value, checked before CFURL access.
                let text = if unsafe { CFGetTypeID(document.0) == CFURLGetTypeID() } {
                    // SAFETY: the owning URL remains live during conversion.
                    string_text(unsafe { CFURLGetString(document.0) })
                } else {
                    string_text(document.0)
                };
                documents.push(text.ok_or_else(|| {
                    format!(
                        "window {index}: AXDocument has unreadable type; documents={documents:?}"
                    )
                })?);
            }
            Ok(documents)
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
        if baseline {
            println!(
                "RECORD baseline startup: screen-recording preflight={}",
                cerebellum_macos::screen_capture_is_permitted()
            );
            match cerebellum_macos::enumerate_windows(Duration::from_secs(2)) {
                Ok(windows) => println!(
                    "RECORD baseline startup: direct window-list count={}",
                    windows.len()
                ),
                Err(reason) => {
                    println!("RECORD baseline startup: direct window-list error={reason}")
                }
            }
        }
        // A failed exclusion check still fails the run, but the desk phases
        // below still run: each desk session costs the person's time, so one
        // session should report every check rather than stop at the first.
        let exclusion_failed = match desk_startup(
            baseline,
            cerebellum_macos::prepare_app_use_desk_probe,
            || match cerebellum_macos::probe_overlay_capture_exclusion() {
                Ok(report) => {
                    println!("PASS overlay_single_window_capture_excludes_preview_and_badge_patterns: {report}");
                    false
                }
                Err(reason) => {
                    eprintln!("FAIL overlay_single_window_capture_excludes_preview_and_badge_patterns: {reason}");
                    true
                }
            },
        ) {
            Ok(failed) => failed,
            Err(reason) => {
                eprintln!("UNMEASURABLE: cannot initialize desk probe: {reason}");
                return 2;
            }
        };
        // Where ScreenCaptureKit's window list arrives: here on the main
        // thread after AppKit starts, then from the measurement's worker
        // thread while the main thread pumps, then from a Tokio worker.
        println!("{}", window_list_check("main_thread_after_appkit_startup"));
        println!(
            "TIME BUDGET: allow about {} s (launch {} s, covering the window up to {} s, \
             {} needs-front attempts per run with {} ms cleanup spacing, \
             two idle windows of {} s, teardown)",
            (2 * (LAUNCH_WAIT
                + COVER_WAIT
                + IDLE_WINDOW
                + FRONT_CLEANUP_SPACING * NEEDS_FRONT_ATTEMPTS as u32)
                + Duration::from_secs(30))
            .as_secs(),
            LAUNCH_WAIT.as_secs(),
            COVER_WAIT.as_secs(),
            NEEDS_FRONT_ATTEMPTS,
            FRONT_CLEANUP_SPACING.as_millis(),
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
        let _helper_pin = if let Some(helper) = helper.filter(|_| !baseline) {
            match cerebellum::computer_capability::cursor::pin_helper_for_probe(&helper) {
                Ok(pin) => Some(pin),
                Err(error) => {
                    eprintln!("UNMEASURABLE: cannot pin the cursor helper: {error}");
                    return 2;
                }
            }
        } else {
            None
        };
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
        // Hold the interrupt registry until discovery has either registered the
        // new identity or refused it; Ctrl-C must not skip a pending launch.
        let mut pending = SCRATCH_PID.lock().unwrap();
        let before = match textedit_pids() {
            Ok(before) if before.is_empty() => before,
            other => {
                eprintln!("UNMEASURABLE: TextEdit must not be running; cannot establish an empty pid set ({other:?})");
                return 2;
            }
        };
        let mut scratch = match launch_scratch(&before) {
            Ok(scratch) => scratch,
            Err(error) => {
                eprintln!("UNMEASURABLE: cannot launch scratch TextEdit: {error}");
                return 2;
            }
        };
        *pending = Some(scratch.identity.clone());
        drop(pending);
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
            cerebellum_macos::with_app_use_desk_probe_run_loop(|| {
                println!("{}", window_list_check("std_thread_while_main_pumps"));
                runtime.block_on(measure(&scratch, person, baseline))
            })
        }));
        let cleaned_up = scratch.finish();
        if cleaned_up {
            println!("SCRATCH {} killed", scratch.pid());
        }
        drop(scratch);
        if !cleaned_up {
            return 2;
        }
        let code = match outcome {
            Ok(Ok(code)) => code,
            Ok(Err(reason)) => {
                eprintln!("UNMEASURABLE: cannot run desk measurement: {reason}");
                2
            }
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
        let mut report = Report {
            failed: code != 0 || exclusion_failed,
        };
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
        use std::io::BufReader;
        use std::process::Stdio;

        println!("BASELINE run with the agent cursor off");
        // A plain child has a different responsibility chain from the main
        // probe. Use the same disclaiming launcher and the same signed binary
        // instead of relying on macOS's helper-attribution heuristics.
        let mut child = baseline_launch_command(executable)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("could not run sibling disclaim_launch: {error}"))?;
        let stdout = child.stdout.take().expect("piped baseline stdout");
        let stderr = child.stderr.take().expect("piped baseline stderr");
        // Drain both pipes concurrently so neither can stall the child. Forward
        // lines immediately, preserving their timing for the outer log reader.
        let out = std::thread::spawn(move || {
            stream_baseline(BufReader::new(stdout), |line| {
                println!("  baseline: {line}")
            })
        });
        let err = std::thread::spawn(move || {
            stream_baseline(BufReader::new(stderr), |line| {
                eprintln!("  baseline stderr: {line}")
            })
        });
        let status = child.wait();
        let stdout = out.join().map_err(|_| "baseline stdout reader panicked")?;
        let stderr = err.join().map_err(|_| "baseline stderr reader panicked")?;
        let status = status.map_err(|error| format!("waiting for baseline: {error}"))?;
        let idle_ns = stdout?;
        stderr?;
        if !status.success() {
            return Err(format!(
                "exit {:?}; see streamed baseline stdout/stderr above",
                status.code(),
            ));
        }
        idle_ns.ok_or_else(|| format!("no {BASELINE_LINE} line"))
    }

    /// Every phase against the scratch app. Returns the process exit code.
    async fn measure(scratch: &Scratch, person: i32, baseline: bool) -> i32 {
        match tokio::spawn(async { window_list_check("tokio_worker_at_measure_start") }).await {
            Ok(line) => println!("{line}"),
            Err(error) => println!(
                "RECORD window-list check stage=tokio_worker_at_measure_start did not run: {error}"
            ),
        }
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
        let plane = Arc::new(ComputerPlane::<NativeCaptureBackend, _, _, _, _>::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::Withhold,
            move || {
                MacOs26PlatformDriver::default()
                    .without_expected_post_condition()
                    .with_takeover_dispatch_review_revision(review.clone())
            },
        )
        .with_fronting_bracket_admitted(true)
        .with_app_use_fronting_admitted(true));
        // `agent_cursor: true` for the measured run, `false` for the
        // baseline; a plane's cursor starts disabled.
        let cursor = plane.cursor();
        if !baseline {
            cursor.enable(true);
        }
        let management = Arc::new(ManagementPlane::new(Arc::new(PlatformResolver::new())));
        let clock = Arc::new(SystemClock::new());
        // A temporary front must hand its restore to a terminal arbiter. The
        // direct plane call alone has no owner for that obligation and refuses.
        let carrier = Arc::new(Allowing::new());
        let calls =
            cerebellum::desk_probe::DeskProbeCalls::default().with_consent_desk(carrier.desk());
        let serve = |name: &'static str, arguments: Value| {
            let (plane, management, clock) = (
                Arc::clone(&plane),
                Arc::clone(&management),
                Arc::clone(&clock),
            );
            let carrier = Arc::clone(&carrier);
            calls.serve(name, move |cancel| async move {
                plane
                    .serve(
                        servable(name).expect("the capability is served"),
                        &arguments,
                        ServeContext {
                            cancel,
                            grantee: "desk-probe",
                            identity: identity(),
                            management: &management,
                            consent: consent(carrier),
                            clock: clock.as_ref(),
                            now_ms: 0,
                        },
                        |_| NativeCaptureBackend::new(Duration::from_secs(10)),
                    )
                    .await
                    .unwrap_or_else(
                        |error| json!({"outcome": "withheld", "error": format!("{error:?}")}),
                    )
            })
        };

        // The scratch window, read through the plane until it answers.
        let _ = cerebellum_macos::take_window_list_errors_for_probe();
        let started = Instant::now();
        let read = loop {
            let read = serve("computer.read_state", json!({"target": TEXTEDIT_BUNDLE})).await;
            for error in cerebellum_macos::take_window_list_errors_for_probe() {
                eprintln!("RECORD probe-only ScreenCaptureKit window-list error: {error}");
            }
            if read_state_outline(&read).is_some() {
                break read;
            }
            if started.elapsed() > LAUNCH_WAIT {
                eprintln!(
                    "UNMEASURABLE: the scratch window never answered a read: {}",
                    read
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
        let tree = read_state_outline(&first)
            .or_else(|| read_state_outline(&read))
            .unwrap_or_default()
            .to_string();
        let text_area = settable_text_area_id(&tree);
        // Written into the scratch document; redacted wherever a reply that
        // may quote it is printed.
        let typed = format!("app use desk probe {}", std::process::id());
        match text_area {
            Some(element_id) => {
                let write = serve(
                    "computer.write_text",
                    json!({
                        "element_id": element_id,
                        "text": typed,
                        "write_mode": "replace_value",
                    }),
                )
                .await;
                report.check(
                    "background write_text fronts nothing",
                    background_reply_verdict("write_text", &write)
                        .map_err(|reason| redact_typed_text(&reason, &typed)),
                );
            }
            None => report.check(
                "background write_text fronts nothing",
                Err(format!("no settable text area in the scratch window; initial read: {read}; latest read: {first}")),
            ),
        }
        let helper = cursor.helper_pid_for_probe();
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
        // Repeated harmless select-all chords expose activation latency, not
        // just one lucky request. Keep late cleanup clear of a new app call.
        // Discard any observations from the preceding background-only calls.
        let _ = cerebellum::desk_probe::take_fronting_timings();
        let _ = cerebellum::desk_probe::take_fronting_landings();
        let text_area_id = text_area.map(str::to_owned);
        // Kept for the whole attempt loop and removed from the run loop when
        // dropped after it.
        let selection_observer = match scratch.observe_selection() {
            Ok(observer) => Some(observer),
            Err(reason) => {
                println!("RECORD selection observer unavailable: {reason}");
                None
            }
        };
        let mut attempts = Vec::with_capacity(NEEDS_FRONT_ATTEMPTS);
        for attempt in 1..=NEEDS_FRONT_ATTEMPTS {
            // Every attempt starts from a caret, so its selection afterwards
            // shows whether this Command-A selected all.
            println!("{}", caret_reset_line(attempt, &scratch.reset_to_caret()));
            tokio::time::sleep(CARET_SETTLE).await;
            let _ = sys::take_selection_changes();
            let selection_before = scratch.selection();
            // The reply's state is read zoomed to the text area, so the
            // chord is judged by the focused element rather than the whole
            // tree, where the Edit menu's highlight appears.
            let mut arguments = json!({"target": TEXTEDIT_BUNDLE, "keys": ["command", "a"]});
            if let Some(id) = &text_area_id {
                arguments["zoom"] = json!(id);
            }
            sampler.needs_front.store(true, Ordering::SeqCst);
            let chord = serve("computer.keys", arguments).await;
            sampler.needs_front.store(false, Ordering::SeqCst);
            let edit_title = scratch.edit_title_highlighted();
            let selection_after = scratch.selection();
            println!(
                "{}",
                selection_line(attempt, &selection_before, &selection_after)
            );
            println!(
                "{}",
                select_all_line(attempt, &selection_before, &selection_after)
            );
            println!("{}", edit_title_line(attempt, &edit_title));
            println!(
                "{}",
                zoomed_read_line(attempt, &chord, text_area_id.as_deref())
            );
            println!(
                "RECORD needs-front attempt {attempt}: outcome={} effect_status={} fronting={}",
                chord["outcome"], chord["effect_status"], chord["fronting"]
            );
            report.check(
                "needs-front chord fronts, sends and restores",
                needs_front_reply_verdict(&chord)
                    .map_err(|reason| redact_typed_text(&reason, &typed)),
            );
            tokio::time::sleep(FRONT_CLEANUP_SPACING).await;
            let selection_changes = sys::take_selection_changes();
            for (pid, latency) in cerebellum::desk_probe::take_fronting_landings() {
                println!("RECORD needs-front attempt {attempt}: pid {pid} pending activation landed {latency} ms after request");
            }
            let timings = cerebellum::desk_probe::take_fronting_timings();
            let mut measured = AttemptTiming::default();
            match timings.as_slice() {
                [timing] if timing.target_pid == scratch.pid() => {
                    for line in timing.record_lines(attempt) {
                        println!("{line}");
                    }
                    println!(
                        "{}",
                        front_to_post_line(attempt, timing.confirmed_front_ms, timing.first_post_ms)
                    );
                    let changes_ms: Vec<f64> = timing
                        .front_requested_at
                        .map(|front| {
                            selection_changes
                                .iter()
                                .filter_map(|at| at.checked_duration_since(front))
                                .map(|since| since.as_secs_f64() * 1000.0)
                                .collect()
                        })
                        .unwrap_or_default();
                    println!(
                        "{}",
                        selection_change_line(attempt, &changes_ms, timing.first_post_ms)
                    );
                    measured.front_ms = timing.confirmed_front_ms.or(timing.late_landing_ms);
                    match timing.confirmed_front_ms {
                        Some(ms) => println!("RECORD needs-front attempt {attempt}: request→confirmed-frontmost {ms:.3} ms (in call)"),
                        None => match timing.late_landing_ms {
                            Some(ms) => println!("RECORD needs-front attempt {attempt}: not confirmed in call; late landing {ms:.3} ms after request"),
                            None => println!("RECORD needs-front attempt {attempt}: not confirmed in call; no late landing observed"),
                        },
                    }
                    // Exceeding the request-to-restore time bound after posting
                    // fails the verdict, but the timing is still a posted
                    // bracket, not cleanup of an unposted chord.
                    if chord["outcome"] == "delivery_unconfirmed" {
                        measured.bracket_ms = timing.restore_confirmed_ms;
                        measured.post_and_restore_ms = timing.confirmed_front_ms.zip(timing.restore_confirmed_ms).map(|(front, restored)| restored - front);
                    } else {
                        measured.cleanup_only_ms = timing.restore_confirmed_ms;
                    }
                }
                _ => println!("RECORD needs-front attempt {attempt}: not confirmed in call; timing unavailable (expected one request for scratch pid {}, got {timings:?})", scratch.pid()),
            }
            match measured.bracket_ms {
                Some(ms) => println!("RECORD needs-front attempt {attempt}: whole posted bracket (request→post→restore confirmed) {ms:.3} ms"),
                None => {
                    println!("RECORD needs-front attempt {attempt}: no posted+restored bracket confirmed");
                    if let Some(ms) = measured.cleanup_only_ms {
                        println!("RECORD needs-front attempt {attempt}: cleanup-only request→restore confirmed {ms:.3} ms (no posted chord confirmed)");
                    }
                }
            }
            attempts.push(measured);
        }
        print_needs_front_summary(&attempts);
        drop(selection_observer);
        let last = serve("computer.read_state", json!({"target": TEXTEDIT_BUNDLE})).await;
        report.check(
            "background read_state after the chord fronts nothing",
            background_reply_verdict("read_state", &last)
                .map_err(|reason| redact_typed_text(&reason, &typed)),
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
    fn both_probe_processes_bootstrap_before_any_optional_exclusion_check() {
        for baseline in [false, true] {
            let events = std::cell::RefCell::new(Vec::new());
            let failed = desk_startup(
                baseline,
                || {
                    events.borrow_mut().push("bootstrap");
                    Ok(())
                },
                || {
                    events.borrow_mut().push("exclusion");
                    true
                },
            )
            .unwrap();
            assert_eq!(failed, !baseline);
            let expected = if baseline {
                vec!["bootstrap"]
            } else {
                vec!["bootstrap", "exclusion"]
            };
            assert_eq!(*events.borrow(), expected);
        }
    }

    #[test]
    fn a_bootstrap_failure_prevents_the_exclusion_check_in_either_process() {
        for baseline in [false, true] {
            let result = desk_startup(
                baseline,
                || Err("no main thread".to_string()),
                || panic!("exclusion must not run without AppKit"),
            );
            assert_eq!(result, Err("no main thread".to_string()));
        }
    }

    #[test]
    fn a_failed_read_reports_the_full_reply_including_the_unreadable_cause() {
        for unreadable in [
            json!({"reason": "window_list_unavailable"}),
            json!({"reason": "generation_unreadable", "pid": 27002}),
        ] {
            let read = json!({
                "outcome": "targets_unreadable",
                "bundle_identity": "com.apple.TextEdit",
                "unreadable": unreadable,
                "remedy": "retry"
            });
            let reason = background_reply_verdict("read_state", &read).unwrap_err();
            assert!(reason.contains(&read.to_string()), "{reason}");
        }
    }

    #[test]
    fn the_helper_is_the_module_binary_beside_the_examples_directory() {
        assert_eq!(
            helper_binary(Path::new("/w/target/debug/examples/app_use_desk_probe")),
            Some(PathBuf::from("/w/target/debug/ck-cerebellum"))
        );
    }

    #[test]
    fn scratch_launch_uses_launchservices_without_activating_textedit() {
        let document = "/private/tmp/ck-desk-probe-abc/probe-abc.txt";
        let command = scratch_launch_command(Path::new(document));
        assert_eq!(command.get_program(), "/usr/bin/open");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "-n",
                "-g",
                "-a",
                "TextEdit",
                document,
                "--args",
                "-ApplePersistenceIgnoreState",
                "YES",
            ]
        );
    }

    #[test]
    fn scratch_launch_requires_exactly_one_new_textedit_pid() {
        assert_eq!(new_scratch_pid(&[], &[200]), Ok(200));
        assert_eq!(new_scratch_pid(&[100], &[100, 200]), Ok(200));
        assert_eq!(new_scratch_pid(&[100], &[200, 200, 100]), Ok(200));
        assert_eq!(new_scratch_pid(&[], &[]), Err(0));
        assert_eq!(new_scratch_pid(&[100], &[100]), Err(0));
        assert_eq!(new_scratch_pid(&[100], &[]), Err(0));
        assert_eq!(new_scratch_pid(&[], &[100, 200]), Err(2));
        assert_eq!(new_scratch_pid(&[100], &[300, 200, 100]), Err(2));
    }

    const SCRATCH_DOCUMENT: &str = "file:///private/tmp/ck-desk-probe-abc/probe-abc.txt";

    fn scratch_process() -> ScratchProcess {
        ScratchProcess {
            pid: 200,
            start_time: 12345,
        }
    }

    #[test]
    fn scratch_kill_accepts_only_the_matching_document() {
        assert!(scratch_process().may_kill(
            &[],
            Some(&[200]),
            Some(12345),
            Some(SCRATCH_DOCUMENT),
            SCRATCH_DOCUMENT,
        ));
    }

    #[test]
    fn scratch_kill_rejects_a_different_document() {
        assert!(!scratch_process().may_kill(
            &[],
            Some(&[200]),
            Some(12345),
            Some("file:///private/tmp/someones-document.txt"),
            SCRATCH_DOCUMENT,
        ));
    }

    #[test]
    fn scratch_kill_rejects_an_unreadable_document() {
        assert!(!scratch_process().may_kill(
            &[],
            Some(&[200]),
            Some(12345),
            None,
            SCRATCH_DOCUMENT,
        ));
    }

    #[test]
    fn scratch_kill_requires_exactly_one_new_textedit_pid() {
        for after in [None, Some(&[][..]), Some(&[200, 300]), Some(&[300])] {
            assert!(!scratch_process().may_kill(
                &[],
                after,
                Some(12345),
                Some(SCRATCH_DOCUMENT),
                SCRATCH_DOCUMENT,
            ));
        }
        assert!(!scratch_process().may_kill(
            &[200],
            Some(&[200]),
            Some(12345),
            Some(SCRATCH_DOCUMENT),
            SCRATCH_DOCUMENT,
        ));
    }

    #[test]
    fn scratch_kill_requires_the_original_process_start_time() {
        let scratch = scratch_process();
        let may_kill = |process: ScratchProcess, start| {
            process.may_kill(
                &[],
                Some(&[process.pid]),
                start,
                Some(SCRATCH_DOCUMENT),
                SCRATCH_DOCUMENT,
            )
        };
        assert!(may_kill(scratch, Some(12345)));
        assert!(!may_kill(scratch, Some(12346)), "a reused pid is not ours");
        assert!(
            !may_kill(scratch, None),
            "unknown or exited processes must not be killed"
        );
        assert!(!may_kill(ScratchProcess { pid: 0, ..scratch }, Some(12345)));
    }

    #[test]
    fn read_state_outline_uses_the_current_reply_field() {
        let reply = json!({
            "outcome": "completed",
            "state_text": "TextEdit — probe-abc.txt\nprobe1 window probe-abc.txt\n",
            "tree": "obsolete field",
        });
        assert_eq!(
            read_state_outline(&reply),
            Some("TextEdit — probe-abc.txt\nprobe1 window probe-abc.txt\n")
        );
        for reply in [
            json!({"outcome": "completed", "tree": "obsolete field"}),
            json!({"outcome": "completed", "state_text": ""}),
            json!({"outcome": "withheld", "state_text": "not a completed read"}),
        ] {
            assert_eq!(read_state_outline(&reply), None);
        }
    }

    #[test]
    fn text_area_lookup_uses_the_renderers_line_grammar() {
        // The line golden in app_state/tests/mod.rs uses this role, states,
        // label and value, with a session-generated id in place of probe1.
        let golden = "  probe1 text area (settable, focused) Message @IceTea, Value: hello";
        assert_eq!(settable_text_area_id(golden), Some("probe1"));
        assert_eq!(
            settable_text_area_id("probe2 text area (settable), Value: hello"),
            Some("probe2")
        );
        for line in [
            "probe3 button Choose a settable text area here",
            "probe4 text area (focused) Message, Value: settable",
            "probe5 text area (not_settable) Message",
            "probe6 text area (settable-extra) Message",
            "probe7 text area Message, Value: settable",
        ] {
            assert_eq!(settable_text_area_id(line), None, "{line}");
        }
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
    fn the_baseline_reexec_uses_the_same_disclaiming_launcher_and_signed_executable() {
        let executable = Path::new("/tmp/cereb-desk/app_use_desk_probe");
        let command = baseline_launch_command(executable);
        assert_eq!(command.get_program(), "/tmp/cereb-desk/disclaim_launch");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                executable.as_os_str(),
                APPROVAL_FLAG.as_ref(),
                BASELINE_FLAG.as_ref(),
            ]
        );
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
    fn the_front_check_brackets_repeated_actions_without_hiding_between_call_samples() {
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
        assert!(front_app_verdict(&two_actions, PERSON).is_ok());
        let mut late_landing = two_actions;
        late_landing[2].front = Some(TARGET);
        assert!(front_app_verdict(&late_landing, PERSON).is_err());
    }

    #[test]
    fn scratch_document_matches_local_url_and_path_forms_but_not_remote_or_partial_names() {
        let url = "file:///private/tmp/private%20scratch/document.txt";
        assert!(scratch_process().may_kill(
            &[],
            Some(&[200]),
            Some(12345),
            Some("/private/tmp/private scratch/document.txt"),
            url
        ));
        assert!(same_document(
            "/private/tmp/private scratch/document.txt",
            url
        ));
        assert!(same_document(
            "file://localhost/private/tmp/private%20scratch/document.txt",
            url
        ));
        assert!(!same_document(
            "file://remote/private/tmp/private%20scratch/document.txt",
            url
        ));
        assert!(!same_document("document.txt", url));
        assert!(!same_document(
            "file:///private/tmp/private%XXscratch/document.txt",
            url
        ));
        assert!(!same_document(
            "file:///private/tmp/other/document.txt",
            url
        ));
        assert!(same_document(
            "/private/tmp/100%/document.txt",
            "file:///private/tmp/100%25/document.txt"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn scratch_document_resolves_the_macos_tmp_alias() {
        assert!(same_document("file:///tmp", "file:///private/tmp"));
    }

    #[test]
    fn the_chord_must_report_a_needs_front_front_that_was_restored() {
        let fronting = |restore: &str, purpose: &str| {
            json!({"outcome": "delivery_unconfirmed", "target_fronted": true, "fronting": {
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

    fn held_chord() -> Value {
        json!({
            "outcome": "delivery_unconfirmed",
            "target_fronted": true,
            "fronting": {
                "mode": "background", "purpose": "needs_front",
                "fronted": true, "restore": "restored"
            }
        })
    }

    #[test]
    fn needs_front_accepts_the_posted_keys_contract_without_claiming_completion() {
        assert_eq!(needs_front_reply_verdict(&held_chord()), Ok(()));
        let mut completed = held_chord();
        completed["outcome"] = json!("completed");
        assert!(needs_front_reply_verdict(&completed)
            .unwrap_err()
            .contains("outcome was \"completed\", expected \"delivery_unconfirmed\""));
    }

    #[test]
    fn needs_front_names_every_missing_or_wrong_bracket_condition() {
        for (pointer, wrong, field) in [
            ("/outcome", json!("fronting_failed"), "outcome"),
            ("/target_fronted", json!(false), "target_fronted"),
            ("/fronting/mode", json!("foreground"), "fronting.mode"),
            ("/fronting/purpose", json!("other"), "fronting.purpose"),
            ("/fronting/fronted", json!(false), "fronting.fronted"),
            (
                "/fronting/restore",
                json!("skipped_person"),
                "fronting.restore",
            ),
        ] {
            let mut reply = held_chord();
            *reply.pointer_mut(pointer).unwrap() = wrong;
            let error = needs_front_reply_verdict(&reply).unwrap_err();
            assert!(error.contains(&format!("{field} was")), "{error}");
            *reply.pointer_mut(pointer).unwrap() = Value::Null;
            let error = needs_front_reply_verdict(&reply).unwrap_err();
            assert!(error.contains(&format!("{field} was null")), "{error}");
        }
        let missing = needs_front_reply_verdict(&json!({})).unwrap_err();
        for field in [
            "outcome",
            "target_fronted",
            "fronting.fronted",
            "fronting.restore",
        ] {
            assert!(missing.contains(&format!("{field} was null")), "{missing}");
        }
        for reason in [json!("fronting_bound_exceeded"), Value::Null] {
            let mut reply = held_chord();
            reply["containment_forfeited_because"] = reason;
            assert!(needs_front_reply_verdict(&reply)
                .unwrap_err()
                .contains("containment_forfeited_because was"));
        }
    }

    #[test]
    fn select_all_is_judged_only_from_a_caret_in_non_empty_text() {
        let range = |start, length| {
            Ok::<_, String>(TextSelection {
                start,
                length,
                text_length: 24,
            })
        };
        assert_eq!(
            select_all_effect(&range(24, 0), &range(0, 24)),
            "selected_all"
        );
        assert_eq!(select_all_effect(&range(24, 0), &range(24, 0)), "unchanged");
        assert_eq!(select_all_effect(&range(24, 0), &range(3, 2)), "other");
        // Already selected before the chord: no change could show.
        assert_eq!(
            select_all_effect(&range(0, 24), &range(0, 24)),
            "not_judged"
        );
        assert_eq!(
            select_all_effect(&range(24, 0), &Err("AX error".into())),
            "not_judged"
        );
        let empty = Ok(TextSelection {
            start: 0,
            length: 0,
            text_length: 0,
        });
        assert_eq!(select_all_effect(&empty, &empty), "not_judged");
        assert_eq!(
            select_all_line(4, &range(24, 0), &range(0, 24)),
            "RECORD needs-front attempt 4: select_all effect=selected_all"
        );
    }

    #[test]
    fn caret_and_edit_title_lines_name_their_result_or_reason() {
        assert_eq!(
            caret_reset_line(2, &Ok(24)),
            "RECORD needs-front attempt 2: selection reset to caret at=24 (UTF-16)"
        );
        assert_eq!(
            caret_reset_line(2, &Err("AX error\n-25200".into())),
            "RECORD needs-front attempt 2: selection reset failed: AX error -25200"
        );
        assert_eq!(
            edit_title_line(3, &Ok(true)),
            "RECORD needs-front attempt 3: edit_title_highlight=seen"
        );
        assert_eq!(
            edit_title_line(3, &Ok(false)),
            "RECORD needs-front attempt 3: edit_title_highlight=not_seen"
        );
        assert_eq!(
            edit_title_line(3, &Err("no Edit menu bar item".into())),
            "RECORD needs-front attempt 3: edit_title_highlight=unreadable (no Edit menu bar item)"
        );
    }

    #[test]
    fn the_zoomed_read_line_keeps_role_and_states_but_never_the_value() {
        let typed = "app use desk probe 58798";
        let reply = json!({
            "state_report": "diff",
            "focused_element_id": "iq3",
            "state_text": format!(
                "Removed element IDs: iq30\nfocused: iq3 text area (settable, focused), Value: {typed}\n"
            ),
        });
        let line = zoomed_read_line(5, &reply, Some("iq3"));
        assert_eq!(
            line,
            "RECORD needs-front attempt 5: zoomed read state_report=\"diff\" focused_element_id=\"iq3\" element=iq3 text area (settable, focused)"
        );
        assert!(!line.contains(typed));
        // A longer id that merely ends with the zoomed one is not it.
        assert_eq!(zoomed_element_summary("xiq3 button", "iq3"), None);
        assert!(zoomed_read_line(5, &reply, None).ends_with("element=absent"));
        assert_eq!(
            redact_typed_text(&format!("reply: {reply}"), typed)
                .matches("<typed text>")
                .count(),
            1
        );
        assert!(!redact_typed_text(&format!("reply: {reply}"), typed).contains(typed));
    }

    #[test]
    fn post_and_selection_timing_lines_relate_to_the_front_request_and_first_post() {
        assert_eq!(
            front_to_post_line(6, Some(25.5), Some(28.0)),
            "RECORD needs-front attempt 6: frontmost confirmed→first post 2.500 ms (first post at_ms=28.000)"
        );
        assert_eq!(
            front_to_post_line(6, None, Some(28.0)),
            "RECORD needs-front attempt 6: first post at_ms=28.000 with no in-call frontmost confirmation"
        );
        assert_eq!(
            front_to_post_line(6, Some(25.5), None),
            "RECORD needs-front attempt 6: no post observed"
        );
        assert_eq!(
            selection_change_line(7, &[40.0, 31.0], Some(28.0)),
            "RECORD needs-front attempt 7: selection_changed count=2 first_at_ms=31.000 (first post→change 3.000 ms)"
        );
        assert_eq!(
            selection_change_line(7, &[31.0], None),
            "RECORD needs-front attempt 7: selection_changed count=1 first_at_ms=31.000"
        );
        assert_eq!(
            selection_change_line(7, &[], Some(28.0)),
            "RECORD needs-front attempt 7: no selection change observed"
        );
    }

    #[test]
    fn window_list_lines_name_stage_thread_and_result() {
        assert_eq!(
            window_list_line(
                "tokio_worker_at_measure_start",
                "tokio-runtime-worker/ThreadId(4)",
                &Ok(397),
                Duration::from_micros(12_500)
            ),
            "RECORD window-list check stage=tokio_worker_at_measure_start thread=tokio-runtime-worker/ThreadId(4) windows=397 elapsed_ms=12.500"
        );
        assert_eq!(
            window_list_line(
                "std_thread_while_main_pumps",
                "unnamed/ThreadId(2)",
                &Err("the window list did not arrive\nwithin 2s".into()),
                Duration::from_secs(2)
            ),
            "RECORD window-list check stage=std_thread_while_main_pumps thread=unnamed/ThreadId(2) error=the window list did not arrive within 2s elapsed_ms=2000.000"
        );
    }

    #[test]
    fn selection_line_reports_both_ranges_and_utf16_text_lengths() {
        let before = Ok(TextSelection {
            start: 2,
            length: 0,
            text_length: 23,
        });
        let after = Ok(TextSelection {
            start: 0,
            length: 23,
            text_length: 23,
        });
        assert_eq!(selection_line(12, &before, &after),
            "RECORD needs-front attempt 12: selection before=2:0 after=0:23 length=23→23 (UTF-16; start:length)");
        let changed = Ok(TextSelection {
            start: 0,
            length: 24,
            text_length: 24,
        });
        assert!(selection_line(13, &after, &changed).contains("length=23→24"));
    }

    #[test]
    fn selection_line_reports_unreadable_sides_with_reasons_on_one_line() {
        let before = Err("scratch AXTextArea not found\nAXChildren unavailable".into());
        let after = Ok(TextSelection {
            start: 0,
            length: 23,
            text_length: 23,
        });
        assert_eq!(selection_line(3, &before, &after),
            "RECORD needs-front attempt 3: selection before=unreadable after=0:23 length=unreadable→23 (UTF-16; start:length); selection unreadable: before: scratch AXTextArea not found AXChildren unavailable");
        let failed_after = Err("AXSelectedTextRange: AX error -25212".into());
        assert_eq!(selection_line(4, &after, &failed_after),
            "RECORD needs-front attempt 4: selection before=0:23 after=unreadable length=23→unreadable (UTF-16; start:length); selection unreadable: after: AXSelectedTextRange: AX error -25212");
        let both = selection_line(5, &before, &failed_after);
        assert!(both.contains("before=unreadable after=unreadable length=unreadable→unreadable"));
        assert!(both.contains("; after: AXSelectedTextRange: AX error -25212"));
        assert_eq!(both.lines().count(), 1);
    }

    #[test]
    fn baseline_stream_emits_each_line_before_reading_the_next() {
        use std::cell::RefCell;
        use std::io::{BufReader, Read};
        use std::rc::Rc;

        struct Output {
            emitted: Rc<RefCell<Vec<String>>>,
            chunk: usize,
        }
        impl Read for Output {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                assert_eq!(self.emitted.borrow().len(), self.chunk);
                let chunks: [&[u8]; 3] = [
                    b"starting\n",
                    b"BASELINE_MODULE_IDLE_CPU_NS=123\n",
                    b"done\n",
                ];
                let Some(chunk) = chunks.get(self.chunk) else {
                    return Ok(0);
                };
                buffer[..chunk.len()].copy_from_slice(chunk);
                self.chunk += 1;
                Ok(chunk.len())
            }
        }
        let emitted = Rc::new(RefCell::new(Vec::new()));
        let output = Output {
            emitted: emitted.clone(),
            chunk: 0,
        };
        assert_eq!(
            stream_baseline(BufReader::new(output), |line| emitted
                .borrow_mut()
                .push(line.into())),
            Ok(Some(123))
        );
        assert_eq!(
            *emitted.borrow(),
            ["starting", "BASELINE_MODULE_IDLE_CPU_NS=123", "done"]
        );
        assert_eq!(stream_baseline(&b"no marker\n"[..], |_| {}), Ok(None));
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
#[test]
fn timing_summary_reports_empty_single_even_and_odd_samples() {
    assert_eq!(timing_summary(&[]), None);
    assert_eq!(
        timing_summary(&[17.5]),
        Some(TimingSummary {
            count: 1,
            min: 17.5,
            median: 17.5,
            p90: 17.5,
            max: 17.5,
        })
    );
    assert_eq!(
        timing_summary(&[30.0, 10.0, 20.0, 40.0]),
        Some(TimingSummary {
            count: 4,
            min: 10.0,
            median: 25.0,
            p90: 40.0,
            max: 40.0,
        })
    );
    assert_eq!(timing_summary(&[30.0, 10.0, 20.0]).unwrap().median, 20.0);
}

#[test]
fn timing_summary_p90_is_nearest_rank_for_twenty_unsorted_attempts() {
    let values = (1..=20).rev().map(f64::from).collect::<Vec<_>>();
    assert_eq!(
        timing_summary(&values),
        Some(TimingSummary {
            count: 20,
            min: 1.0,
            median: 10.5,
            p90: 18.0,
            max: 20.0,
        })
    );
    const { assert!(NEEDS_FRONT_ATTEMPTS >= 20) };
}

#[test]
fn bound_counts_keep_measured_completions_separate_from_estimated_late_cleanups() {
    let attempts = [
        AttemptTiming {
            front_ms: Some(70.0),
            bracket_ms: Some(100.0),
            post_and_restore_ms: Some(30.0),
            cleanup_only_ms: None,
        },
        AttemptTiming {
            front_ms: Some(80.0),
            bracket_ms: Some(130.0),
            post_and_restore_ms: Some(50.0),
            cleanup_only_ms: None,
        },
        // Late fronting and cleanup provide no measured chord completion.
        AttemptTiming {
            front_ms: Some(110.0),
            cleanup_only_ms: Some(140.0),
            ..AttemptTiming::default()
        },
        AttemptTiming {
            front_ms: Some(260.0),
            ..AttemptTiming::default()
        },
        AttemptTiming::default(),
    ];
    assert_eq!(
        bound_counts(&attempts, &CANDIDATE_BOUNDS_MS),
        vec![
            BoundCount {
                bound_ms: 100,
                measured: 1,
                estimated: Some(0)
            },
            BoundCount {
                bound_ms: 150,
                measured: 2,
                estimated: Some(3)
            },
            BoundCount {
                bound_ms: 200,
                measured: 2,
                estimated: Some(3)
            },
            BoundCount {
                bound_ms: 250,
                measured: 2,
                estimated: Some(3)
            },
            BoundCount {
                bound_ms: 300,
                measured: 2,
                estimated: Some(4)
            },
        ]
    );
}

#[test]
fn bound_counts_without_posted_samples_do_not_invent_a_post_cost() {
    let attempts = [AttemptTiming {
        front_ms: Some(80.0),
        cleanup_only_ms: Some(90.0),
        ..AttemptTiming::default()
    }];
    assert_eq!(
        bound_counts(&attempts, &[100]),
        vec![BoundCount {
            bound_ms: 100,
            measured: 0,
            estimated: None
        }]
    );
    assert_eq!(
        bound_counts(&[], &[100]),
        vec![BoundCount {
            bound_ms: 100,
            measured: 0,
            estimated: None
        }]
    );
}
