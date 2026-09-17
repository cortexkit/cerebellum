//! Drive the three global-cursor capabilities OVER THE WIRE and report each
//! verification arm on its own line.
//!
//! `computer.move`, `computer.scroll` and `computer.drag` post input to the
//! whole session rather than to one process, and ship withheld behind the
//! `CEREBELLUM_GLOBAL_DISPATCH_REVIEW_REVISION` build key. Their guards -- the
//! containment rung they record, the focus re-check, the idle gate, and the
//! abort on hardware input -- are covered by unit tests over fake drivers as
//! far as fake drivers can go. What no unit test can supply is a real cursor
//! on a real GUI session with a real person's hand on the mouse, and that is
//! what this probe measures.
//!
//! A WIRE CLIENT, deliberately, and not an in-process harness like
//! `live_synthetic_input`. macOS attributes input-posting permission to the
//! process that was granted it -- the supervised module under its own
//! supervisor -- so a probe that posted from its own process would measure a
//! different principal and could pass while the shipped module could not post
//! at all.
//!
//! Run:
//!
//! ```text
//! cargo run -p cerebellum --example live_global_cursor -- --quiet
//! cargo run -p cerebellum --example live_global_cursor -- --hands
//! cargo run -p cerebellum --example live_global_cursor -- --quiet --connection <file>
//! ```
//!
//! `--quiet` runs the arms that need nobody at the desk. `--hands` runs the
//! arms that need a person in the VM window: the probe counts down and the
//! operator moves the mouse when it says NOW.
//!
//! Every arm prints one line, `ARM <n> <name>: PASS|FAIL <evidence>`, so a
//! reader on the far end of an SSH session can find the verdict without
//! reading the log. Exit 0 only when every arm in the chosen set holds. An arm
//! that could not be run at all prints UNMEASURABLE and exits 1: a null is
//! never reported as a pass.
//!
//! WHERE EACH FACT IS READ, because the two sources say different things.
//! Vocabulary v8 decides what a reply may carry, and for these rows it carries
//! very little: `computer.move` and `computer.drag` declare no
//! `containment_rung` at all, and no synthetic row declares the seize source or
//! the idle numbers. Those facts live in the audit journal, which is why the
//! journal is read here rather than trusted to agree with the wire. Each arm
//! names its source in its evidence line.

use std::process::ExitCode;

/// The global cursor exists where a window server does. On other hosts this
/// still has to compile -- the Linux lint phase builds every target -- so it
/// compiles to a main that says why there is nothing to run.
#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!(
        "this probe drives the macOS global cursor against a running daemon \
         and has nothing to run here"
    );
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> ExitCode {
    probe::run().await
}

#[cfg(target_os = "macos")]
mod probe {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};
    use std::time::Duration;

    use serde_json::{json, Value};
    use subc_control::{ClientControlRequest, ClientControlResponse};
    use subc_protocol::manifest::ProviderRole;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
    use tokio::net::TcpStream;
    use tokio::time::{sleep, timeout};

    const MODULE_ID: &str = "cerebellum";
    const TARGET_BUNDLE: &str = "com.apple.TextEdit";
    const TARGET_APP: &str = "TextEdit";
    /// Activated to steal the front, which is the whole point of arm 3.
    const INTRUDER_APP: &str = "Finder";
    const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

    /// Frame-level timeline on stderr when `CEREBELLUM_PROBE_TRACE` is set.
    /// Each line carries milliseconds since the probe started, so a stalled
    /// reply reads as a gap between a `->` and its `<-` rather than as a
    /// timeout with no history.
    fn trace(line: &str) {
        use std::sync::OnceLock;
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        static ENABLED: OnceLock<bool> = OnceLock::new();
        let enabled = *ENABLED.get_or_init(|| std::env::var_os("CEREBELLUM_PROBE_TRACE").is_some());
        if enabled {
            let start = START.get_or_init(std::time::Instant::now);
            eprintln!("[{:>8} ms] {line}", start.elapsed().as_millis());
        }
    }
    /// The idle gate's threshold in milliseconds, as `OBSERVED_DISPATCH_IDLE_MS`
    /// defines it.
    ///
    /// Written out rather than imported from the module on purpose. Importing it
    /// would compare the running module's threshold against itself, so a build
    /// that silently changed the number would still pass; this way the probe
    /// fails when the desk stops enforcing the second that was specified.
    const IDLE_THRESHOLD_MS: u64 = 1_000;
    /// How long the probe waits for a Once lease to become live after the
    /// consent answer goes out. The answer settles on another task inside the
    /// module, so readiness is polled rather than slept off.
    const LEASE_POLL_ATTEMPTS: u32 = 40;
    const LEASE_POLL_INTERVAL: Duration = Duration::from_millis(50);

    /// One arm's verdict.
    ///
    /// `Unmeasurable` is separate from `Fail` on purpose: an arm that could not
    /// run says nothing about the mechanism, and reporting it as a failure
    /// invites someone to go fix code that was never exercised.
    enum Verdict {
        Pass(String),
        Fail(String),
        Unmeasurable(String),
    }

    struct Arm {
        number: &'static str,
        name: &'static str,
        verdict: Verdict,
    }

    impl Arm {
        fn pass(number: &'static str, name: &'static str, evidence: impl Into<String>) -> Self {
            Self {
                number,
                name,
                verdict: Verdict::Pass(evidence.into()),
            }
        }

        fn fail(number: &'static str, name: &'static str, evidence: impl Into<String>) -> Self {
            Self {
                number,
                name,
                verdict: Verdict::Fail(evidence.into()),
            }
        }

        fn unmeasurable(number: &'static str, name: &'static str, why: impl Into<String>) -> Self {
            Self {
                number,
                name,
                verdict: Verdict::Unmeasurable(why.into()),
            }
        }

        fn held(&self) -> bool {
            matches!(self.verdict, Verdict::Pass(_))
        }

        fn report(&self) {
            let (word, evidence) = match &self.verdict {
                Verdict::Pass(evidence) => ("PASS", evidence),
                Verdict::Fail(evidence) => ("FAIL", evidence),
                Verdict::Unmeasurable(why) => ("UNMEASURABLE", why),
            };
            println!("ARM {} {}: {} {}", self.number, self.name, word, evidence);
        }
    }

    pub async fn run() -> ExitCode {
        let mut hands = false;
        let mut quiet = false;
        let mut connection: Option<PathBuf> = None;
        let mut args = std::env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--quiet" => quiet = true,
                "--hands" => hands = true,
                "--poke" => {
                    let Some(ms) = args.next().and_then(|value| value.parse::<u64>().ok()) else {
                        eprintln!("--poke needs a delay in milliseconds");
                        return ExitCode::from(2);
                    };
                    return poke_after(ms);
                }
                "--connection" => match args.next() {
                    Some(path) => connection = Some(PathBuf::from(path)),
                    None => {
                        eprintln!("--connection needs a file path");
                        return ExitCode::from(2);
                    }
                },
                other => {
                    eprintln!("unknown argument {other:?}");
                    eprintln!("usage: live_global_cursor --quiet | --hands [--connection <file>]");
                    return ExitCode::from(2);
                }
            }
        }
        if quiet == hands {
            eprintln!("choose exactly one of --quiet and --hands");
            eprintln!("usage: live_global_cursor --quiet | --hands [--connection <file>]");
            return ExitCode::from(2);
        }

        let mut wire = match Wire::open(connection.as_deref()).await {
            Ok(wire) => wire,
            Err(reason) => {
                eprintln!("could not reach the daemon: {reason}");
                return ExitCode::from(1);
            }
        };

        // Preconditions first, and reported as UNMEASURABLE rather than as a
        // failing arm: a locked screen or a module that does not serve these
        // capabilities tells you nothing about the guards under test.
        if let Err(reason) = wire.catalogue_serves_pointer_capabilities().await {
            let label = if hands { "1" } else { "4" };
            Arm::unmeasurable(label, "preconditions", reason).report();
            return ExitCode::from(1);
        }
        if cerebellum_macos::screen_is_locked() == Some(true) {
            let label = if hands { "1" } else { "4" };
            Arm::unmeasurable(
                label,
                "preconditions",
                "the screen is locked, so no global post can be delivered",
            )
            .report();
            return ExitCode::from(1);
        }
        if let Err(reason) = front(TARGET_APP) {
            let label = if hands { "1" } else { "4" };
            Arm::unmeasurable(label, "preconditions", reason).report();
            return ExitCode::from(1);
        }

        let arms = if quiet {
            quiet_arms(&mut wire).await
        } else {
            hands_arms(&mut wire).await
        };

        println!();
        for arm in &arms {
            arm.report();
        }
        // On the record for the next vocabulary revision rather than
        // rediscovered by the next person to read a reply and find the field
        // missing.
        println!(
            "note: vocabulary v8 omits containment_rung from the computer.move and \
             computer.drag result schemas; computer.scroll declares it."
        );
        if arms.iter().all(Arm::held) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }

    async fn quiet_arms(wire: &mut Wire) -> Vec<Arm> {
        // The poke arm posts input from a second process, which the idle gate
        // rightly counts as a person for the next second; it runs last so the
        // arms that need a quiet machine are not measuring its residue.
        let four = arm_four(wire).await;
        let three = arm_three(wire).await;
        let two_plus = arm_two_plus(wire).await;
        let (one, seven) = arm_one_and_seven_second_process(wire).await;
        vec![four, three, two_plus, one, seven]
    }

    async fn hands_arms(wire: &mut Wire) -> Vec<Arm> {
        let minus = arm_two_minus(wire).await;
        let one = arm_one_hardware(wire).await;
        vec![minus, one]
    }

    /// Child mode: sleep, post one mouse-move globally from THIS process, exit.
    ///
    /// The tap sees it under this child's pid, which is neither the module's
    /// nor the parent probe's, so the seize watcher classifies it as another
    /// process seizing input: the same stop path a person's input takes,
    /// reachable at a chosen millisecond instead of whenever a hand lands.
    fn poke_after(ms: u64) -> ExitCode {
        // Loading this binary costs tens of milliseconds on a VM, more than
        // the delays being measured. The parent waits for this line before it
        // sends the drag, so the delay counts from a moment both sides share.
        use std::io::Write;
        println!("ready");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(ms));
        let event = match cerebellum_macos::mouse_move_event(cerebellum_macos::EventPoint {
            x: 450.0,
            y: 430.0,
        }) {
            Ok(event) => event,
            Err(error) => {
                eprintln!("poke: could not construct a mouse move: {error:?}");
                return ExitCode::from(1);
            }
        };
        let _ = cerebellum_macos::post_event_globally(event);
        ExitCode::SUCCESS
    }

    // ------------------------------------------------------- arms 1 and 7

    /// A drag stops when another process posts input mid-sequence, and the
    /// stop arrives inside the loop's own latency bound.
    ///
    /// Runs without a person: a child of this probe posts one mouse-move at a
    /// chosen delay after the drag request goes out, so the event lands at a
    /// known point in the sequence. The tap attributes it to the child's pid
    /// and the watcher takes the same stop path a hand would. Three delays
    /// cover the sequence (three posts 50 ms apart plus the tail); a delay that
    /// lands before the idle read refuses `not_idle` instead, which is the
    /// gate doing its job and is reported as such rather than as a miss.
    async fn arm_one_and_seven_second_process(wire: &mut Wire) -> (Arm, Arm) {
        const ONE: &str = "1";
        const ONE_NAME: &str = "abort_on_second_process_input_during_sequence";
        const SEVEN: &str = "7";
        const SEVEN_NAME: &str = "abort_latency_bound";
        let probe_binary = match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => {
                let reason =
                    format!("cannot find this probe's own binary to spawn a poke: {error}");
                return (
                    Arm::unmeasurable(ONE, ONE_NAME, reason.clone()),
                    Arm::unmeasurable(SEVEN, SEVEN_NAME, reason),
                );
            }
        };

        let mut aborts = 0u32;
        let mut worst: Option<(u32, u32)> = None;
        let mut evidence = Vec::new();
        for poke_after_ms in [30u64, 80, 130] {
            // Let the machine go idle past the gate before each attempt; the
            // previous attempt's own posts are carried by the estimator, but
            // the poke was another process's input and clears the carry.
            sleep(Duration::from_millis(1300)).await;
            if let Err(reason) = wire.take_once_lease().await {
                return (
                    Arm::unmeasurable(ONE, ONE_NAME, reason),
                    Arm::unmeasurable(SEVEN, SEVEN_NAME, "arm 1 did not run"),
                );
            }
            let before = match journal_entries() {
                Ok(entries) => entries,
                Err(reason) => {
                    return (
                        Arm::unmeasurable(ONE, ONE_NAME, reason),
                        Arm::unmeasurable(SEVEN, SEVEN_NAME, "arm 1 did not run"),
                    )
                }
            };
            let mut child = match Command::new(&probe_binary)
                .arg("--poke")
                .arg(poke_after_ms.to_string())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()
            {
                Ok(child) => child,
                Err(error) => {
                    let reason = format!("could not spawn the poke child: {error}");
                    return (
                        Arm::unmeasurable(ONE, ONE_NAME, reason.clone()),
                        Arm::unmeasurable(SEVEN, SEVEN_NAME, reason),
                    );
                }
            };
            let child_pid = i64::from(child.id());
            {
                use std::io::BufRead;
                let stdout = child.stdout.take().expect("piped stdout");
                let mut line = String::new();
                let _ = std::io::BufReader::new(stdout).read_line(&mut line);
                if line.trim() != "ready" {
                    let reason = format!("the poke child did not report ready (got {line:?})");
                    return (
                        Arm::unmeasurable(ONE, ONE_NAME, reason.clone()),
                        Arm::unmeasurable(SEVEN, SEVEN_NAME, reason),
                    );
                }
            }
            let reply = match wire
                .tool_call(
                    "computer.drag",
                    json!({
                        "from": "400,400",
                        "to": "520,460",
                        "button": "left",
                        "modifiers": [],
                    }),
                )
                .await
            {
                Ok(reply) => reply,
                Err(reason) => {
                    return (
                        Arm::unmeasurable(ONE, ONE_NAME, reason),
                        Arm::unmeasurable(SEVEN, SEVEN_NAME, "arm 1 did not run"),
                    )
                }
            };
            let _ = child.wait();
            match reply["outcome"].as_str() {
                Some("user_seized_control") => {}
                other => {
                    evidence.push(format!("poke at {poke_after_ms}ms: answered {other:?}"));
                    continue;
                }
            }
            let record = match settled_record(&before, "computer.drag") {
                Ok(record) => record,
                Err(reason) => {
                    return (
                        Arm::unmeasurable(ONE, ONE_NAME, reason),
                        Arm::unmeasurable(SEVEN, SEVEN_NAME, "arm 1 did not run"),
                    )
                }
            };
            let Some(abort) = record.abort.as_ref() else {
                return (
                    Arm::fail(
                        ONE,
                        ONE_NAME,
                        format!(
                            "poke at {poke_after_ms}ms: the wire said user_seized_control but \
                             the journal record carries no abort"
                        ),
                    ),
                    Arm::unmeasurable(SEVEN, SEVEN_NAME, "arm 1 produced no abort record"),
                );
            };
            let source = abort
                .get("sourced_input_kind")
                .and_then(|kind| kind.get("source"))
                .and_then(Value::as_str)
                .unwrap_or("absent");
            let seized_by = abort
                .get("sourced_input_kind")
                .and_then(|kind| kind.get("pid"))
                .and_then(Value::as_i64);
            if source != "other_process" || seized_by != Some(child_pid) {
                return (
                    Arm::fail(
                        ONE,
                        ONE_NAME,
                        format!(
                            "poke at {poke_after_ms}ms: the abort names source={source:?} \
                             pid={seized_by:?}, not the poking child {child_pid}"
                        ),
                    ),
                    Arm::unmeasurable(SEVEN, SEVEN_NAME, "arm 1 did not observe the poke"),
                );
            }
            aborts += 1;
            let end_to_end = abort
                .get("detection_latency_ms")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
            let platform = abort
                .get("platform_delivery_latency_ms")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
            let bound = abort
                .get("maximum_detection_latency_ms")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
            let stopped_at = abort
                .get("stopped_action_index")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX);
            let (Some(end_to_end), Some(bound)) = (end_to_end, bound) else {
                return (
                    Arm::pass(
                        ONE,
                        ONE_NAME,
                        format!("poke at {poke_after_ms}ms: stopped by the child's input"),
                    ),
                    Arm::fail(
                        SEVEN,
                        SEVEN_NAME,
                        format!(
                            "the abort record carries detection_latency_ms={end_to_end:?} and \
                             maximum_detection_latency_ms={bound:?}; the bound cannot be checked \
                             against a missing number"
                        ),
                    ),
                );
            };
            let loop_share = platform.map_or(end_to_end, |p| end_to_end.saturating_sub(p));
            evidence.push(format!(
                "poke at {poke_after_ms}ms: stopped at post {stopped_at} by pid {child_pid}, \
                 detection_latency_ms={end_to_end} (platform {}, loop {loop_share}) bound={bound}",
                platform.map_or("unreported".to_string(), |p| p.to_string())
            ));
            if worst.is_none_or(|(previous, _)| loop_share > previous) {
                worst = Some((loop_share, bound));
            }
        }

        if aborts == 0 {
            return (
                Arm::fail(
                    ONE,
                    ONE_NAME,
                    format!("no poke stopped a drag ({})", evidence.join("; ")),
                ),
                Arm::unmeasurable(SEVEN, SEVEN_NAME, "arm 1 observed no abort to measure"),
            );
        }
        let one = Arm::pass(
            ONE,
            ONE_NAME,
            format!(
                "{aborts} of 3 pokes stopped the drag; {}",
                evidence.join("; ")
            ),
        );
        let seven = match worst {
            Some((measured, bound)) if measured <= bound => Arm::pass(
                SEVEN,
                SEVEN_NAME,
                format!(
                    "worst loop share of detection latency {measured} ms <= bound {bound} over \
                     {aborts} aborts (platform delivery disclosed per poke above)"
                ),
            ),
            Some((measured, bound)) => Arm::fail(
                SEVEN,
                SEVEN_NAME,
                format!(
                    "worst loop share of detection latency {measured} ms exceeds bound {bound}"
                ),
            ),
            None => Arm::unmeasurable(SEVEN, SEVEN_NAME, "no abort carried a latency"),
        };
        (one, seven)
    }

    // ---------------------------------------------------------------- arm 4

    /// A global post records the weakest containment rung and the severity tier
    /// that follows from it, on both sources that can carry the claim.
    ///
    /// Split across three actions because the two sources do not cover the same
    /// ground. Vocabulary v8 gives `computer.move` and `computer.drag` a result
    /// schema without `containment_rung` -- their delivery is always
    /// coordinate-addressed, so the row declines to state a distinction it never
    /// makes -- and the module strips the field before replying. For those two
    /// the rung and the tier are read from the journal, and the wire is checked
    /// for what v8 DOES declare. `computer.scroll` declares the field and
    /// requires it, so the wire literal `global_none` is asserted there.
    async fn arm_four(wire: &mut Wire) -> Arm {
        const NUMBER: &str = "4";
        const NAME: &str = "global_none_tier4_on_wire_and_journal";
        let mut evidence = Vec::new();

        for (capability, arguments) in [
            ("computer.move", json!({"to": "420,360"})),
            (
                "computer.drag",
                json!({
                    "from": "420,360",
                    "to": "560,470",
                    "button": "left",
                    "modifiers": [],
                }),
            ),
        ] {
            let before = match journal_entries() {
                Ok(entries) => entries,
                Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
            };
            let reply = match wire.pointer_action(capability, arguments).await {
                Ok(reply) => reply,
                Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
            };
            if reply["outcome"] != json!("completed") {
                return Arm::fail(
                    NUMBER,
                    NAME,
                    format!("{capability} did not complete: {reply}"),
                );
            }
            // What v8 declares for these two rows, asserted as declared.
            for field in ["outcome", "effect_status", "target_fronted"] {
                if reply.get(field).is_none() {
                    return Arm::fail(
                        NUMBER,
                        NAME,
                        format!("{capability} reply omits the declared field {field}: {reply}"),
                    );
                }
            }
            if reply.get("containment_rung").is_some() {
                return Arm::fail(
                    NUMBER,
                    NAME,
                    format!(
                        "{capability} reply carries containment_rung, which its v8 result \
                         schema does not declare: {reply}"
                    ),
                );
            }
            let record = match settled_record(&before, capability) {
                Ok(record) => record,
                Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
            };
            if record.containment_rung != "global_none" {
                return Arm::fail(
                    NUMBER,
                    NAME,
                    format!(
                        "{capability} journal rung is {:?}, not global_none",
                        record.containment_rung
                    ),
                );
            }
            if record.tier != Some(4) {
                return Arm::fail(
                    NUMBER,
                    NAME,
                    format!(
                        "{capability} journal severity tier is {:?}, not 4",
                        record.tier
                    ),
                );
            }
            evidence.push(format!(
                "{capability} wire outcome=completed effect_status={} target_fronted={} \
                 containment_rung absent as v8 declares; journal rung=global_none tier=4",
                reply["effect_status"], reply["target_fronted"]
            ));
        }

        // The one row whose result schema declares the rung, so the claim
        // "global_none reaches the wire" is asserted somewhere real.
        let reply = match wire
            .pointer_action(
                "computer.scroll",
                json!({"target": "probe", "axis": "vertical", "amount_lines": -1}),
            )
            .await
        {
            Ok(reply) => reply,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        if reply["outcome"] != json!("completed") {
            return Arm::fail(
                NUMBER,
                NAME,
                format!("computer.scroll did not complete: {reply}"),
            );
        }
        if reply["containment_rung"] != json!("global_none") {
            return Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "computer.scroll wire rung is {}, not global_none",
                    reply["containment_rung"]
                ),
            );
        }
        evidence.push("computer.scroll wire containment_rung=global_none".to_string());
        Arm::pass(NUMBER, NAME, evidence.join(" | "))
    }

    // ---------------------------------------------------------------- arm 3

    /// The front is re-checked between taking the lease and posting, so an
    /// application that steals it in between stops the post.
    ///
    /// The positive control is not decoration. A refusal on its own is also what
    /// a probe that can never post produces, and the two read identically; the
    /// second move proves the refusal was about the front and not about the
    /// probe.
    async fn arm_three(wire: &mut Wire) -> Arm {
        const NUMBER: &str = "3";
        const NAME: &str = "focus_toctou_refused";

        if let Err(reason) = wire.take_once_lease().await {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        if let Err(reason) = front(INTRUDER_APP) {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        let before = match journal_entries() {
            Ok(entries) => entries,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        let reply = match wire
            .tool_call("computer.move", json!({"to": "300,300"}))
            .await
        {
            Ok(reply) => reply,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        if reply["outcome"] != json!("target_focus_mismatch") {
            return Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "a move issued while {INTRUDER_APP} was frontmost answered {}, not \
                     target_focus_mismatch",
                    reply["outcome"]
                ),
            );
        }
        let record = match settled_record(&before, "computer.move") {
            Ok(record) => record,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        // `refused` is the terminal the dispatcher writes when the platform
        // never returned a delivery; `handler_returned` is what a delivered post
        // writes. So this distinguishes "stopped before posting" from "posted
        // and then complained", which the reply alone cannot.
        if record.outcome != "refused" {
            return Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "the journal terminal is {:?}, so a post may have been delivered before \
                     the mismatch was reported",
                    record.outcome
                ),
            );
        }
        if record.abort_reason().as_deref() != Some("focus_mismatch") {
            return Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "the journalled abort reason is {:?}, not focus_mismatch",
                    record.abort_reason()
                ),
            );
        }

        if let Err(reason) = front(TARGET_APP) {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        let control = match wire
            .pointer_action("computer.move", json!({"to": "320,320"}))
            .await
        {
            Ok(reply) => reply,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        if control["outcome"] != json!("completed") {
            return Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "the positive control did not complete once {TARGET_APP} was fronted \
                     again ({control}), so the refusal above may not have been about focus"
                ),
            );
        }
        Arm::pass(
            NUMBER,
            NAME,
            format!(
                "wire outcome=target_focus_mismatch with {INTRUDER_APP} fronted; journal \
                 terminal=refused abort.reason=focus_mismatch (no post delivered); positive \
                 control completed with {TARGET_APP} fronted"
            ),
        )
    }

    // --------------------------------------------------------------- arm 2+

    /// An idle desk is not refused as busy.
    ///
    /// The paired half of arm 2-. Without it, a gate that refused every post
    /// would satisfy arm 2- perfectly.
    async fn arm_two_plus(wire: &mut Wire) -> Arm {
        const NUMBER: &str = "2+";
        const NAME: &str = "idle_gate_passes_when_idle";

        if let Err(reason) = wire.take_once_lease().await {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        // Longer than the threshold, and measured from after the lease is taken
        // so the request itself does not shorten the idle window.
        sleep(Duration::from_secs(2)).await;
        let reply = match wire
            .tool_call("computer.move", json!({"to": "340,340"}))
            .await
        {
            Ok(reply) => reply,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        if reply["outcome"] == json!("not_idle") {
            return Arm::fail(
                NUMBER,
                NAME,
                format!("a move after 2s of no input was refused not_idle: {reply}"),
            );
        }
        Arm::pass(
            NUMBER,
            NAME,
            format!(
                "after 2000ms with no input (threshold {IDLE_THRESHOLD_MS}ms) the move \
                 answered {}, which is not not_idle",
                reply["outcome"]
            ),
        )
    }

    // --------------------------------------------------------------- arm 2-

    /// Input from the person at the desk makes the very next post refuse.
    ///
    /// Five attempts at 200ms spacing rather than one, because the operator's
    /// hand and the probe's clock are not synchronised and a single sample
    /// would turn a timing miss into a defect report. Any attempt inside the
    /// window refusing is the arm; the numbers come from the journal, since no
    /// synthetic row declares them on the wire.
    async fn arm_two_minus(wire: &mut Wire) -> Arm {
        const NUMBER: &str = "2-";
        const NAME: &str = "idle_gate_refuses_after_input";

        countdown("idle arm: at NOW, wait one second, then move the mouse for three seconds");
        // Fifteen attempts at 200 ms cover three seconds after NOW: the
        // operator is told to wait a second before moving, the same
        // instruction every cue gets, so the refusal can arrive anywhere in
        // the first few seconds rather than only at once.
        for attempt in 1..=15 {
            if let Err(reason) = wire.take_once_lease().await {
                return Arm::unmeasurable(NUMBER, NAME, reason);
            }
            let before = match journal_entries() {
                Ok(entries) => entries,
                Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
            };
            let reply = match wire
                .tool_call("computer.move", json!({"to": "360,360"}))
                .await
            {
                Ok(reply) => reply,
                Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
            };
            if reply["outcome"] == json!("not_idle") {
                let record = match settled_record(&before, "computer.move") {
                    Ok(record) => record,
                    Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
                };
                let Some((observed, threshold)) = record.idle_numbers() else {
                    return Arm::fail(
                        NUMBER,
                        NAME,
                        format!(
                            "the refusal carried no idle numbers; journalled abort was {:?}",
                            record.abort
                        ),
                    );
                };
                if threshold != IDLE_THRESHOLD_MS {
                    return Arm::fail(
                        NUMBER,
                        NAME,
                        format!("the refusal names a {threshold}ms threshold, not {IDLE_THRESHOLD_MS}ms"),
                    );
                }
                if observed >= threshold {
                    return Arm::fail(
                        NUMBER,
                        NAME,
                        format!(
                            "the refusal reports {observed}ms idle, which is not below its own \
                             {threshold}ms threshold"
                        ),
                    );
                }
                // Same rhythm as every other round: the window runs out and
                // says "stop" before the verdict, so a pass caught on the
                // first attempt does not shorten the gap before the next cue.
                sleep(Duration::from_millis(200) * (15 - attempt)).await;
                speak("stop");
                sleep(Duration::from_secs(3)).await;
                return Arm::pass(
                    NUMBER,
                    NAME,
                    format!(
                        "attempt {attempt}: wire outcome=not_idle; journal \
                         abort.reason.idle_gate_refused hid_idle_ms={observed} \
                         threshold_ms={threshold}"
                    ),
                );
            }
            sleep(Duration::from_millis(200)).await;
        }
        speak("stop");
        sleep(Duration::from_secs(3)).await;
        Arm::fail(
            NUMBER,
            NAME,
            "fifteen moves at 200ms spacing after the countdown were all admitted; either the \
             operator's input did not land in the window or the idle gate did not see it",
        )
    }

    // ------------------------------------------------------------ arms 1, 7

    /// Hardware input during a sequence stops it, and the stop is fast enough.
    ///
    /// Run together because arm 7 reads arm 1's record: the latency is only
    /// meaningful for an abort that actually happened, and measuring it from a
    /// separate run would report a number from a different event.
    ///
    /// A drag expands to exactly three posts -- press, move, release -- whatever
    /// its geometry, so a longer path does not lengthen the window in which the
    /// operator's motion can land; the spacing between posts does. The longest
    /// path the schema permits is used anyway, since it costs nothing, and the
    /// three repeats are what actually buy the coverage.
    ///
    /// The other direction -- that our OWN posts do not abort us -- is arm 4,
    /// which completes a move and a drag with nobody touching anything.
    /// The hands twin of arm 1: the stopping input is a person's, attributed
    /// `hardware` by the tap. The latency bound is measured by the second-
    /// process arm, where the moment of the input is known; here the point is
    /// the attribution and that a real hand takes the same path.
    async fn arm_one_hardware(wire: &mut Wire) -> Arm {
        const ONE: &str = "1h";
        const ONE_NAME: &str = "abort_on_hardware_input_during_sequence";
        // A drag is three posts 50 ms apart plus a 100 ms tail: about a quarter
        // of a second in which a hardware event aborts it. No person can hold
        // still for the second the idle gate requires and then move inside
        // that window on cue. So the probe does the timing: from NOW it issues
        // drags back to back for this long while the operator starts moving
        // about a second in. The first hardware event then lands in one of
        // three places -- mid-sequence (the abort this arm wants), in the tail
        // (clears the carry), or between drags (the next one refuses
        // not_idle). Five rounds; one hit is a measurement.
        const BURST: Duration = Duration::from_secs(6);
        const ROUNDS: u32 = 5;

        let mut aborts = 0u32;
        let mut evidence = Vec::new();

        for round in 1..=ROUNDS {
            countdown(&format!(
                "round {round} of {ROUNDS}: after now, wait one second, then move the mouse \
                 for three seconds"
            ));
            let burst_started = std::time::Instant::now();
            let (mut completed, mut refused_not_idle) = (0u32, 0u32);
            let seized = loop {
                if burst_started.elapsed() > BURST {
                    break None;
                }
                if let Err(reason) = wire.take_once_lease().await {
                    return Arm::unmeasurable(ONE, ONE_NAME, reason);
                }
                let before = match journal_entries() {
                    Ok(entries) => entries,
                    Err(reason) => return Arm::unmeasurable(ONE, ONE_NAME, reason),
                };
                let reply = match wire
                    .tool_call(
                        "computer.drag",
                        json!({
                            "from": "400,400",
                            "to": "520,460",
                            "button": "left",
                            "modifiers": [],
                        }),
                    )
                    .await
                {
                    Ok(reply) => reply,
                    Err(reason) => return Arm::unmeasurable(ONE, ONE_NAME, reason),
                };
                match reply["outcome"].as_str() {
                    Some("user_seized_control") => break Some(before),
                    Some("not_idle") => refused_not_idle += 1,
                    Some("completed") => completed += 1,
                    other => {
                        evidence.push(format!("round {round}: answered {other:?}"));
                        break None;
                    }
                }
            };
            // The window runs its full length whether or not an abort was
            // caught, and ends with a spoken "stop": a round that ended the
            // moment it caught something made the gap after "now" vary
            // between two and ten seconds, and the operator could not tell
            // when a round was over.
            sleep(BURST.saturating_sub(burst_started.elapsed())).await;
            speak("stop");
            sleep(Duration::from_secs(3)).await;
            let Some(before) = seized else {
                evidence.push(format!(
                    "round {round}: no abort within {}s ({completed} completed, \
                     {refused_not_idle} refused not_idle)",
                    BURST.as_secs()
                ));
                continue;
            };
            let record = match settled_record(&before, "computer.drag") {
                Ok(record) => record,
                Err(reason) => return Arm::unmeasurable(ONE, ONE_NAME, reason),
            };
            let Some(abort) = record.abort.as_ref() else {
                return Arm::fail(
                    ONE,
                    ONE_NAME,
                    format!(
                        "round {round}: the wire said user_seized_control but the journal \
                         record carries no abort"
                    ),
                );
            };
            let source = abort
                .get("sourced_input_kind")
                .and_then(|kind| kind.get("source"))
                .and_then(Value::as_str)
                .unwrap_or("absent");
            if source != "hardware" {
                return Arm::fail(
                    ONE,
                    ONE_NAME,
                    format!(
                        "round {round}: the seizing source is {source:?}, not hardware -- \
                         something other than the person at the desk stopped this"
                    ),
                );
            }
            aborts += 1;
            evidence.push(format!(
                "round {round}: wire user_seized_control, source=hardware, \
                 detection_latency_ms={:?} (platform {:?}) (after {completed} completed drags)",
                abort.get("detection_latency_ms").and_then(Value::as_u64),
                abort
                    .get("platform_delivery_latency_ms")
                    .and_then(Value::as_u64)
            ));
        }

        if aborts == 0 {
            // No hardware event landed inside a sequence window this run: the
            // gate refused every drag the hand was already moving for, and the
            // drags that ran were over before it moved. That is the mechanism
            // never being reached, not failing, so the verdict is unmeasurable,
            // with the journal's earlier hardware-sourced aborts cited as the
            // attribution evidence.
            let prior = journal_entries().map_or(0, |entries| {
                entries
                    .values()
                    .filter_map(|entry| entry.get("abort"))
                    .filter(|abort| {
                        abort
                            .get("sourced_input_kind")
                            .and_then(|kind| kind.get("source"))
                            .and_then(Value::as_str)
                            == Some("hardware")
                    })
                    .count()
            });
            return Arm::unmeasurable(
                ONE,
                ONE_NAME,
                format!(
                    "no hardware event landed inside a sequence window in {ROUNDS} rounds ({}); \
                     the journal holds {prior} earlier hardware-sourced mid-sequence aborts \
                     from previous runs",
                    evidence.join("; ")
                ),
            );
        }
        Arm::pass(
            ONE,
            ONE_NAME,
            format!(
                "{aborts} of {ROUNDS} rounds aborted on hardware input; {}",
                evidence.join("; ")
            ),
        )
    }

    // ------------------------------------------------------------- the wire

    /// One authenticated connection carrying both routes.
    ///
    /// Both routes share a socket because the module's consent question comes
    /// back as a REQUEST on the management channel while a reply may still be
    /// outstanding elsewhere, so every read has to be demultiplexed anyway.
    struct Wire {
        stream: TcpStream,
        tool: (u16, u32),
        management: (u16, u32),
        next_corr: u64,
    }

    impl Wire {
        async fn open(explicit: Option<&Path>) -> Result<Self, String> {
            let discovered = connection_file::discover(explicit)
                .map_err(|error| format!("no daemon connection file: {error}"))?;
            let endpoint = discovered
                .info
                .endpoints
                .first()
                .ok_or_else(|| {
                    format!(
                        "connection file {} publishes no endpoint",
                        discovered.path.display()
                    )
                })?
                .clone();
            let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
                .await
                .map_err(|error| format!("connect {}:{}: {error}", endpoint.host, endpoint.port))?;
            authenticate_client(&mut stream, &discovered.info, Duration::from_secs(5))
                .await
                .map_err(|error| format!("authenticate: {error:?}"))?;
            println!("daemon: {}", discovered.path.display());

            let mut wire = Self {
                stream,
                tool: (0, 0),
                management: (0, 0),
                next_corr: 1,
            };
            wire.tool = wire
                .open_route(RouteTarget::ToolProvider {
                    module_id: MODULE_ID.to_string(),
                })
                .await?;
            wire.management = wire
                .open_route(RouteTarget::ManagementSurface {
                    module_id: MODULE_ID.to_string(),
                })
                .await?;
            Ok(wire)
        }

        fn corr(&mut self) -> u64 {
            let corr = self.next_corr;
            self.next_corr += 1;
            corr
        }

        async fn open_route(&mut self, target: RouteTarget) -> Result<(u16, u32), String> {
            // `consumer_capabilities` is read once, at bind, and never again:
            // a route that did not declare elicitation here can never be asked
            // a consent question, and every pointer action needs one.
            let request = ClientControlRequest::RouteOpen {
                target: target.clone(),
                identity: BindIdentity {
                    project_root: PathBuf::from("/tmp"),
                    harness: "live_global_cursor".to_string(),
                    session: "live-global-cursor-probe".to_string(),
                },
                consumer_identity: None,
                consumer_capabilities: Some(vec!["elicitation".to_string()]),
                admission_facts: None,
            };
            let corr = self.corr();
            let body = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
            let frame = Frame::build(
                FrameType::Request,
                cerebellum::control_flags(),
                0,
                0,
                corr,
                body,
            )
            .map_err(|error| format!("build route.open frame: {error}"))?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write route.open: {error:?}"))?;
            let reply = self.await_response(corr).await?;
            match serde_json::from_slice::<ClientControlResponse>(&reply.body) {
                Ok(ClientControlResponse::RouteOpen {
                    route_channel,
                    route_epoch,
                }) => Ok((route_channel, route_epoch)),
                Ok(other) => Err(format!("route.open for {target:?} answered {other:?}")),
                Err(error) => Err(format!(
                    "route.open reply did not parse: {error} ({})",
                    String::from_utf8_lossy(&reply.body)
                )),
            }
        }

        async fn catalogue_serves_pointer_capabilities(&mut self) -> Result<(), String> {
            let corr = self.corr();
            let request = ClientControlRequest::CatalogList {
                module_id: Some(MODULE_ID.to_string()),
            };
            let body = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
            let frame = Frame::build(
                FrameType::Request,
                cerebellum::control_flags(),
                0,
                0,
                corr,
                body,
            )
            .map_err(|error| format!("build catalog.list frame: {error}"))?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write catalog.list: {error:?}"))?;
            let reply = self.await_response(corr).await?;
            let response: ClientControlResponse = serde_json::from_slice(&reply.body)
                .map_err(|error| format!("catalog.list reply did not parse: {error}"))?;
            let ClientControlResponse::CatalogList { modules, .. } = response else {
                return Err("the daemon answered catalog.list with something else".to_string());
            };
            let entry = modules
                .iter()
                .find(|module| module.module_id == MODULE_ID)
                .ok_or_else(|| format!("{MODULE_ID} is not in the daemon's catalogue"))?;
            let mut served = Vec::new();
            for role in &entry.roles {
                if let ProviderRole::ToolProvider { tools, .. } = role {
                    served.extend(tools.iter().map(|tool| tool.name.clone()));
                }
            }
            let missing: Vec<_> = ["computer.move", "computer.scroll", "computer.drag"]
                .into_iter()
                .filter(|wanted| !served.iter().any(|name| name == wanted))
                .collect();
            if missing.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "the daemon's catalogue for {MODULE_ID} does not advertise {missing:?}; \
                     the running module was built without \
                     CEREBELLUM_GLOBAL_DISPATCH_REVIEW_REVISION set, which withholds these \
                     capabilities"
                ))
            }
        }

        /// Take a Once lease and then run one pointer action with it.
        async fn pointer_action(
            &mut self,
            capability: &str,
            arguments: Value,
        ) -> Result<Value, String> {
            self.take_once_lease().await?;
            self.tool_call(capability, arguments).await
        }

        async fn tool_call(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
            let (channel, epoch) = self.tool;
            let corr = self.corr();
            self.send(
                channel,
                epoch,
                corr,
                json!({"name": name, "arguments": arguments}),
            )
            .await?;
            let reply = self.await_response(corr).await?;
            serde_json::from_slice(&reply.body)
                .map_err(|error| format!("{name} reply did not parse: {error}"))
        }

        async fn management_call(&mut self, method: &str, params: Value) -> Result<Value, String> {
            let (channel, epoch) = self.management;
            let corr = self.corr();
            self.send(
                channel,
                epoch,
                corr,
                json!({"method": method, "params": params}),
            )
            .await?;
            let reply = self.await_response(corr).await?;
            serde_json::from_slice(&reply.body)
                .map_err(|error| format!("{method} reply did not parse: {error}"))
        }

        /// Ask for the target, answer the consent question, and wait until the
        /// lease is actually live.
        ///
        /// Every pointer action consumes the Once lease, so this runs before
        /// each one. Readiness is POLLED rather than slept off: the answer is
        /// settled on another task inside the module, and a fixed sleep either
        /// wastes time or races it. `already_held` is the module's own word for
        /// a live lease, so it is the signal used.
        async fn take_once_lease(&mut self) -> Result<(), String> {
            let params = json!({
                "bundle_identity": TARGET_BUNDLE,
                "action_kind": "mutate_durable",
            });
            let reply = self
                .management_call("computer.open_target", params.clone())
                .await?;
            match reply["outcome"].as_str() {
                Some("already_held") => return Ok(()),
                Some("consent_pending") => {}
                _ => {
                    return Err(format!(
                        "computer.open_target for {TARGET_BUNDLE} answered {reply}"
                    ))
                }
            }
            // The question arrives as a reverse request on the management
            // channel; `await_response` answers any it meets while waiting.
            for _ in 0..LEASE_POLL_ATTEMPTS {
                sleep(LEASE_POLL_INTERVAL).await;
                let reply = self
                    .management_call("computer.open_target", params.clone())
                    .await?;
                match reply["outcome"].as_str() {
                    Some("already_held") => return Ok(()),
                    Some("consent_pending") => continue,
                    _ => {
                        return Err(format!(
                            "computer.open_target for {TARGET_BUNDLE} answered {reply} while \
                             waiting for the lease"
                        ))
                    }
                }
            }
            Err(format!(
                "no Once lease for {TARGET_BUNDLE} became live within {}ms of answering the \
                 consent question",
                LEASE_POLL_ATTEMPTS as u64 * LEASE_POLL_INTERVAL.as_millis() as u64
            ))
        }

        async fn send(
            &mut self,
            channel: u16,
            epoch: u32,
            corr: u64,
            body: Value,
        ) -> Result<(), String> {
            trace(&format!(
                "-> request ch={channel} corr={corr} {}",
                body["name"]
                    .as_str()
                    .or(body["method"].as_str())
                    .unwrap_or("?")
            ));
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                channel,
                epoch,
                corr,
                serde_json::to_vec(&body).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("build request frame: {error}"))?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write request: {error:?}"))
        }

        /// Read until the reply to `corr` arrives, answering consent questions
        /// on the way.
        ///
        /// The module's question is a Request frame travelling in the same
        /// direction as its replies, so a reader that only waited for a
        /// Response would deadlock: the lease is never granted, and the answer
        /// the probe is waiting for never comes.
        async fn await_response(&mut self, corr: u64) -> Result<Frame, String> {
            loop {
                let frame = match timeout(REPLY_TIMEOUT, read_frame(&mut self.stream)).await {
                    Ok(Ok(Some(frame))) => {
                        trace(&format!(
                            "<- {:?} ch={} corr={} {} bytes",
                            frame.header.ty,
                            frame.header.channel,
                            frame.header.corr,
                            frame.body.len()
                        ));
                        frame
                    }
                    Ok(Ok(None)) => return Err("the daemon closed the connection".to_string()),
                    Ok(Err(error)) => return Err(format!("read frame: {error:?}")),
                    Err(_) => {
                        return Err(format!(
                            "no reply to correlation {corr} within {}s",
                            REPLY_TIMEOUT.as_secs()
                        ))
                    }
                };
                if frame.header.ty == FrameType::Request {
                    self.answer_question(&frame).await?;
                    continue;
                }
                if frame.header.corr == corr {
                    return Ok(frame);
                }
                // A reply to something already abandoned. Dropped rather than
                // treated as an error: a late answer is not a protocol fault.
            }
        }

        async fn answer_question(&mut self, question: &Frame) -> Result<(), String> {
            let body: Value = serde_json::from_slice(&question.body)
                .map_err(|error| format!("a reverse request did not parse: {error}"))?;
            if body["method"] != json!("elicitation/create") {
                return Err(format!(
                    "the module sent an unexpected reverse request: {body}"
                ));
            }
            // Answered on the SAME correlation the question arrived on. The
            // `id` in the body is the module's ask identifier and is not the
            // frame correlation; answering on that would reach nobody.
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                question.header.channel,
                question.header.epoch,
                question.header.corr,
                serde_json::to_vec(&json!({"decision": "allow_once"}))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("build consent answer frame: {error}"))?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write consent answer: {error:?}"))
        }
    }

    // ----------------------------------------------------------- the record

    /// One settled audit record, reduced to what the arms assert.
    struct Record {
        containment_rung: String,
        tier: Option<u64>,
        outcome: String,
        abort: Option<Value>,
    }

    impl Record {
        fn abort_reason(&self) -> Option<String> {
            let reason = self.abort.as_ref()?.get("reason")?;
            // `reason` is a bare string for the simple stops and a single-key
            // object for the idle refusal, which carries its numbers.
            match reason {
                Value::String(text) => Some(text.clone()),
                Value::Object(map) => map.keys().next().cloned(),
                _ => None,
            }
        }

        /// The observed idle reading and the threshold it was compared against.
        fn idle_numbers(&self) -> Option<(u64, u64)> {
            let refusal = self
                .abort
                .as_ref()?
                .get("reason")?
                .get("idle_gate_refused")?;
            Some((
                refusal
                    .get("hid_idle_ms")
                    .or_else(|| refusal.get("observed_ms"))?
                    .as_u64()?,
                refusal.get("threshold_ms")?.as_u64()?,
            ))
        }
    }

    /// The journal's entries, keyed by sequence.
    ///
    /// Read straight off disk rather than through the audit binding: opening
    /// the binding RECONCILES, which writes, and an instrument that edits the
    /// records it is reporting on is not an instrument.
    fn journal_entries() -> Result<BTreeMap<u64, Value>, String> {
        let path = cerebellum_core::journal::journal_data_path("computer.json")
            .map_err(|error| format!("the journal path did not resolve: {error:?}"))?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            // No journal yet is a legitimate starting state: the first
            // dispatch creates it.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(format!("could not read {}: {error}", path.display())),
        };
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{} did not parse: {error}", path.display()))?;
        let entries = document["state"]["entries"]
            .as_object()
            .ok_or_else(|| format!("{} has no state.entries object", path.display()))?;
        let mut parsed = BTreeMap::new();
        for (sequence, entry) in entries {
            let Ok(sequence) = sequence.parse::<u64>() else {
                continue;
            };
            parsed.insert(sequence, entry.clone());
        }
        Ok(parsed)
    }

    /// The record this capability settled after `before` was taken.
    ///
    /// Matched by sequence rather than by time: the entries carry no timestamp,
    /// and the highest new sequence for the capability is unambiguous even when
    /// something else on the desk journals in between.
    fn settled_record(before: &BTreeMap<u64, Value>, capability: &str) -> Result<Record, String> {
        let wanted = capability
            .strip_prefix("computer.")
            .ok_or_else(|| format!("{capability} is not a computer capability"))?;
        let after = journal_entries()?;
        let mut candidates: Vec<_> = after
            .iter()
            .filter(|(sequence, _)| !before.contains_key(*sequence))
            .collect();
        candidates.sort_by_key(|(sequence, _)| **sequence);
        for (sequence, entry) in candidates.into_iter().rev() {
            let descriptor = decode_base64_json(entry, "invocation_descriptor")
                .map_err(|reason| format!("entry {sequence}: {reason}"))?;
            if descriptor["capability"] != json!(wanted) {
                continue;
            }
            let record = decode_base64_json(entry, "bytes")
                .map_err(|reason| format!("entry {sequence}: {reason}"))?;
            let completed = record["completed_result"]
                .as_array()
                .ok_or_else(|| format!("entry {sequence} has no completed_result bytes"))?
                .iter()
                .map(|byte| byte.as_u64().map(|byte| byte as u8))
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(|| format!("entry {sequence} completed_result is not bytes"))?;
            let outcome: Value = serde_json::from_slice(&completed).map_err(|error| {
                format!("entry {sequence} completed_result did not parse: {error}")
            })?;
            return Ok(Record {
                containment_rung: descriptor["containment_rung"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                tier: entry["severity"]["tier"].as_u64(),
                outcome: outcome["outcome"].as_str().unwrap_or_default().to_string(),
                abort: outcome.get("abort").cloned(),
            });
        }
        Err(format!(
            "no new journal record for {capability}; the module may be writing its journal \
             under a different data home than this probe reads"
        ))
    }

    fn decode_base64_json(entry: &Value, field: &str) -> Result<Value, String> {
        let text = entry[field]
            .as_str()
            .ok_or_else(|| format!("{field} is not a base64 string"))?;
        let bytes = cerebellum_core::serde_base64::decode(text)
            .map_err(|reason| format!("{field} did not decode: {reason}"))?;
        serde_json::from_slice(&bytes).map_err(|error| format!("{field} is not JSON: {error}"))
    }

    // ------------------------------------------------------------- the desk

    /// Bring an application to the front of the GUI session.
    ///
    /// `open -a` rather than anything in-process: this probe normally runs over
    /// SSH as the console user, and `open` hands the request to the window
    /// server's session instead of to this terminal's. A global post is only
    /// delivered to the application that holds the front, so this is a
    /// precondition of every arm and not a convenience.
    fn front(app: &str) -> Result<(), String> {
        let status = Command::new("open")
            .arg("-a")
            .arg(app)
            .status()
            .map_err(|error| format!("could not run `open -a {app}`: {error}"))?;
        if !status.success() {
            return Err(format!(
                "`open -a {app}` exited {status}; the application could not be brought to the \
                 front, so no global post would be delivered to it"
            ));
        }
        // Activation is asynchronous, so the call returning is not the window
        // being frontmost.
        std::thread::sleep(Duration::from_millis(900));
        Ok(())
    }

    /// Ten seconds of warning, then the word the operator is waiting for.
    ///
    /// Announced in TWO places: this process's stdout, and the speaker of the
    /// session under test through `say`. The probe is normally driven over SSH,
    /// where the operator at the VM window cannot see stdout; speech needs no
    /// permission and posts no input event, so it cannot itself trip the idle
    /// gate the arm is measuring. (AppleScript into TextEdit was tried first
    /// and blocks on an Automation consent prompt nobody can answer from SSH.)
    ///
    /// Two short utterances only, each spoken to completion: "get ready" and
    /// "now". Spoken digits overlap one another (a word takes longer than the
    /// second it marks), and a spoken instruction with numbers in it
    /// ("wait one second, then three seconds, ten seconds") was heard as
    /// noise. What to do at "now" is told to the operator ONCE, before the
    /// run, and is the same for every cue: wait a second, then move the
    /// mouse for a few seconds. The seconds are printed for the SSH reader.
    fn countdown(instruction: &str) {
        println!();
        println!("{instruction}");
        speak("get ready");
        for remaining in (1..=10).rev() {
            println!("  {remaining}...");
            std::thread::sleep(Duration::from_secs(1));
        }
        println!("  NOW");
        speak("now");
    }

    /// Spoken to completion so two calls never overlap. A failure to speak
    /// changes nothing about the arm.
    fn speak(text: &str) {
        let _ = std::process::Command::new("/usr/bin/say")
            .arg(text)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}
