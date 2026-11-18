//! Census of the processes a launched Chrome spawns, and of which of them
//! outlive the browser once it is torn down.
//!
//! The question: can a renderer, the GPU process, the network service, a
//! utility helper, or `chrome_crashpad_handler` survive the browser this
//! module launched? Each run launches Chrome the way production does
//! (production's own argument and environment builders, the same suspended
//! spawn with the CDP pipe on descriptors 3 and 4, a background page target),
//! records every process that belongs to it, tears it down with one of the
//! two arms production has, and then looks for survivors.
//!
//! The two teardown arms, as production runs them:
//!
//! - graceful: `Browser.close` written over the CDP pipe
//!   (`NavigationDriver::request_browser_close`), then a bounded wait for the
//!   main process to exit (`termination_grace_period_ms`), escalating to the
//!   kill below only if it has not (`teardown_process_with_grace`);
//! - kill: SIGKILL of the main browser pid alone, after a start-time check
//!   (`ReleasedChild::terminate_and_reap` in cerebellum-macos), which is what
//!   the escalation and every force-terminate path call.
//!
//! A survivor is a census member still alive with the SAME pid and kernel
//! start time 2 s and 10 s after the main process was reaped, so a recycled
//! pid cannot be mistaken for one.
//!
//! An empty survivor list is only evidence if the probe can see a survivor at
//! all, so control runs first plant a process that neither arm can reach and
//! require the survivor list to be exactly that process.
//!
//! Only throwaway profiles under `/tmp` are used; the agent profiles and the
//! data home are never opened. `$TMPDIR` is avoided on purpose: on macOS 27,
//! executing from under it can stall in system policy evaluation.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p cerebellum --example helper_census [-- /path/to/Chrome]
//! ```
//!
//! With no argument the executable comes from `browser.executable_path` in the
//! module's config file.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe counts macOS Chrome helper processes and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(census::run());
}

// The CDP pipe client, shared with the `crashpad_census` example, which
// launches Chrome the same way this probe does.
#[cfg(target_os = "macos")]
#[path = "support/cdp_pipe.rs"]
mod cdp_pipe;

#[cfg(target_os = "macos")]
mod census {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use cerebellum::browser_crash_reports::CrashReportDirectory;
    use cerebellum::browser_launch_service::{
        browser_launch_arguments, browser_launch_environment,
    };
    use cerebellum_macos::{process_start_time, ProcessGeneration, ProcessStartTime};
    use serde_json::json;

    use crate::cdp_pipe::Cdp;

    /// How long a page is left open before the census, so the helpers Chrome
    /// starts lazily (GPU, network, storage, audio) have appeared.
    const SETTLE: Duration = Duration::from_secs(3);
    const FIRST_LOOK: Duration = Duration::from_secs(2);
    const SECOND_LOOK: Duration = Duration::from_secs(10);
    const RUNS_PER_CELL: usize = 2;
    /// A page whose renderer never yields. It is the realistic candidate for a
    /// helper that misses its parent dying, because its main thread never
    /// returns to the message loop that would notice.
    const BUSY_PAGE: &str = "data:text/html,<title>busy</title><script>for(;;){}</script>";
    const IDLE_PAGE: &str = "data:text/html,<title>idle</title><p>idle</p>";

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Arm {
        BrowserClose,
        KillMain,
    }

    impl Arm {
        fn label(self) -> &'static str {
            match self {
                Arm::BrowserClose => "Browser.close",
                Arm::KillMain => "SIGKILL main",
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Page {
        Idle,
        Busy,
    }

    impl Page {
        fn label(self) -> &'static str {
            match self {
                Page::Idle => "idle",
                Page::Busy => "busy",
            }
        }

        fn url(self) -> &'static str {
            match self {
                Page::Idle => IDLE_PAGE,
                Page::Busy => BUSY_PAGE,
            }
        }
    }

    #[derive(Clone, Copy)]
    struct RunSpec {
        number: usize,
        arm: Arm,
        page: Page,
        control: bool,
    }

    impl RunSpec {
        fn label(&self) -> String {
            format!(
                "run {:02} [{}{} / {}]",
                self.number,
                if self.control { "CONTROL " } else { "" },
                self.arm.label(),
                self.page.label()
            )
        }
    }

    #[derive(Clone)]
    struct Member {
        pid: u32,
        start_time_micros: u64,
        kind: String,
        /// `ps`'s recent CPU share, recorded so a busy-page run can show its
        /// renderer really was spinning rather than assume it.
        cpu_percent: f32,
    }

    struct Observation {
        spec: RunSpec,
        census: Vec<Member>,
        teardown: String,
        planted: Option<Member>,
        survivors_first: Vec<Member>,
        survivors_second: Vec<Member>,
        late_arrivals: Vec<Member>,
        cleanup_problems: Vec<String>,
    }

    struct Precondition(String);

    pub fn run() -> i32 {
        let overall = Instant::now();
        let setup = match preconditions() {
            Ok(setup) => setup,
            Err(Precondition(reason)) => {
                println!("VERDICT: PRECONDITION FAILED -- {reason}. Nothing was measured.");
                return 2;
            }
        };
        println!("executable: {}", setup.executable.display());
        println!("macOS: {}", setup.macos_version);
        println!(
            "grace period (from config or default): {} ms",
            setup.grace.as_millis()
        );

        // Controls first: until the probe has shown it can see a survivor, an
        // empty survivor list says nothing about Chrome.
        let mut specs = Vec::new();
        let mut number = 1;
        for arm in [Arm::BrowserClose, Arm::KillMain] {
            specs.push(RunSpec {
                number,
                arm,
                page: Page::Idle,
                control: true,
            });
            number += 1;
        }
        for arm in [Arm::BrowserClose, Arm::KillMain] {
            for page in [Page::Idle, Page::Busy] {
                for _ in 0..RUNS_PER_CELL {
                    specs.push(RunSpec {
                        number,
                        arm,
                        page,
                        control: false,
                    });
                    number += 1;
                }
            }
        }

        // Each run's survivor watch runs on its own thread while the next run
        // launches. Survivors are identified by exact (pid, start time), and
        // every run has its own root, so overlapping runs cannot claim each
        // other's processes; overlapping keeps the whole census inside the
        // time an operator's desk can spare.
        let mut watches: Vec<JoinHandle<Observation>> = Vec::new();
        let mut chrome_version = None;
        let mut failures = Vec::new();
        for spec in specs {
            match launch_and_tear_down(spec, &setup) {
                Ok((watch, version)) => {
                    chrome_version.get_or_insert(version);
                    watches.push(watch);
                }
                Err(reason) => {
                    println!("{}: RUN FAILED -- {reason}", spec.label());
                    failures.push(format!("{}: {reason}", spec.label()));
                }
            }
        }
        let observations: Vec<Observation> = watches
            .into_iter()
            .map(|watch| watch.join().expect("a survivor watch does not panic"))
            .collect();

        println!();
        println!(
            "Chrome: {}",
            chrome_version
                .as_deref()
                .unwrap_or("<no run reached the browser>")
        );
        println!("macOS: {}", setup.macos_version);
        for observation in &observations {
            print_observation(observation);
        }
        print_table(&observations);
        println!("total wall time: {:.1} s", overall.elapsed().as_secs_f64());
        verdict(&observations, &failures)
    }

    struct Setup {
        executable: PathBuf,
        grace: Duration,
        handshake: Duration,
        macos_version: String,
    }

    fn preconditions() -> Result<Setup, Precondition> {
        let executable = std::env::args_os()
            .nth(1)
            .map(PathBuf::from)
            .ok_or_else(|| {
                Precondition("pass the browser executable as the first argument".into())
            })?;
        if !executable.is_absolute() || !executable.is_file() {
            return Err(Precondition(format!(
                "the browser executable {} does not exist",
                executable.display()
            )));
        }
        // With the session locked, the page window would open into a session
        // nobody is using, which is not the condition this census describes.
        // Refused rather than measured.
        match cerebellum_macos::screen_is_locked() {
            Some(false) => {}
            Some(true) => {
                return Err(Precondition(
                    "the screen is locked; unlock it and rerun".to_string(),
                ))
            }
            None => {
                return Err(Precondition(
                    "no window-server session could be read (is this a GUI login?)".to_string(),
                ))
            }
        }
        let grace = Duration::from_millis(5_000);
        let handshake = Duration::from_millis(10_000);
        Ok(Setup {
            executable,
            grace,
            handshake,
            macos_version: macos_version(),
        })
    }

    fn macos_version() -> String {
        let read = |flag: &str| {
            Command::new("/usr/bin/sw_vers")
                .arg(flag)
                .output()
                .ok()
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                .unwrap_or_else(|| "?".to_string())
        };
        format!("{} ({})", read("-productVersion"), read("-buildVersion"))
    }

    /// Launch, census, and tear down one browser, then hand the survivor
    /// watch to a thread. Returns the watch and the browser's version string.
    fn launch_and_tear_down(
        spec: RunSpec,
        setup: &Setup,
    ) -> Result<(JoinHandle<Observation>, String), String> {
        let root = PathBuf::from(format!(
            "/tmp/ck-helper-census-{}-{:02}",
            std::process::id(),
            spec.number
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root)
            .map_err(|error| format!("creating {}: {error}", root.display()))?;
        // Production's own crash-report directory, made the way a launch
        // makes it; a failed launch drops it, which deletes it.
        let crash_reports = match CrashReportDirectory::create() {
            Ok(crash_reports) => crash_reports,
            Err(refusal) => {
                let _ = std::fs::remove_dir_all(&root);
                return Err(format!(
                    "production refused the crash-report directory: {}",
                    refusal.reason_code()
                ));
            }
        };
        let result = launch_in(spec, setup, &root, crash_reports);
        if result.is_err() {
            // The launch failed before a watch owned the root, so nothing else
            // will remove it. Any process that did start is still found by
            // its argv naming the root, and is killed here.
            for member in processes_naming(&root) {
                kill_exact(&member);
            }
            let _ = std::fs::remove_dir_all(&root);
        }
        result
    }

    fn launch_in(
        spec: RunSpec,
        setup: &Setup,
        root: &Path,
        crash_reports: CrashReportDirectory,
    ) -> Result<(JoinHandle<Observation>, String), String> {
        let profile = root.join("profile");
        let crash_dumps = root.join("crash-dumps");
        // Production's own builders, not a copy of them: a probe whose launch
        // drifts from production measures a browser nobody runs.
        let arguments = browser_launch_arguments(&profile, &crash_dumps);
        let environment = browser_launch_environment(&profile, &crash_reports);

        // The same descriptor layout production sets up: the child reads
        // commands from one socket pair and writes responses into another,
        // and the spawn maps those ends onto descriptors 3 and 4.
        let (command_child, command_parent) =
            UnixStream::pair().map_err(|error| format!("command pipe: {error}"))?;
        let (response_parent, response_child) =
            UnixStream::pair().map_err(|error| format!("response pipe: {error}"))?;
        let barred = cerebellum_macos::spawn_barred(
            &setup.executable,
            &arguments,
            &environment,
            command_child.as_raw_fd(),
            response_child.as_raw_fd(),
        )
        .map_err(|error| format!("spawn: {error:?}"))?;
        drop(command_child);
        drop(response_child);
        // Production verifies the signed image identity between spawn and
        // release. That check decides WHETHER to run the browser and cannot
        // change which helpers it later starts, so it is not repeated here.
        let released = barred
            .release()
            .map_err(|error| format!("release: {error:?}"))?;
        let main = released.generation();
        let mut cdp = Cdp::new(command_parent, response_parent);

        let deadline = Instant::now() + setup.handshake;
        let version = cdp
            .call("Browser.getVersion", json!({}), deadline)
            .map_err(|error| format!("handshake: {error}"))?;
        let product = version["product"].as_str().unwrap_or("?").to_string();

        let planted = if spec.control {
            Some(plant_unreachable_process(root)?)
        } else {
            None
        };

        // A background target, as navigation creates it, so the page opens
        // without taking focus from whatever the operator is doing.
        let created = cdp
            .call(
                "Target.createTarget",
                json!({"url": spec.page.url(), "background": true}),
                Instant::now() + setup.handshake,
            )
            .map_err(|error| format!("createTarget: {error}"))?;
        if created["targetId"].as_str().is_none() {
            return Err(format!(
                "createTarget answered without a targetId: {created}"
            ));
        }
        std::thread::sleep(SETTLE);

        let census = take_census(main, root, crash_reports.path());
        if !census.iter().any(|member| member.kind == "renderer") {
            return Err(format!(
                "no renderer was running after {} s, so this run would measure nothing \
                 (census: {})",
                SETTLE.as_secs(),
                describe(&census)
            ));
        }
        if let Some(planted) = &planted {
            // Checked here, immediately before teardown: a planted process
            // that already exited would make the control vacuous.
            if !is_alive(planted) {
                return Err("the planted control process was not running before teardown".into());
            }
            if !census.iter().any(|member| member.pid == planted.pid) {
                return Err("the census did not find the planted control process".into());
            }
        }

        let teardown = tear_down(spec.arm, released, &mut cdp, setup.grace)?;
        drop(cdp);
        let torn_down_at = Instant::now();
        let root = root.to_path_buf();
        let watch = std::thread::spawn(move || {
            watch_for_survivors(
                spec,
                census,
                teardown,
                planted,
                root,
                crash_reports,
                torn_down_at,
            )
        });
        Ok((watch, product))
    }

    /// Plant a process no teardown can reach: not a descendant of the browser,
    /// reparented to launchd the way `chrome_crashpad_handler` is, and naming
    /// the throwaway root in its argv the way crashpad does. `sleep` rejects
    /// extra operands and exits at once, so the root goes into argv[0]
    /// instead: the executable is a symlink inside the root.
    fn plant_unreachable_process(root: &Path) -> Result<Member, String> {
        let link = root.join("planted-control-sleep");
        std::os::unix::fs::symlink("/bin/sleep", &link)
            .map_err(|error| format!("planting control: {error}"))?;
        // The shell backgrounds sleep and exits, so sleep's parent becomes
        // launchd rather than this probe.
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg("\"$0\" 600 </dev/null >/dev/null 2>&1 & echo $!")
            .arg(&link)
            .output()
            .map_err(|error| format!("planting control: {error}"))?;
        let pid: u32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .map_err(|_| "planting control: the shell did not report a pid".to_string())?;
        std::thread::sleep(Duration::from_millis(200));
        match process_start_time(pid) {
            ProcessStartTime::Started(start_time_micros) => Ok(Member {
                pid,
                start_time_micros,
                kind: "planted-control".to_string(),
                cpu_percent: 0.0,
            }),
            other => Err(format!(
                "planted control pid {pid} is not running: {other:?}"
            )),
        }
    }

    fn tear_down(
        arm: Arm,
        released: cerebellum_macos::ReleasedChild,
        cdp: &mut Cdp,
        grace: Duration,
    ) -> Result<String, String> {
        let generation = released.generation();
        let started = Instant::now();
        match arm {
            Arm::BrowserClose => {
                cdp.send("Browser.close", json!({}))
                    .map_err(|error| format!("Browser.close: {error}"))?;
                // The same observation production waits on: the recorded
                // generation no longer answering with its start time.
                let deadline = started + grace;
                while Instant::now() < deadline {
                    if !generation_matches(generation) {
                        released
                            .wait()
                            .map_err(|error| format!("reap after close: {error:?}"))?;
                        return Ok(format!(
                            "exited on Browser.close after {} ms",
                            started.elapsed().as_millis()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                released
                    .terminate_and_reap()
                    .map_err(|error| format!("escalated kill: {error:?}"))?;
                Ok(format!(
                    "did not exit within {} ms; ESCALATED to SIGKILL",
                    grace.as_millis()
                ))
            }
            Arm::KillMain => {
                released
                    .terminate_and_reap()
                    .map_err(|error| format!("kill: {error:?}"))?;
                Ok(format!(
                    "SIGKILL of main pid, reaped after {} ms",
                    started.elapsed().as_millis()
                ))
            }
        }
    }

    fn watch_for_survivors(
        spec: RunSpec,
        census: Vec<Member>,
        teardown: String,
        planted: Option<Member>,
        root: PathBuf,
        crash_reports: CrashReportDirectory,
        torn_down_at: Instant,
    ) -> Observation {
        sleep_until(torn_down_at + FIRST_LOOK);
        let survivors_first: Vec<Member> = census.iter().filter(|m| is_alive(m)).cloned().collect();
        sleep_until(torn_down_at + SECOND_LOOK);
        let survivors_second: Vec<Member> =
            census.iter().filter(|m| is_alive(m)).cloned().collect();
        // Not survivors -- they were not there before teardown -- but a
        // process that STARTS after teardown and names the root would be just
        // as much a leak, and would be missed by the census alone.
        let census_pids: BTreeSet<(u32, u64)> = census
            .iter()
            .map(|member| (member.pid, member.start_time_micros))
            .collect();
        // The crash handler names the per-launch crash-report directory rather
        // than the root, so both are looked for.
        let mut late_arrivals: Vec<Member> = Vec::new();
        for member in processes_naming(&root)
            .into_iter()
            .chain(processes_naming(crash_reports.path()))
        {
            let key = (member.pid, member.start_time_micros);
            if !census_pids.contains(&key)
                && !late_arrivals
                    .iter()
                    .any(|seen| (seen.pid, seen.start_time_micros) == key)
            {
                late_arrivals.push(member);
            }
        }

        let mut cleanup_problems = Vec::new();
        for member in survivors_second.iter().chain(&late_arrivals) {
            kill_exact(member);
        }
        std::thread::sleep(Duration::from_millis(300));
        for member in survivors_second.iter().chain(&late_arrivals) {
            if is_alive(member) {
                cleanup_problems.push(format!(
                    "pid {} ({}) still alive after SIGKILL",
                    member.pid, member.kind
                ));
            }
        }
        if let Err(error) = std::fs::remove_dir_all(&root) {
            cleanup_problems.push(format!("removing {}: {error}", root.display()));
        }
        let crash_reports_path = crash_reports.path().to_path_buf();
        if let Err(error) = crash_reports.remove() {
            cleanup_problems.push(format!(
                "removing {}: {error}",
                crash_reports_path.display()
            ));
        }
        Observation {
            spec,
            census,
            teardown,
            planted,
            survivors_first,
            survivors_second,
            late_arrivals,
            cleanup_problems,
        }
    }

    fn sleep_until(moment: Instant) {
        let now = Instant::now();
        if moment > now {
            std::thread::sleep(moment - now);
        }
    }

    fn generation_matches(generation: ProcessGeneration) -> bool {
        matches!(
            process_start_time(generation.pid),
            ProcessStartTime::Started(start) if start == generation.start_time_micros
        )
    }

    fn is_alive(member: &Member) -> bool {
        generation_matches(ProcessGeneration {
            pid: member.pid,
            start_time_micros: member.start_time_micros,
        })
    }

    fn kill_exact(member: &Member) {
        let _ = cerebellum_macos::terminate_exact_generation(ProcessGeneration {
            pid: member.pid,
            start_time_micros: member.start_time_micros,
        });
    }

    struct Listed {
        ppid: u32,
        cpu_percent: f32,
        args: String,
    }

    /// Every process visible to this user, with its full argv. `ps` rather
    /// than a sysctl walk, because this probe lives outside the one crate
    /// allowed raw system calls and `ps -ww` already reports untruncated argv.
    fn process_table() -> BTreeMap<u32, Listed> {
        let Ok(output) = Command::new("/bin/ps")
            .args(["-axww", "-o", "pid=,ppid=,%cpu=,args="])
            .output()
        else {
            return BTreeMap::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let pid = fields.next()?.parse().ok()?;
                let ppid = fields.next()?.parse().ok()?;
                let cpu_percent = fields.next()?.parse().ok()?;
                let args = fields.collect::<Vec<_>>().join(" ");
                Some((
                    pid,
                    Listed {
                        ppid,
                        cpu_percent,
                        args,
                    },
                ))
            })
            .collect()
    }

    /// The browser's whole subtree plus every process whose argv names the
    /// root. The second half is what catches `chrome_crashpad_handler`, which
    /// double-forks away from the browser and is parented by launchd.
    /// The browser's descendants, and every process whose argv names the root
    /// or the per-launch crash-report directory: the crash handler is
    /// reparented to launchd and names the latter.
    fn take_census(main: ProcessGeneration, root: &Path, crash_reports: &Path) -> Vec<Member> {
        let table = process_table();
        let root_text = root.to_string_lossy().to_string();
        let crash_reports_text = crash_reports.to_string_lossy().to_string();
        let mut selected = BTreeSet::new();
        let mut queue = VecDeque::from([main.pid]);
        while let Some(pid) = queue.pop_front() {
            if !selected.insert(pid) {
                continue;
            }
            queue.extend(
                table
                    .iter()
                    .filter(|(_, listed)| listed.ppid == pid)
                    .map(|(child, _)| *child),
            );
        }
        selected.extend(
            table
                .iter()
                .filter(|(_, listed)| {
                    listed.args.contains(&root_text) || listed.args.contains(&crash_reports_text)
                })
                .map(|(pid, _)| *pid),
        );
        selected
            .into_iter()
            .filter_map(|pid| {
                let listed = table.get(&pid)?;
                let ProcessStartTime::Started(start_time_micros) = process_start_time(pid) else {
                    return None;
                };
                Some(Member {
                    pid,
                    start_time_micros,
                    kind: kind_of(pid == main.pid, &listed.args),
                    cpu_percent: listed.cpu_percent,
                })
            })
            .collect()
    }

    fn processes_naming(root: &Path) -> Vec<Member> {
        let root_text = root.to_string_lossy().to_string();
        process_table()
            .into_iter()
            .filter(|(_, listed)| listed.args.contains(&root_text))
            .filter_map(|(pid, listed)| {
                let ProcessStartTime::Started(start_time_micros) = process_start_time(pid) else {
                    return None;
                };
                Some(Member {
                    pid,
                    start_time_micros,
                    kind: kind_of(false, &listed.args),
                    cpu_percent: listed.cpu_percent,
                })
            })
            .collect()
    }

    fn kind_of(is_main: bool, args: &str) -> String {
        if is_main {
            return "browser".to_string();
        }
        if args.contains("planted-control-sleep") {
            return "planted-control".to_string();
        }
        if args.contains("chrome_crashpad_handler") {
            return "crashpad".to_string();
        }
        let flag = |name: &str| {
            args.split_whitespace()
                .find_map(|word| word.strip_prefix(name))
                .map(str::to_string)
        };
        match (flag("--type="), flag("--utility-sub-type=")) {
            (Some(kind), Some(sub)) => format!("{kind}:{}", sub.trim_end_matches(".mojom")),
            (Some(kind), None) => kind,
            (None, _) => "other".to_string(),
        }
    }

    fn describe(members: &[Member]) -> String {
        if members.is_empty() {
            return "none".to_string();
        }
        members
            .iter()
            .map(|member| {
                format!(
                    "{}({}@{})",
                    member.kind, member.pid, member.start_time_micros
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn print_observation(observation: &Observation) {
        println!("{}", observation.spec.label());
        println!("  census size: {}", observation.census.len());
        println!("  census: {}", describe(&observation.census));
        let busiest_renderer = observation
            .census
            .iter()
            .filter(|member| member.kind == "renderer")
            .map(|member| member.cpu_percent)
            .fold(0.0_f32, f32::max);
        println!("  busiest renderer CPU at census: {busiest_renderer:.1}%");
        println!("  teardown: {}", observation.teardown);
        if let Some(planted) = &observation.planted {
            println!("  planted: {}", describe(std::slice::from_ref(planted)));
        }
        println!(
            "  survivors at 2 s: {}",
            describe(&observation.survivors_first)
        );
        println!(
            "  survivors at 10 s: {}",
            describe(&observation.survivors_second)
        );
        println!(
            "  new processes naming the root at 10 s: {}",
            describe(&observation.late_arrivals)
        );
        if !observation.cleanup_problems.is_empty() {
            println!(
                "  CLEANUP PROBLEMS: {}",
                observation.cleanup_problems.join("; ")
            );
        }
    }

    fn print_table(observations: &[Observation]) {
        println!();
        println!("| arm | page | runs | census sizes | survivors at 2 s | survivors at 10 s |");
        println!("|---|---|---|---|---|---|");
        let mut cells: BTreeMap<(bool, Arm, Page), Vec<&Observation>> = BTreeMap::new();
        for observation in observations {
            let spec = observation.spec;
            cells
                .entry((spec.control, spec.arm, spec.page))
                .or_default()
                .push(observation);
        }
        for ((control, arm, page), runs) in cells {
            let sizes = runs
                .iter()
                .map(|run| run.census.len().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let count = |pick: fn(&Observation) -> &Vec<Member>| {
                runs.iter()
                    .map(|run| {
                        let found = pick(run);
                        if found.is_empty() {
                            "0".to_string()
                        } else {
                            format!(
                                "{} ({})",
                                found.len(),
                                found
                                    .iter()
                                    .map(|member| member.kind.as_str())
                                    .collect::<Vec<_>>()
                                    .join("+")
                            )
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!(
                "| {}{} | {} | {} | {} | {} | {} |",
                if control { "CONTROL " } else { "" },
                arm.label(),
                page.label(),
                runs.len(),
                sizes,
                count(|run| &run.survivors_first),
                count(|run| &run.survivors_second)
            );
        }
    }

    fn verdict(observations: &[Observation], failures: &[String]) -> i32 {
        if !failures.is_empty() {
            println!(
                "VERDICT: INCOMPLETE -- {} run(s) failed: {}",
                failures.len(),
                failures.join(" | ")
            );
            return 1;
        }
        let cleanup: Vec<&String> = observations
            .iter()
            .flat_map(|observation| &observation.cleanup_problems)
            .collect();
        // A control proves the probe can see a survivor only if the survivor
        // list is EXACTLY the planted process at both looks: an extra member
        // would be a real survivor, a missing one a blind probe.
        let mut controls_by_arm = BTreeSet::new();
        for observation in observations.iter().filter(|o| o.spec.control) {
            let Some(planted) = &observation.planted else {
                println!("VERDICT: CONTROL FAILED -- a control run planted nothing");
                return 1;
            };
            let exactly_planted = |found: &Vec<Member>| {
                found.len() == 1
                    && found[0].pid == planted.pid
                    && found[0].start_time_micros == planted.start_time_micros
            };
            if !exactly_planted(&observation.survivors_first)
                || !exactly_planted(&observation.survivors_second)
            {
                println!(
                    "VERDICT: CONTROL FAILED -- {} saw {} at 2 s and {} at 10 s, where only \
                     the planted process should survive. The empty rows prove nothing.",
                    observation.spec.label(),
                    describe(&observation.survivors_first),
                    describe(&observation.survivors_second)
                );
                return 1;
            }
            controls_by_arm.insert(observation.spec.arm);
        }
        if controls_by_arm.len() != 2 {
            println!("VERDICT: CONTROL FAILED -- a control did not run under both arms");
            return 1;
        }
        let measured: Vec<&Observation> = observations.iter().filter(|o| !o.spec.control).collect();
        if measured.len() != 4 * RUNS_PER_CELL {
            println!(
                "VERDICT: INCOMPLETE -- {} measured runs, expected {}",
                measured.len(),
                4 * RUNS_PER_CELL
            );
            return 1;
        }
        let leaked: Vec<String> = measured
            .iter()
            .filter(|o| {
                !o.survivors_first.is_empty()
                    || !o.survivors_second.is_empty()
                    || !o.late_arrivals.is_empty()
            })
            .map(|o| o.spec.label())
            .collect();
        if !cleanup.is_empty() {
            println!(
                "NOTE: cleanup problems (listed per run above): {}",
                cleanup.len()
            );
        }
        if leaked.is_empty() {
            println!(
                "VERDICT: NO SURVIVORS in {} measured runs under either arm; both controls \
                 showed exactly the planted process, so the probe could see one.",
                measured.len()
            );
        } else {
            println!(
                "VERDICT: SURVIVORS FOUND in {} run(s): {}",
                leaked.len(),
                leaked.join(", ")
            );
        }
        if cleanup.is_empty() {
            0
        } else {
            1
        }
    }
}
