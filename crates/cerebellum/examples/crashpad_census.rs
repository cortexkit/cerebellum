//! Which crash database the agent browser's `chrome_crashpad_handler` writes
//! to on macOS, whether it may upload, and how long it outlives the browser.
//!
//! Background, from Chromium's source on the 153 branch (`refs/branch-heads/
//! 8010`; paths are under `chromium/src`):
//!
//! - The browser process starts its handler in `InitMacCrashReporter`
//!   (chrome/app/chrome_main_delegate.cc:1350-1366), called from
//!   `PreSandboxStartup` at :1423 -- BEFORE `InitializeUserDataDir` at :1430
//!   reads `--user-data-dir`. Nothing on that path consults a switch that
//!   turns the handler off.
//! - The database is `chrome::DIR_CRASH_DUMPS`
//!   (chrome/app/chrome_crash_reporter_client.cc:125-128), which on macOS is
//!   the DEFAULT user-data directory plus `Crashpad` "to avoid re-initializing
//!   the exception handler after parsing command line options"
//!   (chrome/common/chrome_paths.cc:204-232). So `--user-data-dir` never moves
//!   it, and the person's own `~/Library/Application Support/Google/Chrome/
//!   Crashpad` is what every agent browser uses.
//! - The one supported override is in `ChromeCrashReporterClient::Create`
//!   (chrome/app/chrome_crash_reporter_client.cc:65-85, compiled on every
//!   POSIX platform including macOS): the `BREAKPAD_DUMP_LOCATION`
//!   environment variable, else a `--breakpad-dump-location` switch (commented
//!   as there for Android tests), overrides `DIR_CRASH_DUMPS` before the
//!   handler starts.
//! - `--crash-dumps-dir` is a headless-shell switch
//!   (headless/public/switches.h:33, read in
//!   headless/lib/headless_content_main_delegate.cc:408); Chrome itself never
//!   reads it, which is why production's copy of it does nothing here.
//!   `--disable-crashpad-for-testing` is only consulted on Linux and ChromeOS
//!   (chrome_main_delegate.cc:1544-1547), and `--disable-crash-reporter` /
//!   `--disable-breakpad` are not read by Chrome at all.
//! - Uploads: the handler is always given `--url` (the upload URL is compiled
//!   in, components/crash/core/app/crash_reporter_client.cc:148-150). Whether
//!   it uploads is a bit in the database's `settings.dat`, written by
//!   `SetUploadConsent` (components/crash/core/app/crashpad.cc:245-263) from
//!   the consent file under the user-data directory as it stands at that
//!   moment -- still the default one on macOS -- and forced off when the
//!   `CHROME_HEADLESS` environment variable is set
//!   (chrome_crash_reporter_client.cc:166-169). The bit layout is
//!   third_party/crashpad/crashpad/client/settings.cc:120-143.
//!
//! Production now sets `BREAKPAD_DUMP_LOCATION` on every macOS launch, to a
//! per-launch directory under the per-user temporary directory that it
//! creates, checks is excluded from backup, and deletes when the session ends
//! (`cerebellum::browser_crash_reports`).
//!
//! Each arm below launches Chrome through production's own argument and
//! environment builders, with a crash-report directory production itself
//! created, applies one candidate change on top, and records every
//! `chrome_crashpad_handler` that starts system-wide during the launch: its
//! `--database` and `--url`, whether that database lets it upload, and when it
//! exits relative to that browser's teardown. The control arm applies nothing
//! and must show the handler's database UNDER that per-launch directory. The
//! unrelocated arm removes the variable and must show the handler on a
//! database outside every directory the probe made -- the person's own folder,
//! which is what a launch without the variable gets. If either does not hold,
//! none of the arms measured anything.
//!
//! Only throwaway roots under `/tmp` and production's per-launch directories
//! are created. The unrelocated arm (and the switch-only arms, which Chrome
//! does not read) necessarily starts a handler on the person's own crash
//! database, as every production launch did before the relocation; the probe
//! never reads that database, only whether the consent file beside it exists.
//! The arm that sets `CHROME_HEADLESS` is only ever run together with a
//! relocated database, because on the person's database it would switch their
//! Chrome's uploads off until their Chrome next starts.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p cerebellum --example crashpad_census [-- [--with-fake-home] [/path/to/Chrome]]
//! ```
//!
//! `--with-fake-home` adds an arm that points CoreFoundation's idea of the
//! home directory into the root (`CFFIXED_USER_HOME`). It is off by default:
//! it moves every home-relative path Chrome resolves, not just the crash
//! database, and may surface keychain dialogs on the desk.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe measures macOS Chrome's crash handler and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(census::run());
}

#[cfg(target_os = "macos")]
#[path = "support/cdp_pipe.rs"]
mod cdp_pipe;

/// Parsing of the handler's command line and of crashpad's settings file.
/// Pure functions, so they are unit-tested on every platform against fixture
/// strings and bytes.
#[cfg(any(target_os = "macos", test))]
mod handler_argv {
    /// The file name of the crash handler executable on macOS and Linux.
    pub const HANDLER_NAME: &str = "chrome_crashpad_handler";

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HandlerArgv {
        pub database: Option<String>,
        pub url: Option<String>,
        pub metrics_dir: Option<String>,
    }

    /// Split a `ps -ww` args column into the executable and its switches.
    ///
    /// `ps` joins argv with single spaces, so a path containing spaces (the
    /// person's database is under `Application Support`) cannot be recovered
    /// by splitting on whitespace. Every argument the handler receives is a
    /// `--switch`, so the column is split before each ` --` instead. That is
    /// wrong only for a value that itself contains ` --`, which neither
    /// Chrome's install path nor the database paths used here do.
    pub fn split_switches(args: &str) -> (String, Vec<(String, Option<String>)>) {
        let mut pieces = args.split(" --");
        let executable = pieces.next().unwrap_or_default().trim().to_string();
        let switches = pieces
            .map(|piece| {
                let piece = piece.trim_end();
                match piece.split_once('=') {
                    Some((name, value)) => (name.to_string(), Some(value.to_string())),
                    None => (piece.to_string(), None),
                }
            })
            .collect();
        (executable, switches)
    }

    /// The handler's command line, or `None` for any other process.
    pub fn parse_handler(args: &str) -> Option<HandlerArgv> {
        let (executable, switches) = split_switches(args);
        let is_handler =
            executable == HANDLER_NAME || executable.ends_with(&format!("/{HANDLER_NAME}"));
        if !is_handler {
            return None;
        }
        let value = |name: &str| {
            switches
                .iter()
                .find(|(switch, _)| switch == name)
                .and_then(|(_, value)| value.clone())
        };
        Some(HandlerArgv {
            database: value("database"),
            url: value("url"),
            metrics_dir: value("metrics-dir"),
        })
    }

    /// What a crashpad database's `settings.dat` says about uploading.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Uploads {
        Enabled,
        Disabled,
    }

    /// crashpad's `Settings::Data`: a native-endian `u32` magic of `'CPds'`,
    /// a `u32` version (1), then a `u32` options word whose bit 0 is
    /// "uploads enabled". Every Mac Chrome runs on is little-endian.
    pub fn uploads_from_settings(bytes: &[u8]) -> Result<Uploads, String> {
        const MAGIC: u32 = u32::from_be_bytes(*b"CPds");
        const VERSION: u32 = 1;
        const UPLOADS_ENABLED: u32 = 1;
        let word = |index: usize| {
            bytes
                .get(index * 4..index * 4 + 4)
                .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        };
        let (Some(magic), Some(version), Some(options)) = (word(0), word(1), word(2)) else {
            return Err(format!("settings.dat is {} bytes, too short", bytes.len()));
        };
        if magic != MAGIC {
            return Err(format!("settings.dat magic is {magic:#010x}, not 'CPds'"));
        }
        if version != VERSION {
            return Err(format!("settings.dat version is {version}, not {VERSION}"));
        }
        Ok(if options & UPLOADS_ENABLED != 0 {
            Uploads::Enabled
        } else {
            Uploads::Disabled
        })
    }
}

#[cfg(target_os = "macos")]
mod census {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use cerebellum::browser_crash_reports::{CrashReportDirectory, BREAKPAD_DUMP_LOCATION};
    use cerebellum::browser_launch_service::{
        browser_launch_arguments, browser_launch_environment,
    };
    use cerebellum_macos::{process_start_time, ProcessGeneration, ProcessStartTime};
    use serde_json::json;

    use crate::cdp_pipe::Cdp;
    use crate::handler_argv::{parse_handler, uploads_from_settings, HandlerArgv, Uploads};

    /// How long a page stays open before teardown, so the browser has
    /// finished initializing crash reporting and its helpers are clients of
    /// the handler the way they are in a real session.
    const SETTLE: Duration = Duration::from_secs(3);
    /// How often the process table is read. It bounds the precision of every
    /// start and exit time the probe reports.
    const POLL: Duration = Duration::from_millis(100);
    /// Quiet time between runs, longer than the attribution slack, so a
    /// handler first seen in it belongs to no run rather than to the wrong one.
    const BETWEEN_RUNS: Duration = Duration::from_millis(1500);
    /// A handler first seen this long after its run's teardown is still
    /// attributed to that run: the poll that would have seen it earlier may
    /// have been in flight.
    const ATTRIBUTION_SLACK: Duration = Duration::from_millis(500);
    /// How long after the last teardown the probe waits for handlers to exit
    /// on their own. Every handler in the earlier census had gone within about
    /// 70 s of the last teardown; this leaves room to see a slower one.
    const EXIT_CAP: Duration = Duration::from_secs(180);
    const RUNS_PER_ARM: usize = 2;
    const IDLE_PAGE: &str = "data:text/html,<title>idle</title><p>idle</p>";

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    enum Candidate {
        /// Production's launch, unchanged: relocated into its per-launch
        /// crash-report directory.
        Control,
        /// Production's launch with `BREAKPAD_DUMP_LOCATION` removed, which is
        /// what a launch without the relocation gets: the person's folder.
        Unrelocated,
        /// The variable removed and
        /// `--breakpad-dump-location=<root>/crashpad-by-switch` added instead.
        BreakpadSwitch,
        /// The variable pointed at `<root>/crashpad-by-env` instead.
        BreakpadEnv,
        /// The variable pointed into the root plus `CHROME_HEADLESS=1`, which
        /// should also clear the upload bit in the relocated database.
        BreakpadEnvUnattended,
        /// The variable removed and switches added that sound as if they
        /// disable crash reporting but that macOS Chrome does not read;
        /// expected to behave as the unrelocated arm.
        DisableSwitches,
        /// The variable removed and `CFFIXED_USER_HOME=<root>/home` added,
        /// moving the default user-data directory and with it the crash
        /// database. Opt-in only.
        FakeHome,
    }

    impl Candidate {
        fn label(self) -> &'static str {
            match self {
                Candidate::Control => "CONTROL (production launch)",
                Candidate::Unrelocated => "production launch without BREAKPAD_DUMP_LOCATION",
                Candidate::BreakpadSwitch => "--breakpad-dump-location",
                Candidate::BreakpadEnv => "BREAKPAD_DUMP_LOCATION",
                Candidate::BreakpadEnvUnattended => "BREAKPAD_DUMP_LOCATION + CHROME_HEADLESS",
                Candidate::DisableSwitches => {
                    "--disable-crash-reporter --disable-breakpad --disable-crashpad-for-testing"
                }
                Candidate::FakeHome => "CFFIXED_USER_HOME",
            }
        }

        /// Add this candidate's change to production's launch inputs.
        fn apply(
            self,
            root: &Path,
            arguments: &mut Vec<OsString>,
            environment: &mut Vec<(OsString, OsString)>,
        ) -> Result<(), String> {
            // Every arm but the control replaces production's relocation, so
            // each one measures its own change rather than production's.
            if self != Candidate::Control {
                environment.retain(|(name, _)| name != BREAKPAD_DUMP_LOCATION);
            }
            let mut set = |name: &str, value: OsString| {
                environment.push((OsString::from(name), value));
            };
            match self {
                Candidate::Control | Candidate::Unrelocated => {}
                Candidate::BreakpadSwitch => {
                    let mut switch = OsString::from("--breakpad-dump-location=");
                    switch.push(root.join("crashpad-by-switch"));
                    arguments.push(switch);
                }
                Candidate::BreakpadEnv => {
                    set(BREAKPAD_DUMP_LOCATION, root.join("crashpad-by-env").into());
                }
                Candidate::BreakpadEnvUnattended => {
                    set(BREAKPAD_DUMP_LOCATION, root.join("crashpad-by-env").into());
                    set("CHROME_HEADLESS", OsString::from("1"));
                }
                Candidate::DisableSwitches => {
                    for switch in [
                        "--disable-crash-reporter",
                        "--disable-breakpad",
                        "--disable-crashpad-for-testing",
                    ] {
                        arguments.push(OsString::from(switch));
                    }
                }
                Candidate::FakeHome => {
                    let home = root.join("home");
                    std::fs::create_dir(&home)
                        .map_err(|error| format!("creating {}: {error}", home.display()))?;
                    set("CFFIXED_USER_HOME", home.into());
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct RunSpec {
        number: usize,
        candidate: Candidate,
    }

    impl RunSpec {
        fn label(&self) -> String {
            format!("run {:02} [{}]", self.number, self.candidate.label())
        }
    }

    /// One launch that reached teardown.
    struct Run {
        spec: RunSpec,
        root: PathBuf,
        /// The per-launch crash-report directory production created for this
        /// run, deleted once every handler has exited and its settings are read.
        crash_reports: CrashReportDirectory,
        spawned_at: Instant,
        torn_down_at: Instant,
        teardown: String,
    }

    /// A handler process, keyed by pid and kernel start time so a recycled
    /// pid is never mistaken for it.
    #[derive(Clone)]
    struct Handler {
        pid: u32,
        start_time_micros: u64,
        argv: HandlerArgv,
        first_seen: Instant,
        gone_at: Option<Instant>,
    }

    type HandlerKey = (u32, u64);

    /// Every handler that started after the probe began, recorded by a thread
    /// that reads the whole process table every `POLL`. System-wide rather
    /// than per browser, because the handler is reparented to launchd and
    /// names no path of the agent's: it can only be found by being new.
    struct Watch {
        seen: Arc<Mutex<BTreeMap<HandlerKey, Handler>>>,
        stop: Arc<AtomicBool>,
        thread: JoinHandle<()>,
        preexisting: usize,
    }

    impl Watch {
        fn start() -> Watch {
            let preexisting: BTreeSet<HandlerKey> =
                handler_rows().into_iter().map(|(key, _)| key).collect();
            let seen = Arc::new(Mutex::new(BTreeMap::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let count = preexisting.len();
            let thread = {
                let seen = Arc::clone(&seen);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        poll_once(&preexisting, &seen);
                        std::thread::sleep(POLL);
                    }
                })
            };
            Watch {
                seen,
                stop,
                thread,
                preexisting: count,
            }
        }

        fn snapshot(&self) -> Vec<Handler> {
            self.seen
                .lock()
                .expect("the handler watch does not panic")
                .values()
                .cloned()
                .collect()
        }

        fn finish(self) -> Vec<Handler> {
            self.stop.store(true, Ordering::Relaxed);
            self.thread
                .join()
                .expect("the handler watch does not panic");
            let seen = self.seen.lock().expect("the handler watch does not panic");
            seen.values().cloned().collect()
        }
    }

    fn poll_once(preexisting: &BTreeSet<HandlerKey>, seen: &Mutex<BTreeMap<HandlerKey, Handler>>) {
        let now = Instant::now();
        let rows = handler_rows();
        let mut seen = seen.lock().expect("the handler watch does not panic");
        for (key, argv) in rows {
            if preexisting.contains(&key) {
                continue;
            }
            seen.entry(key).or_insert(Handler {
                pid: key.0,
                start_time_micros: key.1,
                argv,
                first_seen: now,
                gone_at: None,
            });
        }
        for handler in seen.values_mut() {
            if handler.gone_at.is_none()
                && !generation_alive(handler.pid, handler.start_time_micros)
            {
                handler.gone_at = Some(now);
            }
        }
    }

    /// Every running handler with its kernel start time. `ps` rather than a
    /// sysctl walk, because this probe lives outside the one crate allowed
    /// raw system calls and `ps -ww` already reports untruncated argv.
    fn handler_rows() -> Vec<(HandlerKey, HandlerArgv)> {
        let Ok(output) = Command::new("/bin/ps")
            .args(["-axww", "-o", "pid=,args="])
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                let (pid, args) = line.split_once(' ')?;
                let pid: u32 = pid.parse().ok()?;
                let argv = parse_handler(args.trim())?;
                let ProcessStartTime::Started(start) = process_start_time(pid) else {
                    return None;
                };
                Some(((pid, start), argv))
            })
            .collect()
    }

    fn generation_alive(pid: u32, start_time_micros: u64) -> bool {
        matches!(
            process_start_time(pid),
            ProcessStartTime::Started(start) if start == start_time_micros
        )
    }

    struct Setup {
        executable: PathBuf,
        grace: Duration,
        handshake: Duration,
        macos_version: String,
        with_fake_home: bool,
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

        let mut candidates = vec![
            Candidate::Control,
            Candidate::Unrelocated,
            Candidate::BreakpadSwitch,
            Candidate::BreakpadEnv,
            Candidate::BreakpadEnvUnattended,
            Candidate::DisableSwitches,
        ];
        if setup.with_fake_home {
            candidates.push(Candidate::FakeHome);
        }
        let mut specs = Vec::new();
        for candidate in candidates {
            for _ in 0..RUNS_PER_ARM {
                specs.push(RunSpec {
                    number: specs.len() + 1,
                    candidate,
                });
            }
        }

        let watch = Watch::start();
        println!(
            "handlers already running before the first launch (excluded): {}",
            watch.preexisting
        );
        // Let the watch take its first poll before anything launches, so a
        // handler it records is known to be new.
        std::thread::sleep(POLL * 3);

        let mut runs = Vec::new();
        let mut failures = Vec::new();
        let mut chrome_version = None;
        for spec in specs {
            match launch_and_tear_down(spec, &setup) {
                Ok((run, version)) => {
                    chrome_version.get_or_insert(version);
                    runs.push(run);
                }
                Err(reason) => {
                    println!("{}: RUN FAILED -- {reason}", spec.label());
                    failures.push(format!("{}: {reason}", spec.label()));
                }
            }
            std::thread::sleep(BETWEEN_RUNS);
        }

        // Wait for every new handler to exit on its own, up to the cap.
        let last_teardown = runs
            .iter()
            .map(|run| run.torn_down_at)
            .max()
            .unwrap_or_else(Instant::now);
        while Instant::now() < last_teardown + EXIT_CAP
            && watch
                .snapshot()
                .iter()
                .any(|handler| handler.gone_at.is_none())
        {
            std::thread::sleep(Duration::from_millis(500));
        }
        let handlers = watch.finish();
        let mut cleanup_problems = Vec::new();
        for handler in handlers.iter().filter(|handler| handler.gone_at.is_none()) {
            let _ = cerebellum_macos::terminate_exact_generation(ProcessGeneration {
                pid: handler.pid,
                start_time_micros: handler.start_time_micros,
            });
        }
        std::thread::sleep(Duration::from_millis(300));
        for handler in handlers.iter().filter(|handler| handler.gone_at.is_none()) {
            if generation_alive(handler.pid, handler.start_time_micros) {
                cleanup_problems.push(format!("handler pid {} survived SIGKILL", handler.pid));
            }
        }

        // Settings are read after every handler has exited or been killed,
        // so the file is not read while a handler could still write it.
        let reports: Vec<RunReport> = runs.iter().map(|run| report(run, &handlers)).collect();
        let unattributed: Vec<&Handler> = handlers
            .iter()
            .filter(|handler| !runs.iter().any(|run| owns(run, handler)))
            .collect();
        for run in runs {
            if let Err(error) = std::fs::remove_dir_all(&run.root) {
                cleanup_problems.push(format!("removing {}: {error}", run.root.display()));
            }
            let crash_reports = run.crash_reports.path().to_path_buf();
            if let Err(error) = run.crash_reports.remove() {
                cleanup_problems.push(format!("removing {}: {error}", crash_reports.display()));
            }
        }

        println!();
        println!(
            "Chrome: {}",
            chrome_version
                .as_deref()
                .unwrap_or("<no run reached the browser>")
        );
        println!("macOS: {}", setup.macos_version);
        for report in &reports {
            print_report(report);
        }
        if !unattributed.is_empty() {
            println!(
                "handlers that started outside every run's window (not counted): {}",
                unattributed
                    .iter()
                    .map(|handler| format!(
                        "pid {} database {}",
                        handler.pid,
                        handler.argv.database.as_deref().unwrap_or("<none>")
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        print_table(&reports);
        if !cleanup_problems.is_empty() {
            println!("CLEANUP PROBLEMS: {}", cleanup_problems.join("; "));
        }
        println!("total wall time: {:.1} s", overall.elapsed().as_secs_f64());
        let code = verdict(&reports, &failures);
        if cleanup_problems.is_empty() {
            code
        } else {
            code.max(1)
        }
    }

    fn preconditions() -> Result<Setup, Precondition> {
        let config = cerebellum::browser_config::load_browser_config_file().map_err(|error| {
            Precondition(format!("the module config could not be read: {error}"))
        })?;
        let mut with_fake_home = false;
        let mut executable = None;
        for argument in std::env::args_os().skip(1) {
            if argument == "--with-fake-home" {
                with_fake_home = true;
            } else if executable.is_none() {
                executable = Some(PathBuf::from(argument));
            } else {
                return Err(Precondition(format!(
                    "unexpected argument {}",
                    argument.to_string_lossy()
                )));
            }
        }
        let executable = match executable {
            Some(executable) => executable,
            None => config
                .as_ref()
                .and_then(|config| config.executable_path.clone())
                .ok_or_else(|| {
                    Precondition(
                        "no executable: pass one as an argument or set \
                         browser.executable_path in the module config"
                            .to_string(),
                    )
                })?,
        };
        if !executable.is_absolute() || !executable.is_file() {
            return Err(Precondition(format!(
                "the browser executable {} does not exist",
                executable.display()
            )));
        }
        // With the session locked, the page window would open into a session
        // nobody is using, which is not the condition production runs in.
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
        // Production's defaults when the config names no value.
        let grace = Duration::from_millis(
            config
                .as_ref()
                .map_or(5_000, |config| config.termination_grace_period_ms),
        );
        let handshake = Duration::from_millis(
            config
                .as_ref()
                .map_or(10_000, |config| config.launch_handshake_deadline_ms),
        );
        Ok(Setup {
            executable,
            grace,
            handshake,
            macos_version: macos_version(),
            with_fake_home,
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

    fn launch_and_tear_down(spec: RunSpec, setup: &Setup) -> Result<(Run, String), String> {
        let root = PathBuf::from(format!(
            "/tmp/ck-crashpad-census-{}-{:02}",
            std::process::id(),
            spec.number
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root)
            .map_err(|error| format!("creating {}: {error}", root.display()))?;
        // On macOS `/tmp` is a symlink to `/private/tmp`, and Chrome reports
        // the resolved path; without this, a database under the root would
        // read as outside it.
        let root = std::fs::canonicalize(&root)
            .map_err(|error| format!("resolving {}: {error}", root.display()))?;
        // Production's own directory, made the way a launch makes it. A
        // refusal here is what production would refuse the launch with.
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
            // A browser that started before the failure still names the root
            // in its argv; it is killed here so it cannot outlive the probe.
            // Its handler, if any, is tracked by the watch like every other.
            for (pid, start) in processes_naming(&root) {
                let _ = cerebellum_macos::terminate_exact_generation(ProcessGeneration {
                    pid,
                    start_time_micros: start,
                });
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
    ) -> Result<(Run, String), String> {
        let profile = root.join("profile");
        let crash_dumps = root.join("crash-dumps");
        // Production's own builders, not a copy of them, with the candidate's
        // change added on top: a probe whose baseline drifts from production
        // measures a browser nobody runs.
        let mut arguments = browser_launch_arguments(&profile, &crash_dumps);
        let mut environment = browser_launch_environment(&profile, &crash_reports);
        spec.candidate
            .apply(root, &mut arguments, &mut environment)?;

        let (command_child, command_parent) =
            UnixStream::pair().map_err(|error| format!("command pipe: {error}"))?;
        let (response_parent, response_child) =
            UnixStream::pair().map_err(|error| format!("response pipe: {error}"))?;
        let spawned_at = Instant::now();
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
        // release. That decides WHETHER to run the browser and cannot change
        // how it starts its crash handler, so it is not repeated here.
        let released = barred
            .release()
            .map_err(|error| format!("release: {error:?}"))?;
        let mut cdp = Cdp::new(command_parent, response_parent);

        let version = cdp
            .call(
                "Browser.getVersion",
                json!({}),
                Instant::now() + setup.handshake,
            )
            .map_err(|error| format!("handshake: {error}"))?;
        let product = version["product"].as_str().unwrap_or("?").to_string();
        // A background target, as navigation creates it, so the page opens
        // without taking focus from whatever the operator is doing.
        let created = cdp
            .call(
                "Target.createTarget",
                json!({"url": IDLE_PAGE, "background": true}),
                Instant::now() + setup.handshake,
            )
            .map_err(|error| format!("createTarget: {error}"))?;
        if created["targetId"].as_str().is_none() {
            return Err(format!(
                "createTarget answered without a targetId: {created}"
            ));
        }
        std::thread::sleep(SETTLE);

        let teardown = tear_down(released, &mut cdp, setup.grace)?;
        drop(cdp);
        Ok((
            Run {
                spec,
                root: root.to_path_buf(),
                crash_reports,
                spawned_at,
                torn_down_at: Instant::now(),
                teardown,
            },
            product,
        ))
    }

    /// Production's graceful arm: `Browser.close` over the pipe, a bounded
    /// wait for the main process to exit, and SIGKILL of the main pid if it
    /// has not.
    fn tear_down(
        released: cerebellum_macos::ReleasedChild,
        cdp: &mut Cdp,
        grace: Duration,
    ) -> Result<String, String> {
        let generation = released.generation();
        let started = Instant::now();
        cdp.send("Browser.close", json!({}))
            .map_err(|error| format!("Browser.close: {error}"))?;
        while started.elapsed() < grace {
            if !generation_alive(generation.pid, generation.start_time_micros) {
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

    fn processes_naming(root: &Path) -> Vec<(u32, u64)> {
        let root_text = root.to_string_lossy().to_string();
        let Ok(output) = Command::new("/bin/ps")
            .args(["-axww", "-o", "pid=,args="])
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains(&root_text))
            .filter_map(|line| {
                let pid: u32 = line.split_whitespace().next()?.parse().ok()?;
                match process_start_time(pid) {
                    ProcessStartTime::Started(start) => Some((pid, start)),
                    _ => None,
                }
            })
            .collect()
    }

    /// A handler belongs to the run whose spawn-to-teardown window it was
    /// first seen in. Runs are separated by more than the slack, so the
    /// windows cannot overlap.
    fn owns(run: &Run, handler: &Handler) -> bool {
        handler.first_seen >= run.spawned_at
            && handler.first_seen <= run.torn_down_at + ATTRIBUTION_SLACK
    }

    /// Where a handler's database is, relative to the directories this run made.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Location {
        /// Under the per-launch crash-report directory production created:
        /// where every production launch's handler must write.
        PerLaunch,
        /// Under the run's throwaway root, where a candidate arm pointed it.
        UnderRoot,
        /// Anywhere else: the person's own folder, for a launch that did not
        /// relocate the database.
        Outside,
    }

    impl Location {
        fn describe(self) -> &'static str {
            match self {
                Location::PerLaunch => "under the per-launch crash-report directory",
                Location::UnderRoot => "under the throwaway root",
                Location::Outside => "OUTSIDE every directory the probe made",
            }
        }

        fn short(self) -> &'static str {
            match self {
                Location::PerLaunch => "per-launch dir",
                Location::UnderRoot => "under root",
                Location::Outside => "outside",
            }
        }
    }

    enum UploadState {
        /// The database is outside every directory the probe made and is not
        /// read.
        NotRead {
            consent_file_beside_it: bool,
        },
        Read(Uploads),
        Unreadable(String),
    }

    struct HandlerReport {
        pid: u32,
        start_time_micros: u64,
        database: String,
        url: String,
        metrics_dir: String,
        location: Location,
        uploads: UploadState,
        /// Seconds from this run's teardown to the first poll that no longer
        /// saw the handler; `None` when it was still alive at the cap.
        exit_after_teardown: Option<f64>,
    }

    struct RunReport {
        spec: RunSpec,
        teardown: String,
        handlers: Vec<HandlerReport>,
    }

    fn report(run: &Run, handlers: &[Handler]) -> RunReport {
        let handlers = handlers
            .iter()
            .filter(|handler| owns(run, handler))
            .map(|handler| {
                let database = handler.argv.database.clone().unwrap_or_default();
                let database_path = Path::new(&database);
                let location = if database.is_empty() {
                    Location::Outside
                } else if database_path.starts_with(run.crash_reports.path()) {
                    Location::PerLaunch
                } else if database_path.starts_with(&run.root) {
                    Location::UnderRoot
                } else {
                    Location::Outside
                };
                let uploads = if location != Location::Outside {
                    match std::fs::read(database_path.join("settings.dat")) {
                        Ok(bytes) => match uploads_from_settings(&bytes) {
                            Ok(uploads) => UploadState::Read(uploads),
                            Err(error) => UploadState::Unreadable(error),
                        },
                        Err(error) => UploadState::Unreadable(format!("settings.dat: {error}")),
                    }
                } else {
                    // Only whether the consent file exists, never its content:
                    // it says whether the person's Chrome has upload consent,
                    // which is what decides this handler's uploads.
                    UploadState::NotRead {
                        consent_file_beside_it: database_path
                            .parent()
                            .is_some_and(|parent| parent.join("Consent To Send Stats").exists()),
                    }
                };
                let exit_after_teardown = handler.gone_at.map(|gone| {
                    if gone >= run.torn_down_at {
                        (gone - run.torn_down_at).as_secs_f64()
                    } else {
                        -(run.torn_down_at - gone).as_secs_f64()
                    }
                });
                HandlerReport {
                    pid: handler.pid,
                    start_time_micros: handler.start_time_micros,
                    database,
                    url: handler.argv.url.clone().unwrap_or_default(),
                    metrics_dir: handler.argv.metrics_dir.clone().unwrap_or_default(),
                    location,
                    uploads,
                    exit_after_teardown,
                }
            })
            .collect();
        RunReport {
            spec: run.spec,
            teardown: run.teardown.clone(),
            handlers,
        }
    }

    fn describe_uploads(uploads: &UploadState) -> String {
        match uploads {
            UploadState::NotRead {
                consent_file_beside_it,
            } => format!(
                "not read (outside the probe's directories); consent file beside it: {}",
                if *consent_file_beside_it {
                    "present"
                } else {
                    "absent"
                }
            ),
            UploadState::Read(Uploads::Enabled) => "ENABLED".to_string(),
            UploadState::Read(Uploads::Disabled) => "disabled".to_string(),
            UploadState::Unreadable(reason) => format!("unreadable: {reason}"),
        }
    }

    fn describe_exit(exit: Option<f64>) -> String {
        match exit {
            Some(seconds) if seconds < 0.0 => {
                format!("{:.1} s BEFORE teardown", -seconds)
            }
            Some(seconds) => format!("{seconds:.1} s after teardown"),
            None => format!(
                "STILL ALIVE {} s after the last teardown",
                EXIT_CAP.as_secs()
            ),
        }
    }

    fn print_report(report: &RunReport) {
        println!("{}", report.spec.label());
        println!("  teardown: {}", report.teardown);
        if report.handlers.is_empty() {
            println!("  no handler started");
        }
        for handler in &report.handlers {
            println!(
                "  handler pid {} (start {})",
                handler.pid, handler.start_time_micros
            );
            println!(
                "    --database={} [{}]",
                handler.database,
                handler.location.describe()
            );
            println!("    --url={}", handler.url);
            println!("    --metrics-dir={}", handler.metrics_dir);
            println!("    uploads: {}", describe_uploads(&handler.uploads));
            println!("    exit: {}", describe_exit(handler.exit_after_teardown));
        }
    }

    fn print_table(reports: &[RunReport]) {
        println!();
        println!("| arm | runs | handlers per run | database | uploads | exit after teardown |");
        println!("|---|---|---|---|---|---|");
        let mut cells: BTreeMap<Candidate, Vec<&RunReport>> = BTreeMap::new();
        for report in reports {
            cells.entry(report.spec.candidate).or_default().push(report);
        }
        for (candidate, runs) in cells {
            let handlers: Vec<&HandlerReport> = runs.iter().flat_map(|run| &run.handlers).collect();
            let per_run = runs
                .iter()
                .map(|run| run.handlers.len().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let join = |values: Vec<String>| {
                let unique: BTreeSet<String> = values.into_iter().collect();
                if unique.is_empty() {
                    "-".to_string()
                } else {
                    unique.into_iter().collect::<Vec<_>>().join(" / ")
                }
            };
            let databases = join(
                handlers
                    .iter()
                    .map(|handler| handler.location.short().to_string())
                    .collect(),
            );
            let uploads = join(
                handlers
                    .iter()
                    .map(|handler| match &handler.uploads {
                        UploadState::NotRead { .. } => "not read".to_string(),
                        other => describe_uploads(other),
                    })
                    .collect(),
            );
            let exits = handlers
                .iter()
                .map(|handler| match handler.exit_after_teardown {
                    Some(seconds) => format!("{seconds:.1} s"),
                    None => "alive at cap".to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "| {} | {} | {} | {} | {} | {} |",
                candidate.label(),
                runs.len(),
                per_run,
                databases,
                uploads,
                if exits.is_empty() {
                    "-".to_string()
                } else {
                    exits
                }
            );
        }
    }

    fn verdict(reports: &[RunReport], failures: &[String]) -> i32 {
        if !failures.is_empty() {
            println!(
                "VERDICT: INCOMPLETE -- {} run(s) failed: {}",
                failures.len(),
                failures.join(" | ")
            );
            return 1;
        }
        // The control and the unrelocated arm are what make every other row
        // mean something. The control is production's launch and must show
        // its handler, one per launch, on a database under the per-launch
        // directory production made. The unrelocated arm must show the
        // handler on a database outside every directory the probe made, which
        // proves the relocation is what moved it. A run with no handler would
        // make an arm's "no handler started" indistinguishable from a blind
        // watch.
        let runs_of = |candidate: Candidate| -> Vec<&RunReport> {
            reports
                .iter()
                .filter(|report| report.spec.candidate == candidate)
                .collect()
        };
        for (candidate, expected, name) in [
            (Candidate::Control, Location::PerLaunch, "CONTROL"),
            (
                Candidate::Unrelocated,
                Location::Outside,
                "UNRELOCATED BASELINE",
            ),
        ] {
            let runs = runs_of(candidate);
            if runs.len() != RUNS_PER_ARM {
                println!(
                    "VERDICT: {name} FAILED -- {} runs, expected {RUNS_PER_ARM}",
                    runs.len()
                );
                return 1;
            }
            for run in &runs {
                if run.handlers.is_empty()
                    || run
                        .handlers
                        .iter()
                        .any(|handler| handler.location != expected)
                {
                    println!(
                        "VERDICT: {name} FAILED -- {} did not show every handler on a database \
                         {}, so no arm below measured anything",
                        run.spec.label(),
                        expected.describe()
                    );
                    return 1;
                }
            }
        }
        // The relocated database is a fresh one, so its own settings must
        // read uploads as disabled; enabled would mean the relocation moved
        // the reports but not the decision to send them.
        if runs_of(Candidate::Control)
            .iter()
            .flat_map(|run| &run.handlers)
            .any(|handler| !matches!(handler.uploads, UploadState::Read(Uploads::Disabled)))
        {
            println!(
                "VERDICT: CONTROL FAILED -- a production handler's relocated database did not \
                 read uploads as disabled"
            );
            return 1;
        }
        let mut findings = Vec::new();
        let mut arms: BTreeMap<Candidate, Vec<&RunReport>> = BTreeMap::new();
        for report in reports {
            arms.entry(report.spec.candidate).or_default().push(report);
        }
        for (candidate, runs) in arms {
            if matches!(candidate, Candidate::Control | Candidate::Unrelocated) {
                continue;
            }
            let handlers: Vec<&HandlerReport> = runs.iter().flat_map(|run| &run.handlers).collect();
            let locations: BTreeSet<&'static str> = handlers
                .iter()
                .map(|handler| handler.location.short())
                .collect();
            let outcome = if handlers.is_empty() {
                "no handler started".to_string()
            } else if locations.len() > 1 {
                format!(
                    "MIXED: handlers {}",
                    locations.into_iter().collect::<Vec<_>>().join(" / ")
                )
            } else if handlers[0].location == Location::Outside {
                "database outside, as without the relocation".to_string()
            } else {
                let uploads: BTreeSet<String> = handlers
                    .iter()
                    .map(|handler| describe_uploads(&handler.uploads))
                    .collect();
                format!(
                    "database {}, uploads {}",
                    handlers[0].location.describe(),
                    uploads.into_iter().collect::<Vec<_>>().join(" / ")
                )
            };
            findings.push(format!("{}: {outcome}", candidate.label()));
        }
        println!(
            "VERDICT: RELOCATION CONFIRMED (every production handler on a database under its \
             per-launch directory with uploads disabled; every unrelocated handler outside). \
             Arms: {}",
            findings.join(" | ")
        );
        0
    }
}

#[cfg(test)]
mod tests {
    use super::handler_argv::{parse_handler, split_switches, uploads_from_settings, Uploads};

    /// The handler row a system-wide `ps -axww -o args=` showed on the desk
    /// for an agent browser, with the user name replaced.
    const MEASURED_ROW: &str = "/Applications/Google Chrome.app/Contents/Frameworks/Google \
        Chrome Framework.framework/Versions/153.0.8010.53/Helpers/chrome_crashpad_handler \
        --monitor-self-annotation=ptype=crashpad-handler \
        --database=/Users/someone/Library/Application Support/Google/Chrome/Crashpad \
        --metrics-dir=/Users/someone/Library/Application Support/Google/Chrome \
        --url=https://clients2.google.com/cr/report --annotation=channel= \
        --annotation=plat=OS X --annotation=prod=Chrome_Mac \
        --annotation=ver=153.0.8010.53 --handshake-fd=7";

    #[test]
    fn a_database_path_with_spaces_is_read_whole() {
        let argv = parse_handler(MEASURED_ROW).expect("the row is a handler");
        assert_eq!(
            argv.database.as_deref(),
            Some("/Users/someone/Library/Application Support/Google/Chrome/Crashpad")
        );
        assert_eq!(
            argv.url.as_deref(),
            Some("https://clients2.google.com/cr/report")
        );
        assert_eq!(
            argv.metrics_dir.as_deref(),
            Some("/Users/someone/Library/Application Support/Google/Chrome")
        );
    }

    #[test]
    fn a_relocated_database_under_a_root_is_read() {
        let row = "/opt/chrome/chrome_crashpad_handler \
            --database=/tmp/ck-crashpad-census-1-03/crashpad-by-env \
            --url=https://clients2.google.com/cr/report --handshake-fd=7";
        let argv = parse_handler(row).expect("the row is a handler");
        assert_eq!(
            argv.database.as_deref(),
            Some("/tmp/ck-crashpad-census-1-03/crashpad-by-env")
        );
        assert!(std::path::Path::new(argv.database.as_deref().unwrap())
            .starts_with("/tmp/ck-crashpad-census-1-03"));
    }

    #[test]
    fn a_handler_without_a_url_has_none() {
        let argv = parse_handler("chrome_crashpad_handler --database=/tmp/x --handshake-fd=7")
            .expect("a bare handler name is a handler");
        assert_eq!(argv.url, None);
        assert_eq!(argv.database.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn other_chrome_processes_are_not_handlers() {
        for row in [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome \
             --remote-debugging-pipe --user-data-dir=/tmp/root/profile",
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome \
             Framework.framework/Versions/153.0.8010.53/Helpers/Google Chrome Helper \
             (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer",
            // A process that merely MENTIONS the handler in an argument.
            "/usr/bin/grep chrome_crashpad_handler",
            "/usr/bin/tail --follow=/tmp/chrome_crashpad_handler.log",
        ] {
            assert_eq!(parse_handler(row), None, "{row}");
        }
    }

    #[test]
    fn switches_without_values_keep_their_names() {
        let (executable, switches) =
            split_switches("/x/chrome_crashpad_handler --monitor-self --database=/d");
        assert_eq!(executable, "/x/chrome_crashpad_handler");
        assert_eq!(
            switches,
            vec![
                ("monitor-self".to_string(), None),
                ("database".to_string(), Some("/d".to_string())),
            ]
        );
    }

    /// Bytes laid out as crashpad writes `Settings::Data` on a little-endian
    /// machine: magic, version, options, padding, then the rest.
    fn settings_bytes(options: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::from_be_bytes(*b"CPds").to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&options.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&[0_u8; 16]);
        bytes
    }

    #[test]
    fn the_upload_bit_is_read_from_settings() {
        assert_eq!(
            uploads_from_settings(&settings_bytes(1)),
            Ok(Uploads::Enabled)
        );
        assert_eq!(
            uploads_from_settings(&settings_bytes(0)),
            Ok(Uploads::Disabled)
        );
        // Only bit 0 means uploads; another option bit alone does not.
        assert_eq!(
            uploads_from_settings(&settings_bytes(2)),
            Ok(Uploads::Disabled)
        );
    }

    #[test]
    fn a_settings_file_that_is_not_crashpads_is_refused() {
        let mut wrong_magic = settings_bytes(1);
        wrong_magic[0] ^= 0xff;
        assert!(uploads_from_settings(&wrong_magic).is_err());
        let mut wrong_version = settings_bytes(1);
        wrong_version[4] = 2;
        assert!(uploads_from_settings(&wrong_version).is_err());
        assert!(uploads_from_settings(&settings_bytes(1)[..10]).is_err());
    }
}
