//! Manual, scratch-only comparison of AX alternatives to temporary activation.
//! Build this example without running it. The operator's run instructions and
//! limitations are in the accompanying internal investigation report.

#[cfg(any(target_os = "macos", test))]
fn approved(value: Option<&str>, data_home_present: bool) -> bool {
    value == Some("1") && data_home_present
}

#[cfg(any(target_os = "macos", test))]
fn owns_scratch(
    pid: u32,
    before: &[u32],
    after: &[u32],
    expected_start: u64,
    actual_start: Option<u64>,
    documents: &[String],
    expected_document: &str,
) -> bool {
    pid != 0
        && before.is_empty()
        && after == [pid]
        && actual_start == Some(expected_start)
        && documents == [expected_document]
}

#[cfg(any(target_os = "macos", test))]
fn whole_selection(location: isize, length: isize, text: &str) -> bool {
    !text.is_empty()
        && location == 0
        && usize::try_from(length).ok() == Some(text.encode_utf16().count())
}

fn main() {
    #[cfg(target_os = "macos")]
    let code = desk::entry();
    #[cfg(not(target_os = "macos"))]
    let code = 2;
    std::process::exit(code);
}

#[cfg(target_os = "macos")]
mod desk {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use cerebellum_macos as mac;
    use serde_json::{json, Value};

    const ROOT: &str = "/tmp/cereb-desk";
    const TEXT: &str = "Cerebellum scratch only. Select all this text.\nSecond scratch line.\n";
    const TICK: Duration = Duration::from_millis(10);
    const WAIT: Duration = Duration::from_secs(3);
    const BUNDLE: &str = "com.apple.TextEdit";
    type Result<T> = std::result::Result<T, &'static str>;
    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    static CLEANUP_FAILED: AtomicBool = AtomicBool::new(false);

    extern "C" {
        fn geteuid() -> u32;
        fn dup2(old: i32, new: i32) -> i32;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGPreflightPostEventAccess() -> bool;
    }

    fn private_directory(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|m| {
            // SAFETY: geteuid has no arguments or memory preconditions.
            m.is_dir() && m.mode() & 0o777 == 0o700 && m.uid() == unsafe { geteuid() }
        })
    }

    fn data_home_ok(path: &Path) -> bool {
        let Ok(root) = Path::new(ROOT).canonicalize() else {
            return false;
        };
        let Ok(canonical) = path.canonicalize() else {
            return false;
        };
        // Require a direct child so no unchecked intermediate directory or
        // symlink can redirect a journal path into the operator's home.
        canonical.parent() == Some(root.as_path())
            && path.parent().and_then(|p| p.canonicalize().ok()) == Some(root)
            && private_directory(path)
    }

    #[derive(Clone)]
    struct Log(Arc<Mutex<File>>, Instant);

    impl Log {
        fn event(&self, method: &str, data: Value) {
            if let Ok(mut file) = self.0.lock() {
                let _ = writeln!(
                    file,
                    "{}",
                    json!({"at_ms": self.1.elapsed().as_secs_f64() * 1000.0, "method": method, "data": data})
                );
                let _ = file.flush();
            }
        }
    }

    pub fn entry() -> i32 {
        // Even refusals must not print to the desk. An unsafe/missing log
        // directory is a silent exit 2; the run command creates it explicitly.
        if !private_directory(Path::new(ROOT)) {
            return 2;
        }
        let mut bytes = [0_u8; 12];
        if getrandom::getrandom(&mut bytes).is_err() {
            return 2;
        }
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let log_path = Path::new(ROOT).join(format!("run-alternatives-{nonce}.log"));
        let Ok(file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(log_path)
        else {
            return 2;
        };
        // SAFETY: file owns an open descriptor; dup2 retains independent copies
        // for stdout/stderr, including any panic or framework diagnostic.
        if unsafe { dup2(file.as_raw_fd(), 1) < 0 || dup2(file.as_raw_fd(), 2) < 0 } {
            return 2;
        }
        let log = Log(Arc::new(Mutex::new(file)), Instant::now());
        let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
        if !super::approved(
            std::env::var("CK_DESK_PROBE_APPROVED").ok().as_deref(),
            data.is_some(),
        ) || !data.as_deref().is_some_and(data_home_ok)
        {
            log.event(
                "refused",
                json!({"reason":"approval=1 and private scratch XDG_DATA_HOME required"}),
            );
            return 2;
        }
        // SAFETY: this only checks the current event-posting grant, without
        // prompting. Do not discover a missing grant by trying a live chord.
        let post_access = unsafe { CGPreflightPostEventAccess() };
        if !mac::accessibility_is_permitted()
            || !post_access
            || mac::screen_is_locked() != Some(false)
        {
            log.event("refused", json!({"reason":"unlocked desk and pre-granted Accessibility/event posting required; no permission prompt requested"}));
            return 2;
        }
        // The main-thread AppKit loop keeps application activation live while
        // the measurements and the 10 ms AX sampler run on worker threads.
        let worker_log = log.clone();
        mac::with_app_use_desk_probe_run_loop(move || match run(worker_log.clone(), &nonce) {
            Ok(()) if !CLEANUP_FAILED.load(Ordering::SeqCst) => 0,
            Ok(()) => {
                worker_log.event(
                    "unmeasurable",
                    json!({"reason":"scratch teardown incomplete; manual inspection required"}),
                );
                2
            }
            Err(reason) => {
                worker_log.event("unmeasurable", json!({"reason":reason}));
                2
            }
        })
        .unwrap_or_else(|_| {
            log.event("unmeasurable", json!({"reason":"AppKit run loop failed"}));
            2
        })
    }

    fn textedit_pids() -> Result<Vec<u32>> {
        Ok(mac::workspace_running_applications()
            .map_err(|_| "application inventory unreadable")?
            .into_iter()
            .filter(|a| a.bundle_identifier == BUNDLE)
            .map(|a| a.pid)
            .collect())
    }

    struct Scratch {
        pid: u32,
        start: u64,
        directory: PathBuf,
        document_url: String,
        log: Log,
        cleanup: bool,
    }

    impl Scratch {
        fn launch(log: Log, nonce: &str) -> Result<Self> {
            if !textedit_pids()?.is_empty() {
                return Err("quit TextEdit first; never reuse the person's instance");
            }
            let directory = Path::new(ROOT).join(format!("scratch-{nonce}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|_| "private scratch directory creation failed")?;
            let document = directory.join("alternatives.txt");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&document)
                .map_err(|_| "private scratch file creation failed")?;
            file.write_all(TEXT.as_bytes())
                .map_err(|_| "scratch text write failed")?;
            let canonical = document
                .canonicalize()
                .map_err(|_| "scratch path resolution failed")?;
            let document_url = format!("file://{}", canonical.display());
            let status = Command::new("/usr/bin/open")
                .args(["-g", "-n", "-b", BUNDLE])
                .arg(&document)
                .args(["--args", "-ApplePersistenceIgnoreState", "YES"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|_| "LaunchServices open failed")?;
            if !status.success() {
                return Err("LaunchServices open refused");
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let pids = textedit_pids()?;
                if pids.len() > 1 {
                    return Err("ambiguous new TextEdit; no process will be killed");
                }
                if let Some(&pid) = pids.first() {
                    if let Some(start) = mac::process_start_time_micros(pid) {
                        let mut scratch = Self {
                            pid,
                            start,
                            directory: directory.clone(),
                            document_url: document_url.clone(),
                            log: log.clone(),
                            cleanup: false,
                        };
                        if scratch.prove().is_ok() {
                            scratch.cleanup = true;
                            log.event(
                                "scratch_owned",
                                json!({"pid":pid,"start_micros":start,"document":document_url}),
                            );
                            return Ok(scratch);
                        }
                        // Ownership is not established yet; Drop must not try
                        // cleanup or print any AXDocument from another window.
                    }
                }
                if Instant::now() >= deadline {
                    return Err("new TextEdit's scratch document not proven; left running for manual inspection");
                }
                std::thread::sleep(TICK);
            }
        }

        fn app(&self) -> Result<ax::Owned> {
            ax::app(self.pid)
        }

        fn window(&self) -> Result<ax::Owned> {
            let windows = ax::array(&self.app()?, "AXWindows")?;
            if windows.len() != 1 {
                return Err("scratch must have exactly one window");
            }
            let window = windows.into_iter().next().ok_or("scratch window missing")?;
            if ax::text(&window, "AXDocument")? != self.document_url {
                return Err("scratch AXDocument changed");
            }
            Ok(window)
        }

        fn prove(&self) -> Result<()> {
            let window = self.window()?;
            let documents = vec![ax::text(&window, "AXDocument")?];
            if super::owns_scratch(
                self.pid,
                &[],
                &textedit_pids()?,
                self.start,
                mac::process_start_time_micros(self.pid),
                &documents,
                &self.document_url,
            ) {
                Ok(())
            } else {
                Err("scratch process generation/document no longer proven")
            }
        }

        fn text_element(&self) -> Result<ax::Owned> {
            self.prove()?;
            let focused = ax::attr(&self.app()?, "AXFocusedUIElement")?;
            let window = ax::attr(&focused, "AXWindow")?;
            if ax::text(&window, "AXDocument")? != self.document_url {
                return Err("focused element is not the scratch document");
            }
            if ax::text(&focused, "AXValue")? != TEXT {
                return Err("scratch text changed; refusing non-scratch content");
            }
            Ok(focused)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if !self.cleanup {
                return;
            }
            if self.prove().is_ok() {
                let killed = Command::new("/bin/kill")
                    .args(["-KILL", &self.pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                let deadline = Instant::now() + WAIT;
                let mut gone = false;
                while killed && Instant::now() < deadline {
                    match mac::process_start_time(self.pid) {
                        mac::ProcessStartTime::NoSuchProcess => {
                            gone = true;
                            break;
                        }
                        mac::ProcessStartTime::Started(start) if start != self.start => {
                            gone = true;
                            break;
                        }
                        _ => std::thread::sleep(TICK),
                    }
                }
                let removed = gone && std::fs::remove_dir_all(&self.directory).is_ok();
                if !removed {
                    CLEANUP_FAILED.store(true, Ordering::SeqCst);
                }
                self.log.event("scratch_close", json!({"proven":true,"kill_requested":killed,"gone":gone,"files_removed":removed}));
            } else {
                CLEANUP_FAILED.store(true, Ordering::SeqCst);
                self.log.event(
                    "scratch_close",
                    json!({"proven":false,"left_running":true,"pid":self.pid}),
                );
            }
        }
    }

    #[derive(Clone)]
    struct Sample {
        at: Instant,
        focus: Option<i32>,
        menu_owner: Option<i32>,
    }

    struct Sampler {
        stop: Arc<AtomicBool>,
        target: Arc<AtomicU32>,
        samples: Arc<Mutex<Vec<Sample>>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Sampler {
        fn start(log: Log, person: i32) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let target = Arc::new(AtomicU32::new(0));
            let samples = Arc::new(Mutex::new(Vec::new()));
            let (s, values, target_pid) = (stop.clone(), samples.clone(), target.clone());
            let thread = std::thread::spawn(move || {
                let mut next = Instant::now();
                while !s.load(Ordering::SeqCst) {
                    let at = Instant::now();
                    let focus = ax::front_pid().ok();
                    let menu_owner = ax::menu_owner();
                    let role = |pid: Option<i32>| match pid {
                        Some(p) if p == person => "person",
                        Some(p) if p == target_pid.load(Ordering::SeqCst) as i32 => "scratch",
                        Some(_) => "other",
                        None => "unknown",
                    };
                    log.event("front_sample", json!({"front":role(focus), "menu_bar_owner":role(menu_owner), "read_ms":at.elapsed().as_secs_f64()*1000.0}));
                    values.lock().unwrap().push(Sample {
                        at,
                        focus,
                        menu_owner,
                    });
                    next += TICK;
                    // Slow AX reads are not silently labelled 10 ms samples.
                    if next < Instant::now() {
                        next = Instant::now();
                    }
                    std::thread::sleep(next.saturating_duration_since(Instant::now()));
                }
            });
            Self {
                stop,
                target,
                samples,
                thread: Some(thread),
            }
        }

        fn summary(&self, since: Instant, person: i32) -> Value {
            let samples = self.samples.lock().unwrap();
            let values: Vec<_> = samples.iter().filter(|s| s.at >= since).collect();
            let max_gap = values
                .windows(2)
                .map(|v| v[1].at.duration_since(v[0].at).as_secs_f64() * 1000.0)
                .fold(0.0_f64, f64::max);
            json!({"samples":values.len(),"any_app_fronted_observed":values.iter().any(|s| s.focus.is_some_and(|p|p!=person)),
                "unknown_focus_samples":values.iter().filter(|s|s.focus.is_none()).count(),
                "menu_owner_changed_observed":values.iter().any(|s|s.menu_owner.is_some_and(|p|p!=person)),
                "unknown_menu_owner_samples":values.iter().filter(|s|s.menu_owner.is_none()).count(),
                "max_sample_gap_ms":max_gap,"visual_menu_bar":"person must observe; owner change is not pixel evidence"})
        }
    }

    impl Drop for Sampler {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn background(person: i32) -> Result<()> {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Err("interrupted; scratch cleanup follows");
        }
        if mac::screen_is_locked() != Some(false) {
            return Err("desk locked; no more actions");
        }
        if ax::front_pid()? != person {
            return Err("person's front app changed; no more actions");
        }
        Ok(())
    }

    fn wait_front(pid: i32) -> bool {
        let deadline = Instant::now() + WAIT;
        loop {
            if ax::front_pid() == Ok(pid) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(TICK);
        }
    }

    struct Restore<'a> {
        scratch: &'a Scratch,
        window: ax::Owned,
        original: ax::Point,
        person: i32,
        person_start: u64,
        active: bool,
    }

    impl Restore<'_> {
        fn restore(&mut self) -> Result<(f64, f64)> {
            let start = Instant::now();
            let focus = ax::front_pid()?;
            if focus == self.scratch.pid as i32 {
                if !mac::activate_application(self.person as u32, self.person_start)
                    || !wait_front(self.person)
                {
                    return Err("person's app did not restore; scratch cleanup follows");
                }
            } else if focus != self.person {
                // A person switching to a third app wins; never take it back.
                return Err("third app became frontmost; do not override the person");
            }
            let app_ms = start.elapsed().as_secs_f64() * 1000.0;
            self.scratch.prove()?;
            let start = Instant::now();
            ax::set_point(&self.window, self.original)?;
            let actual = ax::point(&self.window)?;
            let move_ms = start.elapsed().as_secs_f64() * 1000.0;
            if actual != self.original {
                return Err("scratch position did not restore exactly");
            }
            self.active = false;
            Ok((app_ms, move_ms))
        }
    }

    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            if self.active {
                let result = self.restore();
                self.scratch.log.event(
                    "best_effort_restore",
                    json!({"ok":result.is_ok(),"reason":result.err()}),
                );
            }
        }
    }

    fn selection_case(
        scratch: &Scratch,
        sampler: &Sampler,
        person: i32,
        markers: bool,
    ) -> Result<()> {
        background(person)?;
        let start = Instant::now();
        let element = scratch.text_element()?;
        ax::reset_caret(&element)?;
        let method = if markers {
            "AXSelectedTextMarkerRange"
        } else {
            "AXSelectedTextRange"
        };
        let call = Instant::now();
        let result = if markers {
            ax::select_markers(&element, TEXT.encode_utf16().count())
        } else {
            ax::set_range(&element, 0, TEXT.encode_utf16().count() as isize)
        };
        let call_ms = call.elapsed().as_secs_f64() * 1000.0;
        std::thread::sleep(Duration::from_millis(100));
        let range = ax::range(&element);
        let effect = range
            .as_ref()
            .ok()
            .map(|r| super::whole_selection(r.location, r.length, TEXT));
        scratch.log.event(method, json!({"call_ok":result.is_ok(),"reason":result.err(),"effect":effect,
            "readback_error":range.as_ref().err(),"selected_range":range.ok().map(|r|[r.location,r.length]),"call_ms":call_ms,
            "total_ms":start.elapsed().as_secs_f64()*1000.0,"front":sampler.summary(start,person)}));
        background(person)
    }

    const CHORDS: [(&str, &str); 9] = [
        ("select_all", "a"),
        ("copy", "c"),
        ("paste", "v"),
        ("cut", "x"),
        ("undo", "z"),
        ("save", "s"),
        ("new_window", "n"),
        ("close_window", "w"),
        ("find", "f"),
    ];

    fn menu_cases(scratch: &Scratch, sampler: &Sampler, person: i32) -> Result<()> {
        // Traverse only this scratch process's menu tree. No AX title/value is
        // ever logged; command characters avoid localisation-dependent labels.
        let menu = ax::attr(&scratch.app()?, "AXMenuBar")?;
        for (name, character) in CHORDS {
            background(person)?;
            scratch.prove()?;
            let start = Instant::now();
            let mut matches = Vec::new();
            ax::menu_matches(&menu, character, 0, &mut 0, &mut matches)?;
            let mut data =
                json!({"chord":name,"matches":matches.len(),"effect":null,"pressed":false});
            if matches.len() == 1 {
                let item = matches.pop().unwrap();
                data["enabled"] = json!(ax::boolean(&item, "AXEnabled").ok());
                let actions = ax::actions(&item);
                data["actions"] = json!(actions.as_ref().ok());
                data["actions_error"] = json!(actions.as_ref().err());
                data["press_available"] = json!(actions
                    .as_ref()
                    .ok()
                    .map(|a| a.iter().any(|a| a == "AXPress")));
                // Select All has a decisive, content-free AX readback and is
                // safe even when menu validation reports it disabled. Other
                // mappings do not imply a verified executable alternative.
                if name == "select_all" {
                    let text = scratch.text_element()?;
                    ax::reset_caret(&text)?;
                    let call = Instant::now();
                    let result = ax::press(&item);
                    data["call_ms"] = json!(call.elapsed().as_secs_f64() * 1000.0);
                    data["pressed"] = json!(true);
                    data["call_ok"] = json!(result.is_ok());
                    data["reason"] = json!(result.err());
                    std::thread::sleep(Duration::from_millis(100));
                    let readback = ax::range(&text);
                    data["effect"] = json!(readback
                        .as_ref()
                        .ok()
                        .map(|r| super::whole_selection(r.location, r.length, TEXT)));
                    data["readback_error"] = json!(readback.err());
                } else {
                    data["skip"] = json!(match name {
                        "copy" | "cut" | "paste" => "shared clipboard; never read or change it",
                        "new_window" | "close_window" =>
                            "preserve single-document ownership anchor for cleanup",
                        _ => "mapping only; effect oracle not implemented for this command",
                    });
                }
            } else {
                data["skip"] = json!("no unique command-only AX menu item; no title guessing");
            }
            std::thread::sleep(Duration::from_millis(30));
            data["total_ms"] = json!(start.elapsed().as_secs_f64() * 1000.0);
            data["front"] = sampler.summary(start, person);
            scratch.log.event("AXPress_menu", data);
            background(person)?;
        }
        Ok(())
    }

    fn offscreen_cases(
        scratch: &Scratch,
        sampler: &Sampler,
        person: i32,
        person_start: u64,
    ) -> Result<()> {
        let window = scratch.window()?;
        let original = ax::point(&window)?;
        let size = ax::size(&window)?;
        let displays = ax::displays()?;
        let left = displays
            .iter()
            .map(|r| r.origin.x)
            .fold(f64::INFINITY, f64::min);
        let top = displays
            .iter()
            .map(|r| r.origin.y)
            .fold(f64::INFINITY, f64::min);
        let right = displays
            .iter()
            .map(|r| r.origin.x + r.size.width)
            .fold(f64::NEG_INFINITY, f64::max);
        let bottom = displays
            .iter()
            .map(|r| r.origin.y + r.size.height)
            .fold(f64::NEG_INFINITY, f64::max);
        for (direction, requested) in [
            (
                "left",
                ax::Point {
                    x: left - size.width - 200.0,
                    y: original.y,
                },
            ),
            (
                "above",
                ax::Point {
                    x: original.x,
                    y: top - size.height - 200.0,
                },
            ),
            (
                "right",
                ax::Point {
                    x: right + 200.0,
                    y: original.y,
                },
            ),
            (
                "below",
                ax::Point {
                    x: original.x,
                    y: bottom + 200.0,
                },
            ),
        ] {
            background(person)?;
            scratch.prove()?;
            let text = scratch.text_element()?;
            ax::reset_caret(&text)?;
            let start = Instant::now();
            let mut restore = Restore {
                scratch,
                window: ax::retain(&window),
                original,
                person,
                person_start,
                active: true,
            };
            let move_start = Instant::now();
            let move_result = ax::set_point(&window, requested);
            let move_call_ms = move_start.elapsed().as_secs_f64() * 1000.0;
            std::thread::sleep(Duration::from_millis(50));
            let actual = ax::point(&window)?;
            let move_ms = move_start.elapsed().as_secs_f64() * 1000.0;
            let fully_offscreen = !displays.iter().any(|r| ax::intersects(actual, size, *r));
            scratch.log.event("AXPosition_before_front",json!({"direction":direction,"requested":[requested.x,requested.y],
                "actual":[actual.x,actual.y],"original":[original.x,original.y],"size":[size.width,size.height],
                "move_ok":move_result.is_ok(),"reason":move_result.err(),"move_call_ms":move_call_ms,"settle_delay_ms":50,"move_and_settle_ms":move_ms,"fully_offscreen":fully_offscreen}));
            // This is the only intentional activation in the probe. A failed
            // move is not permission to front a visible window.
            if move_result.is_err() {
                restore.restore()?;
                continue;
            }
            background(person)?;
            let front = Instant::now();
            let requested_front = mac::activate_application(scratch.pid, scratch.start);
            let front_confirmed = requested_front && wait_front(scratch.pid as i32);
            let front_ms = front.elapsed().as_secs_f64() * 1000.0;
            let mut posted = false;
            let mut post_ms = None;
            let mut position_at_post = None;
            if front_confirmed
                && !INTERRUPTED.load(Ordering::SeqCst)
                && mac::screen_is_locked() == Some(false)
            {
                scratch.prove()?;
                let events = mac::key_combination_events(
                    mac::VirtualKey::A,
                    mac::KeyModifiers {
                        command: true,
                        ..Default::default()
                    },
                )
                .map_err(|_| "Command-A construction failed")?;
                if ax::front_pid()? == scratch.pid as i32 {
                    position_at_post = ax::point(&window).ok();
                    let post = Instant::now();
                    for event in &events {
                        let _ = mac::post_event_to_pid(scratch.pid as i32, event);
                    }
                    post_ms = Some(post.elapsed().as_secs_f64() * 1000.0);
                    posted = true;
                }
            }
            let restored = restore.restore();
            std::thread::sleep(Duration::from_millis(100));
            let range = ax::range(&text);
            let after = ax::point(&window)?;
            scratch.log.event("offscreen_front_Command_A",json!({"direction":direction,"fully_offscreen_before_front":fully_offscreen,
                "position_at_post":position_at_post.map(|p|[p.x,p.y]),
                "fully_offscreen_at_post":position_at_post.map(|p|!displays.iter().any(|r|ax::intersects(p,size,*r))),
                "front_confirmed":front_confirmed,"front_ms":front_ms,"posted":posted,"post_ms":post_ms,
                "effect":range.as_ref().ok().map(|r|super::whole_selection(r.location,r.length,TEXT)),"readback_error":range.as_ref().err(),
                "restore_ok":restored.is_ok(),"restore_reason":restored.as_ref().err(),
                "restore_app_ms":restored.as_ref().ok().map(|r|r.0),"restore_move_ms":restored.as_ref().ok().map(|r|r.1),
                "position_after_restore":[after.x,after.y],"total_ms":start.elapsed().as_secs_f64()*1000.0,
                "front":sampler.summary(start,person)}));
            restored?;
            background(person)?;
        }
        Ok(())
    }

    fn run(log: Log, nonce: &str) -> Result<()> {
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            // SAFETY: the signal handler only stores into a static atomic.
            unsafe {
                signal_hook::low_level::register(signal, || {
                    INTERRUPTED.store(true, Ordering::SeqCst)
                })
            }
            .map_err(|_| "interrupt handler installation failed")?;
        }
        let person = ax::front_pid()?;
        let person_start = mac::process_start_time_micros(person as u32)
            .ok_or("person's app generation unreadable")?;
        log.event("start",json!({"sampling_target_ms":10,"privacy":"no screen capture, menu titles, external text, pasteboard, daemon or journal access"}));
        let sampler = Sampler::start(log.clone(), person);
        let launch_start = Instant::now();
        let scratch = Scratch::launch(log.clone(), nonce)?;
        sampler.target.store(scratch.pid, Ordering::SeqCst);
        log.event("LaunchServices_background_open",json!({"total_ms":launch_start.elapsed().as_secs_f64()*1000.0,"front":sampler.summary(launch_start,person)}));
        background(person)?;
        std::thread::sleep(Duration::from_millis(100));
        selection_case(&scratch, &sampler, person, false)?;
        selection_case(&scratch, &sampler, person, true)?;
        menu_cases(&scratch, &sampler, person)?;
        log.event("Mail",json!({"skip":"no proven no-front compose/discard ownership path; Mail is not opened or queried"}));
        offscreen_cases(&scratch, &sampler, person, person_start)?;
        log.event("finished",json!({"meaning":"measurement completed; per-case false/unknown/skipped are not successes"}));
        Ok(())
    }

    mod ax {
        use super::Result;
        use std::ffi::{c_void, CString};
        type Ref = *const c_void;
        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq)]
        pub struct Point {
            pub x: f64,
            pub y: f64,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Size {
            pub width: f64,
            pub height: f64,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Rect {
            pub origin: Point,
            pub size: Size,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Range {
            pub location: isize,
            pub length: isize,
        }

        #[link(name = "ApplicationServices", kind = "framework")]
        extern "C" {
            fn AXUIElementCreateApplication(pid: i32) -> Ref;
            fn AXUIElementCreateSystemWide() -> Ref;
            fn AXUIElementGetPid(element: Ref, pid: *mut i32) -> i32;
            fn AXUIElementGetTypeID() -> usize;
            fn AXUIElementSetMessagingTimeout(element: Ref, timeout: f32) -> i32;
            fn AXUIElementCopyAttributeValue(element: Ref, name: Ref, value: *mut Ref) -> i32;
            fn AXUIElementSetAttributeValue(element: Ref, name: Ref, value: Ref) -> i32;
            fn AXUIElementCopyActionNames(element: Ref, value: *mut Ref) -> i32;
            fn AXUIElementPerformAction(element: Ref, action: Ref) -> i32;
            fn AXUIElementCopyParameterizedAttributeValue(
                element: Ref,
                name: Ref,
                parameter: Ref,
                value: *mut Ref,
            ) -> i32;
            fn AXValueCreate(kind: u32, value: *const c_void) -> Ref;
            fn AXValueGetTypeID() -> usize;
            fn AXValueGetType(value: Ref) -> u32;
            fn AXValueGetValue(value: Ref, kind: u32, output: *mut c_void) -> u8;
        }
        #[link(name = "CoreFoundation", kind = "framework")]
        extern "C" {
            fn CFStringCreateWithCString(allocator: Ref, text: *const i8, encoding: u32) -> Ref;
            fn CFStringGetTypeID() -> usize;
            fn CFStringGetLength(value: Ref) -> isize;
            fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
            fn CFStringGetCString(value: Ref, buffer: *mut i8, size: isize, encoding: u32) -> u8;
            fn CFArrayGetTypeID() -> usize;
            fn CFArrayGetCount(value: Ref) -> isize;
            fn CFArrayGetValueAtIndex(value: Ref, index: isize) -> Ref;
            fn CFArrayCreate(
                allocator: Ref,
                values: *const Ref,
                count: isize,
                callbacks: Ref,
            ) -> Ref;
            fn CFNumberCreate(allocator: Ref, kind: isize, value: *const c_void) -> Ref;
            fn CFNumberGetTypeID() -> usize;
            fn CFNumberGetValue(number: Ref, kind: isize, value: *mut c_void) -> u8;
            fn CFBooleanGetTypeID() -> usize;
            fn CFBooleanGetValue(value: Ref) -> u8;
            fn CFGetTypeID(value: Ref) -> usize;
            fn CFRetain(value: Ref) -> Ref;
            fn CFRelease(value: Ref);
        }
        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {
            fn CGGetActiveDisplayList(max: u32, displays: *mut u32, count: *mut u32) -> i32;
            fn CGDisplayBounds(display: u32) -> Rect;
        }
        #[link(name = "objc")]
        extern "C" {
            fn objc_getClass(name: *const i8) -> Ref;
            fn sel_registerName(name: *const i8) -> Ref;
            fn objc_msgSend();
            fn objc_autoreleasePoolPush() -> *mut c_void;
            fn objc_autoreleasePoolPop(pool: *mut c_void);
        }

        pub struct Owned(Ref);
        impl Drop for Owned {
            fn drop(&mut self) {
                // SAFETY: Owned always holds one non-null retained CF object.
                unsafe { CFRelease(self.0) }
            }
        }
        fn owned(value: Ref) -> Result<Owned> {
            if value.is_null() {
                Err("null AX/CF object")
            } else {
                Ok(Owned(value))
            }
        }
        pub fn retain(value: &Owned) -> Owned {
            // SAFETY: value is live and CFRetain adds the returned ownership.
            Owned(unsafe { CFRetain(value.0) })
        }
        fn string(text: &str) -> Owned {
            let text = CString::new(text).expect("static AX attribute without NUL");
            // SAFETY: text is NUL-terminated UTF-8 for the duration of the call.
            owned(unsafe {
                CFStringCreateWithCString(std::ptr::null(), text.as_ptr(), 0x0800_0100)
            })
            .expect("CFString allocation")
        }
        fn status(code: i32) -> Result<()> {
            match code {
                0 => Ok(()),
                -25200 => Err("AX failure (-25200)"),
                -25201 => Err("AX illegal argument (-25201)"),
                -25202 => Err("AX invalid element (-25202)"),
                -25204 => Err("AX cannot complete (-25204); effect requires readback"),
                -25205 => Err("AX attribute unsupported (-25205)"),
                -25206 => Err("AX action unsupported (-25206)"),
                -25211 => Err("AX API disabled (-25211)"),
                -25212 => Err("AX no value (-25212)"),
                -25213 => Err("AX parameterized attribute unsupported (-25213)"),
                _ => Err("other AX error"),
            }
        }
        pub fn app(pid: u32) -> Result<Owned> {
            // SAFETY: application references can be created for any PID;
            // callers establish ownership separately before acting on them.
            let value = owned(unsafe { AXUIElementCreateApplication(pid as i32) })?;
            // SAFETY: value is an application AX element, timeout is seconds.
            status(unsafe { AXUIElementSetMessagingTimeout(value.0, 0.3) })?;
            Ok(value)
        }
        pub fn attr(element: &Owned, name: &str) -> Result<Owned> {
            let mut result = std::ptr::null();
            // SAFETY: both CF objects are live; result is writable CF storage.
            status(unsafe {
                AXUIElementCopyAttributeValue(element.0, string(name).0, &mut result)
            })?;
            owned(result)
        }
        fn set(element: &Owned, name: &str, value: &Owned) -> Result<()> {
            // SAFETY: all objects remain retained for this synchronous call.
            status(unsafe { AXUIElementSetAttributeValue(element.0, string(name).0, value.0) })
        }
        fn string_text(value: &Owned) -> Result<String> {
            // SAFETY: value is live; check the type before invoking CFString.
            unsafe {
                if CFGetTypeID(value.0) != CFStringGetTypeID() {
                    return Err("AX value is not a string");
                }
                let size =
                    CFStringGetMaximumSizeForEncoding(CFStringGetLength(value.0), 0x0800_0100) + 1;
                if !(1..=1_000_000).contains(&size) {
                    return Err("AX string too large");
                }
                let mut bytes = vec![0_u8; size as usize];
                if CFStringGetCString(value.0, bytes.as_mut_ptr().cast(), size, 0x0800_0100) == 0 {
                    return Err("AX string decode failed");
                }
                let length = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                String::from_utf8(bytes[..length].to_vec()).map_err(|_| "AX invalid UTF-8")
            }
        }
        pub fn text(element: &Owned, name: &str) -> Result<String> {
            string_text(&attr(element, name)?)
        }
        fn refs(value: &Owned) -> Result<Vec<Owned>> {
            // SAFETY: check the CFArray type and bound its count before reads;
            // retain each borrowed element while the array remains alive.
            unsafe {
                if CFGetTypeID(value.0) != CFArrayGetTypeID() {
                    return Err("AX value is not an array");
                }
                let count = CFArrayGetCount(value.0);
                if !(0..=4096).contains(&count) {
                    return Err("AX array exceeds probe bound");
                }
                (0..count)
                    .map(|i| owned(CFRetain(CFArrayGetValueAtIndex(value.0, i))))
                    .collect()
            }
        }
        pub fn array(element: &Owned, name: &str) -> Result<Vec<Owned>> {
            let values = refs(&attr(element, name)?)?;
            // SAFETY: all values are retained; reject non-element references.
            if values
                .iter()
                .any(|v| unsafe { CFGetTypeID(v.0) != AXUIElementGetTypeID() })
            {
                return Err("AX children contain non-elements");
            }
            Ok(values)
        }
        pub fn boolean(element: &Owned, name: &str) -> Result<bool> {
            let value = attr(element, name)?;
            // SAFETY: check CFBoolean type before reading it.
            unsafe {
                if CFGetTypeID(value.0) != CFBooleanGetTypeID() {
                    return Err("AX value is not boolean");
                }
                Ok(CFBooleanGetValue(value.0) != 0)
            }
        }
        fn number(element: &Owned, name: &str) -> Result<i64> {
            let value = attr(element, name)?;
            let mut output = 0_i64;
            // SAFETY: check CFNumber type and use kCFNumberSInt64Type storage.
            unsafe {
                if CFGetTypeID(value.0) != CFNumberGetTypeID()
                    || CFNumberGetValue(value.0, 4, (&mut output as *mut i64).cast()) == 0
                {
                    return Err("AX number unreadable");
                }
            }
            Ok(output)
        }
        fn value<T: Copy>(element: &Owned, name: &str, kind: u32, mut output: T) -> Result<T> {
            let value = attr(element, name)?;
            // SAFETY: callers pair the AXValue kind with the corresponding
            // repr(C) storage. Check the runtime type and kind before copying.
            unsafe {
                if CFGetTypeID(value.0) != AXValueGetTypeID() || AXValueGetType(value.0) != kind {
                    return Err("AXValue kind mismatch");
                }
                if AXValueGetValue(value.0, kind, (&mut output as *mut T).cast()) == 0 {
                    return Err("AXValue read failed");
                }
            }
            Ok(output)
        }
        fn set_value<T>(element: &Owned, name: &str, kind: u32, value: T) -> Result<()> {
            // SAFETY: callers pair kind with a correctly laid-out repr(C) T;
            // AXValueCreate copies the pointed-to bytes before returning.
            let value = owned(unsafe { AXValueCreate(kind, (&value as *const T).cast()) })?;
            set(element, name, &value)
        }
        pub fn point(element: &Owned) -> Result<Point> {
            value(element, "AXPosition", 1, Point { x: 0.0, y: 0.0 })
        }
        pub fn size(element: &Owned) -> Result<Size> {
            value(
                element,
                "AXSize",
                2,
                Size {
                    width: 0.0,
                    height: 0.0,
                },
            )
        }
        pub fn range(element: &Owned) -> Result<Range> {
            value(
                element,
                "AXSelectedTextRange",
                4,
                Range {
                    location: 0,
                    length: 0,
                },
            )
        }
        pub fn set_point(element: &Owned, point: Point) -> Result<()> {
            set_value(element, "AXPosition", 1, point)
        }
        pub fn set_range(element: &Owned, location: isize, length: isize) -> Result<()> {
            set_value(
                element,
                "AXSelectedTextRange",
                4,
                Range { location, length },
            )
        }
        pub fn reset_caret(element: &Owned) -> Result<()> {
            set_range(element, 0, 0)?;
            let actual = range(element)?;
            if actual.location == 0 && actual.length == 0 {
                Ok(())
            } else {
                Err("caret reset not verified; no valid Select All comparison")
            }
        }

        fn parameter(element: &Owned, name: &str, input: &Owned) -> Result<Owned> {
            let mut output = std::ptr::null();
            // SAFETY: element, name and parameter are live retained objects.
            status(unsafe {
                AXUIElementCopyParameterizedAttributeValue(
                    element.0,
                    string(name).0,
                    input.0,
                    &mut output,
                )
            })?;
            owned(output)
        }
        pub fn select_markers(element: &Owned, length: usize) -> Result<()> {
            let number = |index: i64| {
                // SAFETY: kCFNumberSInt64Type with matching i64 storage.
                owned(unsafe { CFNumberCreate(std::ptr::null(), 4, (&index as *const i64).cast()) })
            };
            // These WebKit parameterized attributes are not universal AX
            // contracts. Unsupported is an observation, not a failed fallback.
            let start = parameter(element, "AXTextMarkerForIndex", &number(0)?)?;
            let end = parameter(element, "AXTextMarkerForIndex", &number(length as i64)?)?;
            let pointers = [start.0, end.0];
            // SAFETY: the two marker objects outlive this no-callback array and
            // the parameter call, which synchronously consumes its contents.
            let pair = owned(unsafe {
                CFArrayCreate(std::ptr::null(), pointers.as_ptr(), 2, std::ptr::null())
            })?;
            let range = parameter(element, "AXTextMarkerRangeForUnorderedTextMarkers", &pair)?;
            set(element, "AXSelectedTextMarkerRange", &range)
        }
        pub fn actions(element: &Owned) -> Result<Vec<String>> {
            let mut output = std::ptr::null();
            // SAFETY: output is writable CF storage and element is retained.
            status(unsafe { AXUIElementCopyActionNames(element.0, &mut output) })?;
            refs(&owned(output)?)?.iter().map(string_text).collect()
        }
        pub fn press(element: &Owned) -> Result<()> {
            // SAFETY: AXPress is sent only to the unique scratch menu match.
            status(unsafe { AXUIElementPerformAction(element.0, string("AXPress").0) })
        }
        pub fn menu_matches(
            element: &Owned,
            character: &str,
            depth: usize,
            visited: &mut usize,
            found: &mut Vec<Owned>,
        ) -> Result<()> {
            *visited += 1;
            if *visited > 4096 || depth > 12 {
                return Err("menu traversal exceeded probe bound");
            }
            if text(element, "AXMenuItemCmdChar").is_ok_and(|c| c.eq_ignore_ascii_case(character))
                && number(element, "AXMenuItemCmdModifiers") == Ok(0)
            {
                found.push(retain(element));
            }
            match array(element, "AXChildren") {
                Ok(children) => {
                    for child in children {
                        menu_matches(&child, character, depth + 1, visited, found)?;
                    }
                }
                Err("AX attribute unsupported (-25205)" | "AX no value (-25212)") => {}
                Err(reason) => return Err(reason),
            }
            Ok(())
        }
        pub fn front_pid() -> Result<i32> {
            // SAFETY: creation transfers one ownership; timeout bounds the live
            // system-wide focus read independently of the window's visibility.
            let system = owned(unsafe { AXUIElementCreateSystemWide() })?;
            status(unsafe { AXUIElementSetMessagingTimeout(system.0, 0.05) })?;
            let focused = attr(&system, "AXFocusedApplication")?;
            let mut pid = 0;
            // SAFETY: focused is an AX application; pid is writable storage.
            status(unsafe { AXUIElementGetPid(focused.0, &mut pid) })?;
            if pid > 0 {
                Ok(pid)
            } else {
                Err("AX focused app absent")
            }
        }
        pub fn menu_owner() -> Option<i32> {
            // SAFETY: documented NSWorkspace/NSRunningApplication selectors;
            // objc_msgSend is cast to their exact pointer/i32 ABIs. The process
            // runs the AppKit main loop so workspace caches receive updates.
            unsafe {
                let pool = objc_autoreleasePoolPush();
                let result = (|| {
                    let send: unsafe extern "C" fn(Ref, Ref) -> Ref =
                        std::mem::transmute(objc_msgSend as *const ());
                    let integer: unsafe extern "C" fn(Ref, Ref) -> i32 =
                        std::mem::transmute(objc_msgSend as *const ());
                    let class = objc_getClass(c"NSWorkspace".as_ptr());
                    if class.is_null() {
                        return None;
                    }
                    let workspace = send(class, sel_registerName(c"sharedWorkspace".as_ptr()));
                    let app = send(
                        workspace,
                        sel_registerName(c"menuBarOwningApplication".as_ptr()),
                    );
                    if app.is_null() {
                        return None;
                    }
                    let pid = integer(app, sel_registerName(c"processIdentifier".as_ptr()));
                    (pid > 0).then_some(pid)
                })();
                objc_autoreleasePoolPop(pool);
                result
            }
        }
        pub fn displays() -> Result<Vec<Rect>> {
            let mut ids = [0_u32; 32];
            let mut count = 0;
            // SAFETY: array has space for the requested maximum display IDs.
            if unsafe { CGGetActiveDisplayList(32, ids.as_mut_ptr(), &mut count) } != 0
                || count == 0
                || count > 32
            {
                return Err("active display geometry unavailable");
            }
            // SAFETY: each ID came from the just-read active display list.
            Ok(ids[..count as usize]
                .iter()
                .map(|id| unsafe { CGDisplayBounds(*id) })
                .collect())
        }
        pub fn intersects(point: Point, size: Size, screen: Rect) -> bool {
            point.x < screen.origin.x + screen.size.width
                && point.x + size.width > screen.origin.x
                && point.y < screen.origin.y + screen.size.height
                && point.y + size.height > screen.origin.y
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn approval_requires_exact_value_and_scratch_data_home() {
        assert!(super::approved(Some("1"), true));
        for value in [None, Some("0"), Some("true"), Some("1 ")] {
            assert!(!super::approved(value, true));
        }
        assert!(!super::approved(Some("1"), false));
    }

    #[test]
    fn scratch_ownership_requires_unique_new_generation_and_document() {
        let doc = String::from("file:///private/tmp/cereb-desk/scratch/doc.txt");
        let proof = |before: &[u32], after: &[u32], start, docs: &[String]| {
            super::owns_scratch(42, before, after, 99, start, docs, &doc)
        };
        assert!(proof(&[], &[42], Some(99), std::slice::from_ref(&doc)));
        assert!(!proof(&[42], &[42], Some(99), std::slice::from_ref(&doc)));
        assert!(!proof(&[], &[42, 43], Some(99), std::slice::from_ref(&doc)));
        assert!(!proof(&[], &[42], Some(100), std::slice::from_ref(&doc)));
        assert!(!proof(&[], &[42], None, std::slice::from_ref(&doc)));
        assert!(!proof(&[], &[42], Some(99), &[]));
        assert!(!proof(&[], &[42], Some(99), &["file:///person.txt".into()]));
        assert!(!proof(&[], &[42], Some(99), &[doc.clone(), doc.clone()]));
    }

    #[test]
    fn select_all_needs_nonempty_whole_utf16_range_not_a_success_code() {
        assert!(super::whole_selection(0, 4, "a🙂b"));
        assert!(!super::whole_selection(0, 3, "a🙂b"));
        assert!(!super::whole_selection(1, 4, "a🙂b"));
        assert!(!super::whole_selection(0, 0, ""));
        assert!(!super::whole_selection(0, -1, "abc"));
    }
}
