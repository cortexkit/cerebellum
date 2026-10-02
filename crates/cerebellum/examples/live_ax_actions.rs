//! Drive the accessibility actions against a running application through the
//! served plane, the way `computer.write_text`, `computer.press_element` and
//! `computer.press_point` are served, and report what the frontmost
//! application did meanwhile.
//!
//! What it does, in order:
//!
//! 1. Reads the application's state with its window image.
//! 2. Writes a marker text into the first settable text element with
//!    `write_text` (`replace_value`) and reports whether the read-back
//!    confirmed it. Run it against a backgrounded TextEdit document or a
//!    Discord composer: the write goes through accessibility, so the
//!    application stays in the background.
//! 3. With `--press <label>`, presses the first button whose label contains
//!    that text with `press_element`. No button is pressed without it,
//!    because pressing an arbitrary button can close a window or send a
//!    message.
//! 4. With `--point <x>,<y>`, presses whatever the read's image shows at that
//!    pixel with `press_point`.
//! 5. With `--bracket`, and only then, types a short text through the fronting
//!    bracket, which brings the application forward for at most 100 ms at a
//!    time and puts the previous one back. This is the only arm that fronts
//!    anything. It also times per-process posting, so the number of
//!    characters one bracket interval can carry is measured rather than
//!    assumed.
//!
//! Throughout, a sampler reads the frontmost application every 100 ms and the
//! run reports every sample, so a change of frontmost application outside the
//! bracket arm is visible rather than asserted away.
//!
//! Run with:
//!
//! ```text
//! cargo run -p cerebellum --example live_ax_actions -- [bundle-identity] \
//!     [--press <label>] [--point <x>,<y>] [--bracket]
//! ```
//!
//! Without a bundle identity it uses TextEdit, then Discord. It prints
//! `UNMEASURABLE` and exits 2 when the screen is locked, because a locked
//! session hides windows from accessibility and nothing measured would mean
//! anything.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe drives macOS accessibility and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(macos_probe::run());
}

#[cfg(target_os = "macos")]
mod macos_probe {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use cerebellum::computer_capability::{
        computer_audit, servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
    };
    use cerebellum::computer_grants::{
        AlwaysOpenRoute, ConsentContext, GrantCaller, QuestionCarrier,
    };
    use cerebellum::elicit::AskOutcome;
    use cerebellum::management::{ManagementPlane, PlatformResolver};
    use cerebellum::JournalPersistence;
    use cerebellum_computer::platform::native::NativeCaptureBackend;
    use cerebellum_computer::platform::{
        MacOs26PlatformDriver, PlatformDriver, SyntheticAction, SyntheticDispatchRequest,
        TargetResolution,
    };
    use cerebellum_core::clock::SystemClock;
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::JournalIdentity;
    use serde_json::{json, Value};

    const CANDIDATES: [&str; 2] = ["com.apple.TextEdit", "com.hnc.Discord"];

    /// Answers every question "allow for this conversation": running this
    /// probe is the person's consent to what it does, and each arm that goes
    /// beyond a write is named on the command line.
    struct Allowing;

    impl QuestionCarrier for Allowing {
        fn put(
            &self,
            _question: Value,
            _deadline: Duration,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AskOutcome> + Send>> {
            Box::pin(async { AskOutcome::Answered(json!({"decision": "allow_conversation"})) })
        }
    }

    struct Options {
        bundle: Option<String>,
        press: Option<String>,
        point: Option<(u64, u64)>,
        bracket: bool,
    }

    fn options() -> Result<Options, String> {
        let mut options = Options {
            bundle: None,
            press: None,
            point: None,
            bracket: false,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--press" => options.press = Some(args.next().ok_or("--press needs a label")?),
                "--point" => {
                    let raw = args.next().ok_or("--point needs x,y")?;
                    let (x, y) = raw.split_once(',').ok_or("--point needs x,y")?;
                    options.point = Some((
                        x.trim().parse().map_err(|_| "x is not a number")?,
                        y.trim().parse().map_err(|_| "y is not a number")?,
                    ));
                }
                "--bracket" => options.bracket = true,
                other if other.starts_with("--") => return Err(format!("unknown option {other}")),
                bundle => options.bundle = Some(bundle.to_string()),
            }
        }
        Ok(options)
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "live-probe".into(),
            conversation_key: "live-ax-actions".into(),
            agent_project_id: "live-probe".into(),
            session_kind: SessionKind::Primary,
            origin: Default::default(),
        }
    }

    fn consent() -> ConsentContext {
        let (drain_sender, drain) = tokio::sync::watch::channel(false);
        std::mem::forget(drain_sender);
        ConsentContext::new(
            GrantCaller {
                conversation_key: identity().conversation_key,
                agent_project_id: identity().agent_project_id,
                durable_identity_attested: false,
            },
            Some(Arc::new(Allowing) as Arc<dyn QuestionCarrier>),
            Arc::new(AlwaysOpenRoute),
            drain,
            None,
        )
    }

    /// One sample: milliseconds since sampling began, and the frontmost pid.
    type Sample = (u128, Option<i32>);

    /// The frontmost application, sampled every 100 ms until stopped.
    struct Sampler {
        samples: Arc<Mutex<Vec<Sample>>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Sampler {
        fn start() -> Self {
            let samples = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let started = Instant::now();
            let thread = {
                let samples = samples.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        samples.lock().unwrap().push((
                            started.elapsed().as_millis(),
                            cerebellum_macos::frontmost_process_id(),
                        ));
                        std::thread::sleep(Duration::from_millis(100));
                    }
                })
            };
            Self {
                samples,
                stop,
                thread: Some(thread),
            }
        }

        fn finish(mut self) -> Vec<Sample> {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let samples = self.samples.lock().unwrap().clone();
            samples
        }
    }

    pub fn run() -> i32 {
        let options = match options() {
            Ok(options) => options,
            Err(problem) => {
                println!("FAILED: {problem}");
                return 1;
            }
        };
        if cerebellum_macos::screen_is_locked() == Some(true) {
            println!(
                "UNMEASURABLE: the screen is locked, so windows are hidden from accessibility \
                 and no action here could be verified"
            );
            return 2;
        }
        if !cerebellum_macos::accessibility_is_permitted() {
            println!("UNMEASURABLE: this process may not use accessibility");
            return 2;
        }
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                println!("FAILED: no runtime: {error}");
                return 1;
            }
        };
        runtime.block_on(probe(options))
    }

    async fn probe(options: Options) -> i32 {
        let resolver = PlatformResolver::new();
        let candidates: Vec<String> = match &options.bundle {
            Some(bundle) => vec![bundle.clone()],
            None => CANDIDATES.iter().map(ToString::to_string).collect(),
        };
        let resolved = candidates.iter().find_map(|bundle| {
            match cerebellum_computer::platform::native::resolve_target(
                bundle,
                Duration::from_secs(3),
            ) {
                TargetResolution::Resolved(grant) => Some(grant),
                _ => None,
            }
        });
        let Some(target) = resolved else {
            println!("FAILED: none of {candidates:?} is running as exactly one process");
            return 1;
        };
        let audit = match computer_audit(JournalPersistence::Isolated) {
            Ok(audit) => audit,
            Err(error) => {
                println!("FAILED: no isolated journal: {error}");
                return 1;
            }
        };
        let bracket_revision = options.bracket.then(|| "live-probe-unreviewed".to_string());
        let driver_revision = bracket_revision.clone();
        let plane = ComputerPlane::<NativeCaptureBackend, _, _, _, _>::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::Withhold,
            move || {
                MacOs26PlatformDriver::default()
                    .without_expected_post_condition()
                    .with_takeover_dispatch_review_revision(driver_revision.clone())
            },
        )
        .with_fronting_bracket_admitted(options.bracket);
        let management = Arc::new(ManagementPlane::new(Arc::new(resolver)));
        let clock = SystemClock::new();
        let serve = |name: &'static str, arguments: Value| {
            let plane = &plane;
            let management = &management;
            let clock = &clock;
            async move {
                plane
                    .serve(
                        servable(name).expect("the capability is served"),
                        &arguments,
                        ServeContext {
                            cancel: cerebellum::CancelHandle::pending(),
                            grantee: "live-probe",
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

        println!(
            "application: {} (pid {})",
            target.bundle_identity, target.pid
        );
        let sampler = Sampler::start();
        let frontmost_before = cerebellum_macos::frontmost_process_id();
        let mut failed = false;

        let read = serve(
            "computer.read_state",
            json!({"target": target.bundle_identity, "include_image": true}),
        )
        .await;
        let tree = read["tree"].as_str().unwrap_or_default().to_string();
        println!(
            "read_state: {} ({} lines, image {})",
            read["outcome"],
            tree.lines().count(),
            if read.get("image").is_some() {
                "returned"
            } else {
                "absent"
            }
        );

        let settable = tree.lines().find(|line| {
            (line.contains(" text area ") || line.contains(" text field "))
                && line.contains("settable")
        });
        match settable.and_then(|line| line.split_whitespace().next()) {
            Some(element_id) => {
                let marker = format!("cerebellum live probe {}", std::process::id());
                let reply = serve(
                    "computer.write_text",
                    json!({"element_id": element_id, "text": marker, "write_mode": "replace_value"}),
                )
                .await;
                println!(
                    "write_text {element_id}: {} (effect {})",
                    reply["outcome"], reply["effect_status"]
                );
                failed |= reply["outcome"] != "completed";
            }
            None => {
                println!("write_text: SKIPPED, no settable text element in the tree");
                failed = true;
            }
        }

        match &options.press {
            Some(label) => {
                let button = tree
                    .lines()
                    .find(|line| line.contains(" button ") && line.contains(label.as_str()))
                    .and_then(|line| line.split_whitespace().next());
                match button {
                    Some(element_id) => {
                        let reply =
                            serve("computer.press_element", json!({"element_id": element_id}))
                                .await;
                        println!(
                            "press_element {element_id}: {} (changed {}, added {}, removed {})",
                            reply["outcome"],
                            reply["changed"].as_array().map_or(0, Vec::len),
                            reply["added"].as_array().map_or(0, Vec::len),
                            reply["removed"].as_array().map_or(0, Vec::len)
                        );
                        failed |= reply["outcome"] != "completed";
                    }
                    None => {
                        println!("press_element: no button labelled {label:?}");
                        failed = true;
                    }
                }
            }
            None => println!("press_element: SKIPPED, name a harmless button with --press <label>"),
        }

        match (options.point, read["image"]["image_id"].as_str()) {
            (Some((x, y)), Some(image_id)) => {
                let reply = serve(
                    "computer.press_point",
                    json!({"image_id": image_id, "x": x, "y": y}),
                )
                .await;
                println!("press_point ({x}, {y}): {}", reply["outcome"]);
                failed |= reply["outcome"] != "completed";
            }
            (Some(_), None) => {
                println!(
                    "press_point: the read returned no image: {}",
                    read["image_unavailable"]
                );
                failed = true;
            }
            (None, _) => {
                println!("press_point: SKIPPED, give a pixel of the image with --point x,y")
            }
        }

        if options.bracket {
            measure_post_rate(&target);
            let reply = serve(
                "computer.type",
                json!({"target": target.bundle_identity, "text": " bracket"}),
            )
            .await;
            println!(
                "type through the bracket: {} (target_fronted {}, {})",
                reply["outcome"], reply["target_fronted"], reply["containment_forfeited_because"]
            );
        }

        let frontmost_after = cerebellum_macos::frontmost_process_id();
        let samples = sampler.finish();
        let distinct: std::collections::BTreeSet<Option<i32>> =
            samples.iter().map(|(_, pid)| *pid).collect();
        println!("frontmost samples every 100 ms (elapsed ms, pid):");
        for (elapsed, pid) in &samples {
            println!("  {elapsed:>6} {pid:?}");
        }
        let unchanged = frontmost_before == frontmost_after && distinct.len() <= 1;
        println!(
            "frontmost: before {frontmost_before:?}, after {frontmost_after:?}, {} distinct \
             sampled",
            distinct.len()
        );
        if !options.bracket && !unchanged {
            println!("FAILED: the frontmost application changed in a run that fronts nothing");
            return 1;
        }
        if failed {
            println!("FAILED: an arm that ran did not complete");
            return 1;
        }
        println!("PASS");
        0
    }

    /// Time per-process posting of typed text to the target, so the share of
    /// one bracket interval a character takes is a measurement. Posts go to
    /// the target in the background, like the bracket's own posts would.
    fn measure_post_rate(target: &cerebellum_computer::platform::ProcessGrant) {
        let mut driver = MacOs26PlatformDriver::default();
        let text = "0123456789";
        let started = Instant::now();
        for character in text.chars() {
            let _ = driver.dispatch_per_pid(
                SyntheticDispatchRequest {
                    target: target.clone(),
                    action: SyntheticAction::type_text(character.to_string()),
                },
                &|| false,
            );
        }
        let per_character = started.elapsed().as_secs_f64() * 1000.0 / text.len() as f64;
        println!(
            "per-process post: {per_character:.2} ms per character, so about {:.0} characters \
             fit a 100 ms bracket interval before fronting and restoring are counted",
            100.0 / per_character.max(0.01)
        );
    }
}
