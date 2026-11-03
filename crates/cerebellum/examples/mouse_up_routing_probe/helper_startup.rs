//! Query-only startup/restart measurement. No drawing or synthetic input.

use cerebellum_computer::pointer_query::{Client, Reply, MAX_REPLY_BYTES};
use cerebellum_macos::{
    pointer_helper_startup_sample, PointerHelperStartupSample, ProcessGeneration,
};
use std::error::Error;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

enum Command {
    Track(ProcessGeneration, mpsc::SyncSender<()>),
    Finish(Instant),
}

struct Sample {
    at: Instant,
    state: PointerHelperStartupSample,
}

struct Sampler {
    commands: mpsc::Sender<Command>,
    worker: Option<thread::JoinHandle<Vec<Sample>>>,
}

impl Sampler {
    fn start() -> Result<Self> {
        let (commands, rx) = mpsc::channel();
        let (ready, started) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("helper-startup-sampler".into())
            .spawn(move || {
                let mut helpers = Vec::new();
                let mut samples = vec![Sample {
                    at: Instant::now(),
                    state: pointer_helper_startup_sample(&helpers),
                }];
                let _ = ready.send(());
                let mut end = None;
                loop {
                    let ack = match rx.recv_timeout(Duration::from_millis(2)) {
                        Ok(Command::Track(helper, ack)) => {
                            helpers.push(helper);
                            Some(ack)
                        }
                        Ok(Command::Finish(at)) => {
                            end = Some(at);
                            None
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let state = pointer_helper_startup_sample(&helpers);
                    if samples.last().is_none_or(|sample| sample.state != state) {
                        samples.push(Sample {
                            at: Instant::now(),
                            state,
                        });
                    }
                    if let Some(ack) = ack {
                        let _ = ack.send(());
                    }
                    if end.is_some_and(|end| Instant::now() >= end) {
                        // Retain an endpoint even if the final state is
                        // unchanged, so the table shows the sampling coverage.
                        samples.push(Sample {
                            at: Instant::now(),
                            state: pointer_helper_startup_sample(&helpers),
                        });
                        break;
                    }
                }
                samples
            })?;
        started.recv()?;
        Ok(Self {
            commands,
            worker: Some(worker),
        })
    }

    fn track(&self, generation: ProcessGeneration) -> Result<()> {
        let (ack, sampled) = mpsc::sync_channel(1);
        self.commands.send(Command::Track(generation, ack))?;
        sampled.recv()?;
        Ok(())
    }

    fn finish(mut self, at: Instant) -> Result<Vec<Sample>> {
        self.commands.send(Command::Finish(at))?;
        self.worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| "sampler panicked".into())
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Finish(Instant::now()));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) fn run(executable: &Path) -> Result<()> {
    // Start sampling before pinning or launching anything. Unlike the routing
    // mode, the parent probe does not initialize NSApplication or post input.
    let origin = Instant::now();
    let sampler = Sampler::start()?;
    let mut events = Vec::new();
    let mut last_query = origin;
    let result = (|| -> Result<()> {
        let pin = cerebellum_macos::PinnedExecutable::for_probe(executable)?;
        let path = pin.launch_path()?;
        let mut queries_ok = true;
        for launch in 1..=2 {
            let (barred, pipe, replies) =
                cerebellum_macos::spawn_barred_cursor(&path, &["--agent-cursor".into()])
                    .map_err(|error| format!("helper spawn: {error:?}"))?;
            let generation = barred.generation();
            sampler.track(generation)?;
            if !pin.accepts_child(generation.pid) {
                return Err("pinned helper child verification failed".into());
            }
            let child = barred
                .release()
                .map_err(|error| format!("helper release: {error:?}"))?;
            events.push((
                Instant::now(),
                format!("launch {launch}: released helper pid={}", generation.pid),
            ));
            let (tx, rx) = mpsc::sync_channel(1);
            let reader = thread::Builder::new()
                .name("startup-query-reply".into())
                .spawn(move || {
                    let mut line = Vec::new();
                    let read = std::io::BufReader::new(std::fs::File::from(replies))
                        .take(MAX_REPLY_BYTES + 1)
                        .read_until(b'\n', &mut line);
                    let reply = if matches!(read, Ok(1..))
                        && line.len() as u64 <= MAX_REPLY_BYTES
                        && line.last() == Some(&b'\n')
                    {
                        serde_json::from_slice::<Reply>(&line).map_err(|_| "malformed helper reply")
                    } else {
                        Err("missing or oversized helper reply")
                    };
                    let _ = tx.send(reply);
                })?;
            let client = Client::new(
                Arc::new(Mutex::new(Box::new(std::fs::File::from(pipe)))),
                rx,
            );
            // One query per launch, with no retry and no badge, picture or
            // preview command sent to the helper.
            // Startup measurement allows 5 s; production's reply cap is 50 ms.
            let query = client.window_at([220.0, 220.0], Duration::from_secs(5));
            queries_ok &= query.is_ok();
            last_query = Instant::now();
            events.push((last_query, format!("launch {launch}: query {query:?}")));
            if launch == 2 {
                // Keep the restarted helper alive throughout the observation
                // tail so delayed startup effects are not hidden by its death.
                thread::sleep(Duration::from_secs(2));
            }
            child
                .terminate_and_reap()
                .map_err(|error| format!("helper kill/reap: {error:?}"))?;
            reader.join().map_err(|_| "reply reader panicked")?;
            events.push((
                Instant::now(),
                format!("launch {launch}: killed and reaped pid={}", generation.pid),
            ));
        }
        if queries_ok {
            Ok(())
        } else {
            Err("one or both helper queries failed; see the table".into())
        }
    })();
    let samples = sampler.finish(last_query + Duration::from_secs(2))?;
    let mut rows = Vec::new();
    for sample in samples {
        let front = format!("{:?}", sample.state.frontmost_pid);
        if sample.state.helpers.is_empty() {
            rows.push((sample.at, format!("sample | {front} | - | - | -")));
        }
        for helper in sample.state.helpers {
            rows.push((
                sample.at,
                format!(
                    "sample | {front} | {} | {:?} | {:?}",
                    helper.pid, helper.activation_policy, helper.on_screen_windows
                ),
            ));
        }
    }
    rows.extend(
        events
            .into_iter()
            .map(|(at, event)| (at, format!("{event} | - | - | - | -"))),
    );
    rows.sort_by_key(|(at, _)| *at);
    let mut out = std::io::stdout().lock();
    writeln!(out, "Query-only helper startup/restart; no drawings or input. Sampling target: 2 ms (scheduler/API delays possible).")?;
    writeln!(out, "Records every observed change, not transitions between samples. Window metadata uses CGWindowList only; None means unreadable/absent, not zero.")?;
    writeln!(out, "ms | event | NSWorkspace.frontmostApplication pid | helper pid | NSRunningApplication.activationPolicy | on-screen window IDs")?;
    for (at, row) in rows {
        writeln!(
            out,
            "{:.3} | {row}",
            at.saturating_duration_since(origin).as_secs_f64() * 1000.0
        )?;
    }
    result
}
