//! Send interrupt frames to a running cerebellum module over the production wire.
//!
//! Arms 1 through 3 are deskless: they do not front a window, move the cursor,
//! post a key, or touch pixels. Arm 4 moves the real cursor and is therefore
//! available only with the explicit `--hands` flag.
//!
//! ```text
//! cargo run -p cerebellum --example live_interrupt
//! cargo run -p cerebellum --example live_interrupt -- --hands
//! cargo run -p cerebellum --example live_interrupt -- --connection <file>
//! ```
//!
//! Every arm prints exactly one verdict line. An arm that cannot run is
//! UNMEASURABLE, never PASS. UNMEASURABLE fails the process when the arm was
//! requested; the unrequested desk arm is the sole exception.

use std::process::ExitCode;

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    println!("ARM 1 unknown_corr_is_ignored: UNMEASURABLE this live probe requires macOS");
    println!("ARM 2 late_cancel_changes_nothing: UNMEASURABLE this live probe requires macOS");
    println!("ARM 3 cancelled_wait_stops_early: UNMEASURABLE this live probe requires macOS");
    println!("ARM 4 cancelled_drag_releases_button: UNMEASURABLE desk arm not requested");
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() -> ExitCode {
    probe::run().await
}

#[cfg(target_os = "macos")]
mod probe {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    const FINDER_BUNDLE: &str = "com.apple.finder";
    const CANCEL_SILENCE: Duration = Duration::from_millis(250);
    const ROUTINE_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
    const CANCELLED_WAIT_REPLY_TIMEOUT: Duration = Duration::from_secs(6);
    const WAIT_CANCEL_AFTER: Duration = Duration::from_secs(1);
    const WAIT_MUST_FINISH_BEFORE: Duration = Duration::from_secs(5);
    const TINY_WAIT_MS: u64 = 250;
    const LONG_WAIT_MS: u64 = 30_000;
    const TARGET_POLL_ATTEMPTS: u32 = 40;
    const TARGET_POLL_INTERVAL: Duration = Duration::from_millis(50);
    const DRAG_FULL_SEQUENCE_LENGTH: u64 = 3;
    const DRAG_CANCEL_AFTER_HEARTBEAT: Duration = Duration::from_millis(20);

    struct Options {
        hands: bool,
        connection: Option<PathBuf>,
    }

    impl Options {
        fn parse() -> Result<Self, String> {
            let mut hands = false;
            let mut connection = None;
            let mut args = std::env::args().skip(1);
            while let Some(argument) = args.next() {
                match argument.as_str() {
                    "--hands" => hands = true,
                    "--connection" => {
                        let Some(path) = args.next() else {
                            return Err("--connection needs a file path".to_string());
                        };
                        connection = Some(PathBuf::from(path));
                    }
                    other => return Err(format!("unknown argument {other:?}")),
                }
            }
            Ok(Self { hands, connection })
        }
    }

    enum Verdict {
        Pass(String),
        Fail(String),
        Unmeasurable(String),
    }

    struct Arm {
        number: &'static str,
        name: &'static str,
        requested: bool,
        verdict: Verdict,
    }

    impl Arm {
        fn pass(number: &'static str, name: &'static str, evidence: impl Into<String>) -> Self {
            Self {
                number,
                name,
                requested: true,
                verdict: Verdict::Pass(evidence.into()),
            }
        }

        fn fail(number: &'static str, name: &'static str, evidence: impl Into<String>) -> Self {
            Self {
                number,
                name,
                requested: true,
                verdict: Verdict::Fail(evidence.into()),
            }
        }

        fn unmeasurable(
            number: &'static str,
            name: &'static str,
            reason: impl Into<String>,
        ) -> Self {
            Self {
                number,
                name,
                requested: true,
                verdict: Verdict::Unmeasurable(reason.into()),
            }
        }

        fn skipped(number: &'static str, name: &'static str, reason: impl Into<String>) -> Self {
            Self {
                number,
                name,
                requested: false,
                verdict: Verdict::Unmeasurable(reason.into()),
            }
        }

        fn held(&self) -> bool {
            matches!(self.verdict, Verdict::Pass(_))
                || (!self.requested && matches!(self.verdict, Verdict::Unmeasurable(_)))
        }

        fn report(&self) {
            let (word, evidence) = match &self.verdict {
                Verdict::Pass(evidence) => ("PASS", evidence),
                Verdict::Fail(evidence) => ("FAIL", evidence),
                Verdict::Unmeasurable(evidence) => ("UNMEASURABLE", evidence),
            };
            println!("ARM {} {}: {} {}", self.number, self.name, word, evidence);
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RequestId {
        channel: u16,
        epoch: u32,
        corr: u64,
    }

    enum SilenceFailure {
        UnexpectedFrame(String),
        Transport(String),
    }

    struct Wire {
        stream: TcpStream,
        tool: (u16, u32),
        management: (u16, u32),
        next_corr: u64,
        project_root: String,
        conversation: String,
        impossible_identifier: String,
        elicitation_decision: &'static str,
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

            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
                .as_nanos();
            let run_id = format!("{}-{nonce}", std::process::id());
            let mut wire = Self {
                stream,
                tool: (0, 0),
                management: (0, 0),
                next_corr: 1,
                project_root: format!("/tmp/ck-live-interrupt-{run_id}"),
                conversation: format!("live-interrupt-{run_id}"),
                impossible_identifier: format!("ck-live-interrupt-never-{run_id}"),
                elicitation_decision: "deny",
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
            println!("daemon: {}", discovered.path.display());
            Ok(wire)
        }

        fn corr(&mut self) -> u64 {
            let corr = self.next_corr;
            self.next_corr = self.next_corr.saturating_add(1);
            corr
        }

        fn tool_id(&mut self) -> RequestId {
            RequestId {
                channel: self.tool.0,
                epoch: self.tool.1,
                corr: self.corr(),
            }
        }

        async fn open_route(&mut self, target: RouteTarget) -> Result<(u16, u32), String> {
            // Use one run-specific project-root identity on both routes so a
            // later probe run does not intentionally reuse this run's grant.
            let request = ClientControlRequest::RouteOpen {
                target: target.clone(),
                identity: BindIdentity::new(
                    self.project_root.clone(),
                    "live_interrupt",
                    self.conversation.clone(),
                ),
                consumer_identity: None,
                consumer_capabilities: Some(vec!["elicitation".to_string()]),
                admission_facts: None,
            };
            let corr = self.corr();
            let frame = Frame::build(
                FrameType::Request,
                cerebellum::control_flags(),
                0,
                0,
                corr,
                serde_json::to_vec(&request).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("build route.open frame: {error}"))?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write route.open: {error:?}"))?;
            let reply = self.await_response(corr, ROUTINE_REPLY_TIMEOUT).await?;
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

        async fn catalogue_tools(&mut self) -> Result<BTreeSet<String>, String> {
            let corr = self.corr();
            let request = ClientControlRequest::CatalogList {
                module_id: Some(MODULE_ID.to_string()),
            };
            let frame = Frame::build(
                FrameType::Request,
                cerebellum::control_flags(),
                0,
                0,
                corr,
                serde_json::to_vec(&request).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("build catalog.list frame: {error}"))?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write catalog.list: {error:?}"))?;
            let reply = self.await_response(corr, ROUTINE_REPLY_TIMEOUT).await?;
            let response: ClientControlResponse = serde_json::from_slice(&reply.body)
                .map_err(|error| format!("catalog.list reply did not parse: {error}"))?;
            let ClientControlResponse::CatalogList { modules, .. } = response else {
                return Err("the daemon answered catalog.list with something else".to_string());
            };
            let entry = modules
                .iter()
                .find(|module| module.module_id == MODULE_ID)
                .ok_or_else(|| format!("{MODULE_ID} is not in the daemon's catalogue"))?;
            let mut tools = BTreeSet::new();
            for role in &entry.roles {
                if let ProviderRole::ToolProvider { tools: served, .. } = role {
                    tools.extend(served.iter().map(|tool| tool.name.clone()));
                }
            }
            Ok(tools)
        }

        async fn take_target(
            &mut self,
            bundle_identity: &str,
            decision: &'static str,
        ) -> Result<(), String> {
            self.elicitation_decision = decision;
            let result = self.take_target_inner(bundle_identity).await;
            self.elicitation_decision = "deny";
            result
        }

        /// Settle the application's app grant. The operation waits for the
        /// answer, which this probe's own relay gives, and replies `granted`.
        async fn take_target_inner(&mut self, bundle_identity: &str) -> Result<(), String> {
            let params = json!({"bundle_identity": bundle_identity});
            for _ in 0..=TARGET_POLL_ATTEMPTS {
                let reply = self
                    .management_call("computer.open_target", params.clone())
                    .await?;
                match reply["outcome"].as_str() {
                    Some("granted") => return Ok(()),
                    Some("consent_pending") => sleep(TARGET_POLL_INTERVAL).await,
                    _ => {
                        return Err(format!(
                            "computer.open_target for {bundle_identity} answered {reply}"
                        ))
                    }
                }
            }
            Err(format!(
                "computer.open_target for {bundle_identity} was not granted within {}ms",
                TARGET_POLL_ATTEMPTS as u128 * TARGET_POLL_INTERVAL.as_millis()
            ))
        }

        async fn management_call(&mut self, method: &str, params: Value) -> Result<Value, String> {
            let id = RequestId {
                channel: self.management.0,
                epoch: self.management.1,
                corr: self.corr(),
            };
            self.send_request(id, json!({"method": method, "params": params}))
                .await?;
            let reply = self.await_response(id.corr, ROUTINE_REPLY_TIMEOUT).await?;
            serde_json::from_slice(&reply.body)
                .map_err(|error| format!("{method} reply did not parse: {error}"))
        }

        async fn start_tool_call(
            &mut self,
            name: &str,
            arguments: Value,
        ) -> Result<RequestId, String> {
            let id = self.tool_id();
            self.send_request(id, json!({"name": name, "arguments": arguments}))
                .await?;
            Ok(id)
        }

        async fn finish_tool_call(
            &mut self,
            name: &str,
            id: RequestId,
            wait: Duration,
        ) -> Result<Value, String> {
            let reply = self.await_response(id.corr, wait).await?;
            if (reply.header.channel, reply.header.epoch) != (id.channel, id.epoch) {
                return Err(format!(
                    "{name} reply used route ({}, {}), expected ({}, {})",
                    reply.header.channel, reply.header.epoch, id.channel, id.epoch
                ));
            }
            serde_json::from_slice(&reply.body)
                .map_err(|error| format!("{name} reply did not parse: {error}"))
        }

        async fn tiny_wait(&mut self) -> Result<(RequestId, Value), String> {
            let request = wait_arguments(&self.impossible_identifier, TINY_WAIT_MS);
            let id = self.start_tool_call("computer.wait", request).await?;
            let reply = self
                .finish_tool_call("computer.wait", id, ROUTINE_REPLY_TIMEOUT)
                .await?;
            Ok((id, reply))
        }

        async fn send_request(&mut self, id: RequestId, body: Value) -> Result<(), String> {
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                id.channel,
                id.epoch,
                id.corr,
                serde_json::to_vec(&body).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("build request frame: {error}"))?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write request: {error:?}"))
        }

        async fn send_cancel(&mut self, id: RequestId) -> Result<(), String> {
            let frame = cancel_frame(id)?;
            write_frame(&mut self.stream, &frame)
                .await
                .map_err(|error| format!("write Cancel: {error:?}"))
        }

        async fn expect_silence(&mut self, window: Duration) -> Result<(), SilenceFailure> {
            match timeout(window, read_frame(&mut self.stream)).await {
                Err(_) => Ok(()),
                Ok(Ok(None)) => Err(SilenceFailure::Transport(
                    "the daemon closed the connection while Cancel silence was measured"
                        .to_string(),
                )),
                Ok(Err(error)) => Err(SilenceFailure::Transport(format!(
                    "read while measuring Cancel silence: {error:?}"
                ))),
                Ok(Ok(Some(frame))) => {
                    if frame.header.ty == FrameType::Request {
                        self.answer_question(&frame)
                            .await
                            .map_err(SilenceFailure::Transport)?;
                    }
                    Err(SilenceFailure::UnexpectedFrame(frame_summary(&frame)))
                }
            }
        }

        async fn await_response(&mut self, corr: u64, wait: Duration) -> Result<Frame, String> {
            let deadline = Instant::now() + wait;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(format!(
                        "no reply to correlation {corr} within {}ms",
                        wait.as_millis()
                    ));
                }
                let frame = match timeout(remaining, read_frame(&mut self.stream)).await {
                    Ok(Ok(Some(frame))) => frame,
                    Ok(Ok(None)) => return Err("the daemon closed the connection".to_string()),
                    Ok(Err(error)) => return Err(format!("read frame: {error:?}")),
                    Err(_) => {
                        return Err(format!(
                            "no reply to correlation {corr} within {}ms",
                            wait.as_millis()
                        ))
                    }
                };
                if frame.header.ty == FrameType::Request {
                    self.answer_question(&frame).await?;
                    continue;
                }
                if frame.header.corr != corr {
                    return Err(format!(
                        "unexpected frame while awaiting correlation {corr}: {}",
                        frame_summary(&frame)
                    ));
                }
                return match frame.header.ty {
                    FrameType::Response => Ok(frame),
                    FrameType::Error => Err(format!(
                        "correlation {corr} returned an Error frame: {}",
                        String::from_utf8_lossy(&frame.body)
                    )),
                    other => Err(format!(
                        "correlation {corr} returned unexpected frame type {other:?}"
                    )),
                };
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
            let answer = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                question.header.channel,
                question.header.epoch,
                question.header.corr,
                serde_json::to_vec(&json!({"decision": self.elicitation_decision}))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("build elicitation answer: {error}"))?;
            write_frame(&mut self.stream, &answer)
                .await
                .map_err(|error| format!("write elicitation answer: {error:?}"))
        }
    }

    pub async fn run() -> ExitCode {
        let options = match Options::parse() {
            Ok(options) => options,
            Err(reason) => {
                eprintln!("{reason}");
                eprintln!("usage: live_interrupt [--hands] [--connection <file>]");
                return ExitCode::from(2);
            }
        };
        let screen = screen_state();
        let mut wire = match Wire::open(options.connection.as_deref()).await {
            Ok(wire) => wire,
            Err(reason) => {
                report_unreachable(&reason, options.hands);
                return ExitCode::from(1);
            }
        };
        let tools = match wire.catalogue_tools().await {
            Ok(tools) => tools,
            Err(reason) => {
                report_unreachable(&format!("catalogue unavailable: {reason}"), options.hands);
                return ExitCode::from(1);
            }
        };

        let mut arms = if !tools.contains("computer.wait") {
            let reason = "the running daemon does not advertise computer.wait";
            vec![
                Arm::unmeasurable("1", "unknown_corr_is_ignored", reason),
                Arm::unmeasurable("2", "late_cancel_changes_nothing", reason),
                Arm::unmeasurable("3", "cancelled_wait_stops_early", reason),
            ]
        } else {
            match wire.take_target(FINDER_BUNDLE, "allow_conversation").await {
                Ok(()) => vec![
                    arm_one(&mut wire, &screen).await,
                    arm_two(&mut wire, &screen).await,
                    arm_three(&mut wire, &screen).await,
                ],
                Err(reason) => vec![
                    Arm::unmeasurable("1", "unknown_corr_is_ignored", reason.clone()),
                    Arm::unmeasurable("2", "late_cancel_changes_nothing", reason.clone()),
                    Arm::unmeasurable("3", "cancelled_wait_stops_early", reason),
                ],
            }
        };

        let desk = if !options.hands {
            Arm::skipped(
                "4",
                "cancelled_drag_releases_button",
                "desk arm not requested",
            )
        } else if !tools.contains("computer.drag") {
            Arm::unmeasurable(
                "4",
                "cancelled_drag_releases_button",
                "the running daemon does not advertise computer.drag",
            )
        } else {
            arm_four(&mut wire).await
        };
        arms.push(desk);

        for arm in &arms {
            arm.report();
        }
        if arms.iter().all(Arm::held) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }

    async fn arm_one(wire: &mut Wire, screen: &str) -> Arm {
        const NUMBER: &str = "1";
        const NAME: &str = "unknown_corr_is_ignored";
        let unknown = wire.tool_id();
        if let Err(reason) = wire.send_cancel(unknown).await {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        match wire.expect_silence(CANCEL_SILENCE).await {
            Ok(()) => {}
            Err(SilenceFailure::UnexpectedFrame(frame)) => {
                return Arm::fail(
                    NUMBER,
                    NAME,
                    format!("unknown_corr={} produced {frame}", unknown.corr),
                )
            }
            Err(SilenceFailure::Transport(reason)) => return Arm::fail(NUMBER, NAME, reason),
        }
        match wire.tiny_wait().await {
            Ok((followup, reply)) if ordinary_tiny_wait_reply(&reply) => Arm::pass(
                NUMBER,
                NAME,
                format!(
                    "unknown_corr={} silence_ms={} followup_corr={} outcome={} attempts={} {screen}",
                    unknown.corr,
                    CANCEL_SILENCE.as_millis(),
                    followup.corr,
                    reply["outcome"],
                    reply["attempts"]
                ),
            ),
            Ok((followup, reply)) => Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "unknown_corr={} was silent, but followup_corr={} did not complete normally: {reply}",
                    unknown.corr, followup.corr
                ),
            ),
            Err(reason) => Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "unknown_corr={} was silent, but the same route did not answer the follow-up: {reason}",
                    unknown.corr
                ),
            ),
        }
    }

    async fn arm_two(wire: &mut Wire, screen: &str) -> Arm {
        const NUMBER: &str = "2";
        const NAME: &str = "late_cancel_changes_nothing";
        let (completed, first) = match wire.tiny_wait().await {
            Ok(reply) => reply,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        if !ordinary_tiny_wait_reply(&first) {
            return Arm::fail(
                NUMBER,
                NAME,
                format!("the request to complete before Cancel was not normal: {first}"),
            );
        }
        if let Err(reason) = wire.send_cancel(completed).await {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        match wire.expect_silence(CANCEL_SILENCE).await {
            Ok(()) => {}
            Err(SilenceFailure::UnexpectedFrame(frame)) => {
                return Arm::fail(
                    NUMBER,
                    NAME,
                    format!("late Cancel for corr={} produced {frame}", completed.corr),
                )
            }
            Err(SilenceFailure::Transport(reason)) => return Arm::fail(NUMBER, NAME, reason),
        }
        match wire.tiny_wait().await {
            Ok((second, reply)) if ordinary_tiny_wait_reply(&reply) => Arm::pass(
                NUMBER,
                NAME,
                format!(
                    "completed_corr={} first_outcome={} first_attempts={} late_cancel_silence_ms={} second_corr={} second_outcome={} second_attempts={} {screen}",
                    completed.corr,
                    first["outcome"],
                    first["attempts"],
                    CANCEL_SILENCE.as_millis(),
                    second.corr,
                    reply["outcome"],
                    reply["attempts"]
                ),
            ),
            Ok((second, reply)) => Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "late Cancel for corr={} was silent, but second_corr={} did not complete normally: {reply}",
                    completed.corr, second.corr
                ),
            ),
            Err(reason) => Arm::fail(
                NUMBER,
                NAME,
                format!(
                    "late Cancel for corr={} was silent, but the second request was not answered: {reason}",
                    completed.corr
                ),
            ),
        }
    }

    async fn arm_three(wire: &mut Wire, screen: &str) -> Arm {
        const NUMBER: &str = "3";
        const NAME: &str = "cancelled_wait_stops_early";
        let started = Instant::now();
        let arguments = wait_arguments(&wire.impossible_identifier, LONG_WAIT_MS);
        let request = match wire.start_tool_call("computer.wait", arguments).await {
            Ok(request) => request,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        sleep(WAIT_CANCEL_AFTER).await;
        if let Err(reason) = wire.send_cancel(request).await {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        let reply = match wire
            .finish_tool_call("computer.wait", request, CANCELLED_WAIT_REPLY_TIMEOUT)
            .await
        {
            Ok(reply) => reply,
            Err(reason) => {
                let liveness = wire.tiny_wait().await;
                return Arm::fail(
                    NUMBER,
                    NAME,
                    format!(
                        "corr={} had no prompt cancelled reply after elapsed_ms={}: {reason}; liveness={}",
                        request.corr,
                        started.elapsed().as_millis(),
                        describe_wait_result(&liveness)
                    ),
                );
            }
        };
        let elapsed = started.elapsed();
        let liveness = wire.tiny_wait().await;
        let live = matches!(&liveness, Ok((_, reply)) if ordinary_tiny_wait_reply(reply));
        let outcome = reply["outcome"].as_str();
        let attempts = reply["attempts"].as_u64();
        if outcome == Some("indeterminate") && wait_evidence_contains(&reply, "no_lease") {
            return Arm::unmeasurable(
                NUMBER,
                NAME,
                format!(
                    "corr={} could not enter the polling loop after computer.open_target reported a live target: outcome=indeterminate attempts={:?} elapsed_ms={} liveness={}",
                    request.corr,
                    attempts,
                    elapsed.as_millis(),
                    describe_wait_result(&liveness)
                ),
            );
        }
        if outcome == Some("cancelled")
            && attempts.is_some_and(|attempts| attempts > 0)
            && elapsed < WAIT_MUST_FINISH_BEFORE
            && live
        {
            let (_, live_reply) = liveness.expect("the matches! arm established success");
            return Arm::pass(
                NUMBER,
                NAME,
                format!(
                    "corr={} outcome=cancelled attempts={} elapsed_ms={} bound_ms={} liveness_outcome={} liveness_attempts={} {screen}",
                    request.corr,
                    attempts.unwrap_or_default(),
                    elapsed.as_millis(),
                    WAIT_MUST_FINISH_BEFORE.as_millis(),
                    live_reply["outcome"],
                    live_reply["attempts"]
                ),
            );
        }
        Arm::fail(
            NUMBER,
            NAME,
            format!(
                "corr={} outcome={:?} attempts={:?} elapsed_ms={} bound_ms={} liveness={}",
                request.corr,
                outcome,
                attempts,
                elapsed.as_millis(),
                WAIT_MUST_FINISH_BEFORE.as_millis(),
                describe_wait_result(&liveness)
            ),
        )
    }

    async fn arm_four(wire: &mut Wire) -> Arm {
        const NUMBER: &str = "4";
        const NAME: &str = "cancelled_drag_releases_button";
        if cerebellum_macos::screen_is_locked() == Some(true) {
            return Arm::unmeasurable(NUMBER, NAME, "the screen is locked");
        }
        let bundle_identity = match frontmost_bundle_identity() {
            Ok(bundle_identity) => bundle_identity,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };
        let tap = match cerebellum_macos::SessionEventTap::listen(256) {
            Ok(tap) => tap,
            Err(error) => {
                return Arm::unmeasurable(
                    NUMBER,
                    NAME,
                    format!("could not listen for the module's dispatch heartbeat: {error:?}"),
                )
            }
        };
        if let Err(reason) = wire
            .take_target(&bundle_identity, "allow_conversation")
            .await
        {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }

        // Invoking the probe is itself recent desk input. Wait beyond the
        // one-second idle threshold so, if no new desk input lands, the drag
        // reaches dispatch instead of the expected not-idle refusal.
        sleep(Duration::from_millis(1_300)).await;
        let own_pid = i64::from(std::process::id());
        let started = Instant::now();
        let request = match wire
            .start_tool_call(
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
            Ok(request) => request,
            Err(reason) => return Arm::unmeasurable(NUMBER, NAME, reason),
        };

        // Wait synchronously for the module's dispatch heartbeat before
        // cancelling the drag.
        let marker = match wait_for_heartbeat(tap, own_pid) {
            Ok(marker) => marker,
            Err(reason) => {
                let _ = wire.send_cancel(request).await;
                let reply = wire
                    .finish_tool_call("computer.drag", request, ROUTINE_REPLY_TIMEOUT)
                    .await;
                return Arm::unmeasurable(
                    NUMBER,
                    NAME,
                    format!("{reason}; drag_reply={}", describe_reply(&reply)),
                );
            }
        };
        sleep(DRAG_CANCEL_AFTER_HEARTBEAT).await;
        if let Err(reason) = wire.send_cancel(request).await {
            return Arm::unmeasurable(NUMBER, NAME, reason);
        }
        let reply = match wire
            .finish_tool_call("computer.drag", request, ROUTINE_REPLY_TIMEOUT)
            .await
        {
            Ok(reply) => reply,
            Err(reason) => return Arm::fail(NUMBER, NAME, reason),
        };
        let posts_returned = reply["posts_returned"].as_u64();
        let released = reply["reason"] == json!("caller_interrupted_held_input_released");
        if reply["outcome"] == json!("cancelled")
            && posts_returned.is_some_and(|posts| posts > 0 && posts < DRAG_FULL_SEQUENCE_LENGTH)
            && released
        {
            return Arm::pass(
                NUMBER,
                NAME,
                format!(
                    "corr={} outcome=cancelled posts_returned={} full_sequence_length={} held_state=released module_recovery_report={} heartbeat_nonce={} cancel_after_heartbeat_ms={} elapsed_ms={}; button-not-held is asserted from the module recovery report, not the window server",
                    request.corr,
                    posts_returned.unwrap_or_default(),
                    DRAG_FULL_SEQUENCE_LENGTH,
                    reply["reason"],
                    marker,
                    DRAG_CANCEL_AFTER_HEARTBEAT.as_millis(),
                    started.elapsed().as_millis()
                ),
            );
        }
        Arm::fail(
            NUMBER,
            NAME,
            format!(
                "corr={} outcome={} posts_returned={:?} full_sequence_length={} held_state_report={} heartbeat_nonce={} elapsed_ms={}; button-not-held cannot be asserted unless the module reports release recovery (the window server is not consulted)",
                request.corr,
                reply["outcome"],
                posts_returned,
                DRAG_FULL_SEQUENCE_LENGTH,
                reply["reason"],
                marker,
                started.elapsed().as_millis()
            ),
        )
    }

    fn wait_arguments(identifier: &str, timeout_ms: u64) -> Value {
        json!({
            "predicate": {
                "kind": "element_present",
                "element": {"Identifier": identifier},
            },
            "timeout_ms": timeout_ms,
        })
    }

    fn ordinary_tiny_wait_reply(reply: &Value) -> bool {
        matches!(reply["outcome"].as_str(), Some("timeout" | "indeterminate"))
            && reply["settle_path"] == json!("poll_with_deadline")
            && reply["evidence"].is_string()
    }

    fn wait_evidence_contains(reply: &Value, needle: &str) -> bool {
        reply["evidence"]
            .as_str()
            .is_some_and(|evidence| evidence.contains(needle))
    }

    fn cancel_frame(id: RequestId) -> Result<Frame, String> {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Cancel,
            Flags::new(false, Priority::Interactive, false),
            id.channel,
            id.epoch,
            id.corr,
            Vec::new(),
        )
        .map_err(|error| format!("build Cancel frame: {error}"))
    }

    fn frame_summary(frame: &Frame) -> String {
        format!(
            "{:?} frame ch={} epoch={} corr={} body={}",
            frame.header.ty,
            frame.header.channel,
            frame.header.epoch,
            frame.header.corr,
            String::from_utf8_lossy(&frame.body)
        )
    }

    fn describe_wait_result(result: &Result<(RequestId, Value), String>) -> String {
        match result {
            Ok((id, reply)) => format!("corr={} reply={reply}", id.corr),
            Err(reason) => format!("error={reason}"),
        }
    }

    fn describe_reply(result: &Result<Value, String>) -> String {
        match result {
            Ok(reply) => reply.to_string(),
            Err(reason) => format!("error={reason}"),
        }
    }

    fn screen_state() -> String {
        match cerebellum_macos::screen_is_locked() {
            Some(true) => "screen_locked=true (deskless arm still ran)".to_string(),
            Some(false) => "screen_locked=false".to_string(),
            None => "screen_locked=unknown (deskless arm still ran)".to_string(),
        }
    }

    fn frontmost_bundle_identity() -> Result<String, String> {
        let pid = cerebellum_macos::frontmost_process_id()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or_else(|| "the frontmost process could not be read".to_string())?;
        let windows =
            cerebellum_macos::enumerate_windows(Duration::from_secs(2)).map_err(|error| {
                format!("the frontmost application's windows were unreadable: {error:?}")
            })?;
        windows
            .into_iter()
            .find(|window| window.owner_pid == pid && !window.owner_bundle_identifier.is_empty())
            .map(|window| window.owner_bundle_identifier)
            .ok_or_else(|| {
                format!(
                    "frontmost pid {pid} has no bundle identity in the window-server reading; no window was fronted"
                )
            })
    }

    fn wait_for_heartbeat(
        tap: cerebellum_macos::SessionEventTap,
        own_pid: i64,
    ) -> Result<u64, String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("no module dispatch heartbeat arrived within 5s".to_string());
            }
            match tap.events().recv_timeout(remaining) {
                Ok(event) if event.marker_nonce != 0 && event.source_unix_process_id != own_pid => {
                    return Ok(event.marker_nonce)
                }
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return Err("no module dispatch heartbeat arrived within 5s".to_string())
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("the dispatch heartbeat tap stopped delivering".to_string())
                }
            }
        }
    }

    fn report_unreachable(reason: &str, hands: bool) {
        Arm::unmeasurable("1", "unknown_corr_is_ignored", reason).report();
        Arm::unmeasurable("2", "late_cancel_changes_nothing", reason).report();
        Arm::unmeasurable("3", "cancelled_wait_stops_early", reason).report();
        if hands {
            Arm::unmeasurable("4", "cancelled_drag_releases_button", reason).report();
        } else {
            Arm::skipped(
                "4",
                "cancelled_drag_releases_button",
                "desk arm not requested",
            )
            .report();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cancel_frame_has_empty_body_and_preserves_the_target_request_tuple() {
            let id = RequestId {
                channel: 7,
                epoch: 11,
                corr: 13,
            };
            let frame = cancel_frame(id).expect("Cancel frame builds");

            assert_eq!(frame.header.ty, FrameType::Cancel);
            assert_eq!(frame.header.channel, id.channel);
            assert_eq!(frame.header.epoch, id.epoch);
            assert_eq!(frame.header.corr, id.corr);
            assert!(frame.body.is_empty());
        }

        #[test]
        fn impossible_wait_is_a_typed_identifier_predicate_at_the_requested_deadline() {
            let request = wait_arguments("not-present", LONG_WAIT_MS);

            assert_eq!(request["predicate"]["kind"], "element_present");
            assert_eq!(request["predicate"]["element"]["Identifier"], "not-present");
            assert_eq!(request["timeout_ms"], LONG_WAIT_MS);
        }

        #[test]
        fn only_the_unrequested_desk_arm_may_be_unmeasurable_without_failing_exit() {
            assert!(Arm::skipped("4", "desk", "not requested").held());
            assert!(!Arm::unmeasurable("3", "wait", "could not run").held());
            assert!(!Arm::fail("1", "cancel", "wrong reply").held());
        }
    }
}
