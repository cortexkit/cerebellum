//! Run the production click classification against a real, headless browser.
//!
//! Five targets on one loopback page, each one a case the click path has to
//! get right: a same-origin link, a cross-origin absolute link, a relative
//! link, a plain button outside any form, and the submit button of a login
//! form. For each, this prints the classification record the snapshot path
//! would retain, or the named reason it could not produce one.
//!
//! The browser runs headless with `--remote-debugging-pipe`, so no window is
//! ever shown, and its only page is served by this process on 127.0.0.1. No
//! real site is contacted: the cross-origin link is never followed.
//!
//! Run with:
//!
//! ```text
//! cargo run -p cerebellum --example classify_live
//! cargo run -p cerebellum --example classify_live -- --capture <path>
//! ```
//!
//! `--capture` also writes the page's `DOM.getFlattenedDocument` result, with
//! the document URL, target id and frame id it was classified against, as the
//! JSON a unit test can replay without a browser. Set `CK_CHROME` to use a
//! browser other than the default Google Chrome install.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!(
        "this probe launches the browser through the macOS barrier and has nothing to run here"
    );
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(reason) = probe::run() {
        eprintln!("PROBE FAILED: {reason}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
mod probe {
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use cerebellum::browser::navigation::classify_flattened_document;
    use cerebellum::snapshot_store::BackendNodeIdentity;
    use serde_json::{json, Value};

    /// The element ids on the fixture page, in the order they are reported.
    const TARGETS: [(&str, &str); 5] = [
        ("same", "same-origin link"),
        ("cross", "cross-origin absolute link"),
        ("relative", "relative link"),
        ("plain", "plain button outside any form"),
        ("submit", "login form submit button"),
    ];

    const DEADLINE: Duration = Duration::from_secs(20);

    fn page(port: u16) -> String {
        format!(
            "<!doctype html><html><head><title>classification fixture</title></head><body>\
             <p><a id=\"same\" href=\"http://127.0.0.1:{port}/next\">Same-origin link</a></p>\
             <p><a id=\"cross\" href=\"https://cross-origin.invalid/landing\">Cross-origin link</a></p>\
             <p><a id=\"relative\" href=\"next.html\">Relative link</a></p>\
             <div><button id=\"plain\" type=\"button\">Plain button</button></div>\
             <form id=\"login\" action=\"/session\" method=\"post\">\
             <input id=\"user\" name=\"user\" autocomplete=\"username\">\
             <input id=\"pass\" name=\"pass\" type=\"password\" autocomplete=\"current-password\">\
             <button id=\"submit\" type=\"submit\">Sign in</button>\
             </form></body></html>"
        )
    }

    /// Serve the fixture page to every request until the process exits.
    fn serve(listener: TcpListener, body: String) {
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Both);
                drop::<TcpStream>(stream);
            }
        });
    }

    struct Pipe {
        commands: UnixStream,
        responses: UnixStream,
        buffer: Vec<u8>,
        events: Vec<Value>,
        next_id: u64,
    }

    impl Pipe {
        fn call(
            &mut self,
            session: Option<&str>,
            method: &str,
            params: Value,
        ) -> Result<Value, String> {
            self.next_id += 1;
            let id = self.next_id;
            let mut message = json!({"id": id, "method": method, "params": params});
            if let Some(session) = session {
                message["sessionId"] = Value::String(session.to_string());
            }
            let mut bytes = serde_json::to_vec(&message).map_err(|error| error.to_string())?;
            bytes.push(0);
            self.commands
                .write_all(&bytes)
                .map_err(|error| format!("{method}: write failed: {error}"))?;
            let started = Instant::now();
            loop {
                if let Some(frame) = self.frame()? {
                    if frame.get("id").and_then(Value::as_u64) == Some(id) {
                        if let Some(error) = frame.get("error") {
                            return Err(format!("{method}: {error}"));
                        }
                        return Ok(frame.get("result").cloned().unwrap_or(Value::Null));
                    }
                    if frame.get("method").is_some() {
                        self.events.push(frame);
                    }
                    continue;
                }
                if started.elapsed() > DEADLINE {
                    return Err(format!("{method}: no answer within {DEADLINE:?}"));
                }
            }
        }

        fn wait_for_event(&mut self, method: &str) -> Result<(), String> {
            let started = Instant::now();
            loop {
                if let Some(index) = self
                    .events
                    .iter()
                    .position(|event| event["method"] == method)
                {
                    self.events.remove(index);
                    return Ok(());
                }
                match self.frame()? {
                    Some(frame) if frame.get("method").is_some() => self.events.push(frame),
                    Some(_) => {}
                    None if started.elapsed() > DEADLINE => {
                        return Err(format!("no {method} within {DEADLINE:?}"))
                    }
                    None => {}
                }
            }
        }

        /// One complete frame, or `None` after a read that completed none.
        fn frame(&mut self) -> Result<Option<Value>, String> {
            if let Some(at) = self.buffer.iter().position(|byte| *byte == 0) {
                let frame: Vec<u8> = self.buffer.drain(..=at).collect();
                return serde_json::from_slice(&frame[..frame.len() - 1])
                    .map(Some)
                    .map_err(|error| format!("unparseable CDP frame: {error}"));
            }
            let mut chunk = [0u8; 65536];
            let read = self
                .responses
                .read(&mut chunk)
                .map_err(|error| format!("pipe read failed: {error}"))?;
            if read == 0 {
                return Err("the browser closed its pipe".into());
            }
            self.buffer.extend_from_slice(&chunk[..read]);
            Ok(None)
        }
    }

    /// The backend node id of the element whose `id` attribute is `wanted`.
    fn backend_id_of(result: &Value, wanted: &str) -> Option<u64> {
        result["nodes"].as_array()?.iter().find_map(|node| {
            let attributes = node["attributes"].as_array()?;
            attributes
                .chunks(2)
                .any(|pair| pair[0] == "id" && pair.get(1).is_some_and(|value| value == wanted))
                .then(|| node["backendNodeId"].as_u64())
                .flatten()
        })
    }

    pub fn run() -> Result<(), String> {
        let capture_path = {
            let mut args = std::env::args().skip(1);
            match (args.next().as_deref(), args.next()) {
                (Some("--capture"), Some(path)) => Some(PathBuf::from(path)),
                (None, None) => None,
                _ => return Err("usage: classify_live [--capture <path>]".into()),
            }
        };
        let chrome = std::env::var_os("CK_CHROME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            });
        if !chrome.is_file() {
            println!("skipped: no browser at {}", chrome.display());
            return Ok(());
        }

        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|error| format!("bind: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("local addr: {error}"))?
            .port();
        serve(listener, page(port));
        let page_url = format!("http://127.0.0.1:{port}/");

        let profile = std::env::temp_dir().join(format!("ck-classify-{}", std::process::id()));
        std::fs::create_dir_all(&profile).map_err(|error| format!("profile dir: {error}"))?;
        let args: Vec<OsString> = vec![
            OsString::from("--headless=new"),
            OsString::from("--remote-debugging-pipe"),
            OsString::from("--no-first-run"),
            OsString::from("--no-default-browser-check"),
            OsString::from(format!("--user-data-dir={}", profile.display())),
        ];
        let (command_child, command_parent) =
            UnixStream::pair().map_err(|error| format!("command pipe: {error}"))?;
        let (response_parent, response_child) =
            UnixStream::pair().map_err(|error| format!("response pipe: {error}"))?;
        let barred = cerebellum_macos::spawn_barred(
            &chrome,
            &args,
            &[],
            command_child.as_raw_fd(),
            response_child.as_raw_fd(),
        )
        .map_err(|error| format!("spawn: {error:?}"))?;
        let browser = barred
            .release()
            .map_err(|error| format!("release: {error:?}"))?;
        drop(command_child);
        drop(response_child);

        let mut pipe = Pipe {
            commands: command_parent,
            responses: response_parent,
            buffer: Vec::new(),
            events: Vec::new(),
            next_id: 0,
        };
        let outcome = classify_page(&mut pipe, &page_url, capture_path);
        let _ = browser.terminate_and_reap();
        let _ = std::fs::remove_dir_all(&profile);
        outcome
    }

    fn classify_page(
        pipe: &mut Pipe,
        page_url: &str,
        capture_path: Option<PathBuf>,
    ) -> Result<(), String> {
        let version = pipe.call(None, "Browser.getVersion", json!({}))?;
        println!("browser: {}", version["product"]);
        let created = pipe.call(None, "Target.createTarget", json!({"url": "about:blank"}))?;
        let target_id = created["targetId"]
            .as_str()
            .ok_or("Target.createTarget returned no targetId")?
            .to_string();
        let attached = pipe.call(
            None,
            "Target.attachToTarget",
            json!({"targetId": target_id, "flatten": true}),
        )?;
        let session = attached["sessionId"]
            .as_str()
            .ok_or("Target.attachToTarget returned no sessionId")?
            .to_string();
        let session = Some(session.as_str());
        pipe.call(session, "Page.enable", json!({}))?;
        pipe.call(session, "Page.navigate", json!({"url": page_url}))?;
        pipe.wait_for_event("Page.loadEventFired")?;

        let tree = pipe.call(session, "Page.getFrameTree", json!({}))?;
        let frame_id = tree["frameTree"]["frame"]["id"]
            .as_str()
            .ok_or("Page.getFrameTree returned no main frame id")?
            .to_string();
        // The URL the browser reports for the main frame is what a session's
        // navigation tracker records, and so what the snapshot path passes on.
        let document_url = tree["frameTree"]["frame"]["url"]
            .as_str()
            .ok_or("Page.getFrameTree returned no main frame url")?
            .to_string();
        pipe.call(session, "DOM.enable", json!({}))?;
        let flattened = pipe.call(
            session,
            "DOM.getFlattenedDocument",
            json!({"depth": -1, "pierce": true}),
        )?;
        let result = flattened
            .as_object()
            .ok_or("DOM.getFlattenedDocument returned no result object")?;
        println!("document url: {document_url}");

        for (element_id, label) in TARGETS {
            let Some(backend_node_id) = backend_id_of(&flattened, element_id) else {
                println!("{label}: element #{element_id} not found in the capture");
                continue;
            };
            let identity = BackendNodeIdentity::new(&target_id, &frame_id, backend_node_id)
                .map_err(|error| format!("identity for #{element_id}: {error:?}"))?;
            match classify_flattened_document(result, &identity, 1, &document_url) {
                Ok(record) => println!(
                    "{label}: classified kind={:?} submit={} destination={} \
                     required_tier={} credential={} financial={}",
                    record.target_kind,
                    record.activation_invokes_form_submit,
                    record
                        .activation_destination_origin
                        .as_deref()
                        .unwrap_or("none"),
                    record.required_tier,
                    record.credential,
                    record.financial,
                ),
                Err(reason) => println!("{label}: UNAVAILABLE {reason}"),
            }
        }

        if let Some(path) = capture_path {
            let capture = json!({
                "document_url": document_url,
                "target_id": target_id,
                "frame_id": frame_id,
                "result": flattened,
            });
            let text = serde_json::to_string_pretty(&capture)
                .map_err(|error| format!("serialize capture: {error}"))?;
            std::fs::write(&path, text + "\n")
                .map_err(|error| format!("write {}: {error}", path.display()))?;
            println!("capture written to {}", path.display());
        }
        Ok(())
    }
}
