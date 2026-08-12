//! Does a browser launched through the barrier still run its renderers?
//!
//! The handshake proves the BROWSER process answers. Renderers are separate
//! processes that reach the browser through a mach bootstrap service, and a
//! launcher can break that while leaving the handshake perfectly healthy — a
//! session that connects and then cannot load a page. Every assertion in the
//! readiness tests would still call such a session ready.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn send(p: &mut UnixStream, v: serde_json::Value) {
    let mut b = serde_json::to_vec(&v).expect("json");
    b.push(0);
    p.write_all(&b).expect("write");
}

fn recv(p: &mut UnixStream, want: u64, buffer: &mut Vec<u8>) -> serde_json::Value {
    loop {
        if let Some(at) = buffer.iter().position(|b| *b == 0) {
            let frame: Vec<u8> = buffer.drain(..=at).collect();
            let v: serde_json::Value =
                serde_json::from_slice(&frame[..frame.len() - 1]).expect("frame json");
            if v.get("id").and_then(serde_json::Value::as_u64) == Some(want) {
                return v;
            }
            continue;
        }
        let mut chunk = [0u8; 65536];
        let n = p.read(&mut chunk).expect("read");
        assert!(n > 0, "pipe closed awaiting {want}");
        buffer.extend_from_slice(&chunk[..n]);
    }
}

fn main() {
    let chrome = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        eprintln!("skipped: no Chrome at {}", chrome.display());
        return;
    }
    let profile = std::env::temp_dir().join(format!("ck-renderer-{}", std::process::id()));
    std::fs::create_dir_all(&profile).expect("profile dir");

    let args: Vec<OsString> = vec![
        OsString::from("--remote-debugging-pipe"),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
        OsString::from(format!("--user-data-dir={}", profile.display())),
    ];

    let (command_child, mut command_parent) = UnixStream::pair().expect("command pair");
    let (mut response_parent, response_child) = UnixStream::pair().expect("response pair");

    let barred = cerebellum_macos::spawn_barred(
        &chrome,
        &args,
        &[],
        command_child.as_raw_fd(),
        response_child.as_raw_fd(),
    )
    .expect("spawn barred");
    let released = barred.release().expect("release");
    drop(command_child);
    drop(response_child);

    let mut buffer: Vec<u8> = Vec::new();
    send(
        &mut command_parent,
        serde_json::json!({"id":1,"method":"Browser.getVersion"}),
    );
    let v = recv(&mut response_parent, 1, &mut buffer);
    println!("browser: {}", v["result"]["product"]);

    send(
        &mut command_parent,
        serde_json::json!({"id":2,"method":"Target.createTarget","params":{"url":"about:blank"}}),
    );
    let t = recv(&mut response_parent, 2, &mut buffer);
    let target = t["result"]["targetId"]
        .as_str()
        .expect("targetId")
        .to_string();

    send(
        &mut command_parent,
        serde_json::json!({"id":3,"method":"Target.attachToTarget","params":{"targetId":target,"flatten":true}}),
    );
    let a = recv(&mut response_parent, 3, &mut buffer);
    let session = a["result"]["sessionId"]
        .as_str()
        .expect("sessionId")
        .to_string();

    send(
        &mut command_parent,
        serde_json::json!({"id":4,"sessionId":session,"method":"Runtime.evaluate","params":{"expression":"6*7","returnByValue":true}}),
    );
    let e = recv(&mut response_parent, 4, &mut buffer);
    let value = e["result"]["result"]["value"].as_i64();
    println!("RENDERER RESULT: {value:?}");
    println!(
        "VERDICT: {}",
        if value == Some(42) {
            "renderers work under the barrier"
        } else {
            "RENDERERS BROKEN under the barrier"
        }
    );

    let _ = released.terminate_and_reap();
    let _ = std::fs::remove_dir_all(&profile);
}
