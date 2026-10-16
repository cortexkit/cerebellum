//! Byte-for-byte examples for callers implementing turn-stop, not simulated replies.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use subc_protocol::{Frame, FrameType};

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/turn-stop-cancel-v1")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn frame(frame: &Frame) -> Value {
    let mut bytes = frame.header.encode().to_vec();
    bytes.extend_from_slice(&frame.body);
    json!({
        "type": format!("{:?}", frame.header.ty),
        "channel": frame.header.channel, "epoch": frame.header.epoch,
        "corr": frame.header.corr, "body_length": frame.body.len(),
        "body_utf8": std::str::from_utf8(&frame.body).unwrap(),
        "wire_hex": hex(&bytes),
    })
}

pub fn cancel(request: &Frame) -> Frame {
    Frame::build_with_version(
        request.header.ver,
        FrameType::Cancel,
        request.header.flags,
        request.header.channel,
        request.header.epoch,
        request.header.corr,
        Vec::new(),
    )
    .unwrap()
}

pub fn check(case: &str, state: &str, request: &Frame, cancel: &Frame, reply: Option<&Frame>) {
    assert_eq!(cancel.header.ty, FrameType::Cancel);
    assert!(cancel.body.is_empty(), "wire Cancel has no JSON body");
    let value = json!({
        "contract": "turn-stop-cancel-v1", "case": case, "state": state,
        "request": frame(request), "cancel": frame(cancel),
        "reply": reply.map(frame).unwrap_or(json!("no reply")),
    });
    assert_private_text_absent(&value);
    let bytes = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
    let dir = directory();
    let path = dir.join(format!("{case}.json"));
    // Serialize regeneration within each test binary so parallel cases cannot
    // publish a checksum file describing only part of another case's write.
    static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _write = WRITE.lock().unwrap();
    if std::env::var_os("CEREBELLUM_WRITE_TURN_STOP_VECTORS").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::write(dir.join("SHA256SUMS"), sums()).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        bytes,
        "{case} wire bytes changed"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap(),
        sums()
    );
}

fn sums() -> String {
    let mut files: Vec<_> = std::fs::read_dir(directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "SHA256SUMS")
        .collect();
    files.sort();
    files
        .iter()
        .map(|path| {
            format!(
                "{}  {}\n",
                hex(&Sha256::digest(std::fs::read(path).unwrap())),
                path.file_name().unwrap().to_str().unwrap()
            )
        })
        .collect()
}

fn assert_private_text_absent(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                assert!(
                    ![
                        "state_text",
                        "page_text",
                        "dom_text",
                        "html",
                        "text",
                        "title",
                        "label",
                        "value",
                        "records",
                        "png_base64"
                    ]
                    .contains(&key.as_str()),
                    "private screen/page content field: {key}"
                );
                if key == "body_utf8" {
                    let text = value.as_str().unwrap();
                    if !text.is_empty() {
                        assert_private_text_absent(&serde_json::from_str::<Value>(text).unwrap());
                    }
                } else {
                    assert_private_text_absent(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_private_text_absent(value);
            }
        }
        Value::String(text) => {
            assert!(
                !["/Users/", "/private/", "/tmp/", "/.t/"]
                    .iter()
                    .any(|prefix| text.contains(prefix)),
                "vectors must not contain machine-local paths"
            );
            // Wait evidence is itself JSON inside a string. Inspect that too,
            // otherwise readback text could evade the same content-field fence.
            if let Ok(nested) = serde_json::from_str::<Value>(text) {
                if nested.is_object() || nested.is_array() {
                    assert_private_text_absent(&nested);
                }
            }
        }
        _ => {}
    }
}

#[test]
fn turn_stop_vectors_contain_no_screen_or_page_text() {
    let mut count = 0;
    for entry in std::fs::read_dir(directory()).unwrap() {
        let path = entry.unwrap().path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_private_text_absent(&value);
            count += 1;
        }
    }
    assert!(count >= 9, "the complete turn-stop corpus is scanned");
}
