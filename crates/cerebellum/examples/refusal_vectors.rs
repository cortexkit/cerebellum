//! Mint the capability-refusal vectors from the served dispatcher.
//!
//! A consumer deriving its action enum from the daemon catalogue has a
//! staleness window: a name it read at bind can stop being served before it
//! calls. What the wire answers in that window is a fact of THIS module's
//! dispatcher, and a consumer that hard-codes it drifts the day the
//! dispatcher moves. Every row here is produced by DRIVING the production
//! request handler with an empty admission set (what an unbound build
//! resolves to) and recording the code it answered, so the file cannot
//! describe a dispatcher that does not exist.
//!
//! Run: `cargo run -p cerebellum --example refusal_vectors`
//!
//! JSON on stdout, one object per named capability, intended to be committed
//! by the consumer as a fixture and re-minted whenever this contract moves.
//! The three codes and what each asks of the caller:
//!   unknown_method            no build of this module knows the name
//!   capability_not_admitted   this build knows it and does not serve it
//!   browser_not_configured    served, but this host has no browser configured

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("the computer plane is served on macOS only; mint these vectors there");
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    use serde_json::json;
    use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
    use tokio::sync::mpsc;

    // Every name a consumer could read from a catalogue or a vocabulary, plus
    // one no build knows, so the unknown arm is minted rather than assumed.
    let names = [
        "computer.click",
        "computer.type",
        "computer.keys",
        "computer.scroll",
        "computer.move",
        "computer.drag",
        "computer.screenshot",
        "computer.wait",
        "computer_use",
        "browser_use",
        "browser.launch",
        "browser.navigate",
        "browser.snapshot",
        "browser.type",
        "browser.click_point",
        "computer.hover",
    ];

    let mut vectors = Vec::new();
    // Two hosts: one with a browser configured (executable unset, so a
    // browser tool that is served dispatches and refuses on its own terms),
    // one with none, which is where `browser_not_configured` comes from.
    for browser_configured in [true, false] {
        for name in names {
            let (tx, mut rx) = mpsc::channel::<Frame>(4);
            let health = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
            let request = json!({"name": name, "arguments": {}});
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                8,
                1,
                7,
                serde_json::to_vec(&request).expect("request encodes"),
            )
            .expect("frame builds");
            if browser_configured {
                cerebellum::handle_tool_request_for_test_admitting(frame, &tx, &health, &[]).await
            } else {
                cerebellum::handle_tool_request_for_test_unconfigured_browser(
                    frame,
                    &tx,
                    &health,
                    &[],
                )
                .await
            }
            .expect("the handler answers");
            let reply = rx.recv().await.expect("one reply frame");
            let body: serde_json::Value =
                serde_json::from_slice(&reply.body).expect("reply body is JSON");
            // A route ERROR carries `code`; a dispatched tool REPLY carries
            // `outcome`. Both are recorded so a consumer can tell "refused at the
            // door" from "served and refused inside".
            vectors.push(json!({
                "name": name,
                "admitted": [],
                "browser_configured": browser_configured,
                "frame": format!("{:?}", reply.header.ty).to_lowercase(),
                "code": body["code"],
                "outcome": body["outcome"],
                "message": body["message"],
            }));
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "ck-cerebellum-refusal-vectors/v1",
            "minted_from": "handle_tool_request with an empty admission set",
            "vectors": vectors,
        }))
        .expect("vectors encode")
    );
}
