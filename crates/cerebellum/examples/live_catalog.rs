//! Read what the RUNNING daemon says this module serves.
//!
//! A placement readback instrument. After a binary is placed and the module
//! restarted, the questions are "did the daemon accept it" and "what did it
//! accept" -- and both are answered only by the daemon's catalogue, never by
//! the binary (which has no manifest flag) or by the source (which says what
//! was built, not what was admitted). `ck module status` answers the first;
//! nothing on the CLI answers the second, so this does.
//!
//! Prints the tool names and management operations the daemon holds for
//! cerebellum, one per line, and the counts. Exit 0 when the module is in the
//! catalogue; exit 1 with the reason when it is not, so an absent module is a
//! reported state rather than an empty list mistaken for a small one.
//!
//! Run: `cargo run -p cerebellum --example live_catalog [-- <connection-file>]`
//! With no argument the daemon's own discovery ladder is used.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use subc_control::{ClientControlRequest, ClientControlResponse};
use subc_protocol::manifest::ProviderRole;
use subc_protocol::{Frame, FrameType};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MODULE_ID: &str = "cerebellum";

#[tokio::main]
async fn main() -> ExitCode {
    let explicit = std::env::args().nth(1);
    let discovered = match connection_file::discover(explicit.as_deref().map(Path::new)) {
        Ok(discovered) => discovered,
        Err(error) => {
            eprintln!("no daemon connection file: {error}");
            return ExitCode::from(1);
        }
    };
    let Some(endpoint) = discovered.info.endpoints.first() else {
        eprintln!(
            "connection file {} publishes no endpoint",
            discovered.path.display()
        );
        return ExitCode::from(1);
    };
    let mut stream = match TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port)).await
    {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("connect {}:{}: {error}", endpoint.host, endpoint.port);
            return ExitCode::from(1);
        }
    };
    if let Err(error) =
        authenticate_client(&mut stream, &discovered.info, Duration::from_secs(5)).await
    {
        eprintln!("authenticate: {error:?}");
        return ExitCode::from(1);
    }

    let request = ClientControlRequest::CatalogList {
        module_id: Some(MODULE_ID.to_string()),
    };
    let frame = Frame::build(
        FrameType::Request,
        cerebellum::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&request).expect("serialize catalog.list"),
    )
    .expect("build control frame");
    if let Err(error) = write_frame(&mut stream, &frame).await {
        eprintln!("write catalog.list: {error:?}");
        return ExitCode::from(1);
    }
    let reply = match timeout(Duration::from_secs(5), read_frame(&mut stream)).await {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) => {
            eprintln!("daemon closed the connection before answering");
            return ExitCode::from(1);
        }
        Ok(Err(error)) => {
            eprintln!("read catalog.list reply: {error:?}");
            return ExitCode::from(1);
        }
        Err(_) => {
            eprintln!("catalog.list: no reply within 5s");
            return ExitCode::from(1);
        }
    };
    let response: ClientControlResponse = match serde_json::from_slice(&reply.body) {
        Ok(response) => response,
        Err(error) => {
            eprintln!("catalog.list reply did not parse: {error}");
            return ExitCode::from(1);
        }
    };
    let ClientControlResponse::CatalogList { modules, .. } = response else {
        eprintln!("daemon answered catalog.list with something else");
        return ExitCode::from(1);
    };
    let Some(entry) = modules.iter().find(|module| module.module_id == MODULE_ID) else {
        eprintln!(
            "{MODULE_ID} is NOT in the daemon's catalogue ({} module(s) listed) -- \
             not registered, or registered under another id",
            modules.len()
        );
        return ExitCode::from(1);
    };

    let mut tools = Vec::new();
    let mut operations = Vec::new();
    for role in &entry.roles {
        match role {
            ProviderRole::ToolProvider { tools: t, .. } => {
                tools.extend(t.iter().map(|tool| tool.name.clone()));
            }
            ProviderRole::ManagementSurface {
                operations: ops, ..
            } => {
                operations.extend(ops.iter().map(|op| op.name.clone()));
            }
            _ => {}
        }
    }
    tools.sort();
    println!("daemon: {}", discovered.path.display());
    println!("module: {MODULE_ID}");
    println!("tools ({}):", tools.len());
    for name in &tools {
        println!("  {name}");
    }
    println!("management operations ({}):", operations.len());
    for name in &operations {
        println!("  {name}");
    }
    ExitCode::SUCCESS
}
