//! Manual, scratch-account-only peer identity experiment. See peer_identity/RUN.md.

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = cerebellum_macos::peer_identity_probe::run() {
        eprintln!("STOP peer-identity: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}
