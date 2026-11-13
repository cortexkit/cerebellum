//! Manual, scratch-account-only peer identity experiment. See peer_identity/RUN.md.

#[cfg(target_os = "macos")]
fn main() {
    use cerebellum_macos::peer_identity_probe::{ProbeCheck, ProbeVerdict};
    let result = cerebellum_macos::peer_identity_probe::run().and_then(|verdict| match verdict {
        ProbeVerdict::RoleComplete => Ok(()),
        ProbeVerdict::LegitimateFirstFrame => {
            println!("legitimate-first-frame");
            Ok(())
        }
        ProbeVerdict::Rig { passed, result } => {
            for check in passed {
                println!(
                    "{}",
                    match check {
                        ProbeCheck::Legitimate => "PASS control-legitimate first-frame=received",
                        ProbeCheck::Unsigned => "PASS control-unsigned helper-byte=no wait=10s",
                        ProbeCheck::SwappedHelper =>
                            "PASS control-swapped-helper released=no request-sent=no",
                        ProbeCheck::ExecAttack =>
                            "PASS attack-exec helper-byte=no wait=10s signed-alive=yes",
                        ProbeCheck::VersionWriteAttack =>
                            "PASS attack-version-write helper-byte=no wait=10s signed-alive=yes",
                    }
                );
            }
            if result.is_ok() {
                println!("PASS peer-identity candidate: both attacks silent; both controls passed");
            }
            result
        }
    });
    if let Err(error) = result {
        eprintln!("STOP peer-identity: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}
