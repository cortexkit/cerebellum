use std::process::ExitCode;

fn main() -> ExitCode {
    // Setup probes the executable without Chrome. These exact one-shot
    // invocations finish before native messaging reserves stdout for frames.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--version" {
        println!("ck-cerebellum-native-host {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.len() == 1 && args[0] == "--register" {
        #[cfg(target_os = "macos")]
        {
            return match cerebellum_native_host::registration::register_running_executable() {
                Ok(_) => ExitCode::SUCCESS,
                Err(reason) => {
                    eprintln!("ck-cerebellum-native-host --register: {reason}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("Usage: ck-cerebellum-native-host --register (macOS only)");
            return ExitCode::from(2);
        }
    }

    if cerebellum_native_host::run().is_ok() {
        ExitCode::SUCCESS
    } else {
        // Native messaging reserves stdout for frames; refusals stay silent on stderr too.
        ExitCode::FAILURE
    }
}
