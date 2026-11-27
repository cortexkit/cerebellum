use std::process::ExitCode;

fn main() -> ExitCode {
    // Setup probes the executable without Chrome. These exact one-shot
    // invocations finish before native messaging reserves stdout for frames.
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    if first.as_deref().is_some_and(|arg| arg == "--version") && args.next().is_none() {
        println!("ck-cerebellum-native-host {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if first.as_deref().is_some_and(|arg| arg == "--register") && args.next().is_none() {
        if let Err(reason) = cerebellum_native_host::check_build_gate() {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            return match cerebellum_native_host::registration::register_running_executable() {
                Ok(_) => ExitCode::SUCCESS,
                Err(reason) => {
                    eprintln!("ck-cerebellum-native-host --register: {reason}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            eprintln!("native messaging registration is unavailable on this platform");
            return ExitCode::FAILURE;
        }
    }

    if cerebellum_native_host::run().is_ok() {
        ExitCode::SUCCESS
    } else {
        // Native messaging reserves stdout for frames; refusals stay silent on stderr too.
        ExitCode::FAILURE
    }
}
