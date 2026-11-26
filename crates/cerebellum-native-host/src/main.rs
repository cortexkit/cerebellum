use std::process::ExitCode;

fn main() -> ExitCode {
    // Setup probes the executable without Chrome. Only the exact one-shot
    // invocation may print text on the native-messaging stream.
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|arg| arg == "--version") && args.next().is_none() {
        println!("ck-cerebellum-native-host {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    if cerebellum_native_host::run().is_ok() {
        ExitCode::SUCCESS
    } else {
        // Native messaging reserves stdout for frames; refusals stay silent on stderr too.
        ExitCode::FAILURE
    }
}
