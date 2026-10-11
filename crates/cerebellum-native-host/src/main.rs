use std::process::ExitCode;

fn main() -> ExitCode {
    if cerebellum_native_host::run().is_ok() {
        ExitCode::SUCCESS
    } else {
        // Native messaging reserves stdout for frames; refusals stay silent on stderr too.
        ExitCode::FAILURE
    }
}
