// Test-only privacy trampoline for embedded subc-daemon supervisors, never shipped.
// The daemon running inside each integration test launches modules through this
// executable so macOS does not attribute their privacy requests to the test
// process that launched them.
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    subc_os::privacy_identity::trampoline_main(&args);
    std::process::exit(2);
}
