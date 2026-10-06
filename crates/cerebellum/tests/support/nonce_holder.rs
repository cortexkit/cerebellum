// Test-only nonce holder for reserved-module fixtures, never shipped.
// Keep one native image alive so the daemon can verify the configured program;
// a shell can replace its executable before the daemon checks that the launched
// program matches the configured one.
fn main() {
    let nonce = subc_os::launch_nonce()
        .expect("read daemon launch nonce")
        .expect("daemon must supply a launch nonce");
    let path = std::path::PathBuf::from(std::env::var_os("NONCE_OUT").expect("nonce output path"));
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, nonce.value()).expect("write launch nonce");
    std::fs::rename(temporary, path).expect("publish launch nonce");
    loop {
        std::thread::park();
    }
}
