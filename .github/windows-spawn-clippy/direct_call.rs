pub fn forbidden_direct_call() -> std::io::Result<std::process::Child> {
    std::process::Command::new("unused").spawn()
}
