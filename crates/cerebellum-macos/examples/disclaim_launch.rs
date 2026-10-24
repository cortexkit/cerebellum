//! Launch an operator-approved desk probe without lending it the launcher's
//! macOS privacy permissions. The probe must hold its own permission grants.

#[cfg(target_os = "macos")]
fn main() {
    use std::os::unix::process::ExitStatusExt;

    let mut arguments = std::env::args_os().skip(1);
    let Some(executable) = arguments.next() else {
        eprintln!("usage: disclaim_launch <executable> [arguments ...]");
        std::process::exit(2);
    };
    let arguments = arguments.collect::<Vec<_>>();
    match cerebellum_macos::spawn_disclaimed_and_wait(std::path::Path::new(&executable), &arguments)
    {
        Ok(status) => {
            std::process::exit(
                status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
            );
        }
        Err(error) => {
            eprintln!("REFUSED: could not launch or wait for {executable:?}: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("REFUSED: disclaim_launch requires macOS");
    std::process::exit(2);
}
