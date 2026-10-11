//! A silent native-messaging relay that authenticates its Chrome parent and the
//! local cerebellum socket server. Cerebellum separately authenticates the host.
//!
//! The host never interprets action payloads. The cerebellum browser bridge owns
//! action admission, epochs, deadlines, cancellation and chunking.

pub mod browsers;
#[cfg(any(target_os = "macos", test))]
mod framing;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(unix, any(target_os = "macos", test)))]
mod relay;

pub fn run() -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::run()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native messaging is supported on macOS only",
        ))
    }
}
