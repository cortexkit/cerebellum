/// A generous real-clock bound for tests to detect a wait that never finishes.
/// This is a hang detector, not a claim about how quickly work should complete;
/// timing claims belong in tests with a simulated or injected clock.
pub const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(60);
