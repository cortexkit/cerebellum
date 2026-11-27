fn main() {
    if let Some(platform) = match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("linux") => Some("LINUX"),
        Ok("windows") => Some("WINDOWS"),
        _ => None,
    } {
        println!(
            "cargo:rustc-env=CEREBELLUM_{platform}_TARGET={}",
            std::env::var("TARGET").expect("Cargo sets TARGET for build scripts")
        );
    }
    println!("cargo:rerun-if-changed=build.rs");
}
