fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!(
            "cargo:rustc-env=CEREBELLUM_LINUX_TARGET={}",
            std::env::var("TARGET").expect("Cargo sets TARGET for build scripts")
        );
    }
    println!("cargo:rerun-if-changed=build.rs");
}
