// Target cfgs of the rival crates that build there with their default features (rule D2):
// pb_c for the C-backed crates (not on wasm32), pb_oqs for oqs (not on wasm32 or 32-bit ARM).
fn main() {
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let wasm = family.split(',').any(|f| f == "wasm");

    println!("cargo::rustc-check-cfg=cfg(pb_c)");

    println!("cargo::rustc-check-cfg=cfg(pb_oqs)");

    println!("cargo::rustc-check-cfg=cfg(rab_v16)");

    if !wasm {
        println!("cargo::rustc-cfg=pb_c");
    }

    if !wasm && arch != "arm" {
        println!("cargo::rustc-cfg=pb_oqs");
    }
}
