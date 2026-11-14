// Sets crypto_pq_optimized when the crate is compiled at opt-level 3, where LLVM keeps the arrays
// that wipe::wipe_unless_optimized takes in registers (D-76). At 2 some of them stay in memory
// (keccak::permute e, for one), so 2 sets nothing, as does every other level and a level that
// cannot be read: those arrays are then wiped. It never panics.
use std::env;
use std::io::Write;

// The opt-level that rustc applies: the profile's, which cargo passes in OPT_LEVEL with package
// overrides applied, unless RUSTFLAGS name one, of which the last wins.
fn opt_level() -> Option<String> {
    let mut level = env::var("OPT_LEVEL").ok();

    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();

    let mut fields = flags.split('\x1f');

    while let Some(field) = fields.next() {
        let option = if field == "-C" || field == "--codegen" {
            fields.next()
        } else if let Some(option) = field.strip_prefix("--codegen=") {
            Some(option)
        } else if field.starts_with("--") {
            None
        } else if let Some(option) = field.strip_prefix("-C") {
            Some(option)
        } else if field == "-O" {
            Some("opt-level=3")
        } else {
            None
        };

        if let Some(value) = option.and_then(|option| option.strip_prefix("opt-level=")) {
            level = Some(value.to_owned());
        }
    }

    level
}

fn main() {
    let mut out = std::io::stdout().lock();

    let _ = writeln!(out, "cargo::rerun-if-changed=build.rs");

    if opt_level().as_deref() == Some("3") {
        let _ = writeln!(out, "cargo::rustc-cfg=crypto_pq_optimized");
    }
}
