// Category 3 against aws-lc-rs and pqcrypto-mlkem (kem-eng overlay-13, body.rs); both are
// C-backed and build only where pb_c is set.
#[cfg(pb_c)]
mod body;

fn main() {
    #[cfg(pb_c)]
    body::main();

    #[cfg(not(pb_c))]
    println!("SKIP\tkem2\taws-lc-rs 1.19.0 and pqcrypto-mlkem 0.1.1 do not build for this target");
}
