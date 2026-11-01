// Category 3 against oqs (kem-eng overlay-12, body.rs). oqs builds only where pb_oqs is set.
#[cfg(pb_oqs)]
mod body;

fn main() {
    #[cfg(pb_oqs)]
    body::main();

    #[cfg(not(pb_oqs))]
    println!("SKIP\tkem\toqs 0.11.0 does not build for this target");
}
