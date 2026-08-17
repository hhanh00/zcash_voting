//! Prints the deterministic delegation proof fingerprints — run from the fork
//! workspace (crates.io deps) AND from the app workspace (patched deps) and
//! compare. Identical hashes mean byte-identical proof serialization.
//!
//! Run: cargo run -p zcash_voting --example proof_probe
fn main() {
    let (len, proof_hex, pi_hex) = zcash_voting::zkp1::delegation_proof_probe();
    println!("delegation proof size: {len} bytes");
    println!("delegation proof sha256[..16]: {proof_hex}");
    println!("public inputs sha256[..8]: {pi_hex}");
}
