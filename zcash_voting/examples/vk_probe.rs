//! Prints a deterministic delegation-circuit fingerprint — run this from the
//! fork workspace (crates.io deps) AND from the app workspace (patched deps)
//! and compare the output.
//!
//! Run: cargo run -p zcash_voting --example vk_probe
use sha2::{Digest, Sha256};
use voting_circuits::delegation::delegation_cached_keys;

fn main() {
    let (params, _pk, vk) = delegation_cached_keys().expect("delegation keygen");
    // VerifyingKey derives Debug over its content (domain, fixed
    // commitments, permutation, constraint system) — no pointers — so the
    // hash below is a deterministic circuit-layout fingerprint.
    let fp = format!("k={} vk={:?}", params.k(), vk);
    let digest = Sha256::digest(fp.as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    println!("delegation circuit fingerprint: {hex}");
}
