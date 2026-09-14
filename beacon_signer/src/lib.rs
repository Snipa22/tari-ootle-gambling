//! Core signing/hashing logic for the `beacon_signer` CLI.
//!
//! This is the exact same real, tested crypto the sibling `randomness_beacon` crate's own test
//! suite (`randomness_beacon/tests/test.rs::sign`/`commitment_for`) uses to construct real
//! `commit`/`reveal` calls against the live `RandomnessBeacon` template -- reused byte-for-byte
//! here, not re-derived. See this crate's `tests/acceptance.rs` for the end-to-end proof that a
//! signature this module produces is actually accepted by the real template.

use blake2::{Blake2s256, Digest};
use ootle_byte_type::ToByteType;
use tari_crypto::{
    keys::PublicKey as _,
    ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
};
use tari_ootle_common_types::RistrettoSchnorrBlake2bVerifier;
use tari_template_lib_types::crypto::SchnorrSignatureBytes;

/// Signature domain for `RandomnessBeacon::commit`'s detached signature. Must exactly match
/// `BeaconCommitDomain::domain()` in `randomness_beacon/src/lib.rs` -- `tests/acceptance.rs`
/// proves this hasn't drifted by actually feeding a signature signed under this domain into the
/// real compiled template and confirming it's accepted.
pub const COMMIT_DOMAIN: &[u8] = b"tari-ootle-gambling/beacon/commit/v1";

/// Signature domain for `RandomnessBeacon::reveal`'s detached signature. Must exactly match
/// `BeaconRevealDomain::domain()` in `randomness_beacon/src/lib.rs` -- same drift-proofing as
/// `COMMIT_DOMAIN` above, via `tests/acceptance.rs`.
pub const REVEAL_DOMAIN: &[u8] = b"tari-ootle-gambling/beacon/reveal/v1";

/// Generates a fresh Ristretto keypair using real randomness.
///
/// NOTE: `::rand` (leading `::`) would be required here if `tari_template_lib::prelude::*`'s own
/// `rand` *module* were ever in scope in this crate (it shadows the external `rand` crate name --
/// see the identical note in `randomness_beacon/tests/test.rs::sign`). This crate never imports
/// that prelude (it is a native CLI, not a WASM template), so plain `rand::rng()` is unambiguous
/// here, but the leading-`::` form is used anyway for byte-for-byte consistency with the reused
/// logic below.
pub fn generate_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
    let mut rng = ::rand::rng();
    RistrettoPublicKey::random_keypair(&mut rng)
}

/// Signs `(round_id, payload)` under `domain`, using exactly the message shape
/// `RandomnessBeacon::commit`/`reveal` verify against (8 little-endian `round_id` bytes followed
/// by the raw payload bytes -- a 32-byte commitment for `commit`, the raw secret for `reveal`).
///
/// Byte-for-byte identical to `randomness_beacon/tests/test.rs::sign` -- this is the off-chain
/// step a real beacon signer performs.
pub fn sign(
    secret: &RistrettoSecretKey,
    public: &RistrettoPublicKey,
    domain: &[u8],
    round_id: u64,
    payload: &[u8],
) -> SchnorrSignatureBytes {
    let mut message = Vec::with_capacity(8 + payload.len());
    message.extend_from_slice(&round_id.to_le_bytes());
    message.extend_from_slice(payload);

    // NOTE: `::rand` (leading `::`) is required -- see the identical note in
    // `randomness_beacon/tests/test.rs::sign`. `tari_template_lib::prelude::*`'s own `rand`
    // *module* otherwise shadows the external `rand` crate name in this scope. Not actually in
    // scope in this crate (see `generate_keypair` above), but kept for consistency.
    let mut rng = ::rand::rng();
    let (nonce, public_nonce) = RistrettoPublicKey::random_keypair(&mut rng);

    let challenge = RistrettoSchnorrBlake2bVerifier::compute_challenge(
        domain,
        &message,
        &public.to_byte_type(),
        &public_nonce.to_byte_type(),
    );

    let signature =
        RistrettoSchnorr::sign_raw_uniform(secret, nonce, &challenge).expect("signing failed");
    signature.to_byte_type()
}

/// Blake2s-256 of `secret` -- must exactly match `RandomnessBeacon::hash_secret` in
/// `randomness_beacon/src/lib.rs` (byte-for-byte identical to
/// `randomness_beacon/tests/test.rs::commitment_for`).
pub fn hash_secret(secret: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    hasher.update(secret);
    hasher.finalize().to_vec()
}
