//! Tari Ootle commit-then-reveal K-of-N randomness beacon template -- v1 research spike.
//!
//! See README.md in the repository root for the full design writeup: why commit-then-reveal is
//! necessary at all, the combination-function choice (hash-of-concatenation, not XOR) and the
//! reasoning behind it, the flagged design decisions, and "Known limitations / not solved".

use tari_template_lib::prelude::*;

// NOTE: as with both sibling repos (`tari-ootle-escrow`, `tari-ootle-oracle`), we deliberately do
// NOT re-export any types out of `randomness_beacon_template` here. The `#[template]` macro
// consumes/rewrites the `mod randomness_beacon_template { .. }` item and the resulting path is
// not a normal importable module from outside this file. Every public method on
// `RandomnessBeacon` therefore only takes/returns primitive types (`u64`, `u32`, `bool`,
// `Vec<u8>`, `Option<..>`, `RistrettoPublicKeyBytes`, `SchnorrSignatureBytes`) at its ABI
// boundary -- see the "Fixed-size array types" finding in README for why `[u8; 32]` specifically
// cannot be used here despite being the brief's own suggested signature shape.

#[template]
mod randomness_beacon_template {
    use blake2::{Blake2s256, Digest};

    use super::*;

    // NOTE: the `#[template]` macro treats the *first* `pub struct` or `pub enum` declared in
    // this module as "the component" (see the same note in both sibling builds).
    // `RandomnessBeacon` must therefore be declared textually before `RoundRecord` below.
    pub struct RandomnessBeacon {
        /// N registered signer identities.
        signers: Vec<RistrettoPublicKeyBytes>,
        /// K -- minimum number of distinct registered signers that must both commit AND reveal
        /// (with a reveal that hash-matches their own earlier commitment) before a round
        /// finalizes.
        threshold: u32,
        /// One entry per round_id that has ever seen at least one commitment.
        ///
        /// Deliberately a `Vec` scanned linearly by `round_id`, not a map -- same rationale as
        /// the sibling oracle build's `rounds: Vec<RoundRecord>`: `tari_template_lib` component
        /// state needs types the `#[template]` macro can auto-derive CBOR (de)serialize for, and
        /// a plain `Vec` of small records is simplest for a v1 spike with a small number of
        /// rounds. `tari_template_lib`'s `extra-maps` feature (`FastMap`) would be the obvious
        /// v2 upgrade if round counts grow large.
        rounds: Vec<RoundRecord>,
    }

    /// Per-round bookkeeping: every commitment seen so far, every reveal seen so far, and the
    /// finalized combined random output once `>= threshold` signers have done both.
    #[derive(Debug, Clone)]
    pub struct RoundRecord {
        round_id: u64,
        /// One entry per signer that has committed for this round. Per DECISION 3 (see README),
        /// a signer's first commitment for a round is final -- resubmitting the *same*
        /// commitment again is a harmless no-op, resubmitting a *different* one panics.
        ///
        /// `Vec<u8>` rather than a fixed `[u8; 32]` -- see README "Fixed-size array types don't
        /// work at the template ABI boundary" for why. Always exactly 32 bytes in practice
        /// (`commit()` asserts this on the way in), but represented as `Vec<u8>` throughout for
        /// consistency with every other ABI-facing byte value in this template.
        commitments: Vec<(RistrettoPublicKeyBytes, Vec<u8>)>,
        /// One entry per signer that has revealed for this round. A signer can only appear here
        /// if they already appear in `commitments` with a matching hash -- `reveal()` checks and
        /// rejects both "never committed" and "hash doesn't match commitment" before recording
        /// anything.
        reveals: Vec<(RistrettoPublicKeyBytes, Vec<u8>)>,
        /// Set once `>= threshold` distinct signers have both committed and revealed. Once
        /// `Some`, this round is immutable -- see DECISION 4 (README): further commit()/reveal()
        /// calls for a finalized round_id are rejected outright, not silently accepted as no-ops,
        /// because (unlike the oracle build's opaque `Vec<u8>` value) there is no "does this
        /// agree with what's already finalized" comparison that makes sense for a fresh
        /// commitment/reveal pair once the combined output is already fixed.
        finalized: Option<Vec<u8>>,
    }

    /// Signature domain for `commit`'s detached signature. Mixed into the Blake2b Fiat-Shamir
    /// challenge that the engine's `SignatureVerifier` recomputes and checks against -- see
    /// README "Signature verification" (same real, working primitive the sibling oracle build
    /// found and used; copied here rather than re-derived).
    pub struct BeaconCommitDomain;
    impl SignatureDomain for BeaconCommitDomain {
        fn domain() -> &'static [u8] {
            b"tari-ootle-gambling/beacon/commit/v1"
        }
    }

    /// Signature domain for `reveal`'s detached signature. Deliberately a *different* domain
    /// string from `BeaconCommitDomain` -- see README "Signature verification" for why a signer's
    /// commit signature must not also be replayable as a valid reveal signature (or vice versa)
    /// even though both ultimately sign `(round_id, some_bytes)`.
    pub struct BeaconRevealDomain;
    impl SignatureDomain for BeaconRevealDomain {
        fn domain() -> &'static [u8] {
            b"tari-ootle-gambling/beacon/reveal/v1"
        }
    }

    impl RandomnessBeacon {
        /// Registers `signers` as the N federated beacon signer identities and `threshold` (K) as
        /// the number of signers that must both commit and reveal before a round finalizes.
        pub fn create(signers: Vec<RistrettoPublicKeyBytes>, threshold: u32) -> Component<Self> {
            assert!(!signers.is_empty(), "Must have at least one signer");
            assert!(
                threshold >= 1 && (threshold as usize) <= signers.len(),
                "threshold must be between 1 and the number of signers"
            );
            // No duplicate signer identities -- otherwise a single signer's commit/reveal could
            // be (mis)counted more than once toward the threshold. Mirrors the oracle build's
            // identical check in `Oracle::create`.
            for i in 0..signers.len() {
                for j in (i + 1)..signers.len() {
                    assert_ne!(signers[i], signers[j], "Duplicate signer identity in signers list");
                }
            }

            let component = Self {
                signers,
                threshold,
                rounds: Vec::new(),
            };

            // Same reasoning as the oracle build: anyone may relay a `commit`/`reveal` call on a
            // registered signer's behalf (the detached signature is what authorizes, not
            // `CallerContext`), so there is no dynamic caller-identity-based access control
            // needed at the component level.
            Component::new(component)
                .with_access_rules(ComponentAccessRules::new().default(rule!(allow_all)))
                .create()
        }

        /// Phase 1: `signer` commits to `commitment = Blake2s256(secret_bytes)` for `round_id`,
        /// without revealing `secret_bytes` yet. Authenticated by a detached Schnorr signature
        /// over `(round_id, commitment)` -- anyone may relay this call, same pattern as the
        /// oracle build's `submit_value` (see README "Signature verification").
        ///
        /// `commitment` is `Vec<u8>`, not `[u8; 32]` as the brief's sketch suggested -- see
        /// README "Fixed-size array types don't work at the template ABI boundary". Must be
        /// exactly 32 bytes (asserted below); anything else is rejected outright rather than
        /// silently truncated/padded.
        ///
        /// DECISION 3 (flagged, see README): a signer's *first* commitment for a round is final.
        /// Calling this again for the same `(signer, round_id)` with a *different* commitment
        /// panics. Resubmitting the exact same commitment again is a harmless no-op (safely
        /// retry-able after e.g. a relay failure), mirroring the oracle build's
        /// `submit_value` resubmission policy.
        ///
        /// Rejects (panics) if: `signer` is not registered, `commitment` is not 32 bytes, the
        /// signature doesn't verify, or the round is already finalized (DECISION 4).
        pub fn commit(
            &mut self,
            round_id: u64,
            signer: RistrettoPublicKeyBytes,
            commitment: Vec<u8>,
            signature: SchnorrSignatureBytes,
        ) {
            assert!(
                self.signers.contains(&signer),
                "signer is not a registered beacon signer for this component"
            );
            assert_eq!(commitment.len(), 32, "commitment must be exactly 32 bytes (a Blake2s-256 hash)");

            let message = Self::commit_message(round_id, &commitment);
            let sig: Signature<BeaconCommitDomain> = signature.into();
            sig.assert_valid(&PublicKey::from(signer), &message);

            let record = Self::round_mut_or_insert(&mut self.rounds, round_id);
            assert!(
                record.finalized.is_none(),
                "round {round_id} is already finalized; no further commitments are accepted"
            );

            match record.commitments.iter().find(|(pk, _)| pk == &signer) {
                Some((_, existing)) => {
                    assert!(
                        existing == &commitment,
                        "signer has already committed a different value for round {round_id}; a \
                         signer's first commitment for a round is final"
                    );
                    // Resubmitting the same commitment again is a harmless no-op.
                },
                None => {
                    record.commitments.push((signer, commitment));
                },
            }
        }

        /// Phase 2: `signer` reveals `secret` for `round_id`. Rejected outright if `secret`'s
        /// Blake2s-256 hash doesn't match the commitment `signer` submitted in `commit()` for
        /// this `round_id` -- this is the property that stops a signer changing their mind after
        /// seeing others' commitments (see README "Why commit-then-reveal"). Same detached
        /// signature-based auth as `commit()`, over `(round_id, secret)`, under the *separate*
        /// `BeaconRevealDomain`.
        ///
        /// Rejects (panics) if: `signer` is not registered, the signature doesn't verify, the
        /// signer never committed for this `round_id` (off-schedule reveal), the hash doesn't
        /// match the earlier commitment, the signer already revealed a *different* value for this
        /// round, or the round is already finalized (DECISION 4).
        ///
        /// Once this reveal brings the number of (committed AND revealed) signers for `round_id`
        /// to `>= threshold`, the round finalizes immediately: the combined random output is
        /// fixed as the Blake2s-256 hash of the concatenation of exactly those `threshold`
        /// revealed secrets, sorted by signer public key bytes for a deterministic combination
        /// regardless of reveal arrival order (see README "Combination function").
        pub fn reveal(
            &mut self,
            round_id: u64,
            signer: RistrettoPublicKeyBytes,
            secret: Vec<u8>,
            signature: SchnorrSignatureBytes,
        ) {
            assert!(
                self.signers.contains(&signer),
                "signer is not a registered beacon signer for this component"
            );

            let message = Self::reveal_message(round_id, &secret);
            let sig: Signature<BeaconRevealDomain> = signature.into();
            sig.assert_valid(&PublicKey::from(signer), &message);

            let threshold = self.threshold;
            let record = Self::round_mut_or_insert(&mut self.rounds, round_id);
            assert!(
                record.finalized.is_none(),
                "round {round_id} is already finalized; no further reveals are accepted"
            );

            let commitment = record
                .commitments
                .iter()
                .find(|(pk, _)| pk == &signer)
                .map(|(_, c)| c.clone())
                .unwrap_or_else(|| {
                    panic!(
                        "signer has not committed for round {round_id} yet; reveal must be \
                         preceded by a matching commit"
                    )
                });

            let computed = Self::hash_secret(&secret);
            assert!(
                computed == commitment,
                "revealed secret's hash does not match signer's earlier commitment for round \
                 {round_id}"
            );

            match record.reveals.iter().find(|(pk, _)| pk == &signer) {
                Some((_, existing)) => {
                    assert!(
                        existing == &secret,
                        "signer has already revealed a different value for round {round_id}; a \
                         signer's first reveal is final"
                    );
                    // Resubmitting the same secret again is a harmless no-op.
                    return;
                },
                None => {
                    record.reveals.push((signer, secret));
                },
            }

            Self::try_finalize(record, threshold);
        }

        /// The finalized combined random output for `round_id`, once `>= threshold` signers have
        /// both committed and revealed. `None` if the round has never been committed to, or has
        /// not yet reached the threshold. Always exactly 32 bytes when `Some` (a Blake2s-256
        /// digest) -- `Vec<u8>`, not `[u8; 32]`, for the same ABI-boundary reason as `commit`'s
        /// `commitment` parameter (see README).
        pub fn get_random(&self, round_id: u64) -> Option<Vec<u8>> {
            self.find_round(round_id).and_then(|r| r.finalized.clone())
        }

        /// Whether `round_id` has finalized a combined random output.
        pub fn is_finalized(&self, round_id: u64) -> bool {
            self.get_random(round_id).is_some()
        }

        /// The registered signer set (read-only accessor, mainly for tests/off-chain observers).
        pub fn signers(&self) -> Vec<RistrettoPublicKeyBytes> {
            self.signers.clone()
        }

        /// K, the configured threshold (read-only accessor).
        pub fn threshold(&self) -> u32 {
            self.threshold
        }

        /// Number of distinct registered signers that have committed for `round_id` so far
        /// (mainly for tests/off-chain observers).
        pub fn commit_count(&self, round_id: u64) -> u32 {
            self.find_round(round_id).map(|r| r.commitments.len() as u32).unwrap_or(0)
        }

        /// Number of distinct registered signers that have (validly) revealed for `round_id` so
        /// far (mainly for tests/off-chain observers).
        pub fn reveal_count(&self, round_id: u64) -> u32 {
            self.find_round(round_id).map(|r| r.reveals.len() as u32).unwrap_or(0)
        }

        // ---------------------------------------------------------------------------------
        // Internal helpers
        // ---------------------------------------------------------------------------------

        /// The exact bytes each signer signs for `commit`: `round_id` as 8 little-endian bytes,
        /// followed by the 32-byte commitment. Domain separation is handled by
        /// `BeaconCommitDomain`, mixed in separately by the engine's signature verifier.
        fn commit_message(round_id: u64, commitment: &[u8]) -> Vec<u8> {
            let mut message = Vec::with_capacity(8 + commitment.len());
            message.extend_from_slice(&round_id.to_le_bytes());
            message.extend_from_slice(commitment);
            message
        }

        /// The exact bytes each signer signs for `reveal`: `round_id` as 8 little-endian bytes,
        /// followed by the raw revealed secret bytes. Domain separation is handled by
        /// `BeaconRevealDomain` (a *different* domain from `BeaconCommitDomain`, see its doc
        /// comment above).
        fn reveal_message(round_id: u64, secret: &[u8]) -> Vec<u8> {
            let mut message = Vec::with_capacity(8 + secret.len());
            message.extend_from_slice(&round_id.to_le_bytes());
            message.extend_from_slice(secret);
            message
        }

        /// Blake2s-256 hash of `secret` -- the commitment scheme's hash function. See README
        /// "Combination function" for why Blake2s-256 (32-byte output, pure computation, no
        /// engine call needed) rather than the engine's Blake2b-based signature primitive, which
        /// is a different mechanism entirely (checked via an engine call, not computable
        /// standalone inside a template).
        fn hash_secret(secret: &[u8]) -> Vec<u8> {
            let mut hasher = Blake2s256::new();
            hasher.update(secret);
            hasher.finalize().to_vec()
        }

        fn find_round(&self, round_id: u64) -> Option<&RoundRecord> {
            self.rounds.iter().find(|r| r.round_id == round_id)
        }

        fn round_mut_or_insert(rounds: &mut Vec<RoundRecord>, round_id: u64) -> &mut RoundRecord {
            if let Some(idx) = rounds.iter().position(|r| r.round_id == round_id) {
                return &mut rounds[idx];
            }
            rounds.push(RoundRecord {
                round_id,
                commitments: Vec::new(),
                reveals: Vec::new(),
                finalized: None,
            });
            rounds.last_mut().expect("just pushed above")
        }

        /// Finalizes `record` if the number of signers who have now both committed and revealed
        /// has reached `threshold`. The combined output is the Blake2s-256 hash of the
        /// concatenation of all revealed secrets *so far* (which, because this is called
        /// immediately after every single reveal is recorded, is always exactly `threshold`
        /// secrets the first time this triggers -- see README "Combination function" for why the
        /// frozen set is always exactly size `threshold`, not "however many happened to reveal by
        /// the time someone checked").
        fn try_finalize(record: &mut RoundRecord, threshold: u32) {
            if record.reveals.len() < threshold as usize {
                return;
            }
            // Deterministic ordering regardless of reveal arrival order: sort by signer public
            // key bytes before concatenating. Two signers revealing in a different wall-clock
            // order must combine to the identical output.
            let mut sorted = record.reveals.clone();
            sorted.sort_by(|(pk_a, _), (pk_b, _)| pk_a.as_bytes().cmp(pk_b.as_bytes()));

            let mut hasher = Blake2s256::new();
            for (_, secret) in &sorted {
                hasher.update(secret);
            }
            record.finalized = Some(hasher.finalize().to_vec());
        }
    }
}
