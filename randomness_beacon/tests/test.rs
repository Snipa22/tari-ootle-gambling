use tari_ootle_common_types::RistrettoSchnorrBlake2bVerifier;
use tari_template_lib::prelude::*;
use tari_template_test_tooling::{
    TemplateTest,
    byte_type::ToByteType,
    crypto::{PublicKey as _, RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
    engine_types::commit_result::RejectReason,
    support::assert_error::assert_reject_reason,
    transaction::args,
};

/// Must exactly match `BeaconCommitDomain::domain()` in `src/lib.rs`.
const COMMIT_DOMAIN: &[u8] = b"tari-ootle-gambling/beacon/commit/v1";
/// Must exactly match `BeaconRevealDomain::domain()` in `src/lib.rs`.
const REVEAL_DOMAIN: &[u8] = b"tari-ootle-gambling/beacon/reveal/v1";

const SIGNER_SEED_BASE: u8 = 10;

struct Setup {
    test: TemplateTest,
    beacon: ComponentAddress,
    signer_sks: Vec<RistrettoSecretKey>,
    signer_pks: Vec<RistrettoPublicKey>,
}

/// Creates a `RandomnessBeacon` component with `num_signers` registered signers and the given
/// `threshold`.
fn setup(num_signers: usize, threshold: u32) -> Setup {
    let mut test = TemplateTest::my_crate();
    let template = test.get_template_address("RandomnessBeacon");

    let mut signer_sks = Vec::new();
    let mut signer_pks = Vec::new();
    let mut signer_pk_bytes = Vec::new();
    for i in 0..num_signers {
        let (sk, pk) = test.new_key_pair(SIGNER_SEED_BASE + i as u8);
        signer_pk_bytes.push(pk.to_byte_type());
        signer_sks.push(sk);
        signer_pks.push(pk);
    }

    test.execute_expect_success(
        test.transaction()
            .call_function(template, "create", args![signer_pk_bytes, threshold])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );

    let (beacon, _) = test
        .read_only_state_store()
        .get_components_by_template_address(template)
        .unwrap()
        .remove(0);

    Setup {
        test,
        beacon,
        signer_sks,
        signer_pks,
    }
}

/// Signs `(round_id, payload)` under `domain`, using exactly the message shape
/// `RandomnessBeacon::commit`/`reveal` verify against (8 little-endian `round_id` bytes followed
/// by the raw payload bytes -- a 32-byte commitment for `commit`, the raw secret for `reveal`).
/// This is the off-chain step a real beacon signer's wallet would perform.
fn sign(secret: &RistrettoSecretKey, public: &RistrettoPublicKey, domain: &[u8], round_id: u64, payload: &[u8]) -> SchnorrSignatureBytes {
    let mut message = Vec::with_capacity(8 + payload.len());
    message.extend_from_slice(&round_id.to_le_bytes());
    message.extend_from_slice(payload);

    // NOTE: `::rand` (leading `::`) is required -- see the identical note in the sibling oracle
    // build's `tests/test.rs::sign_submission`. `tari_template_lib::prelude::*`'s own `rand`
    // *module* otherwise shadows the external `rand` crate name in this scope.
    let mut rng = ::rand::rng();
    let (nonce, public_nonce) = RistrettoPublicKey::random_keypair(&mut rng);

    let challenge = RistrettoSchnorrBlake2bVerifier::compute_challenge(
        domain,
        &message,
        &public.to_byte_type(),
        &public_nonce.to_byte_type(),
    );

    let signature = RistrettoSchnorr::sign_raw_uniform(secret, nonce, &challenge).expect("signing failed");
    signature.to_byte_type()
}

/// Blake2s-256 of `secret` -- must exactly match `RandomnessBeacon::hash_secret` in `src/lib.rs`.
/// Returns `Vec<u8>` (not `[u8; 32]`) because that's the type the template's `commit` method
/// actually takes -- see README "Fixed-size array types don't work at the template ABI
/// boundary".
fn commitment_for(secret: &[u8]) -> Vec<u8> {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(secret);
    hasher.finalize().to_vec()
}

fn commit_ok(s: &mut Setup, round_id: u64, secret: &[u8], signer_index: usize) -> Vec<u8> {
    let commitment = commitment_for(secret);
    let pk = s.signer_pks[signer_index].clone();
    let sig = sign(&s.signer_sks[signer_index], &pk, COMMIT_DOMAIN, round_id, &commitment);

    s.test.execute_expect_success(
        s.test
            .transaction()
            .call_method(s.beacon, "commit", args![round_id, pk.to_byte_type(), commitment.clone(), sig])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    );
    commitment
}

fn commit_expect_failure(s: &mut Setup, round_id: u64, commitment: Vec<u8>, signer_index: usize) -> RejectReason {
    let pk = s.signer_pks[signer_index].clone();
    let sig = sign(&s.signer_sks[signer_index], &pk, COMMIT_DOMAIN, round_id, &commitment);

    s.test.execute_expect_failure(
        s.test
            .transaction()
            .call_method(s.beacon, "commit", args![round_id, pk.to_byte_type(), commitment, sig])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    )
}

fn reveal_ok(s: &mut Setup, round_id: u64, secret: &[u8], signer_index: usize) {
    let pk = s.signer_pks[signer_index].clone();
    let sig = sign(&s.signer_sks[signer_index], &pk, REVEAL_DOMAIN, round_id, secret);

    s.test.execute_expect_success(
        s.test
            .transaction()
            .call_method(s.beacon, "reveal", args![round_id, pk.to_byte_type(), secret.to_vec(), sig])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    );
}

fn reveal_expect_failure(s: &mut Setup, round_id: u64, secret: &[u8], signer_index: usize) -> RejectReason {
    let pk = s.signer_pks[signer_index].clone();
    let sig = sign(&s.signer_sks[signer_index], &pk, REVEAL_DOMAIN, round_id, secret);

    s.test.execute_expect_failure(
        s.test
            .transaction()
            .call_method(s.beacon, "reveal", args![round_id, pk.to_byte_type(), secret.to_vec(), sig])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    )
}

fn get_random(s: &mut Setup, round_id: u64) -> Option<Vec<u8>> {
    s.test.call_method(s.beacon, "get_random", args![round_id], vec![])
}

fn is_finalized(s: &mut Setup, round_id: u64) -> bool {
    s.test.call_method(s.beacon, "is_finalized", args![round_id], vec![])
}

fn commit_count(s: &mut Setup, round_id: u64) -> u32 {
    s.test.call_method(s.beacon, "commit_count", args![round_id], vec![])
}

fn reveal_count(s: &mut Setup, round_id: u64) -> u32 {
    s.test.call_method(s.beacon, "reveal_count", args![round_id], vec![])
}

/// Reference implementation of the combination function (Blake2s-256 of the concatenation of
/// revealed secrets, sorted by signer public key bytes) -- must exactly match
/// `RandomnessBeacon::try_finalize` in `src/lib.rs`.
fn expected_combined_output(mut secrets_by_pk: Vec<(RistrettoPublicKey, &[u8])>) -> Vec<u8> {
    use blake2::{Blake2s256, Digest};
    secrets_by_pk.sort_by(|(pk_a, _), (pk_b, _)| pk_a.to_byte_type().as_bytes().cmp(pk_b.to_byte_type().as_bytes()));
    let mut hasher = Blake2s256::new();
    for (_, secret) in &secrets_by_pk {
        hasher.update(secret);
    }
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------------------------
// Full happy path: K-of-N commit -> reveal -> finalize, with the correct combined output.
// ---------------------------------------------------------------------------------------------

#[test]
fn k_of_n_commit_then_reveal_finalizes_with_correct_combined_output() {
    let mut s = setup(5, 3);
    let secrets: [&[u8]; 3] = [b"alice-secret", b"bob-secret", b"carol-secret"];

    for (i, secret) in secrets.iter().enumerate() {
        commit_ok(&mut s, 1, secret, i);
    }
    assert!(!is_finalized(&mut s, 1));
    assert_eq!(commit_count(&mut s, 1), 3);

    reveal_ok(&mut s, 1, secrets[0], 0);
    assert!(!is_finalized(&mut s, 1));
    reveal_ok(&mut s, 1, secrets[1], 1);
    assert!(!is_finalized(&mut s, 1));
    reveal_ok(&mut s, 1, secrets[2], 2);

    assert!(is_finalized(&mut s, 1));
    assert_eq!(reveal_count(&mut s, 1), 3);

    let expected = expected_combined_output(vec![
        (s.signer_pks[0].clone(), secrets[0]),
        (s.signer_pks[1].clone(), secrets[1]),
        (s.signer_pks[2].clone(), secrets[2]),
    ]);
    assert_eq!(get_random(&mut s, 1), Some(expected));
}

/// Same three signers revealing in the opposite order must combine to the identical output --
/// demonstrates the deterministic-regardless-of-arrival-order property documented in the README.
#[test]
fn combined_output_is_independent_of_reveal_order() {
    let mut s = setup(5, 3);
    let secrets: [&[u8]; 3] = [b"alice-secret", b"bob-secret", b"carol-secret"];
    for (i, secret) in secrets.iter().enumerate() {
        commit_ok(&mut s, 1, secret, i);
    }
    reveal_ok(&mut s, 1, secrets[2], 2);
    reveal_ok(&mut s, 1, secrets[1], 1);
    reveal_ok(&mut s, 1, secrets[0], 0);

    let expected = expected_combined_output(vec![
        (s.signer_pks[0].clone(), secrets[0]),
        (s.signer_pks[1].clone(), secrets[1]),
        (s.signer_pks[2].clone(), secrets[2]),
    ]);
    assert_eq!(get_random(&mut s, 1), Some(expected));
}

// ---------------------------------------------------------------------------------------------
// Below-threshold reveals leave the round unfinalized.
// ---------------------------------------------------------------------------------------------

#[test]
fn below_threshold_reveals_leave_round_unfinalized() {
    let mut s = setup(5, 3);
    commit_ok(&mut s, 1, b"a", 0);
    commit_ok(&mut s, 1, b"b", 1);
    reveal_ok(&mut s, 1, b"a", 0);
    reveal_ok(&mut s, 1, b"b", 1);

    assert!(!is_finalized(&mut s, 1));
    assert_eq!(get_random(&mut s, 1), None);
    assert_eq!(reveal_count(&mut s, 1), 2);
}

// ---------------------------------------------------------------------------------------------
// Reveal rejected if hash doesn't match earlier commitment -- the core "can't change your mind
// after seeing others' commitments" enforcement mechanism (see README for why this specific
// property is what's being tested, not an end-to-end adversarial simulation).
// ---------------------------------------------------------------------------------------------

#[test]
fn reveal_rejected_if_hash_does_not_match_commitment() {
    let mut s = setup(3, 2);
    commit_ok(&mut s, 1, b"committed-secret", 0);

    // Signer 0 tries to reveal a DIFFERENT secret than the one they committed to.
    let reason = reveal_expect_failure(&mut s, 1, b"a-different-secret", 0);
    assert_reject_reason(reason, "does not match signer's earlier commitment");
    assert_eq!(reveal_count(&mut s, 1), 0);
}

/// The concrete mechanism proving "the last revealer can't bias the outcome by choosing their
/// value after seeing everyone else's reveals": once a signer has committed, ANY attempt to
/// reveal something inconsistent with that commitment -- including one crafted after seeing
/// every other signer's already-revealed secret -- is rejected. This is what actually provides
/// the "can't change your mind" property; see README "Why commit-then-reveal" for why a true
/// end-to-end adversarial simulation ("what if they'd chosen differently") isn't directly
/// testable in one test, and this is the mechanism test that stands in for it.
#[test]
fn signer_cannot_reveal_a_value_chosen_after_seeing_other_reveals() {
    let mut s = setup(3, 3);
    commit_ok(&mut s, 1, b"alice-secret", 0);
    commit_ok(&mut s, 1, b"bob-secret", 1);
    commit_ok(&mut s, 1, b"carol-secret", 2);

    // Alice and Bob reveal first.
    reveal_ok(&mut s, 1, b"alice-secret", 0);
    reveal_ok(&mut s, 1, b"bob-secret", 1);
    assert!(!is_finalized(&mut s, 1));

    // Carol, having now seen both other secrets, tries to reveal something else instead of her
    // committed value (e.g. to steer the combined output). Rejected -- she is locked into the
    // value she committed to before any reveals happened.
    let reason = reveal_expect_failure(&mut s, 1, b"a-value-carol-picked-after-seeing-alice-and-bob", 2);
    assert_reject_reason(reason, "does not match signer's earlier commitment");

    // Carol's only option is to reveal what she actually committed to.
    reveal_ok(&mut s, 1, b"carol-secret", 2);
    assert!(is_finalized(&mut s, 1));
}

// ---------------------------------------------------------------------------------------------
// Off-schedule reveal (before committing) is rejected cleanly.
// ---------------------------------------------------------------------------------------------

#[test]
fn reveal_before_commit_is_rejected() {
    let mut s = setup(3, 2);
    let reason = reveal_expect_failure(&mut s, 1, b"never-committed", 0);
    assert_reject_reason(reason, "has not committed for round");
    assert_eq!(reveal_count(&mut s, 1), 0);
}

// ---------------------------------------------------------------------------------------------
// Non-registered signer's commit/reveal is rejected / does not count.
// ---------------------------------------------------------------------------------------------

#[test]
fn non_registered_signer_commit_is_rejected() {
    let mut s = setup(3, 2);
    let (outsider_sk, outsider_pk) = s.test.new_key_pair(200);
    let commitment = commitment_for(b"42");
    let sig = sign(&outsider_sk, &outsider_pk, COMMIT_DOMAIN, 1, &commitment);

    let result = s.test.execute_expect_failure(
        s.test
            .transaction()
            .call_method(s.beacon, "commit", args![1u64, outsider_pk.to_byte_type(), commitment, sig])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    );
    assert_reject_reason(result, "signer is not a registered beacon signer");
    assert_eq!(commit_count(&mut s, 1), 0);
}

#[test]
fn non_registered_signer_reveal_is_rejected() {
    let mut s = setup(3, 2);
    let (outsider_sk, outsider_pk) = s.test.new_key_pair(200);
    let sig = sign(&outsider_sk, &outsider_pk, REVEAL_DOMAIN, 1, b"42");

    let result = s.test.execute_expect_failure(
        s.test
            .transaction()
            .call_method(s.beacon, "reveal", args![1u64, outsider_pk.to_byte_type(), b"42".to_vec(), sig])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    );
    assert_reject_reason(result, "signer is not a registered beacon signer");
}

// ---------------------------------------------------------------------------------------------
// A signer can't commit twice for the same round with a different commitment.
// ---------------------------------------------------------------------------------------------

#[test]
fn resubmitting_the_same_commitment_is_a_harmless_noop() {
    let mut s = setup(3, 2);
    commit_ok(&mut s, 1, b"42", 0);
    assert_eq!(commit_count(&mut s, 1), 1);

    // Same signer, same commitment again -- must not error, and must not double-count.
    commit_ok(&mut s, 1, b"42", 0);
    assert_eq!(commit_count(&mut s, 1), 1);
}

#[test]
fn committing_a_different_value_for_the_same_round_is_rejected() {
    let mut s = setup(3, 2);
    let real_commitment = commit_ok(&mut s, 1, b"42", 0);
    let other_commitment = commitment_for(b"99");
    assert_ne!(real_commitment, other_commitment);

    let reason = commit_expect_failure(&mut s, 1, other_commitment, 0);
    assert_reject_reason(reason, "first commitment for a round is final");
    assert_eq!(commit_count(&mut s, 1), 1);
}

// ---------------------------------------------------------------------------------------------
// A signer can't reveal twice for the same round with a different (but somehow hash-matching --
// not realistically constructible, so this exercises the "already revealed" guard directly via
// resubmitting the identical secret, proving it's a no-op not an error) value.
// ---------------------------------------------------------------------------------------------

#[test]
fn resubmitting_the_same_reveal_is_a_harmless_noop() {
    let mut s = setup(3, 2);
    commit_ok(&mut s, 1, b"42", 0);
    reveal_ok(&mut s, 1, b"42", 0);
    assert_eq!(reveal_count(&mut s, 1), 1);

    reveal_ok(&mut s, 1, b"42", 0);
    assert_eq!(reveal_count(&mut s, 1), 1);
}

// ---------------------------------------------------------------------------------------------
// Once finalized, further commit/reveal calls for that round_id are rejected outright
// (DECISION 4, see README).
// ---------------------------------------------------------------------------------------------

#[test]
fn finalized_round_rejects_further_commits_and_reveals() {
    let mut s = setup(3, 2);
    commit_ok(&mut s, 1, b"a", 0);
    commit_ok(&mut s, 1, b"b", 1);
    reveal_ok(&mut s, 1, b"a", 0);
    reveal_ok(&mut s, 1, b"b", 1);
    assert!(is_finalized(&mut s, 1));

    // A third, previously-silent signer now tries to commit for the same already-finalized
    // round.
    let commitment = commitment_for(b"c");
    let reason = commit_expect_failure(&mut s, 1, commitment, 2);
    assert_reject_reason(reason, "already finalized");

    // And the same signer trying to reveal without having committed would fail for a different
    // reason anyway, but committing is rejected first, so there's nothing to reveal.
    assert_eq!(commit_count(&mut s, 1), 2);
}

// ---------------------------------------------------------------------------------------------
// Rounds are independent of one another.
// ---------------------------------------------------------------------------------------------

#[test]
fn rounds_are_independent() {
    let mut s = setup(3, 2);
    commit_ok(&mut s, 1, b"round-one-a", 0);
    commit_ok(&mut s, 1, b"round-one-b", 1);
    reveal_ok(&mut s, 1, b"round-one-a", 0);
    reveal_ok(&mut s, 1, b"round-one-b", 1);
    assert!(is_finalized(&mut s, 1));

    assert!(!is_finalized(&mut s, 2));
    assert_eq!(get_random(&mut s, 2), None);

    commit_ok(&mut s, 2, b"round-two-a", 0);
    commit_ok(&mut s, 2, b"round-two-b", 1);
    reveal_ok(&mut s, 2, b"round-two-a", 0);
    reveal_ok(&mut s, 2, b"round-two-b", 1);
    assert!(is_finalized(&mut s, 2));

    assert_ne!(get_random(&mut s, 1), get_random(&mut s, 2));
}

// ---------------------------------------------------------------------------------------------
// Constructor validation.
// ---------------------------------------------------------------------------------------------

#[test]
fn create_rejects_threshold_above_signer_count() {
    let mut test = TemplateTest::my_crate();
    let template = test.get_template_address("RandomnessBeacon");
    let (_sk, pk) = test.new_key_pair(1);

    let reason = test.execute_expect_failure(
        test.transaction()
            .call_function(template, "create", args![vec![pk.to_byte_type()], 2u32])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
    assert_reject_reason(reason, "threshold must be between 1 and the number of signers");
}

#[test]
fn create_rejects_duplicate_signers() {
    let mut test = TemplateTest::my_crate();
    let template = test.get_template_address("RandomnessBeacon");
    let (_sk, pk) = test.new_key_pair(1);

    let reason = test.execute_expect_failure(
        test.transaction()
            .call_function(template, "create", args![vec![pk.to_byte_type(), pk.to_byte_type()], 1u32])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
    assert_reject_reason(reason, "Duplicate signer identity");
}
