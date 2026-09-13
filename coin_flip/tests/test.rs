use blake2::{Blake2s256, Digest};
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

/// Must exactly match `randomness_beacon`'s `BeaconCommitDomain`/`BeaconRevealDomain`.
const COMMIT_DOMAIN: &[u8] = b"tari-ootle-gambling/beacon/commit/v1";
const REVEAL_DOMAIN: &[u8] = b"tari-ootle-gambling/beacon/reveal/v1";

const SIGNER_SEED_BASE: u8 = 10;

struct Setup {
    test: TemplateTest,
    beacon: ComponentAddress,
    coin_flip: ComponentAddress,
    signer_sks: Vec<RistrettoSecretKey>,
    signer_pks: Vec<RistrettoPublicKey>,
}

/// Creates a `RandomnessBeacon` (from the sibling `randomness_beacon` crate) and a `CoinFlip`
/// consulting it, with the house bankroll funded from a fresh funded test account.
///
/// This is what proves the cross-component-call finding in README "Cross-component calls":
/// `TemplateTest::new(CARGO_MANIFEST_DIR, [".", "../randomness_beacon"])` compiles and registers
/// BOTH templates as separate deployed WASM components in the same test package, and
/// `CoinFlip::resolve_bet`'s `ComponentManager::get(beacon).call("get_random", ..)` genuinely
/// calls across that boundary at runtime -- exercised by every test in this file.
fn setup(num_signers: usize, threshold: u32, house_funding: u64) -> Setup {
    let mut test = TemplateTest::new(env!("CARGO_MANIFEST_DIR"), [".", "../randomness_beacon"]);
    let beacon_template = test.get_template_address("RandomnessBeacon");
    let coin_flip_template = test.get_template_address("CoinFlip");

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
            .call_function(beacon_template, "create", args![signer_pk_bytes, threshold])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );
    let (beacon, _) = test
        .read_only_state_store()
        .get_components_by_template_address(beacon_template)
        .unwrap()
        .remove(0);

    let (house_account, _house_proof, house_sk) = test.create_funded_account();
    test.execute_expect_success(
        test.transaction()
            .call_method(house_account, "withdraw", args![TARI_TOKEN, Amount::from(house_funding)])
            .put_last_instruction_output_on_workspace("house_bucket")
            .call_function(coin_flip_template, "create", args![beacon, Workspace("house_bucket")])
            .build_and_seal(&house_sk),
        vec![],
    );
    let (coin_flip, _) = test
        .read_only_state_store()
        .get_components_by_template_address(coin_flip_template)
        .unwrap()
        .remove(0);

    Setup {
        test,
        beacon,
        coin_flip,
        signer_sks,
        signer_pks,
    }
}

/// Signs `(round_id, payload)` under `domain` -- identical construction to
/// `randomness_beacon/tests/test.rs::sign`, duplicated here because these are separate crates.
fn sign(secret: &RistrettoSecretKey, public: &RistrettoPublicKey, domain: &[u8], round_id: u64, payload: &[u8]) -> SchnorrSignatureBytes {
    let mut message = Vec::with_capacity(8 + payload.len());
    message.extend_from_slice(&round_id.to_le_bytes());
    message.extend_from_slice(payload);

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

fn commitment_for(secret: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2s256::new();
    hasher.update(secret);
    hasher.finalize().to_vec()
}

fn commit(s: &mut Setup, round_id: u64, secret: &[u8], signer_index: usize) {
    let commitment = commitment_for(secret);
    let pk = s.signer_pks[signer_index].clone();
    let sig = sign(&s.signer_sks[signer_index], &pk, COMMIT_DOMAIN, round_id, &commitment);
    s.test.execute_expect_success(
        s.test
            .transaction()
            .call_method(s.beacon, "commit", args![round_id, pk.to_byte_type(), commitment, sig])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    );
}

fn reveal(s: &mut Setup, round_id: u64, secret: &[u8], signer_index: usize) {
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

/// Predicted combined beacon output for `secrets`, revealed by signers `0..secrets.len()` --
/// must exactly match `RandomnessBeacon::try_finalize`'s combination function.
fn predicted_combined_output(s: &Setup, secrets: &[&[u8]]) -> Vec<u8> {
    let mut pairs: Vec<(RistrettoPublicKey, &[u8])> =
        secrets.iter().enumerate().map(|(i, sec)| (s.signer_pks[i].clone(), *sec)).collect();
    pairs.sort_by(|(a, _), (b, _)| a.to_byte_type().as_bytes().cmp(b.to_byte_type().as_bytes()));
    let mut hasher = Blake2s256::new();
    for (_, sec) in &pairs {
        hasher.update(sec);
    }
    hasher.finalize().to_vec()
}

/// Commits then reveals `secrets` (length must be `>= threshold`) from signers `0..secrets.len()`,
/// finalizing `round_id` on the beacon. Returns the predicted combined output (see
/// `predicted_combined_output`) so tests can compute the expected coin-flip outcome up front,
/// deterministically, rather than discovering it after the fact.
fn finalize_round(s: &mut Setup, round_id: u64, secrets: &[&[u8]]) -> Vec<u8> {
    for (i, secret) in secrets.iter().enumerate() {
        commit(s, round_id, secret, i);
    }
    for (i, secret) in secrets.iter().enumerate() {
        reveal(s, round_id, secret, i);
    }
    predicted_combined_output(s, secrets)
}

/// Must exactly match `CoinFlip::resolve_bet`'s documented outcome convention: bit 0 of byte 0.
fn outcome_heads(combined_output: &[u8]) -> bool {
    combined_output[0] & 1 == 0
}

fn place_bet(s: &mut Setup, round_id: u64, guess_heads: bool, stake: u64, player_account: ComponentAddress, player_sk: &RistrettoSecretKey) {
    s.test.execute_expect_success(
        s.test
            .transaction()
            .call_method(player_account, "withdraw", args![TARI_TOKEN, Amount::from(stake)])
            .put_last_instruction_output_on_workspace("stake_bucket")
            .call_method(s.coin_flip, "place_bet", args![
                round_id,
                guess_heads,
                Workspace("stake_bucket"),
                player_account
            ])
            .build_and_seal(player_sk),
        vec![],
    );
}

fn place_bet_expect_failure(
    s: &mut Setup,
    round_id: u64,
    guess_heads: bool,
    stake: u64,
    player_account: ComponentAddress,
    player_sk: &RistrettoSecretKey,
) -> RejectReason {
    s.test.execute_expect_failure(
        s.test
            .transaction()
            .call_method(player_account, "withdraw", args![TARI_TOKEN, Amount::from(stake)])
            .put_last_instruction_output_on_workspace("stake_bucket")
            .call_method(s.coin_flip, "place_bet", args![
                round_id,
                guess_heads,
                Workspace("stake_bucket"),
                player_account
            ])
            .build_and_seal(player_sk),
        vec![],
    )
}

fn resolve_bet_ok(s: &mut Setup, round_id: u64) {
    s.test.execute_expect_success(
        s.test
            .transaction()
            .call_method(s.coin_flip, "resolve_bet", args![round_id])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    );
}

fn resolve_bet_expect_failure(s: &mut Setup, round_id: u64) -> RejectReason {
    s.test.execute_expect_failure(
        s.test
            .transaction()
            .call_method(s.coin_flip, "resolve_bet", args![round_id])
            .build_and_seal(s.test.secret_key()),
        vec![s.test.owner_proof()],
    )
}

fn balance(s: &mut Setup, account: ComponentAddress) -> Amount {
    s.test.call_method(account, "balance", args![TARI_TOKEN], vec![])
}

fn house_balance(s: &mut Setup) -> Amount {
    s.test.call_method(s.coin_flip, "house_balance", args![], vec![])
}

fn bet_player_won(s: &mut Setup, round_id: u64) -> Option<bool> {
    s.test.call_method(s.coin_flip, "bet_player_won", args![round_id], vec![])
}

// ---------------------------------------------------------------------------------------------
// Full happy path, winning guess: signers commit -> reveal -> beacon finalizes -> player bets
// (correctly) -> resolve -> player receives 2x stake, house pays out 1x net.
// ---------------------------------------------------------------------------------------------

#[test]
fn full_happy_path_correct_guess_pays_out_double() {
    let mut s = setup(3, 2, 1_000_000);
    let round_id = 1;
    let stake = 1_000u64;

    let (player_account, _proof, player_sk) = s.test.create_funded_account();
    let player_balance_before = balance(&mut s, player_account);
    let house_balance_before = house_balance(&mut s);

    let secrets: [&[u8]; 2] = [b"alice-secret", b"bob-secret"];
    let predicted = predicted_combined_output(&s, &secrets);
    let guess_heads = outcome_heads(&predicted);

    place_bet(&mut s, round_id, guess_heads, stake, player_account, &player_sk);
    let combined = finalize_round(&mut s, round_id, &secrets);
    assert_eq!(combined, predicted);

    resolve_bet_ok(&mut s, round_id);

    assert_eq!(bet_player_won(&mut s, round_id), Some(true));
    // Player spent `stake` placing the bet, then received `2 * stake` back: net +stake.
    assert_eq!(balance(&mut s, player_account), player_balance_before + stake);
    // House received `stake` (forfeited into the vault) then paid out `2 * stake`: net -stake.
    assert_eq!(house_balance(&mut s), house_balance_before - stake);
}

// ---------------------------------------------------------------------------------------------
// Full happy path, losing guess: stake is forfeited to the house, player receives nothing.
// ---------------------------------------------------------------------------------------------

#[test]
fn full_happy_path_incorrect_guess_forfeits_stake_to_house() {
    let mut s = setup(3, 2, 1_000_000);
    let round_id = 1;
    let stake = 1_000u64;

    let (player_account, _proof, player_sk) = s.test.create_funded_account();
    let player_balance_before = balance(&mut s, player_account);
    let house_balance_before = house_balance(&mut s);

    let secrets: [&[u8]; 2] = [b"alice-secret", b"bob-secret"];
    let predicted = predicted_combined_output(&s, &secrets);
    // Deliberately guess the WRONG side.
    let guess_heads = !outcome_heads(&predicted);

    place_bet(&mut s, round_id, guess_heads, stake, player_account, &player_sk);
    finalize_round(&mut s, round_id, &secrets);
    resolve_bet_ok(&mut s, round_id);

    assert_eq!(bet_player_won(&mut s, round_id), Some(false));
    // Player only ever spent `stake` placing the bet, got nothing back.
    assert_eq!(balance(&mut s, player_account), player_balance_before - stake);
    // House keeps the forfeited stake.
    assert_eq!(house_balance(&mut s), house_balance_before + stake);
}

// ---------------------------------------------------------------------------------------------
// resolve_bet fails/rejects cleanly if called before the beacon round is finalized.
// ---------------------------------------------------------------------------------------------

#[test]
fn resolve_bet_fails_before_beacon_round_is_finalized() {
    let mut s = setup(3, 2, 1_000_000);
    let round_id = 1;
    let (player_account, _proof, player_sk) = s.test.create_funded_account();

    place_bet(&mut s, round_id, true, 1_000, player_account, &player_sk);
    // Only one of the two required signers commits+reveals -- round never finalizes.
    commit(&mut s, round_id, b"alice-secret", 0);
    reveal(&mut s, round_id, b"alice-secret", 0);

    let reason = resolve_bet_expect_failure(&mut s, round_id);
    assert_reject_reason(reason, "is not finalized yet");
}

// ---------------------------------------------------------------------------------------------
// resolve_bet fails cleanly if no bet was ever placed for that round_id.
// ---------------------------------------------------------------------------------------------

#[test]
fn resolve_bet_fails_if_no_bet_was_ever_placed() {
    let mut s = setup(3, 2, 1_000_000);
    let reason = resolve_bet_expect_failure(&mut s, 999);
    assert_reject_reason(reason, "no bet was ever placed");
}

// ---------------------------------------------------------------------------------------------
// resolve_bet fails cleanly on a second call for an already-resolved bet.
// ---------------------------------------------------------------------------------------------

#[test]
fn resolve_bet_fails_on_double_resolve() {
    let mut s = setup(3, 2, 1_000_000);
    let round_id = 1;
    let (player_account, _proof, player_sk) = s.test.create_funded_account();

    place_bet(&mut s, round_id, true, 1_000, player_account, &player_sk);
    finalize_round(&mut s, round_id, &[b"a", b"b"]);
    resolve_bet_ok(&mut s, round_id);

    let reason = resolve_bet_expect_failure(&mut s, round_id);
    assert_reject_reason(reason, "already been resolved");
}

// ---------------------------------------------------------------------------------------------
// Only one bet per round_id is supported on a given CoinFlip instance (DEVIATION FROM BRIEF,
// see README "One bet per round_id").
// ---------------------------------------------------------------------------------------------

#[test]
fn place_bet_fails_if_a_bet_already_exists_for_the_round_id() {
    let mut s = setup(3, 2, 1_000_000);
    let round_id = 1;
    let (player_a, _proof_a, sk_a) = s.test.create_funded_account();
    let (player_b, _proof_b, sk_b) = s.test.create_funded_account();

    place_bet(&mut s, round_id, true, 1_000, player_a, &sk_a);
    let reason = place_bet_expect_failure(&mut s, round_id, false, 500, player_b, &sk_b);
    assert_reject_reason(reason, "a bet has already been placed for round");
}

// ---------------------------------------------------------------------------------------------
// A zero-value stake is rejected.
// ---------------------------------------------------------------------------------------------

#[test]
fn place_bet_fails_on_zero_stake() {
    let mut s = setup(3, 2, 1_000_000);
    let (player_account, _proof, player_sk) = s.test.create_funded_account();
    let reason = place_bet_expect_failure(&mut s, 1, true, 0, player_account, &player_sk);
    assert_reject_reason(reason, "stake must be non-zero");
}

// ---------------------------------------------------------------------------------------------
// The house bankroll can be topped up after construction.
// ---------------------------------------------------------------------------------------------

#[test]
fn fund_house_increases_house_balance() {
    let mut s = setup(3, 2, 1_000_000);
    let before = house_balance(&mut s);

    let (funder_account, _proof, funder_sk) = s.test.create_funded_account();
    s.test.execute_expect_success(
        s.test
            .transaction()
            .call_method(funder_account, "withdraw", args![TARI_TOKEN, Amount::from(5_000u64)])
            .put_last_instruction_output_on_workspace("top_up")
            .call_method(s.coin_flip, "fund_house", args![Workspace("top_up")])
            .build_and_seal(&funder_sk),
        vec![],
    );

    assert_eq!(house_balance(&mut s), before + 5_000u64);
}

// ---------------------------------------------------------------------------------------------
// Rounds/bets are independent of one another on the same CoinFlip instance.
// ---------------------------------------------------------------------------------------------

#[test]
fn bets_on_different_round_ids_are_independent() {
    let mut s = setup(3, 2, 1_000_000);
    let (player_account, _proof, player_sk) = s.test.create_funded_account();

    let secrets_1: [&[u8]; 2] = [b"round1-a", b"round1-b"];
    let predicted_1 = predicted_combined_output(&s, &secrets_1);
    place_bet(&mut s, 1, outcome_heads(&predicted_1), 1_000, player_account, &player_sk);
    finalize_round(&mut s, 1, &secrets_1);
    resolve_bet_ok(&mut s, 1);
    assert_eq!(bet_player_won(&mut s, 1), Some(true));

    let secrets_2: [&[u8]; 2] = [b"round2-a", b"round2-b"];
    let predicted_2 = predicted_combined_output(&s, &secrets_2);
    place_bet(&mut s, 2, !outcome_heads(&predicted_2), 1_000, player_account, &player_sk);
    finalize_round(&mut s, 2, &secrets_2);
    resolve_bet_ok(&mut s, 2);
    assert_eq!(bet_player_won(&mut s, 2), Some(false));
}
