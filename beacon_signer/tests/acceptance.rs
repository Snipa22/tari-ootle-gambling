//! Real, end-to-end acceptance test: proves a signature produced by this crate's own compiled
//! `beacon_signer` binary (not just the internal `beacon_signer::sign` function) is accepted by
//! the real, compiled `RandomnessBeacon` template -- i.e. `sig.assert_valid` inside
//! `RandomnessBeacon::commit`/`reveal` does not panic.
//!
//! This is the load-bearing correctness check for the whole `beacon_signer` utility (see
//! `DISPATCH_BRIEF.md`): a signer tool that produces signatures the real template rejects is
//! worse than useless.

use std::process::Command;

use tari_template_lib_types::crypto::{RistrettoPublicKeyBytes, SchnorrSignatureBytes};
use tari_template_test_tooling::{transaction::args, TemplateTest};

/// Runs the real, compiled `beacon_signer` binary (`env!("CARGO_BIN_EXE_beacon_signer")`,
/// set by Cargo for integration tests) with `args` and returns its stdout, asserting it exited
/// successfully.
fn run_cli(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_beacon_signer"))
        .args(args)
        .output()
        .expect("failed to run the beacon_signer binary");
    assert!(
        output.status.success(),
        "beacon_signer {args:?} exited with failure; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("beacon_signer produced non-utf8 stdout")
}

/// Extracts the value of a `<field>: <value>` line from `beacon_signer`'s stdout.
fn extract_field(stdout: &str, field: &str) -> String {
    let prefix = format!("{field}: ");
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| {
            panic!("beacon_signer output missing a `{field}: ` line; full output:\n{stdout}")
        })
        .trim()
        .to_string()
}

#[test]
fn cli_produced_commit_and_reveal_signatures_are_accepted_by_the_real_template() {
    // 1. `generate-key` -> a real keypair.
    let stdout = run_cli(&["generate-key"]);
    let public_key_hex = extract_field(&stdout, "public_key");
    let secret_key_hex = extract_field(&stdout, "secret_key");

    // 2. `hash-secret` with some real secret bytes -> the real commitment.
    let secret_hex = hex::encode(b"beacon-signer-acceptance-test-secret");
    let stdout = run_cli(&["hash-secret", "--secret", &secret_hex]);
    let commitment_hex = extract_field(&stdout, "commitment");
    assert_eq!(
        hex::decode(&commitment_hex).unwrap(),
        beacon_signer::hash_secret(&hex::decode(&secret_hex).unwrap()),
        "CLI's hash-secret must match the library's own hash_secret"
    );

    // 3. `sign-commit` with round_id=1, that commitment -> a real signature.
    let stdout = run_cli(&[
        "sign-commit",
        "--secret-key",
        &secret_key_hex,
        "--public-key",
        &public_key_hex,
        "--round-id",
        "1",
        "--commitment",
        &commitment_hex,
    ]);
    let commit_signature_hex = extract_field(&stdout, "signature");

    // `sign-reveal`, same round, the real secret -> a real signature.
    let stdout = run_cli(&[
        "sign-reveal",
        "--secret-key",
        &secret_key_hex,
        "--public-key",
        &public_key_hex,
        "--round-id",
        "1",
        "--secret",
        &secret_hex,
    ]);
    let reveal_signature_hex = extract_field(&stdout, "signature");

    let signer_pk =
        RistrettoPublicKeyBytes::from_hex(&public_key_hex).expect("valid public key hex from CLI");
    let commitment = hex::decode(&commitment_hex).expect("valid commitment hex from CLI");
    let secret = hex::decode(&secret_hex).expect("valid secret hex");
    let commit_signature =
        SchnorrSignatureBytes::from_bytes(&hex::decode(&commit_signature_hex).unwrap())
            .expect("valid signature bytes from CLI");
    let reveal_signature =
        SchnorrSignatureBytes::from_bytes(&hex::decode(&reveal_signature_hex).unwrap())
            .expect("valid signature bytes from CLI");

    // 4. Actually verify the signatures are valid: build a real `RandomnessBeacon` component
    // (compiling the real, sibling `randomness_beacon` crate's WASM) with this CLI-generated
    // signer registered, and feed the CLI's own `commit`/`reveal` output into it.
    let mut test = TemplateTest::new("../randomness_beacon", ["."]);
    let template = test.get_template_address("RandomnessBeacon");

    test.execute_expect_success(
        test.transaction()
            .call_function(template, "create", args![vec![signer_pk], 1u32])
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );

    let (beacon, _) = test
        .read_only_state_store()
        .get_components_by_template_address(template)
        .unwrap()
        .remove(0);

    // The load-bearing check: `commit()` calls `sig.assert_valid(..)` internally and panics
    // (rejecting the transaction) if the signature doesn't verify. `execute_expect_success`
    // fails this test if that happens.
    test.execute_expect_success(
        test.transaction()
            .call_method(
                beacon,
                "commit",
                args![1u64, signer_pk, commitment.clone(), commit_signature],
            )
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );

    // Same load-bearing check for `reveal()`'s signature, under the separate reveal domain.
    // Threshold is 1, so this also finalizes the round immediately.
    test.execute_expect_success(
        test.transaction()
            .call_method(
                beacon,
                "reveal",
                args![1u64, signer_pk, secret.clone(), reveal_signature],
            )
            .build_and_seal(test.secret_key()),
        vec![test.owner_proof()],
    );

    let is_finalized: bool = test.call_method(beacon, "is_finalized", args![1u64], vec![]);
    assert!(
        is_finalized,
        "round should finalize once the sole (threshold=1) signer has revealed"
    );

    let random: Option<Vec<u8>> = test.call_method(beacon, "get_random", args![1u64], vec![]);
    assert_eq!(
        random,
        Some(beacon_signer::hash_secret(&secret)),
        "with a single signer, the combined output is just Blake2s-256 of their one revealed secret"
    );
}
