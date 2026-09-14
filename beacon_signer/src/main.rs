//! `beacon_signer` -- a small, standalone off-chain signer CLI for the tari-ootle-gambling
//! `RandomnessBeacon` template's `commit`/`reveal` calls.
//!
//! All I/O is hex strings on stdin/stdout/args -- no file handling. An operator pipes this
//! tool's output into other tooling (e.g. constructing a `call_ootle_write_function` JSON-RPC
//! call against the `tari-ootle-mcp-gateway`, or a raw wallet-daemon transaction) to actually
//! drive a live `RandomnessBeacon` component's `commit`/`reveal` methods.
//!
//! See `beacon_signer::sign`/`hash_secret` (this crate's `src/lib.rs`) for the real signing
//! logic, reused byte-for-byte from `randomness_beacon/tests/test.rs`, and
//! `tests/acceptance.rs` for the end-to-end proof that a signature this binary produces is
//! actually accepted by the real, compiled `RandomnessBeacon` template.

use beacon_signer::{generate_keypair, hash_secret, sign, COMMIT_DOMAIN, REVEAL_DOMAIN};
use clap::{Parser, Subcommand};
use tari_crypto::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    tari_utilities::hex::Hex,
};

#[derive(Parser)]
#[command(
    name = "beacon_signer",
    about = "Off-chain Schnorr signer for the RandomnessBeacon template's commit/reveal calls"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates a fresh Ristretto keypair and prints the public key and secret key (both hex).
    GenerateKey,
    /// Produces a real detached Schnorr signature (hex) for a `RandomnessBeacon::commit` call.
    SignCommit {
        /// The signer's secret key, hex-encoded.
        #[arg(long)]
        secret_key: String,
        /// The signer's public key, hex-encoded (`RistrettoPublicKeyBytes` format).
        #[arg(long)]
        public_key: String,
        /// The round this commitment is for.
        #[arg(long)]
        round_id: u64,
        /// The 32-byte Blake2s-256 commitment, hex-encoded (see `hash-secret`).
        #[arg(long)]
        commitment: String,
    },
    /// Produces a real detached Schnorr signature (hex) for a `RandomnessBeacon::reveal` call.
    SignReveal {
        /// The signer's secret key, hex-encoded.
        #[arg(long)]
        secret_key: String,
        /// The signer's public key, hex-encoded (`RistrettoPublicKeyBytes` format).
        #[arg(long)]
        public_key: String,
        /// The round this reveal is for.
        #[arg(long)]
        round_id: u64,
        /// The raw secret being revealed, hex-encoded.
        #[arg(long)]
        secret: String,
    },
    /// Prints the Blake2s-256 commitment (hex) for a given secret, so an operator can go
    /// secret -> commitment -> (later) reveal without re-deriving the hash by hand.
    HashSecret {
        /// The raw secret, hex-encoded.
        #[arg(long)]
        secret: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::GenerateKey => {
            let (secret_key, public_key) = generate_keypair();
            println!("public_key: {}", public_key.to_hex());
            println!("secret_key: {}", secret_key.to_hex());
        }
        Command::SignCommit {
            secret_key,
            public_key,
            round_id,
            commitment,
        } => {
            let secret_key = parse_secret_key(&secret_key);
            let public_key = parse_public_key(&public_key);
            let commitment = parse_hex_bytes("--commitment", &commitment);
            assert!(
                commitment.len() == 32,
                "--commitment must be exactly 32 bytes (a Blake2s-256 hash)"
            );

            let signature = sign(
                &secret_key,
                &public_key,
                COMMIT_DOMAIN,
                round_id,
                &commitment,
            );
            println!("signature: {}", hex::encode(signature.to_bytes()));
        }
        Command::SignReveal {
            secret_key,
            public_key,
            round_id,
            secret,
        } => {
            let secret_key = parse_secret_key(&secret_key);
            let public_key = parse_public_key(&public_key);
            let secret = parse_hex_bytes("--secret", &secret);

            let signature = sign(&secret_key, &public_key, REVEAL_DOMAIN, round_id, &secret);
            println!("signature: {}", hex::encode(signature.to_bytes()));
        }
        Command::HashSecret { secret } => {
            let secret = parse_hex_bytes("--secret", &secret);
            println!("commitment: {}", hex::encode(hash_secret(&secret)));
        }
    }
}

fn parse_secret_key(hex_str: &str) -> RistrettoSecretKey {
    RistrettoSecretKey::from_hex(hex_str).unwrap_or_else(|err| {
        eprintln!("error: --secret-key is not a valid Ristretto secret key hex string: {err}");
        std::process::exit(1);
    })
}

fn parse_public_key(hex_str: &str) -> RistrettoPublicKey {
    RistrettoPublicKey::from_hex(hex_str).unwrap_or_else(|err| {
        eprintln!("error: --public-key is not a valid Ristretto public key hex string: {err}");
        std::process::exit(1);
    })
}

fn parse_hex_bytes(flag: &str, hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).unwrap_or_else(|err| {
        eprintln!("error: {flag} is not a valid hex string: {err}");
        std::process::exit(1);
    })
}
