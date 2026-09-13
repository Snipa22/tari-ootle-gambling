# tari-ootle-gambling

A **research spike** (v1) implementing a commit-then-reveal K-of-N randomness beacon and the
simplest possible gambling game on top of it, for the Tari Ootle L2, targeting the Esmeralda
testnet. Written against `tari_template_lib = "0.31.1"` / `tari_template_test_tooling = "0.40.0"`,
the same stack as the sibling
[`tari-ootle-escrow`](https://github.com/Snipa22/tari-ootle-escrow) and
[`tari-ootle-oracle`](https://github.com/Snipa22/tari-ootle-oracle) builds.

This is a spike, not production code, and is not intended for deployment. Several design
decisions below are explicitly flagged as open questions for review rather than silently picked
defaults. Regulatory/licensing concerns for gambling are explicitly out of scope for this
exercise (per the dispatch brief).

## Workspace layout

Two template crates in one Cargo workspace (both under this repo's root `Cargo.toml`, `members =
["randomness_beacon", "coin_flip"]`), rather than one crate holding two templates -- chosen
because the two components are conceptually independent (`RandomnessBeacon` has no idea `CoinFlip`
exists; a second, third, or Nth consumer game could reuse the same beacon deployment) and
independent crates make that separation explicit rather than incidental. The tradeoff: `[profile.*]`
sections can only live in the *workspace root* manifest in a multi-member workspace (Cargo
silently ignores them in member manifests), so the release/dev profile tuning both templates need
(small-`panic = "abort"` WASM output, faster dev-mode `wasmer`/`cranelift`) lives in the root
`Cargo.toml`, not in either member's own `Cargo.toml` -- flagged here since both sibling repos
(each a single-crate workspace) never had to make this call.

```
tari-ootle-gambling/
├── Cargo.toml              # workspace root -- [workspace] + shared [profile.*] sections
├── randomness_beacon/      # Component 1
│   ├── Cargo.toml
│   ├── src/lib.rs
│   └── tests/test.rs
└── coin_flip/               # Component 2, consumes Component 1 via cross-component call
    ├── Cargo.toml
    ├── src/lib.rs
    └── tests/test.rs
```

`coin_flip/tests/test.rs` registers **both** templates in one `TemplateTest` via
`TemplateTest::new(CARGO_MANIFEST_DIR, [".", "../randomness_beacon"])` -- see "Cross-component
calls" below for why this is the single most important thing this test file proves.

## Component 1: `RandomnessBeacon`

```rust
pub struct RandomnessBeacon {
    signers: Vec<RistrettoPublicKeyBytes>,   // N registered signer identities
    threshold: u32,                           // K
    rounds: Vec<RoundRecord>,                 // round_id -> commitments + reveals + finalized output
}

impl RandomnessBeacon {
    pub fn create(signers: Vec<RistrettoPublicKeyBytes>, threshold: u32) -> Component<Self>;

    pub fn commit(&mut self, round_id: u64, signer: RistrettoPublicKeyBytes,
                   commitment: Vec<u8>, signature: SchnorrSignatureBytes);

    pub fn reveal(&mut self, round_id: u64, signer: RistrettoPublicKeyBytes,
                   secret: Vec<u8>, signature: SchnorrSignatureBytes);

    pub fn get_random(&self, round_id: u64) -> Option<Vec<u8>>;  // 32 bytes when Some
    pub fn is_finalized(&self, round_id: u64) -> bool;

    // Read-only accessors, mainly for tests/off-chain observers:
    pub fn signers(&self) -> Vec<RistrettoPublicKeyBytes>;
    pub fn threshold(&self) -> u32;
    pub fn commit_count(&self, round_id: u64) -> u32;
    pub fn reveal_count(&self, round_id: u64) -> u32;
}
```

`commitment`/`secret`/`get_random`'s return are `Vec<u8>`, not `[u8; 32]` as the brief's own sketch
suggested -- see "Fixed-size array types don't work at the template ABI boundary" below, a real
finding, not a style choice.

### Why commit-then-reveal, precisely

Without a commit phase, the **last** signer to reveal could see every other signer's already-
revealed value first and choose their own contribution to steer the final combined output toward
an outcome they want -- e.g. if the combined value decides a coin flip, the last revealer could
simply try both of their own two possible secrets (well, in principle any secret they like) and
pick whichever one flips the coin their way, entirely after the fact.

Requiring a hash-committed value **before any reveals happen** closes this: by the time reveals
start, every signer is already locked into a value they can't change. `reveal()` rejects any
secret whose Blake2s-256 hash doesn't match the commitment that same signer submitted earlier for
that `round_id` -- so "reveal something different after seeing everyone else's reveals" is not a
choice available to any signer, including the last one to reveal.

`tests/test.rs::signer_cannot_reveal_a_value_chosen_after_seeing_other_reveals` makes this concrete:
two of three signers reveal first, the third tries to reveal a value chosen *after* seeing both
of theirs (simulating exactly the attack this scheme defeats), and it's rejected -- their only
valid move is to reveal what they actually committed to.

### Signature verification

Both `commit()` and `reveal()` authorize via a detached Schnorr signature, not
`CallerContext`-based access control -- anyone may relay either call on a registered signer's
behalf, exactly the pattern the sibling oracle build established and confirmed actually works
(`tari_template_lib::models::signature_verifier::Verifiable::assert_valid`, backed by a real
engine call to a domain-separated `RistrettoSchnorrBlake2bVerifier`). Copied here rather than
re-derived; see the oracle build's own README for the full verification-primitive writeup.

**Two separate `SignatureDomain`s, not one, and this matters:** `BeaconCommitDomain` (domain
string `b"tari-ootle-gambling/beacon/commit/v1"`) for `commit()`, `BeaconRevealDomain`
(`b"tari-ootle-gambling/beacon/reveal/v1"`) for `reveal()`. Both ultimately sign a message shaped
`round_id.to_le_bytes() ++ some_bytes` (the 32-byte commitment for `commit`, the raw secret for
`reveal`) -- if they shared one domain, a signer's `commit(round_id, commitment)` signature would
also be a technically-valid signature over `reveal(round_id, commitment)` for the same `round_id`
(since the domain-separated challenge wouldn't distinguish which phase the bytes were "supposed"
to mean), which could let a relayer replay a commitment as if it were a (almost certainly
hash-mismatching, and thus harmless, but still semantically confused) reveal, or vice versa.
Separate domains rule this out structurally rather than relying on the hash-mismatch check alone
to save it.

Off-chain signer side (exercised in `tests/test.rs::sign`): compute the domain-separated Blake2b
challenge via `RistrettoSchnorrBlake2bVerifier::compute_challenge`, then
`RistrettoSchnorr::sign_raw_uniform(secret_key, nonce, &challenge)` -- identical to the oracle
build's `sign_submission` helper, parameterized by which of the two domains applies.

### Combination function: Blake2s-256 of the concatenation, not XOR

**Chosen: `Blake2s256(secret_1 || secret_2 || ... || secret_K)`, with the K revealed secrets sorted
by signer public key bytes before concatenation** (so the combined output is identical regardless
of the wall-clock order signers happened to reveal in --
`tests/test.rs::combined_output_is_independent_of_reveal_order` demonstrates this directly).

The brief's own hint leaned toward hash-of-concatenation being the safer default and asked for
real reasoning rather than cargo-culting a choice. Here it is:

- **XOR requires a fixed-width value.** Each signer in this design picks an arbitrary-length
  `secret: Vec<u8>` (there is no protocol-level requirement that it be exactly 32 bytes, or that
  every signer use the same length as every other signer). XOR-combining values of different
  lengths has no single obvious definition (truncate to the shortest? zero-pad the shortest to
  the longest? XOR only the overlapping prefix and concatenate the remainder?) -- every option
  either silently discards signer-chosen entropy or requires bolting on a fixed-length-secret rule
  that isn't otherwise needed. Hash-of-concatenation has no such problem: `Digest::update` happily
  accepts secrets of any length, one after another.
- **Is XOR actually exploitable here even *with* a fixed length, given commitments are hashes, not
  values?** The brief raised this as an open question worth thinking through rather than assuming.
  Reasoning: once every signer has committed (hash-locked) *before* any reveals happen, no signer
  can pick their own revealed value as a function of anyone else's revealed value, XOR or not --
  the whole point of the commit phase is that revealed values are already fixed before reveals
  start. So XOR would not, in fact, reintroduce the "last revealer bias" problem the commit phase
  exists to solve, **given a fixed secret length**. The real problem with XOR here is the
  variable-length one above, not a resurrected last-revealer bias.
- **Hash-of-concatenation has a stronger avalanche property regardless.** Even if secret length
  were fixed, changing a single bit in any one secret changes the *entire* Blake2s-256 output
  unpredictably, rather than flipping only the corresponding bit position the way XOR would. For a
  primitive whose entire purpose is "unpredictable in advance, uniformly distributed", the
  stronger mixing is the safer general-purpose default even where XOR wouldn't be strictly broken.

Both reasons independently favour hash-of-concatenation; the variable-length one alone would have
been sufficient given this design's `Vec<u8>` secrets.

### Coin flip convention (used by `CoinFlip`, documented here since it derives from this
component's output)

Bit 0 of byte 0 of the 32-byte combined output: `0` => heads, `1` => tails. Arbitrary but fixed --
any single bit of a hash output that's uniformly distributed and unpredictable in advance is
itself uniformly distributed and unpredictable in advance, so which bit is chosen doesn't matter
cryptographically, only that it's documented and fixed (so nobody can dispute the outcome after
the fact).

### Design decisions flagged for review

The brief listed three open questions needing a judgment call, plus one more this build
identified on top of them:

1. **What if a signer commits but never reveals (goes offline)?** The round simply never
   finalizes if fewer than K signers who committed also reveal -- no forced resolution, no
   timeout, matches the "stay stuck" precedent from both prior templates
   (`tests/test.rs::below_threshold_reveals_leave_round_unfinalized`). No epoch-based timeout was
   added here either (unlike the escrow build's `ArbitrationPending`) -- see "Known limitations".

2. **Combination function.** See "Combination function" above -- hash-of-concatenation, with real
   reasoning for why (not just "recommended"), covering both the variable-length problem and the
   XOR-with-hash-locked-commitments question the brief specifically asked to be thought through
   rather than assumed.

3. **Can extra signers commit/reveal beyond the registered N, or off-schedule?** Rejected cleanly
   in both directions: a non-registered signer's commit/reveal is rejected
   (`non_registered_signer_commit_is_rejected`, `non_registered_signer_reveal_is_rejected`), and
   revealing before committing is rejected (`reveal_before_commit_is_rejected`).

4. **DECISION (this build, flagged): once a round is finalized, further `commit`/`reveal` calls
   for that `round_id` are rejected outright** -- not silently accepted as harmless no-ops the way
   the oracle build's late-but-agreeing submissions are. Reasoning: the oracle build's
   "agreeing late submission" no-op only makes sense because there's an obvious equality check
   ("does this late value match what's already committed?"). Here, there is no equivalent
   check that makes sense for a *fresh* commitment/reveal pair once the combined output is
   already fixed -- a signer's commitment for an already-finalized round can never itself equal
   the *combined* output, so "does it agree" isn't a coherent question to ask. Simple outright
   rejection avoids that ambiguity (`finalized_round_rejects_further_commits_and_reveals`).

   Two smaller resubmission-idempotency decisions, mirroring the oracle build's DECISION 2
   exactly: a signer's first `commit()` for a round is final (same commitment again = no-op,
   different commitment = rejected -- `resubmitting_the_same_commitment_is_a_harmless_noop`,
   `committing_a_different_value_for_the_same_round_is_rejected`); same for `reveal()`
   (`resubmitting_the_same_reveal_is_a_harmless_noop`). The "different reveal" rejection case for
   an already-revealed signer is defence-in-depth only -- since a reveal must already hash-match
   the earlier commitment, a *second* genuinely different secret that also hash-matches would
   require a Blake2s-256 collision, not realistically constructible; the check exists anyway for
   symmetry with `commit()`'s policy and because "cheap defensive check with no downside" is a
   reasonable default even when the attack it stops is already blocked by an independent
   mechanism.

### Fixed-size array types don't work at the template ABI boundary

**A genuine, unexpected finding, not a style choice.** The brief's own sketch used `commitment:
[u8; 32]` and `get_random(..) -> Option<[u8; 32]>`. Implementing it literally fails to compile,
with the `#[template]` macro itself panicking during macro expansion:

```
error: custom attribute panicked
  = help: message: not yet implemented: get_type_ast only supports paths and tuples.
          Encountered:Type::Array { .. }
```

Verified against `tari_template_macros` 0.22.1's real source
(`src/template/ast.rs::get_type_ast`): the function that builds the ABI type descriptor for every
method argument and return type has exactly two match arms, `syn::Type::Path` and
`syn::Type::Tuple`, with a `todo!()` fallback for everything else -- including `syn::Type::Array`,
which is what a raw `[u8; N]` parses as. This is unrelated to whether `minicbor` can actually
(de)serialize a `[u8; 32]` -- it demonstrably can (`minicbor` 2.3.0 has a real, generic
`impl<C, T: Encode<C>, const N: usize> Encode<C> for [T; N]`, confirmed by reading its source) --
the failure is specifically in the macro's ABI-generation pass, which never even gets that far.

**Fix:** use `Vec<u8>` everywhere a fixed-size byte array would otherwise be the natural type,
exactly the same choice the sibling oracle build already made for its `value: Vec<u8>` parameter
(that build never needed a fixed-size array in the first place, so this specific limitation was
never exercised there -- this is the first of the three template builds in this series to hit
it). `commit()` and `reveal()` both assert the expected length (`commitment.len() == 32`) at
runtime instead of getting that guarantee for free from the type system. Every internal helper
(`hash_secret`, `try_finalize`'s combination step) was changed to return/accept `Vec<u8>`
accordingly for consistency, even in places not directly on the ABI boundary.

## Component 2: `CoinFlip`

```rust
pub struct CoinFlip {
    beacon: ComponentAddress,        // the RandomnessBeacon component instance to consult
    house_vault: Vault,              // house bankroll -- see "House funding" below
    bets: Vec<PendingBet>,           // round_id -> pending/resolved bet -- see "One bet per round_id"
}

impl CoinFlip {
    pub fn create(beacon: ComponentAddress, house_bucket: Bucket) -> Component<Self>;
    pub fn fund_house(&mut self, bucket: Bucket);

    pub fn place_bet(&mut self, round_id: u64, guess_heads: bool, stake: Bucket,
                      player_account: ComponentAddress);
    pub fn resolve_bet(&mut self, round_id: u64);

    // Read-only accessors, mainly for tests/off-chain observers:
    pub fn beacon(&self) -> ComponentAddress;
    pub fn house_balance(&self) -> Amount;
    pub fn is_bet_resolved(&self, round_id: u64) -> bool;
    pub fn bet_outcome_heads(&self, round_id: u64) -> Option<bool>;
    pub fn bet_player_won(&self, round_id: u64) -> Option<bool>;
}
```

Deliberately the simplest possible "gambling" mechanic: a player locks a stake, picks heads or
tails, a `RandomnessBeacon` round determines the outcome, winner takes double or the stake is
forfeited to the house. The interesting engineering in this spike is the randomness beacon
underneath, not this game logic on top.

### Cross-component calls (the most important finding for this component)

The brief flagged this as genuinely new territory: neither the escrow nor oracle build needed to
call into another already-deployed component, and it explicitly raised the possibility that
templates might only be invokable via top-level `Transaction` instructions, unable to call each
other directly at all -- in which case the correct pivot would have been `resolve_bet` taking the
beacon's already-fetched random value as a plain argument, composed at the transaction-builder
level instead.

**Finding: direct cross-component calls from inside template code are real, working API.**
Verified against real source, then proven with a passing, genuinely cross-crate test:

- `tari_template_lib::component::ComponentManager::get(address) -> ComponentManager` followed by
  `.call::<_, R, _>(method, args) -> R` (or `.invoke(method, args)` for a unit-returning method)
  issues a real engine call (`EngineOp::CallInvoke` / `CallAction::CallMethod`), decoding the
  callee's actual return value -- not a stub, not client-side composition.
- This is not a novel discovery in isolation -- the sibling **escrow** build already used
  `ComponentManager::get(self.seller_account).invoke("deposit", args![bucket])` to deposit into
  account components from inside `finalize_payout`. What *is* new here is calling `.call()` (not
  just `.invoke()`) to get a real decoded return value back from a **custom**, non-builtin
  component instance (a second `RandomnessBeacon`, not a builtin `Account`), and proving the whole
  round trip actually executes correctly at runtime across two independently-compiled WASM
  template crates.
- `CoinFlip::resolve_bet` calls `ComponentManager::get(self.beacon).call("get_random",
  args![round_id])`, decoding `Option<Vec<u8>>` back from the beacon -- exactly the design
  sketched in the brief, no pivot needed.
- Proven by `coin_flip/tests/test.rs`, which registers **both** templates in one `TemplateTest`
  (`TemplateTest::new(CARGO_MANIFEST_DIR, [".", "../randomness_beacon"])`) and every single test
  in that file exercises the real cross-component call at runtime by calling `resolve_bet` after
  driving the beacon to finalization via ordinary `commit`/`reveal` transactions.

**Consequence:** the brief's flagged fallback (transaction-builder-level composition of a beacon
read + a `resolve_bet` call in the same transaction) is **not needed**. `resolve_bet` genuinely
only takes `round_id` as its argument, exactly as sketched, and reaches into the beacon itself.

### Design decisions flagged for review

1. **House funding (DEVIATION FROM BRIEF).** The brief's sketch had a bare `house_account:
   ComponentAddress`, described only as "where lost stakes go" -- with no mechanism at all for
   where the *other half* of a winning payout comes from (winner takes *double* their stake; the
   player's own forfeited-or-not stake alone can never cover that). This is a real gap in the
   brief's own sketch, not a nitpick: as written, a winning bet has no funding source. Fixed here
   by giving `CoinFlip` its own `house_vault: Vault`, funded via a `Bucket` argument to `create()`
   (exactly mirroring the sibling escrow build's `locked_vault: Vault::from_bucket(locked_bucket)`
   pattern) and toppable-up later via `fund_house()`. Forfeited stakes deposit into this vault;
   winning payouts withdraw `2 * stake` from it. Net effect per resolved bet: house down by
   exactly 1x stake on a win, up by exactly 1x stake on a loss -- the standard even-money coin-flip
   house edge model (zero house edge in this v1; a real product would want a smaller-than-2x
   payout multiplier or a rake, out of scope here).

2. **One bet per `round_id` per `CoinFlip` instance (DEVIATION FROM BRIEF).** The brief's sketch
   had a single `stake_vault: Vault` field, which can only ever hold one pending bet's stake for
   the *entire component* at a time -- yet both `place_bet` and `resolve_bet` take a `round_id`
   parameter, which only makes sense if multiple rounds/bets need to be trackable independently.
   Taken literally, the single-`Vault`-field sketch and the `round_id`-keyed method signatures
   are in tension. Resolved here with `bets: Vec<PendingBet>` (each entry owning its own `Vault`,
   mirroring the `Vec<RoundRecord>` pattern already used in both the oracle build and this
   repo's own `RandomnessBeacon`), keyed uniquely by `round_id`: **at most one bet may be pending
   per `round_id` on a given `CoinFlip` instance** (`place_bet` rejects a second bet for a
   `round_id` that already has one --
   `place_bet_fails_if_a_bet_already_exists_for_the_round_id`). This is a real restriction, not
   just an implementation detail: two different players cannot both bet against the *same*
   beacon round on the *same* `CoinFlip` instance. In practice this is not a meaningful limitation
   -- an orchestrator driving many concurrent coin-flip games would naturally hand out a fresh
   `round_id` per bet anyway (the beacon supports arbitrarily many independent rounds), so
   "one bet per round_id" and "one round_id per bet" end up being the same thing operationally.
   Flagged anyway since it's a real deviation from the brief's literal struct shape, not a
   transparent implementation choice.

3. **Resolved bets are kept, not removed, after resolution.** `bets: Vec<PendingBet>` grows
   forever rather than removing an entry once resolved -- deliberately, so a repeat
   `resolve_bet(round_id)` call gets a precise "already been resolved" rejection
   (`resolve_bet_fails_on_double_resolve`) rather than an ambiguous "no such bet" one that could
   also mean "never placed" (`resolve_bet_fails_if_no_bet_was_ever_placed`). Same linear-`Vec`-
   scan tradeoff as `RandomnessBeacon::rounds` -- fine for a spike, `FastMap` would be the obvious
   v2 upgrade if bet counts grow large.

4. **`fund_house` is not in the brief's sketch.** Added because "the house bankroll can be topped
   up after construction" felt like an obvious operational requirement once `house_vault` was
   introduced to fix the funding gap in decision 1 above, and it made an easy, useful test
   (`fund_house_increases_house_balance`). Flagged as a v1 addition, not derived from the brief.

5. **No dynamic per-caller access control on `place_bet`/`resolve_bet`.** Anyone may place a bet
   (it's a public game) and anyone may trigger `resolve_bet` for any pending round (there's
   nothing to gain by resolving early or by someone other than the player triggering it -- the
   payout is entirely determined by the beacon's already-finalized, tamper-evident output, not by
   who calls `resolve_bet`). Mirrors the oracle build's identical reasoning for leaving its
   component-level access rule fully permissive.

## Testing

Both crates' `tests/test.rs` use `tari_template_test_tooling::TemplateTest` (24 tests total, all
passing):

**`randomness_beacon/tests/test.rs`** (15 tests) --
- Full happy path: K-of-N commit -> reveal -> finalize with the correct combined output
  (`k_of_n_commit_then_reveal_finalizes_with_correct_combined_output`), and that the same output
  results regardless of reveal arrival order (`combined_output_is_independent_of_reveal_order`).
- Below-threshold reveals leave a round unfinalized
  (`below_threshold_reveals_leave_round_unfinalized`).
- Reveal rejected if its hash doesn't match the earlier commitment
  (`reveal_rejected_if_hash_does_not_match_commitment`) -- **the concrete mechanism test for
  "the last revealer can't bias the outcome"**: `signer_cannot_reveal_a_value_chosen_after_seeing_other_reveals`
  has two signers reveal first, then has the third try to reveal something chosen *after* seeing
  both, and shows it's rejected. As the brief itself anticipated, a true end-to-end adversarial
  simulation ("what if they'd chosen differently, does the output change unfairly") isn't directly
  testable in one test -- what's tested instead, plainly, is the mechanism that provides the
  property: reveal-must-match-commitment is actually enforced, even against a secret chosen with
  full knowledge of every other signer's reveal.
- A signer can't commit twice for a round with a different commitment
  (`committing_a_different_value_for_the_same_round_is_rejected`), or reveal before committing
  (`reveal_before_commit_is_rejected`) -- mirrors the oracle's no-flip-flop precedent.
- Non-registered signers are rejected for both `commit` and `reveal`
  (`non_registered_signer_commit_is_rejected`, `non_registered_signer_reveal_is_rejected`).
- Resubmission idempotency for both `commit` and `reveal`
  (`resubmitting_the_same_commitment_is_a_harmless_noop`,
  `resubmitting_the_same_reveal_is_a_harmless_noop`).
- A finalized round rejects further commits/reveals
  (`finalized_round_rejects_further_commits_and_reveals`).
- Rounds are independent of one another (`rounds_are_independent`).
- Constructor validation (`create_rejects_threshold_above_signer_count`,
  `create_rejects_duplicate_signers`).

**`coin_flip/tests/test.rs`** (9 tests, registering **both** templates together per "Cross-
component calls" above) --
- Full happy path on both a winning and a losing guess, with exact balance-delta assertions
  (`full_happy_path_correct_guess_pays_out_double`,
  `full_happy_path_incorrect_guess_forfeits_stake_to_house`).
- `resolve_bet` rejects cleanly before the beacon round is finalized
  (`resolve_bet_fails_before_beacon_round_is_finalized`), if no bet was ever placed
  (`resolve_bet_fails_if_no_bet_was_ever_placed`), and on a repeat resolve
  (`resolve_bet_fails_on_double_resolve`).
- `place_bet` rejects a second bet for an already-used `round_id`
  (`place_bet_fails_if_a_bet_already_exists_for_the_round_id`) and a zero-value stake
  (`place_bet_fails_on_zero_stake`).
- `fund_house` increases the house bankroll (`fund_house_increases_house_balance`).
- Bets on different `round_id`s are independent (`bets_on_different_round_ids_are_independent`).

Run tests with:

```
cargo test
```

## Confirmed environment facts reused from the sibling repos (not rediscovered)

- `cargo install tari-ootle-cli` fails in this environment (no root, missing `openssl-sys` deps)
  -- the Cargo workspace was hand-rolled directly, per both sibling repos' already-established
  finding.
- **Required pin, applied from the first `cargo test`:** `tari_engine` 0.40.0 (pulled in
  transitively by `tari_template_test_tooling`) calls `wasmer_compiler::BaseTunables::for_target`,
  removed in `wasmer-compiler` 7.4.0. Both member crates' dev-dependencies pin `wasmer =
  "=7.1.0"`, `wasmer-compiler = "=7.1.0"`, `wasmer-compiler-cranelift = "=7.1.0"`,
  `wasmer-middlewares = "=7.1.0"`.
- `RistrettoSchnorrBlake2bVerifier::compute_challenge` + `RistrettoSchnorr::sign_raw_uniform` +
  `Verifiable::assert_valid` -- the real, working, engine-backed Schnorr signature primitive the
  oracle build found and documented, reused here for `RandomnessBeacon::commit`/`reveal`'s
  detached-signature authorization (see "Signature verification" under Component 1 above for the
  two-separate-domains reasoning specific to this build).
- `rand::rng()` is shadowed by `tari_template_lib::prelude::*`'s own `rand` module inside test
  code -- refer to the real host-side crate as `::rand` (leading `::`) wherever real randomness is
  needed for test-side signing.
- Confidential resources are deliberately **not used** for stakes/payouts here -- plain public
  fungible (`TARI_TOKEN`/XTR, via `TemplateTest::create_funded_account`'s built-in faucet) is used
  throughout, per the brief's explicit instruction to sidestep the escrow build's unresolved
  confidential-withdrawal-proof-verification gap entirely for this spike.

## Known limitations / not solved

- **No epoch-based timeout for a stalled beacon round.** If fewer than K signers who committed
  also reveal, the round stays unfinalized forever -- no timeout, no forced resolution, matching
  DECISION 1 above and both sibling repos' identical "stay stuck" precedent for their own
  unresolved-forever states. A production version would likely want an epoch-based expiry (the
  only time primitive Ootle templates have, per the escrow build's finding) that lets a round be
  abandoned and retried under a fresh `round_id` after enough epochs elapse with no progress.
- **No cross-instance signature replay protection.** `BeaconCommitDomain`/`BeaconRevealDomain`'s
  domain strings are fixed constants, not derived from a specific `RandomnessBeacon` instance's
  own address -- identical flagged limitation to the oracle build's `OracleSubmitDomain`. A
  signer's commit/reveal signatures are technically portable across any `RandomnessBeacon`
  instances that happen to register that signer and use the same `round_id`. Not exploitable for
  a single long-lived beacon instance; would need the component address mixed into the signed
  message before multiple concurrent beacon instances sharing a signer set are deployed.
- **`rounds: Vec<RoundRecord>` / `bets: Vec<PendingBet>` are linear-scanned.** Fine for a spike;
  `tari_template_lib`'s `extra-maps` feature (`FastMap`) would be the obvious upgrade if round/bet
  counts grow large -- same note as both sibling repos.
- **No `emit_event` calls.** Same as both sibling repos -- left out of this spike for time; state
  is only visible via the read-only accessor methods or direct component state introspection.
- **No access control on `RandomnessBeacon::create` / `CoinFlip::create`.** Anyone can register any
  signer set and stand up a new beacon, or point a new `CoinFlip` at any beacon address (including
  one they don't control and that may never finalize anything) -- presumably fine for openly-
  creatable spike components, but worth confirming for a production model.
- **`CoinFlip`'s payout is exactly 2x with no house edge and no fee.** A real product would want
  either a smaller-than-2x multiplier or an explicit rake taken from the pot; this spike pays out
  the simplest possible "double or nothing" with zero edge, which is not economically viable for
  an actual house to run indefinitely (it's a fair coin flip with a genuinely fair random source,
  so the house's expected value here is exactly zero, not positive).
- **A house that runs out of bankroll mid-game has no defined behaviour beyond `Vault::withdraw`'s
  own panic-on-insufficient-balance.** `resolve_bet` doesn't pre-check `house_vault.balance() >=
  2 * stake` before attempting the withdrawal on a winning resolution; an underfunded house simply
  causes that transaction to fail with the engine's own insufficient-balance error rather than a
  purpose-written one. Acceptable for a spike; a production version would want an explicit,
  clearly-worded check (and probably a policy for what happens to the bet in that case).
- **One bet per `round_id` per `CoinFlip` instance.** See "Design decisions flagged for review"
  item 2 above -- a real deviation from the brief's sketch, not just an implementation detail.

## Tari CLI (`tari-ootle-cli`)

Not attempted in this pass, per the already-established finding from both sibling repos:
`cargo install tari-ootle-cli` fails in this environment (`openssl-sys` needs pkg-config/dev
headers, no root to install them). The Cargo workspace was hand-rolled directly instead.

## Deployment

Not attempted in this pass, per the brief ("Do not attempt deployment/publishing to Esmeralda").
Build+test verification only.
