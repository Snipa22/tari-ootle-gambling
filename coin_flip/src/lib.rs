//! Tari Ootle simplest-possible gambling game -- v1 research spike.
//!
//! `CoinFlip` is deliberately the simplest possible "gambling" mechanic on top of the
//! `RandomnessBeacon` component in the sibling crate `randomness_beacon`. The interesting
//! engineering in this spike is the randomness beacon underneath, not this game logic. See
//! README.md for the cross-component-call finding (the most important design fact for this
//! component -- does calling into an already-deployed `RandomnessBeacon` instance from inside a
//! template method actually work?), the flagged deviations from the brief's suggested struct
//! shape, and "Known limitations / not solved".

use tari_template_lib::prelude::*;

// NOTE: as with both sibling repos and the `randomness_beacon` crate in this workspace, we
// deliberately do NOT re-export any types out of `coin_flip_template` here -- see the identical
// note in `randomness_beacon/src/lib.rs`.

#[template]
mod coin_flip_template {
    use super::*;

    // NOTE: the `#[template]` macro treats the *first* `pub struct` or `pub enum` declared in
    // this module as "the component". `CoinFlip` must therefore be declared textually before
    // `PendingBet` below.
    pub struct CoinFlip {
        /// The `RandomnessBeacon` component instance this game consults for outcomes. The caller
        /// is responsible for having already driven that round's commit/reveal phases to
        /// finalization on the beacon -- this template doesn't orchestrate the beacon's phases,
        /// it only consumes the finalized result via a cross-component call (see README "Cross-
        /// component calls").
        beacon: ComponentAddress,
        /// The house's bankroll, used both as the destination for forfeited stakes and the
        /// source of the extra 1x needed to pay a winner 2x their stake.
        ///
        /// DEVIATION FROM BRIEF (flagged, see README "House funding"): the brief's sketch had a
        /// bare `house_account: ComponentAddress` described only as "where lost stakes go", with
        /// no mechanism at all for where a *winning* payout's other half comes from. A `Vault`
        /// owned directly by this component, funded via a `Bucket` at construction time (exactly
        /// like the sibling escrow build's `locked_vault` pattern), is the minimal fix that
        /// actually makes "winner takes double" implementable.
        house_vault: Vault,
        /// One entry per round_id that a bet has ever been placed for on this `CoinFlip`
        /// instance. Kept (not removed) after resolution so a repeat `resolve_bet` call gets a
        /// clear "already resolved" error rather than "no such bet".
        ///
        /// DEVIATION FROM BRIEF (flagged, see README "One bet per round_id"): the brief's sketch
        /// had a single `stake_vault: Vault` field, which can only ever hold one pending bet at a
        /// time for the whole component -- yet `place_bet`/`resolve_bet` both take a `round_id`
        /// parameter, implying multiple rounds must be trackable. A `Vec<PendingBet>` keyed by
        /// `round_id` (mirroring the oracle/beacon builds' `Vec<RoundRecord>` pattern) is the
        /// straightforward fix; each bet's stake lives in its own `Vault`.
        bets: Vec<PendingBet>,
    }

    /// One player's pending or resolved bet, tied to a specific beacon `round_id`.
    #[derive(Debug)]
    pub struct PendingBet {
        round_id: u64,
        player_account: ComponentAddress,
        guess_heads: bool,
        /// Holds the player's locked stake until `resolve_bet` withdraws it (win or lose). Empty
        /// (but still present, for record-keeping) after resolution.
        vault: Vault,
        resolved: bool,
        /// Set by `resolve_bet`, for tests/off-chain observers -- `None` until resolved.
        outcome_heads: Option<bool>,
        /// Set by `resolve_bet`, for tests/off-chain observers -- `None` until resolved.
        player_won: Option<bool>,
    }

    impl CoinFlip {
        /// Creates a new `CoinFlip` game consulting `beacon` for round outcomes, with its house
        /// bankroll initially funded by `house_bucket`.
        ///
        /// DEVIATION FROM BRIEF (see `house_vault`'s doc comment above): takes a `Bucket` to fund
        /// an internal `Vault`, not a bare `house_account: ComponentAddress`.
        pub fn create(beacon: ComponentAddress, house_bucket: Bucket) -> Component<Self> {
            let component = Self {
                beacon,
                house_vault: Vault::from_bucket(house_bucket),
                bets: Vec::new(),
            };

            // No dynamic per-caller authorization is needed here: anyone may place a bet (it's a
            // public game), and `resolve_bet` is safe for anyone to call (it only pays out
            // according to the beacon's already-finalized, tamper-evident random output -- there
            // is nothing for a malicious caller to gain by triggering resolution themselves
            // rather than waiting for the player to). Mirrors the oracle build's reasoning for
            // leaving the component-level access rule fully permissive.
            Component::new(component)
                .with_access_rules(ComponentAccessRules::new().default(rule!(allow_all)))
                .create()
        }

        /// Lets anyone top up the house bankroll after construction (e.g. so a spike test can
        /// verify the house can be resupplied without redeploying the component). Not part of the
        /// brief's sketch, added for operational completeness; flagged as a v1 addition in the
        /// README.
        pub fn fund_house(&mut self, bucket: Bucket) {
            self.house_vault.deposit(bucket);
        }

        /// Player locks `stake` and picks a side, tied to a specific beacon `round_id` (the
        /// caller is responsible for having already kicked off that round's commit phase on the
        /// beacon -- see `beacon`'s doc comment above). Rejects (panics) if a bet has already
        /// been placed for this `round_id` on this `CoinFlip` instance (see `bets`'s doc comment
        /// above for why only one bet per `round_id` is supported in this v1 spike) or if `stake`
        /// is empty.
        pub fn place_bet(&mut self, round_id: u64, guess_heads: bool, stake: Bucket, player_account: ComponentAddress) {
            assert!(!stake.is_empty(), "stake must be non-zero");
            assert!(
                !self.bets.iter().any(|b| b.round_id == round_id),
                "a bet has already been placed for round {round_id} on this CoinFlip instance"
            );

            self.bets.push(PendingBet {
                round_id,
                player_account,
                guess_heads,
                vault: Vault::from_bucket(stake),
                resolved: false,
                outcome_heads: None,
                player_won: None,
            });
        }

        /// Once the beacon's `round_id` is finalized, resolves the bet: derives heads/tails from
        /// `get_random`'s low bit (see convention below), pays out 2x stake to the player if they
        /// guessed right, forfeits the stake to the house bankroll if wrong.
        ///
        /// Outcome convention (documented per the brief's request, see README "Coin flip
        /// convention"): bit 0 of byte 0 of the beacon's combined 32-byte random output. `0` =>
        /// heads, `1` => tails. Arbitrary but fixed; any single bit of a hash-derived,
        /// unpredictable-in-advance 32-byte output is uniformly distributed and unbiased, so
        /// which bit is chosen doesn't matter cryptographically -- only that it's documented and
        /// fixed.
        ///
        /// Rejects (panics) if: no bet was ever placed for `round_id` on this instance, the bet
        /// for `round_id` was already resolved, or the beacon's `round_id` is not yet finalized
        /// (`RandomnessBeacon::get_random` returns `None`).
        pub fn resolve_bet(&mut self, round_id: u64) {
            let idx = self
                .bets
                .iter()
                .position(|b| b.round_id == round_id)
                .unwrap_or_else(|| panic!("no bet was ever placed for round {round_id} on this CoinFlip instance"));
            assert!(
                !self.bets[idx].resolved,
                "bet for round {round_id} has already been resolved"
            );

            // Cross-component call into the already-deployed RandomnessBeacon instance -- see
            // README "Cross-component calls" for the finding that `ComponentManager::get(addr)
            // .call(method, args)` is real, working API (not the brief's flagged fallback of
            // composing reads/calls at the transaction-builder level instead).
            //
            // `Option<Vec<u8>>`, not `Option<[u8; 32]>` -- matches `RandomnessBeacon::get_random`'s
            // actual return type; see that crate's README note "Fixed-size array types don't
            // work at the template ABI boundary" (the same limitation applies here: this method
            // signature is inside a `#[template]` module too).
            let random: Option<Vec<u8>> =
                ComponentManager::get(self.beacon).call("get_random", args![round_id]);
            let random = random.unwrap_or_else(|| {
                panic!(
                    "beacon round {round_id} is not finalized yet; cannot resolve a bet before \
                     randomness is available"
                )
            });

            let outcome_heads = random[0] & 1 == 0;
            let guess_heads = self.bets[idx].guess_heads;
            let player_account = self.bets[idx].player_account;
            let stake_amount = self.bets[idx].vault.balance();
            let player_won = guess_heads == outcome_heads;

            // Move the stake into the house bankroll unconditionally first -- simplest way to
            // express "winner takes double" without needing `Bucket::join`: on a win, immediately
            // withdraw 2x stake back out of the (now stake-augmented) house bankroll and pay it to
            // the player, netting the house down by exactly 1x stake; on a loss, leave it there,
            // netting the house up by exactly 1x stake.
            let stake_bucket = self.bets[idx].vault.withdraw_all();
            self.house_vault.deposit(stake_bucket);

            if player_won {
                let payout = self.house_vault.withdraw(stake_amount * 2u64);
                ComponentManager::get(player_account).invoke("deposit", args![payout]);
            }

            let bet = &mut self.bets[idx];
            bet.resolved = true;
            bet.outcome_heads = Some(outcome_heads);
            bet.player_won = Some(player_won);
        }

        // ---------------------------------------------------------------------------------
        // Read-only accessors (mainly for tests / off-chain observers)
        // ---------------------------------------------------------------------------------

        pub fn beacon(&self) -> ComponentAddress {
            self.beacon
        }

        pub fn house_balance(&self) -> Amount {
            self.house_vault.balance()
        }

        pub fn is_bet_resolved(&self, round_id: u64) -> bool {
            self.find_bet(round_id).map(|b| b.resolved).unwrap_or(false)
        }

        /// `None` if no bet exists for `round_id`, or it hasn't resolved yet.
        pub fn bet_outcome_heads(&self, round_id: u64) -> Option<bool> {
            self.find_bet(round_id).and_then(|b| b.outcome_heads)
        }

        /// `None` if no bet exists for `round_id`, or it hasn't resolved yet.
        pub fn bet_player_won(&self, round_id: u64) -> Option<bool> {
            self.find_bet(round_id).and_then(|b| b.player_won)
        }

        fn find_bet(&self, round_id: u64) -> Option<&PendingBet> {
            self.bets.iter().find(|b| b.round_id == round_id)
        }
    }
}
