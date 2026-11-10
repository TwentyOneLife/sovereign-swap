//! Two engines swapping on Bitcoin Core and Knots BLAKE2b regtest, success and failure paths.
//! Scenario numbers refer to `docs/edge-cases.md`.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, Network};
use serde_json::json;

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine, EngineError};
use sovereign_swap::node::{ChainNode, NodeError};
use sovereign_swap::policy::Policy;
use sovereign_swap::replay::ReplayError;
use sovereign_swap::silentpayments::SilentPaymentAddress;
use sovereign_swap::swap::{BidError, Chain, FeeTerms, Offer, Phase};
use sovereign_swap::transport::{memory_pair, Memory};

/// Shallow depths keep regtest runs short; `Policy::standard` is tested on its own.
fn config() -> Config {
    Config {
        min_spend_fee: Amount::from_sat(2_000),
        fee_rate_sat_vb: 2,
        policy: Policy {
            btc: vec![(Amount::from_sat(100_000_000), 2)],
            xbtc: vec![(Amount::from_sat(100_000_000), 3)],
            funding_minconf_btc: 1,
            funding_minconf_xbtc: 1,
        },
        btc_payout: None,
        xbtc_payout: None,
    }
}

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

struct Party {
    dir: PathBuf,
    name: &'static str,
    transport: Memory,
    engine: Option<Engine<Memory>>,
}

impl Party {
    fn new(name: &'static str, transport: Memory, btc: &Node, xbtc: &Node) -> Party {
        let dir = std::env::temp_dir().join(format!(
            "sovswap-engine-{}-{}-{name}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        let mut party = Party {
            dir,
            name,
            transport,
            engine: None,
        };
        party.reopen(btc, xbtc);
        party
    }

    /// Drops the engine and builds it again from its files, as after a crash.
    fn reopen(&mut self, btc: &Node, xbtc: &Node) {
        self.engine = None;
        let open = |node: &Node| ChainNode::open(node.rpc.clone(), self.name).unwrap();
        self.engine = Some(
            Engine::open(
                &self.dir,
                open(btc),
                open(xbtc),
                self.transport.clone(),
                config(),
            )
            .unwrap(),
        );
    }

    fn engine(&mut self) -> &mut Engine<Memory> {
        self.engine.as_mut().unwrap()
    }

    fn tick(&mut self) {
        for (id, e) in self.engine().tick() {
            eprintln!("{} {:02x?}: {e:?}", self.name, &id[..4]);
        }
    }

    fn phase(&self) -> Option<Phase> {
        self.engine
            .as_ref()
            .unwrap()
            .swaps()
            .next()
            .map(|s| s.phase)
    }

    /// Sends coins from the test's mining wallet to this party's funding wallet.
    fn deposit(&self, node: &Node, btc: f64) {
        let address = node
            .rpc
            .wallet(self.name)
            .call("getnewaddress", json!([]))
            .unwrap();
        node.wallet()
            .call("sendtoaddress", json!([address, btc]))
            .unwrap();
    }
}

impl Drop for Party {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn offer(maker_chain: Chain) -> Offer {
    Offer {
        id: [7; 16],
        maker_chain,
        maker_amount: Amount::from_sat(50_000_000),
        taker_amount: Amount::from_sat(15_000_000),
        min_maker_amount: Amount::from_sat(1_000_000),
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 2,
        taker_lock_depth: 2,
        margin_blocks: 3,
        fee: None,
    }
}

struct World {
    btc: Node,
    xbtc: Node,
}

impl World {
    fn start() -> Option<World> {
        let (btc, xbtc) = binaries()?;
        let world = World {
            btc: Node::start(&btc, None),
            xbtc: Node::start(&xbtc, Some(20)),
        };
        world.btc.mine(101);
        world.xbtc.mine(101);
        Some(world)
    }

    fn node(&self, chain: Chain) -> &Node {
        match chain {
            Chain::Btc => &self.btc,
            Chain::Xbtc => &self.xbtc,
        }
    }

    fn mine(&self) {
        self.btc.mine(1);
        self.xbtc.mine(1);
    }

    /// A maker selling on `maker_chain` and a taker buying, both funded, the offer published,
    /// seen, and bid for in full.
    fn parties(&self, maker_chain: Chain) -> (Party, Party) {
        self.parties_for(maker_chain, offer(maker_chain).maker_amount)
    }

    /// As `parties`, with the taker bidding for `maker_part` of the offer.
    fn parties_for(&self, maker_chain: Chain, maker_part: Amount) -> (Party, Party) {
        self.parties_offer(offer(maker_chain), maker_chain, maker_part)
    }

    /// The shared setup: fund both parties, publish `offer`, have the taker see and bid for it.
    fn parties_offer(
        &self,
        offer: Offer,
        maker_chain: Chain,
        maker_part: Amount,
    ) -> (Party, Party) {
        let (a, b) = memory_pair();
        let mut maker = Party::new("maker", a, &self.btc, &self.xbtc);
        let mut taker = Party::new("taker", b, &self.btc, &self.xbtc);
        maker.deposit(self.node(maker_chain), 2.0);
        taker.deposit(self.node(maker_chain.other()), 2.0);
        self.mine();
        maker.engine().publish(offer.clone()).unwrap();
        taker.tick();
        assert_eq!(taker.engine().seen_offers(), std::slice::from_ref(&offer));
        taker.engine().bid(&offer, maker_part, [9; 16]).unwrap();
        (maker, taker)
    }

    /// Ticks both (each only while `active`), mining a block per round, until `done` or `rounds` run out.
    fn run(
        &self,
        maker: &mut Party,
        taker: &mut Party,
        rounds: u32,
        active: impl Fn(&Party, &Party) -> (bool, bool),
        restart: bool,
        done: impl Fn(&Party, &Party) -> bool,
    ) {
        for _ in 0..rounds {
            let (m, t) = active(maker, taker);
            if m {
                maker.tick();
            }
            if t {
                taker.tick();
            }
            if done(maker, taker) {
                return;
            }
            if restart {
                maker.reopen(&self.btc, &self.xbtc);
                taker.reopen(&self.btc, &self.xbtc);
            }
            self.mine();
        }
        panic!(
            "not done: maker {:?}, taker {:?}",
            maker.phase(),
            taker.phase()
        );
    }
}

fn both(phase: Phase) -> impl Fn(&Party, &Party) -> bool {
    move |m, t| m.phase() == Some(phase) && t.phase() == Some(phase)
}

fn always(_: &Party, _: &Party) -> (bool, bool) {
    (true, true)
}

#[test]
fn swap_maker_sells_xbtc() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    w.run(&mut maker, &mut taker, 30, always, false, both(Phase::Done));
}

/// The full voluntary-fee path (design 0010): a fee-bearing offer, both sides pay a silent payment
/// fee output, exchange the share and proof, and verify each other's before proceeding. Reaching
/// Done proves the gate saw both fees as Verified (a missing or bad fee would stall the swap), so
/// this exercises the signer, the FeeProof message, verify_fee and the three-state gate together.
#[test]
fn swap_with_fees_completes_end_to_end() {
    let Some(w) = World::start() else { return };
    let secp = Secp256k1::new();
    let recipient = SilentPaymentAddress {
        scan: PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x33; 32]).unwrap()),
        spend: PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x44; 32]).unwrap()),
        network: Network::Regtest,
    };
    let fee = FeeTerms {
        maker_bps: 20,
        taker_bps: 30,
        btc_address: Some(recipient.encode()),
        xbtc_address: Some(recipient.encode()),
    };
    let fee_offer = Offer {
        fee: Some(fee),
        ..offer(Chain::Xbtc)
    };
    let (mut maker, mut taker) =
        w.parties_offer(fee_offer.clone(), Chain::Xbtc, fee_offer.maker_amount);
    w.run(&mut maker, &mut taker, 30, always, false, both(Phase::Done));
}

/// The configurable minimum trade (settings `min_trade_sat`, design 0010): lowered on both engines,
/// the voluntary fee applies to legs below the 100_000 sat default, and the swap completes. Reaching
/// Done proves the override reached BOTH fee paths on both parties: each funds its lock with a fee
/// output (the funding path) and verifies the counterparty's (the verify path). With the default
/// minimum these sub-100k legs would make the fee BelowMinimum, so funding would error and the
/// counterparty's fee would verify as Failed.
#[test]
fn a_lowered_min_trade_lets_the_fee_apply_to_a_small_swap() {
    let Some(w) = World::start() else { return };
    let secp = Secp256k1::new();
    let recipient = SilentPaymentAddress {
        scan: PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x55; 32]).unwrap()),
        spend: PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x66; 32]).unwrap()),
        network: Network::Regtest,
    };
    let fee = FeeTerms {
        maker_bps: 20,
        taker_bps: 30,
        btc_address: Some(recipient.encode()),
        xbtc_address: Some(recipient.encode()),
    };
    // Both legs sit below the 100_000 sat default minimum trade but above the swap floor.
    let small = Offer {
        maker_amount: Amount::from_sat(90_000),
        taker_amount: Amount::from_sat(60_000),
        min_maker_amount: Amount::from_sat(90_000),
        fee: Some(fee),
        ..offer(Chain::Xbtc)
    };
    let (mut maker, mut taker) = w.parties_offer(small.clone(), Chain::Xbtc, small.maker_amount);
    // Lower the minimum on both engines, as a test deployment would through its settings.
    maker.engine().set_min_trade_sat(1_000);
    taker.engine().set_min_trade_sat(1_000);
    w.run(&mut maker, &mut taker, 30, always, false, both(Phase::Done));
}

#[test]
fn swap_maker_sells_btc() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Btc);
    w.run(&mut maker, &mut taker, 30, always, false, both(Phase::Done));
}

/// Row 16: both engines are rebuilt from their files after every round.
#[test]
fn swap_survives_a_restart_after_every_step() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    w.run(&mut maker, &mut taker, 30, always, true, both(Phase::Done));
}

/// Row 12: the maker's first claim never reaches the node; it claims again.
#[test]
fn swap_completes_when_the_first_claim_is_dropped() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    w.run(&mut maker, &mut taker, 4, always, false, |m, _| {
        m.phase() == Some(Phase::Locked)
    });
    // Locked and waiting: the next broadcast is the claim.
    maker.engine().drop_broadcasts = 1;
    w.run(&mut maker, &mut taker, 30, always, false, both(Phase::Done));
}

/// Row 5: the taker never locks; the maker refunds once its lock runs out.
#[test]
fn maker_refunds_when_the_taker_never_locks() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    taker.tick();
    w.run(
        &mut maker,
        &mut taker,
        60,
        |_, _| (true, false),
        false,
        |m, _| m.phase() == Some(Phase::Refunded),
    );
}

/// Row 5, the other way: the maker stops after the taker locked; both get their coins back.
#[test]
fn both_refund_when_the_maker_never_claims() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    let active = |_: &Party, t: &Party| (t.phase() != Some(Phase::Locked), true);
    w.run(&mut maker, &mut taker, 40, active, false, |_, t| {
        t.phase() == Some(Phase::Refunded)
    });
    w.run(&mut maker, &mut taker, 60, always, false, |m, _| {
        m.phase() == Some(Phase::Refunded)
    });
}

/// Row 14.
#[test]
fn an_engine_does_not_bid_on_its_own_offer() {
    let Some(w) = World::start() else { return };
    let (a, _b) = memory_pair();
    let mut maker = Party::new("maker", a, &w.btc, &w.xbtc);
    let offer = offer(Chain::Xbtc);
    maker.engine().publish(offer.clone()).unwrap();
    assert!(matches!(
        maker.engine().bid(&offer, offer.maker_amount, [9; 16]),
        Err(EngineError::Bid(BidError::OwnOffer))
    ));
}

/// The configurable minimum swap leg (settings `min_swap_sat`): the engine refuses a bid for a leg
/// below the 10_000 sat default, and accepts the same bid once the minimum is lowered. This is the
/// bid side of the gate; the offer side is covered by `NewOffer::validate` in the daemon tests.
#[test]
fn a_lowered_min_swap_lets_a_small_leg_be_bid() {
    let Some(w) = World::start() else { return };
    let (a, _b) = memory_pair();
    let mut taker = Party::new("taker", a, &w.btc, &w.xbtc);
    // A 1:1 offer whose full leg (4_000 sat) is below the default minimum.
    let small = Offer {
        maker_amount: Amount::from_sat(4_000),
        taker_amount: Amount::from_sat(4_000),
        min_maker_amount: Amount::ZERO,
        ..offer(Chain::Xbtc)
    };
    // At the default minimum the bid is refused.
    assert!(matches!(
        taker.engine().bid(&small, Amount::from_sat(4_000), [1; 16]),
        Err(EngineError::Bid(BidError::BelowMinimum))
    ));
    // Lowered, the same bid is accepted.
    taker.engine().set_min_swap_sat(3_000);
    assert!(taker
        .engine()
        .bid(&small, Amount::from_sat(4_000), [2; 16])
        .is_ok());
}

/// Replay, engine level: a maker whose only xBTC coins also exist on BTC must not lock them.
#[test]
fn engine_refuses_to_lock_coins_that_exist_on_both_chains() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let w = World {
        btc: Node::start(&btc, None),
        xbtc: Node::start(&xbtc, Some(150)),
    };
    let (a, b) = memory_pair();
    let mut maker = Party::new("maker", a, &w.btc, &w.xbtc);
    let mut taker = Party::new("taker", b, &w.btc, &w.xbtc);
    // Shared history: blocks 1 to 149 pay the maker's xBTC wallet on both chains.
    let shared = w
        .xbtc
        .rpc
        .wallet("maker")
        .call("getnewaddress", json!([]))
        .unwrap();
    w.btc.call("generatetoaddress", json!([149, shared]));
    for height in 1..150 {
        let block = w.btc.call(
            "getblock",
            json!([w.btc.call("getblockhash", json!([height])), 0]),
        );
        w.xbtc.call("submitblock", json!([block]));
    }
    w.btc.mine(101);
    w.xbtc.mine(10);
    taker.deposit(&w.btc, 2.0);
    w.mine();
    let offer = offer(Chain::Xbtc);
    maker.engine().publish(offer.clone()).unwrap();
    taker.tick();
    taker
        .engine()
        .bid(&offer, offer.maker_amount, [9; 16])
        .unwrap();
    let errors = maker.engine().tick();
    assert!(
        errors.iter().any(|(_, e)| matches!(
            e,
            EngineError::Node(NodeError::Replay(ReplayError::SpendableOnOtherChain(_)))
        )),
        "{errors:?}"
    );
    assert_eq!(maker.phase(), Some(Phase::Locking));
    assert!(
        w.xbtc
            .call("getrawmempool", json!([]))
            .as_array()
            .unwrap()
            .is_empty(),
        "nothing broadcast"
    );
}

fn unconfirmed_balance(node: &Node, wallet: &str) -> f64 {
    let b = node
        .rpc
        .wallet(wallet)
        .call("getbalances", json!([]))
        .unwrap();
    b["mine"]["trusted"].as_f64().unwrap() + b["mine"]["untrusted_pending"].as_f64().unwrap()
}

/// Row 3 (`test_11_bad_itx`): the maker locks less than agreed. The taker never locks; the maker
/// gets its own lock back.
#[test]
fn taker_does_not_lock_against_a_short_maker_lock() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    maker.engine().lock_amount_override = Some(Amount::from_sat(49_000_000));
    let before = unconfirmed_balance(&w.btc, "taker");
    w.run(&mut maker, &mut taker, 60, always, false, |m, t| {
        t.phase() == Some(Phase::Abandoned) && m.phase() == Some(Phase::Refunded)
    });
    assert_eq!(
        unconfirmed_balance(&w.btc, "taker"),
        before,
        "the taker spent nothing"
    );
}

/// Row 4 (`test_10_bad_ptx`): the taker locks less than agreed. The maker never reveals the
/// secret; both refund.
#[test]
fn maker_does_not_reveal_against_a_short_taker_lock() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    taker.engine().lock_amount_override = Some(Amount::from_sat(14_000_000));
    w.run(
        &mut maker,
        &mut taker,
        70,
        always,
        false,
        both(Phase::Refunded),
    );
}

/// Row 11: the taker is offline until too little of the maker's lock remains, then refuses to lock.
#[test]
fn a_taker_back_too_late_does_not_lock() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    taker.tick();
    // 40-block maker lock; the taker needs 2 + 20 + 3 + 3 = 28 blocks left when it locks.
    for _ in 0..15 {
        maker.tick();
        w.mine();
    }
    w.run(&mut maker, &mut taker, 50, always, false, |m, t| {
        t.phase() == Some(Phase::Abandoned) && m.phase() == Some(Phase::Refunded)
    });
}

/// Row 13 (`test_04_ltc_btc_redeem_reorg`): the block holding the taker's claim is reorged out.
/// The engine keeps watching and the swap completes.
#[test]
fn swap_completes_after_the_takers_claim_is_reorged_out() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    // Wider round budgets than the other rows (#141): a reorg adds a re-confirmation and a re-claim on
    // top of the normal depths, so 30 rounds can run out on a slow CI runner and time out spuriously.
    w.run(&mut maker, &mut taker, 60, always, false, |_, t| {
        t.phase() == Some(Phase::Claiming)
    });
    w.xbtc.mine(1);
    let tip = w.xbtc.call("getbestblockhash", json!([]));
    w.xbtc.call("invalidateblock", json!([tip]));
    taker.tick();
    assert_eq!(
        taker.phase(),
        Some(Phase::Claiming),
        "not done while the claim is unconfirmed"
    );
    w.run(&mut maker, &mut taker, 60, always, false, both(Phase::Done));
}

/// Row 15 (`test_15_variable_amount`): the taker takes 40 % of the offer.
#[test]
fn a_partial_bid_swaps_the_proportional_amount() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties_for(Chain::Xbtc, Amount::from_sat(20_000_000));
    w.run(&mut maker, &mut taker, 30, always, false, both(Phase::Done));
    let swap = maker.engine().swaps().next().unwrap().clone();
    assert_eq!(
        (swap.maker_part, swap.taker_part),
        (Amount::from_sat(20_000_000), Amount::from_sat(6_000_000))
    );
}

/// Row 16/18, downtime variant: the taker locks, then its engine is down while blocks pass beyond
/// its refund window, and the maker never claims. On return the taker still refunds in time: the
/// deadline lives in the swap file, not in a running timer.
#[test]
fn a_taker_offline_past_its_window_still_refunds_on_return() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    // Tick both until the taker's own lock is on chain, then the maker goes dark.
    w.run(&mut maker, &mut taker, 40, always, false, |_, t| {
        t.phase() == Some(Phase::Locked)
    });
    // The taker is offline; the taker's lock (20 blocks) runs out while nobody ticks.
    for _ in 0..25 {
        w.mine();
    }
    taker.reopen(&w.btc, &w.xbtc);
    w.run(
        &mut maker,
        &mut taker,
        10,
        |_, _| (false, true),
        false,
        |_, t| t.phase() == Some(Phase::Refunded),
    );
}

/// A replayed offer, bid and accept must not create a second swap on either side.
#[test]
fn duplicate_messages_do_not_create_duplicate_swaps() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    let offer = offer(Chain::Xbtc);
    // Replay the offer and the bid with the same ids.
    maker.engine().publish(offer.clone()).unwrap();
    taker.tick();
    let _ = taker.engine().bid(&offer, offer.maker_amount, [9; 16]);
    for _ in 0..3 {
        maker.tick();
        taker.tick();
        w.mine();
    }
    assert_eq!(
        maker.engine().swaps().count(),
        1,
        "maker made a duplicate swap"
    );
    assert_eq!(
        taker.engine().swaps().count(),
        1,
        "taker made a duplicate swap"
    );
    // The filled offer was pruned, so a replayed bid finds nothing to take.
    assert!(
        maker.engine().own_offers().is_empty(),
        "a filled offer must be pruned"
    );
}

/// A withdrawn offer must leave the taker's discovery and not come back when the relay replays the
/// original offer event.
#[test]
fn a_withdrawn_offer_disappears_and_does_not_reappear_on_replay() {
    let Some(w) = World::start() else { return };
    let (a, b) = memory_pair();
    let mut maker = Party::new("maker", a, &w.btc, &w.xbtc);
    let mut taker = Party::new("taker", b, &w.btc, &w.xbtc);
    let offer = offer(Chain::Xbtc);
    maker.engine().publish(offer.clone()).unwrap();
    taker.tick();
    assert_eq!(taker.engine().seen_offers(), std::slice::from_ref(&offer));
    // The maker withdraws it; the taker drops it on the next tick.
    maker.engine().withdraw(offer.id).unwrap();
    taker.tick();
    assert!(
        taker.engine().seen_offers().is_empty(),
        "a withdrawn offer must disappear"
    );
    // A relay replay of the original offer event must not bring it back.
    maker.engine().publish(offer.clone()).unwrap();
    taker.tick();
    assert!(
        taker.engine().seen_offers().is_empty(),
        "a withdrawn offer must not reappear on replay"
    );
}

/// Withdrawing an id that is not one of our own offers is an error, not a silent success: a never-ours
/// id and an already-withdrawn id both report, so the HTTP layer can return 422 instead of a
/// misleading `{"withdrawn":...}` 200 (#78).
#[test]
fn withdrawing_a_non_owned_offer_is_rejected() {
    let Some(w) = World::start() else { return };
    let (a, _b) = memory_pair();
    let mut maker = Party::new("maker", a, &w.btc, &w.xbtc);
    let offer = offer(Chain::Xbtc);
    maker.engine().publish(offer.clone()).unwrap();
    // The real owned offer withdraws cleanly.
    maker.engine().withdraw(offer.id).unwrap();
    // A second withdraw of the same id now finds nothing and must error.
    assert!(
        maker.engine().withdraw(offer.id).is_err(),
        "withdrawing an already-withdrawn offer must be an error (#78)"
    );
    // An id that was never ours (e.g. a peer's offer) must likewise error, never report success.
    assert!(
        maker.engine().withdraw([0u8; 16]).is_err(),
        "withdrawing a non-owned offer must be an error (#78)"
    );
}

/// Operator abort is only for a swap that has committed no coin: once our lock is funded it must be
/// refused, so a funded swap can only ever reach a timelock refund, never a forced abandon that would
/// strand the coin (#65).
#[test]
fn abort_refuses_a_swap_whose_lock_is_funded() {
    let Some(w) = World::start() else { return };
    let (mut maker, mut taker) = w.parties(Chain::Xbtc);
    // Drive until the taker's own lock is funded and on chain.
    w.run(&mut maker, &mut taker, 40, always, false, |_, t| {
        t.phase() == Some(Phase::Locked)
    });
    let swap_id = taker.engine().swaps().next().expect("a swap").id;
    assert!(
        matches!(
            taker.engine().abort(swap_id),
            Err(EngineError::AlreadyFunded)
        ),
        "abort must refuse a funded swap"
    );
    assert_ne!(
        taker.phase(),
        Some(Phase::Abandoned),
        "a funded swap must not be force-abandoned by abort"
    );
}
