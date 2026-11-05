//! Two engines swapping on Bitcoin Core and Knots BLAKE2b regtest, success and failure paths.
//! Scenario numbers refer to `docs/edge-cases.md`.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use bitcoin::Amount;
use serde_json::json;

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine, EngineError};
use sovereign_swap::node::{ChainNode, NodeError};
use sovereign_swap::replay::ReplayError;
use sovereign_swap::swap::{BidError, Chain, Offer, Phase};
use sovereign_swap::transport::{memory_pair, Memory};

const CONFIG: Config = Config {
    spend_fee: Amount::from_sat(2_000),
    fee_rate_sat_vb: 2,
};

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
                CONFIG,
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
        let (a, b) = memory_pair();
        let mut maker = Party::new("maker", a, &self.btc, &self.xbtc);
        let mut taker = Party::new("taker", b, &self.btc, &self.xbtc);
        maker.deposit(self.node(maker_chain), 2.0);
        taker.deposit(self.node(maker_chain.other()), 2.0);
        self.mine();
        let offer = offer(maker_chain);
        maker.engine().publish(offer.clone()).unwrap();
        taker.tick();
        assert_eq!(taker.engine().seen_offers(), std::slice::from_ref(&offer));
        taker
            .engine()
            .bid(&offer, offer.maker_amount, [9; 16])
            .unwrap();
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
