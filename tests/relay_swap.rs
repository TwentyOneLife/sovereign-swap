//! A full BTC/xBTC swap routed over the in-process relay: the maker and taker discover each other
//! through the relay (a broadcast offer, a routed bid), never set up 1:1. Proves M3b-2 routing end
//! to end. See docs/design/0006.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::Amount;
use serde_json::json;

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine};
use sovereign_swap::envelope::Identity;
use sovereign_swap::node::ChainNode;
use sovereign_swap::policy::Policy;
use sovereign_swap::relay::{InProcessConn, Relay};
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::swap::{Chain, Offer, Phase};

fn config() -> Config {
    Config {
        min_spend_fee: Amount::from_sat(2_000),
        fee_rate_sat_vb: 2,
        policy: Policy {
            btc: vec![(Amount::ONE_BTC, 1)],
            xbtc: vec![(Amount::ONE_BTC, 2)],
            funding_minconf_btc: 1,
            funding_minconf_xbtc: 1,
        },
        btc_payout: None,
        xbtc_payout: None,
    }
}

fn offer() -> Offer {
    Offer {
        id: [7; 16],
        maker_chain: Chain::Xbtc,
        maker_amount: Amount::from_sat(500_000),
        taker_amount: Amount::from_sat(150_000),
        min_maker_amount: Amount::from_sat(500_000),
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 1,
        taker_lock_depth: 1,
        margin_blocks: 2,
        fee: None,
    }
}

struct Party {
    dir: PathBuf,
    name: &'static str,
    engine: Engine<RelayTransport<InProcessConn>>,
}

impl Party {
    fn new(
        name: &'static str,
        id_seed: u8,
        routing_seed: u8,
        relay: &Relay,
        btc: &Node,
        xbtc: &Node,
    ) -> Party {
        let dir = std::env::temp_dir().join(format!("sovswap-relay-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let tp = RelayTransport::new(
            Identity::from_seed(&[id_seed; 32]),
            &[routing_seed; 32],
            InProcessConn::new(relay.clone()),
        );
        let open = |n: &Node| ChainNode::open(n.rpc.clone(), name).unwrap();
        let engine = Engine::open(&dir, open(btc), open(xbtc), tp, config()).unwrap();
        Party { dir, name, engine }
    }

    fn tick(&mut self) {
        let errs = self.engine.tick();
        assert!(errs.is_empty(), "tick errors: {errs:?}");
    }

    fn phase(&self) -> Option<Phase> {
        self.engine.swaps().next().map(|s| s.phase)
    }

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

#[test]
fn a_full_swap_routes_over_the_relay() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let mut maker = Party::new("maker", 11, 101, &relay, &core, &knots);
    let mut taker = Party::new("taker", 22, 202, &relay, &core, &knots);
    maker.deposit(&knots, 2.0);
    taker.deposit(&core, 2.0);
    core.mine(1);
    knots.mine(1);

    maker.engine.publish(offer()).unwrap();
    taker.tick(); // discovers the offer over the relay
    taker
        .engine
        .bid(&offer(), offer().maker_amount, [9; 16])
        .unwrap();

    let mut rounds = 0;
    while maker.phase() != Some(Phase::Done) || taker.phase() != Some(Phase::Done) {
        maker.tick();
        taker.tick();
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 40,
            "stuck: maker {:?}, taker {:?}",
            maker.phase(),
            taker.phase()
        );
    }

    // The maker's offer was taken, so it must have left own_offers (consumed on the accepted bid).
    // This is the invariant the periodic re-announce relies on: a taken offer is never re-advertised,
    // so re-announcement can never cause a double-fill.
    assert!(
        maker.engine.own_offers().is_empty(),
        "a taken offer must leave own_offers so it is never re-announced"
    );
}

/// Periodic offer re-announcement (design 0020 decision 2): on its timer `tick` re-broadcasts every
/// live own offer, so an offer a relay evicted from its bounded store returns and a peer that
/// subscribes after the eviction can still discover it. A withdrawn offer is not re-announced.
#[test]
fn a_live_offer_is_reannounced_on_the_timer_but_a_withdrawn_one_is_not() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let mut maker = Party::new("reann-maker", 11, 101, &relay, &core, &knots);

    // Count the maker's broadcasts by polling the relay as a key that is not the maker's own (the
    // relay never returns a subscriber its own events). Offers and withdrawals are both broadcasts.
    let secp = Secp256k1::new();
    let other = Keypair::from_seckey_slice(&secp, &[9u8; 32])
        .unwrap()
        .x_only_public_key()
        .0;
    let count = || relay.query(0, &other).0.len();

    maker.engine.publish(offer()).unwrap();
    assert_eq!(count(), 1, "publish broadcasts the offer once");

    // Before the period elapses, a tick must not re-announce.
    maker
        .engine
        .set_reannounce_interval(Duration::from_secs(3600));
    maker.tick();
    assert_eq!(count(), 1, "no re-announce before the period elapses");

    // Once the period has elapsed (zero), a tick re-announces the live offer.
    maker.engine.set_reannounce_interval(Duration::ZERO);
    maker.tick();
    assert_eq!(count(), 2, "a live offer is re-announced after the period");

    // Withdrawing removes it from own_offers (and broadcasts one Withdraw), so later ticks never
    // re-announce it again.
    maker.engine.withdraw(offer().id).unwrap();
    let after_withdraw = count();
    maker.tick();
    maker.tick();
    assert_eq!(
        count(),
        after_withdraw,
        "a withdrawn offer is never re-announced"
    );
}
