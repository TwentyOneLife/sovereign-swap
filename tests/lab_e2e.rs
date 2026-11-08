//! A full BTC/xBTC swap carried over a *real* Nostr relay reached by WebSocket, settling on real
//! regtest nodes. This is `relay_swap.rs` (the in-process-relay swap) with the real-wire transport
//! of `ws_relay.rs`: `RelayTransport<WsConn>` instead of `RelayTransport<InProcessConn>`.
//!
//! It is the driver the homelab's module 13 runs against the lab relay, to prove the relay carries
//! a real swap (clean, and again while the relay is under a flood). It is gated on three env vars
//! and skips with a note when they are absent, exactly as `regtest.rs` skips without node binaries:
//!   RELAY         ws:// URL of the relay (e.g. ws://<relay-host>:7777/)
//!   BTC_BITCOIND  path to a Bitcoin Core binary       (via common::binaries)
//!   XBTC_BITCOIND path to a Bitcoin Knots BLAKE2b binary
//!
//! The two regtest nodes are spawned as child processes bound to localhost, so no node port is ever
//! exposed; the only off-box traffic is the WebSocket to the relay.

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use serde_json::json;

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine};
use sovereign_swap::envelope::Identity;
use sovereign_swap::node::ChainNode;
use sovereign_swap::policy::Policy;
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::swap::{Chain, Offer, Phase};
use sovereign_swap::ws::WsConn;

fn config() -> Config {
    Config {
        spend_fee: Amount::from_sat(2_000),
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
    engine: Engine<RelayTransport<WsConn>>,
}

impl Party {
    fn new(
        name: &'static str,
        id_seed: u8,
        routing_seed: u8,
        relay_url: &str,
        btc: &Node,
        xbtc: &Node,
    ) -> Party {
        let dir = std::env::temp_dir().join(format!("sovswap-lab-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Direct ws (None = no SOCKS5 proxy); inside the lab the circuit is the macvlan, not Tor.
        let conn = WsConn::connect(relay_url, None).expect("connect to the lab relay");
        let tp = RelayTransport::new(
            Identity::from_seed(&[id_seed; 32]),
            &[routing_seed; 32],
            conn,
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
fn a_full_swap_settles_over_the_real_relay() {
    let Ok(relay_url) = std::env::var("RELAY") else {
        eprintln!("skipped: set RELAY to the relay ws:// URL (e.g. ws://<relay-host>:7777/)");
        return;
    };
    let Some((btc, xbtc)) = binaries() else {
        return;
    };

    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);

    let mut maker = Party::new("maker", 11, 101, &relay_url, &core, &knots);
    let mut taker = Party::new("taker", 22, 202, &relay_url, &core, &knots);
    maker.deposit(&knots, 2.0);
    taker.deposit(&core, 2.0);
    core.mine(1);
    knots.mine(1);

    // Let both parties' REQ subscriptions register on the real relay before the first publish; over
    // a real socket this is not instantaneous the way the in-process relay is.
    std::thread::sleep(Duration::from_millis(500));

    maker.engine.publish(offer()).unwrap();

    // The taker discovers the offer over the relay. Poll rather than a single tick: delivery crosses
    // a real WebSocket.
    let discovered = {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            taker.tick();
            if taker
                .engine
                .seen_offers()
                .iter()
                .any(|o| o.id == offer().id)
            {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    assert!(
        discovered,
        "taker never discovered the offer over the relay"
    );

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
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            rounds < 120,
            "stuck: maker {:?}, taker {:?}",
            maker.phase(),
            taker.phase()
        );
    }

    println!("LAB_E2E_OK: swap settled over {relay_url} in {rounds} rounds");
}
