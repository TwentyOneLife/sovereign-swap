//! A full swap carried over the real post-quantum envelope, not the plaintext in-memory transport.
//! Proves the format-3 seal/open (design 0005) carries a live swap end to end.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::Amount;
use serde_json::json;

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine};
use sovereign_swap::envelope::Identity;
use sovereign_swap::node::ChainNode;
use sovereign_swap::policy::Policy;
use sovereign_swap::swap::{Chain, Offer, Phase};
use sovereign_swap::transport::{memory_bytes_pair, EnvelopeTransport, MemoryBytes};

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
        user_held_spends: false,
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
        valid_until: None,
    }
}

struct Party {
    dir: PathBuf,
    name: &'static str,
    engine: Engine<EnvelopeTransport<MemoryBytes>>,
}

impl Party {
    fn new(
        name: &'static str,
        transport: EnvelopeTransport<MemoryBytes>,
        btc: &Node,
        xbtc: &Node,
    ) -> Party {
        let dir = std::env::temp_dir().join(format!("sovswap-env-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let open = |n: &Node| ChainNode::open(n.rpc.clone(), name).unwrap();
        let engine = Engine::open(&dir, open(btc), open(xbtc), transport, config()).unwrap();
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
fn a_full_swap_runs_over_the_post_quantum_envelope() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);

    // Each side's long-term identity; each learns the other's public keys out of band here (that
    // discovery is the Nostr client's job in M3b).
    let maker_id = Arc::new(Identity::from_seed(&[11; 32]));
    let taker_id = Arc::new(Identity::from_seed(&[22; 32]));
    let (maker_wire, taker_wire) = memory_bytes_pair();
    let maker_tp =
        EnvelopeTransport::new(Arc::clone(&maker_id), taker_id.public().clone(), maker_wire);
    let taker_tp =
        EnvelopeTransport::new(Arc::clone(&taker_id), maker_id.public().clone(), taker_wire);

    // The engine opens wallets by a fixed name; use one "env" wallet per node here.
    let mut maker = Party::new("maker", maker_tp, &core, &knots);
    let mut taker = Party::new("taker", taker_tp, &core, &knots);
    maker.deposit(&knots, 2.0);
    taker.deposit(&core, 2.0);
    core.mine(1);
    knots.mine(1);

    let offer = offer();
    maker.engine.publish(offer.clone()).unwrap();
    taker.tick(); // receives the signed offer over the envelope
    taker
        .engine
        .bid(&offer, offer.maker_amount, [9; 16])
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
}
