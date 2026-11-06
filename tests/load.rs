//! Many swaps through one engine pair at once: throughput, and that swaps do not interfere.
//!
//! A real risk once more than one swap runs is shared state: a key index reused, one swap's lock
//! funded from another's coin, a file clobbered. This drives N swaps between the same maker and
//! taker concurrently and requires every one to settle. Count from SOVSWAP_LOAD_SWAPS (default 30);
//! run at 100 for a soak.

mod common;

use std::path::PathBuf;
use std::time::Instant;

use bitcoin::Amount;
use serde_json::json;

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine};
use sovereign_swap::node::ChainNode;
use sovereign_swap::policy::Policy;
use sovereign_swap::swap::{Chain, Offer, Phase};
use sovereign_swap::transport::{memory_pair, Memory};

const MAKER_AMOUNT: Amount = Amount::from_sat(200_000);
const TAKER_AMOUNT: Amount = Amount::from_sat(120_000);
/// One funding coin per swap, sized to cover its lock and fee on its own.
const PER_SWAP_COIN: Amount = Amount::from_sat(400_000);

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
    }
}

fn offer(index: usize) -> Offer {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&(index as u64).to_le_bytes());
    Offer {
        id,
        maker_chain: Chain::Xbtc,
        maker_amount: MAKER_AMOUNT,
        taker_amount: TAKER_AMOUNT,
        min_maker_amount: MAKER_AMOUNT,
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 1,
        taker_lock_depth: 1,
        margin_blocks: 2,
        fee: None,
    }
}

fn swap_id(index: usize) -> [u8; 16] {
    let mut id = [0xAAu8; 16];
    id[..8].copy_from_slice(&(index as u64).to_le_bytes());
    id
}

struct Party {
    dir: PathBuf,
    engine: Engine<Memory>,
}

impl Party {
    fn new(name: &'static str, transport: Memory, btc: &Node, xbtc: &Node) -> Party {
        let dir = std::env::temp_dir().join(format!("sovswap-load-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let open = |n: &Node| ChainNode::open(n.rpc.clone(), name).unwrap();
        let engine = Engine::open(&dir, open(btc), open(xbtc), transport, config()).unwrap();
        Party { dir, engine }
    }

    fn tick(&mut self) {
        let errors = self.engine.tick();
        assert!(errors.is_empty(), "tick errors: {errors:?}");
    }

    fn done(&self) -> usize {
        self.engine
            .swaps()
            .filter(|s| s.phase == Phase::Done)
            .count()
    }

    fn not_done(&self) -> Vec<Phase> {
        self.engine
            .swaps()
            .map(|s| s.phase)
            .filter(|p| *p != Phase::Done)
            .collect()
    }
}

impl Drop for Party {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Gives `node`'s wallet `name` `count` confirmed coins of `each`, so funding never has to combine.
fn fund_wallet(node: &Node, name: &str, count: usize, each: Amount) {
    let wallet = node.rpc.wallet(name);
    let mut outputs = serde_json::Map::new();
    for _ in 0..count {
        let address = wallet.call("getnewaddress", json!([])).unwrap();
        outputs.insert(address.as_str().unwrap().to_owned(), json!(each.to_btc()));
    }
    node.wallet()
        .call("sendmany", json!(["", outputs]))
        .unwrap();
    node.mine(1);
}

#[test]
fn many_swaps_run_concurrently_without_interference() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let n: usize = std::env::var("SOVSWAP_LOAD_SWAPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);

    let (a, b) = memory_pair();
    let mut maker = Party::new("maker", a, &core, &knots);
    let mut taker = Party::new("taker", b, &core, &knots);
    // Maker locks xBTC, taker locks BTC: fund each on its own chain, one coin per swap plus a few.
    fund_wallet(&knots, "maker", 2 * n + 10, PER_SWAP_COIN);
    fund_wallet(&core, "taker", 2 * n + 10, PER_SWAP_COIN);

    for i in 0..n {
        let offer = offer(i);
        maker.engine.publish(offer.clone()).unwrap();
        taker.tick();
        taker.engine.bid(&offer, MAKER_AMOUNT, swap_id(i)).unwrap();
    }

    let start = Instant::now();
    let mut rounds = 0;
    while maker.done() < n || taker.done() < n {
        maker.tick();
        taker.tick();
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "after {rounds} rounds: maker {:?}, taker {:?}",
            maker.not_done(),
            taker.not_done()
        );
    }
    eprintln!(
        "{n} swaps settled in {rounds} rounds, {:.1}s",
        start.elapsed().as_secs_f64()
    );

    // Isolation: every swap used a distinct key index and settled exactly once.
    let mut indices: Vec<u32> = maker.engine.swaps().map(|s| s.key_index).collect();
    indices.sort_unstable();
    let unique = indices.len();
    indices.dedup();
    assert_eq!(indices.len(), unique, "a key index was reused across swaps");
    assert_eq!(maker.done(), n);
    assert_eq!(taker.done(), n);
}
