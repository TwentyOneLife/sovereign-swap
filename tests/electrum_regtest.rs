//! Live regtest for the E1 Electrum `ChainBackend` (design 0016): runs a real Fulcrum against the
//! regtest Core bitcoind and checks `ElectrumBackend` reads a funded lock back the way the chain holds
//! it. Skips unless `BTC_BITCOIND` and `FULCRUM_BIN` are set (scripts/fetch-nodes.sh +
//! scripts/test-in-container.sh).

mod common;

use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Amount, Network, PubkeyHash};

use common::{binaries, connect_electrum, Fulcrum, Node};
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::ChainBackend;

#[test]
fn electrum_backend_reads_a_funded_lock_from_a_live_fulcrum() {
    let Some((btc, _)) = binaries() else {
        return;
    };
    let node = Node::start(&btc, None);
    // Mine before launching Fulcrum: Fulcrum refuses to serve while bitcoind is in initial block
    // download, and mining recent-timestamped blocks takes regtest out of IBD. Also matures a coinbase
    // so the wallet can fund.
    node.mine(101);
    let Some(fulcrum) = Fulcrum::start(&node) else {
        eprintln!("skipped: set FULCRUM_BIN (scripts/fetch-nodes.sh)");
        return;
    };

    let contract = Contract {
        secret_hash: sha256::Hash::hash(&[7u8; 32]).to_byte_array(),
        claim_pkh: PubkeyHash::from_byte_array([0x11; 20]),
        refund_pkh: PubkeyHash::from_byte_array([0x22; 20]),
        lock_blocks: 144,
    };
    let amount = Amount::from_sat(1_000_000);
    let lock = node.fund(&contract, amount); // funds the contract address + mines 1

    let be = connect_electrum("127.0.0.1", fulcrum.port, Network::Regtest);

    // Let Fulcrum index up to the node's tip (it polls bitcoind every polltime = 1s).
    let tip = node.height() as u32;
    let deadline = Instant::now() + Duration::from_secs(30);
    while be.height().unwrap_or(0) < tip {
        assert!(Instant::now() < deadline, "Fulcrum did not reach tip {tip}");
        std::thread::sleep(Duration::from_millis(300));
    }

    assert_eq!(be.height().unwrap(), tip);
    assert_eq!(be.get_tx(lock.txid).unwrap().compute_txid(), lock.txid);

    // lock_view reads the funded, unspent lock back through Fulcrum.
    let view = be
        .lock_view(&contract, amount, &[])
        .unwrap()
        .expect("the lock is visible via Electrum");
    assert_eq!(view.outpoint, lock);
    assert_eq!(view.value, amount);
    assert!(view.amount_ok);
    assert!(view.confirmed_height.is_some());
    assert!(view.spend.is_none(), "the lock is unspent");

    // A wrong agreed amount still finds the output but flags amount_ok = false.
    let other = be
        .lock_view(&contract, amount + Amount::from_sat(1), &[])
        .unwrap()
        .expect("still finds the output");
    assert!(!other.amount_ok);
    assert_eq!(other.outpoint, lock);

    // estimate_fee may be None on a quiet regtest; just exercise the path.
    let _ = be.estimate_fee_sat_vb(1);

    drop(fulcrum);
}
