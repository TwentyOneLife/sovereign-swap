//! E1 (design 0016) at the *engine* level: a full two-party BTC/xBTC swap whose BTC-side chain reads
//! and broadcasts all go through a real Fulcrum Electrum server (`set_read_backend`), while the xBTC
//! side stays on the node RPC. This is the mixed per-chain configuration a thin client runs, and it
//! exercises the path `electrum_regtest.rs` could not: the counterparty learning the secret from a
//! claim seen *through Electrum* (`lock_view` populating `spend.preimage` from scripthash history),
//! and a claim/refund broadcast over Electrum.
//!
//! Routed over the in-process relay like `relay_swap.rs`. Skipped without `BTC_BITCOIND`,
//! `XBTC_BITCOIND` (common::binaries) and `FULCRUM_BIN` (scripts/fetch-nodes.sh +
//! scripts/test-in-container.sh).

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use bitcoin::{Amount, Network};
use serde_json::{json, Value};

use common::{binaries, Fulcrum, Node};
use sovereign_swap::electrum::ElectrumBackend;
use sovereign_swap::engine::{Config, Engine};
use sovereign_swap::envelope::Identity;
use sovereign_swap::node::{ChainBackend, ChainNode};
use sovereign_swap::policy::Policy;
use sovereign_swap::relay::{InProcessConn, Relay};
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::signer::InteractiveSigner;
use sovereign_swap::swap::{Chain, Offer, Phase};

type Tp = RelayTransport<InProcessConn>;

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

/// A party whose BTC reads and broadcasts go through `fulcrum_port`; xBTC stays on the node RPC.
fn open_party(
    dir: &Path,
    name: &'static str,
    seeds: (u8, u8),
    relay: &Relay,
    core: &Node,
    knots: &Node,
    fulcrum_port: u16,
) -> Engine<Tp> {
    let tp = RelayTransport::new(
        Identity::from_seed(&[seeds.0; 32]),
        &[seeds.1; 32],
        InProcessConn::new(relay.clone()),
    );
    let btc = ChainNode::open(core.rpc.clone(), name).unwrap();
    let xbtc = ChainNode::open(knots.rpc.clone(), name).unwrap();
    let mut engine = Engine::open(dir, btc, xbtc, tp, config()).unwrap();
    let electrum = common::connect_electrum("127.0.0.1", fulcrum_port, Network::Regtest);
    engine.set_read_backend(Chain::Btc, Box::new(electrum));
    engine
}

fn tick(e: &mut Engine<Tp>) {
    let errs = e.tick();
    assert!(errs.is_empty(), "tick errors: {errs:?}");
}

/// Wait until Fulcrum has indexed up to the node's tip, so a tick that reads BTC through Electrum
/// never acts on a chain view that is a block or two behind the node.
fn wait_synced(probe: &ElectrumBackend, core: &Node) {
    let tip = core.height() as u32;
    let deadline = Instant::now() + Duration::from_secs(30);
    while probe.height().unwrap_or(0) < tip {
        assert!(Instant::now() < deadline, "Fulcrum did not reach tip {tip}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn a_full_swap_settles_with_btc_read_and_broadcast_over_electrum() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    // Mine before launching Fulcrum: it refuses to serve during initial block download, and this also
    // matures coinbases so both node wallets can fund.
    core.mine(101);
    knots.mine(101);
    let Some(fulcrum) = Fulcrum::start(&core) else {
        eprintln!("skipped: set FULCRUM_BIN (scripts/fetch-nodes.sh)");
        return;
    };
    let probe = common::connect_electrum("127.0.0.1", fulcrum.port, Network::Regtest);
    let relay = Relay::new();

    let mdir = std::env::temp_dir().join(format!("sovswap-eswap-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-eswap-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_party(
        &mdir,
        "maker",
        (11, 101),
        &relay,
        &core,
        &knots,
        fulcrum.port,
    );
    let mut taker = open_party(
        &tdir,
        "taker",
        (22, 202),
        &relay,
        &core,
        &knots,
        fulcrum.port,
    );

    // Maker locks xBTC, taker locks BTC: fund each party's node wallet on its own chain.
    let maddr = knots
        .rpc
        .wallet("maker")
        .call("getnewaddress", json!([]))
        .unwrap();
    knots
        .wallet()
        .call("sendtoaddress", json!([maddr, 2.0]))
        .unwrap();
    let taddr = core
        .rpc
        .wallet("taker")
        .call("getnewaddress", json!([]))
        .unwrap();
    core.wallet()
        .call("sendtoaddress", json!([taddr, 2.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);
    wait_synced(&probe, &core);

    maker.publish(offer()).unwrap();
    tick(&mut taker); // discover the offer over the relay
    taker.bid(&offer(), offer().maker_amount, [9; 16]).unwrap();

    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
        || taker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
    {
        core.mine(1);
        knots.mine(1);
        wait_synced(&probe, &core);
        tick(&mut maker);
        tick(&mut taker);
        rounds += 1;
        assert!(
            rounds < 100,
            "stuck: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    drop(fulcrum);
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

fn wpkh_descriptors(listed: &Value) -> (String, String) {
    let mut receive = None;
    let mut change = None;
    for d in listed["descriptors"].as_array().unwrap() {
        let desc = d["desc"].as_str().unwrap_or("");
        if desc.starts_with("wpkh(") {
            if d["internal"].as_bool().unwrap_or(false) {
                change = Some(desc.to_owned());
            } else {
                receive = Some(desc.to_owned());
            }
        }
    }
    (
        receive.expect("a wpkh receive descriptor"),
        change.expect("a wpkh change descriptor"),
    )
}

/// A taker that funds BTC interactively (watch-only funding wallet + the InteractiveSigner that parks)
/// AND reads/broadcasts BTC through Fulcrum. This is the thin client's real target config, where the
/// design 0019 adoption of a user-broadcast lock must go through the Electrum backend (`lock_view` and
/// `get_tx` over scripthash/transaction.get), not the node RPC.
fn open_interactive_taker_electrum(
    dir: &Path,
    relay: &Relay,
    core: &Node,
    knots: &Node,
    receive: &str,
    change: &str,
    fulcrum_port: u16,
) -> Engine<Tp> {
    let tp = RelayTransport::new(
        Identity::from_seed(&[22; 32]),
        &[202; 32],
        InProcessConn::new(relay.clone()),
    );
    let btc = ChainNode::open_cold(
        core.rpc.clone(),
        "takerfund",
        receive,
        change,
        Box::new(InteractiveSigner),
    )
    .unwrap();
    let xbtc = ChainNode::open(knots.rpc.clone(), "taker").unwrap();
    let mut engine = Engine::open(dir, btc, xbtc, tp, config()).unwrap();
    let electrum = common::connect_electrum("127.0.0.1", fulcrum_port, Network::Regtest);
    engine.set_read_backend(Chain::Btc, Box::new(electrum));
    engine
}

/// Design 0019 over E1 (design 0016): the taker funds BTC interactively and reads BTC through Fulcrum.
/// The user broadcasts the signed lock themselves within the window; the engine must observe its own
/// lock through the Electrum backend (`lock_view`), adopt it (`get_tx` over Electrum), clear the
/// prompt, and the swap must settle. Only the node backend was exercised for adoption before.
#[test]
fn an_interactive_lock_is_adopted_with_btc_reads_over_electrum() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let Some(fulcrum) = Fulcrum::start(&core) else {
        eprintln!("skipped: set FULCRUM_BIN (scripts/fetch-nodes.sh)");
        return;
    };
    let probe = common::connect_electrum("127.0.0.1", fulcrum.port, Network::Regtest);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-eadopt-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-eadopt-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    // Maker: plain party reading BTC over Electrum too (it must see and claim the taker's BTC lock).
    let mut maker = open_party(
        &mdir,
        "maker",
        (11, 101),
        &relay,
        &core,
        &knots,
        fulcrum.port,
    );
    let mut taker = open_interactive_taker_electrum(
        &tdir,
        &relay,
        &core,
        &knots,
        &receive,
        &change,
        fulcrum.port,
    );

    let maddr = knots
        .rpc
        .wallet("maker")
        .call("getnewaddress", json!([]))
        .unwrap();
    knots
        .wallet()
        .call("sendtoaddress", json!([maddr, 2.0]))
        .unwrap();
    let taddr = core
        .rpc
        .wallet("takerfund")
        .call("getnewaddress", json!([]))
        .unwrap();
    core.wallet()
        .call("sendtoaddress", json!([taddr, 1.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);
    wait_synced(&probe, &core);

    // Drive until the taker parks its interactive BTC funding lock.
    maker.publish(offer()).unwrap();
    tick(&mut taker);
    taker.bid(&offer(), offer().maker_amount, [9; 16]).unwrap();
    let mut rounds = 0;
    let (swap_id, parked) = loop {
        core.mine(1);
        knots.mine(1);
        wait_synced(&probe, &core);
        tick(&mut maker);
        tick(&mut taker);
        if let Some(id) = taker.swaps().next().map(|s| s.id) {
            if let Some(psbt) = taker.pending_lock_psbt(id) {
                break (id, psbt);
            }
        }
        rounds += 1;
        assert!(
            rounds < 60,
            "taker never parked: {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    };

    // The user signs it and broadcasts it themselves, over the node (the engine reads it over Fulcrum).
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    assert_eq!(signed["complete"], true, "the user's wallet fully signs it");
    let fin = core.call("finalizepsbt", json!([signed["psbt"].as_str().unwrap()]));
    let hex = fin["hex"].as_str().expect("the finalized funding tx hex");
    core.call("sendrawtransaction", json!([hex]));
    core.mine(1);
    wait_synced(&probe, &core);

    // One tick adopts the lock observed through Electrum and clears the prompt.
    tick(&mut taker);
    assert!(
        taker.pending_lock_psbt(swap_id).is_none(),
        "the engine adopts its on-chain lock (seen over Electrum) and clears the prompt, got {:?}",
        taker.pending_lock_psbt(swap_id)
    );

    // And it settles end to end, with the BTC legs read and broadcast over Electrum.
    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
        || taker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
    {
        core.mine(1);
        knots.mine(1);
        wait_synced(&probe, &core);
        tick(&mut maker);
        tick(&mut taker);
        rounds += 1;
        assert!(
            rounds < 100,
            "stuck: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    drop(fulcrum);
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}
