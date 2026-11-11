//! E2 (design 0017) at the *engine* level: a full two-party BTC/xBTC swap where the taker funds its
//! own lock interactively. The engine builds the unsigned funding PSBT and parks the swap; the user
//! signs it in their own keyed wallet (no spendable key on the engine host); the signed PSBT is
//! submitted back via `submit_signed_lock`, which validates, finalizes, broadcasts, and lets the swap
//! run on to `Phase::Done` with the claim/refund signed automatically by `self.keys`.
//!
//! The existing `cold_signer.rs` interactive tests cover the park/resume at the `ChainNode` level;
//! these cover the whole engine round, plus the safety guards that only exist at the engine level:
//!   - a parked lock survives an engine restart without rebuilding or double-funding,
//!   - a tampered or unsigned submission is rejected and leaves the swap parked,
//!   - a late submission is refused once the swap has abandoned (so a user cannot strand coin in an
//!     HTLC the engine no longer drives to a refund).
//!
//! Routed over the in-process relay, exactly like `relay_swap.rs`. Skipped without `BTC_BITCOIND` and
//! `XBTC_BITCOIND` (scripts/test-in-container.sh provides both).

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bitcoin::{Amount, Network, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine, EngineError, FeeTamper};
use sovereign_swap::envelope::Identity;
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::{ChainBackend, ChainNode, NodeError};
use sovereign_swap::policy::Policy;
use sovereign_swap::relay::{InProcessConn, Relay};
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::signer::InteractiveSigner;
use sovereign_swap::swap::{BidError, Chain, FeeTerms, LockView, Offer, Phase};

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

/// The maker: a plain node on both chains (locks xBTC from its node wallet).
fn open_maker(dir: &Path, relay: &Relay, core: &Node, knots: &Node) -> Engine<Tp> {
    let tp = RelayTransport::new(
        Identity::from_seed(&[11; 32]),
        &[101; 32],
        InProcessConn::new(relay.clone()),
    );
    let btc = ChainNode::open(core.rpc.clone(), "maker").unwrap();
    let xbtc = ChainNode::open(knots.rpc.clone(), "maker").unwrap();
    Engine::open(dir, btc, xbtc, tp, config()).unwrap()
}

/// The taker: BTC funded interactively (a watch-only wallet from the user's descriptors, plus the
/// `InteractiveSigner` that parks instead of signing), xBTC a plain node. Reopenable from the same
/// dir, which is what the restart test exercises.
fn open_taker(
    dir: &Path,
    relay: &Relay,
    core: &Node,
    knots: &Node,
    receive: &str,
    change: &str,
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
    Engine::open(dir, btc, xbtc, tp, config()).unwrap()
}

/// An offer where the maker locks BTC (so the maker's own funding leg is the interactive one).
fn offer_btc() -> Offer {
    Offer {
        id: [7; 16],
        maker_chain: Chain::Btc,
        maker_amount: Amount::from_sat(150_000),
        taker_amount: Amount::from_sat(500_000),
        min_maker_amount: Amount::from_sat(150_000),
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 1,
        taker_lock_depth: 1,
        margin_blocks: 2,
        fee: None,
    }
}

/// A plain party: both chains on the node RPC (used as the non-interactive counterparty).
fn open_plain(
    dir: &Path,
    name: &'static str,
    seeds: (u8, u8),
    relay: &Relay,
    core: &Node,
    knots: &Node,
) -> Engine<Tp> {
    let tp = RelayTransport::new(
        Identity::from_seed(&[seeds.0; 32]),
        &[seeds.1; 32],
        InProcessConn::new(relay.clone()),
    );
    let btc = ChainNode::open(core.rpc.clone(), name).unwrap();
    let xbtc = ChainNode::open(knots.rpc.clone(), name).unwrap();
    Engine::open(dir, btc, xbtc, tp, config()).unwrap()
}

/// A maker whose BTC leg funds interactively (watch-only from the user's descriptors + the
/// InteractiveSigner), xBTC a plain node. Mirrors open_taker for the maker role.
fn open_maker_interactive(
    dir: &Path,
    relay: &Relay,
    core: &Node,
    knots: &Node,
    receive: &str,
    change: &str,
) -> Engine<Tp> {
    let tp = RelayTransport::new(
        Identity::from_seed(&[11; 32]),
        &[101; 32],
        InProcessConn::new(relay.clone()),
    );
    let btc = ChainNode::open_cold(
        core.rpc.clone(),
        "makerfund",
        receive,
        change,
        Box::new(InteractiveSigner),
    )
    .unwrap();
    let xbtc = ChainNode::open(knots.rpc.clone(), "maker").unwrap();
    Engine::open(dir, btc, xbtc, tp, config()).unwrap()
}

fn tick(e: &mut Engine<Tp>) {
    let errs = e.tick();
    assert!(errs.is_empty(), "tick errors: {errs:?}");
}

/// Drive the two engines until the taker parks its funding lock awaiting the user's signature, and
/// return the swap id and the parked unsigned PSBT.
/// Wait until `wallet` on `node` reports a confirmed (minconf 1) UTXO, mining a block per retry so it
/// is self-healing whether or not the caller pre-mined. Building the funding PSBT on an early tick
/// otherwise races bitcoind's asynchronous wallet update after a freshly mined block, which
/// intermittently surfaced as an "Insufficient funds" error on that tick (#148).
fn wait_for_confirmed_utxo(node: &Node, wallet: &str) {
    let w = node.rpc.wallet(wallet);
    for _ in 0..60 {
        let utxos = w.call("listunspent", json!([1])).unwrap();
        if utxos.as_array().is_some_and(|a| !a.is_empty()) {
            return;
        }
        node.mine(1);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("funding wallet {wallet} never showed a confirmed UTXO");
}

fn drive_until_parked(
    maker: &mut Engine<Tp>,
    taker: &mut Engine<Tp>,
    core: &Node,
    knots: &Node,
) -> ([u8; 16], String) {
    // The maker funds its lock from "maker" on knots, the taker builds its funding PSBT from the
    // watch-only "takerfund" on core. Make sure both wallets have actually registered their confirmed
    // deposits before driving, so the first funding build never races the wallet (#148).
    wait_for_confirmed_utxo(knots, "maker");
    wait_for_confirmed_utxo(core, "takerfund");
    maker.publish(offer()).unwrap();
    tick(taker); // discover the offer over the relay
    taker.bid(&offer(), offer().maker_amount, [9; 16]).unwrap();

    let mut rounds = 0;
    loop {
        tick(maker);
        tick(taker);
        core.mine(1);
        knots.mine(1);
        if let Some(id) = taker.swaps().next().map(|s| s.id) {
            if let Some(psbt) = taker.pending_lock_psbt(id) {
                return (id, psbt);
            }
        }
        rounds += 1;
        assert!(
            rounds < 60,
            "taker never parked a funding lock: {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    }
}

#[test]
fn a_full_swap_settles_with_an_interactive_taker_funding_lock() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    // The user's own keyed wallet; its public descriptors drive the taker's watch-only funding wallet.
    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-iswap-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-iswap-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

    // Maker funds its xBTC leg from its node wallet; the taker's watch-only BTC wallet gets a coin so
    // it can build a funded PSBT the user will sign.
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

    let (swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);

    // A garbage body and the still-unsigned PSBT are both rejected, and neither clears the parked
    // state nor broadcasts anything.
    assert!(
        taker.submit_signed_lock(swap_id, "not-a-psbt").is_err(),
        "a non-PSBT body must be rejected"
    );
    assert!(
        taker.submit_signed_lock(swap_id, &parked).is_err(),
        "the still-unsigned parked PSBT must be rejected (not fully signed)"
    );
    assert_eq!(
        taker.pending_lock_psbt(swap_id).as_deref(),
        Some(parked.as_str()),
        "a rejected submission leaves the swap parked on the same PSBT"
    );

    // The user signs it in their own wallet and submits it back.
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    assert_eq!(signed["complete"], true, "the user's wallet fully signs it");
    let signed_psbt = signed["psbt"].as_str().unwrap().to_owned();
    taker.submit_signed_lock(swap_id, &signed_psbt).unwrap();
    assert!(
        taker.pending_lock_psbt(swap_id).is_none(),
        "a funded lock clears the pending PSBT"
    );
    // Submitting again, now that the lock has broadcast, is refused rather than funding twice.
    assert!(
        taker.submit_signed_lock(swap_id, &signed_psbt).is_err(),
        "a second submission after funding is refused"
    );

    // The swap runs to completion: the taker's lock confirms, the maker claims it (revealing the
    // secret), and the taker claims the maker's lock with that secret, all signed by self.keys.
    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
        || taker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
    {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "stuck: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

#[test]
fn a_parked_funding_lock_survives_an_engine_restart() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-irestart-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-irestart-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

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

    let (swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);

    // Restart the taker from the same dir: a fresh Engine over the same state and wallets.
    drop(taker);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);
    assert_eq!(taker.swaps().count(), 1, "the parked swap reloads");
    assert_eq!(
        taker.pending_lock_psbt(swap_id).as_deref(),
        Some(parked.as_str()),
        "the same parked PSBT comes back after a restart"
    );

    // A tick after the restart must not rebuild the lock (fresh inputs would strand the eventual
    // signature) nor broadcast anything: the PSBT stays byte-for-byte the same and still parked.
    tick(&mut taker);
    core.mine(1);
    knots.mine(1);
    assert_eq!(
        taker.pending_lock_psbt(swap_id).as_deref(),
        Some(parked.as_str()),
        "a post-restart tick never rebuilds or broadcasts a parked lock"
    );

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

#[test]
fn a_late_signed_lock_is_refused_after_the_swap_abandons() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-ilate-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-ilate-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

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

    let (swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);

    // The user did sign it, but took too long. Crucially, DON'T tick the taker before submitting: the
    // maker-chain height runs past the taker's lock deadline while the swap still sits in `Locking`
    // (its phase only flips to `Abandoned` on a tick). This is the dangerous between-ticks gap a plain
    // phase check misses. The submit itself must re-decide against the fresh chain view and refuse.
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    let signed_psbt = signed["psbt"].as_str().unwrap().to_owned();
    assert_eq!(
        taker.swaps().next().map(|s| s.phase),
        Some(Phase::Locking),
        "the parked swap is still in Locking (no tick has flipped it to Abandoned)"
    );
    knots.mine(160); // run the maker-chain height well past the taker's lock deadline

    // The late signed lock is refused, nothing is broadcast, and the dead PSBT is cleared so the UI
    // stops asking for a signature. Submitting would otherwise commit the user's coin to an HTLC the
    // engine no longer drives to a refund.
    let err = taker.submit_signed_lock(swap_id, &signed_psbt).unwrap_err();
    assert!(
        matches!(err, EngineError::NoLongerFundable),
        "a late submit past the lock deadline must be refused, got {err:?}"
    );
    assert!(
        taker.pending_lock_psbt(swap_id).is_none(),
        "the refusal clears the dead parked PSBT"
    );
    assert_eq!(
        taker.swaps().next().map(|s| s.phase),
        Some(Phase::Abandoned),
        "the re-decision abandons the swap"
    );

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

#[test]
fn a_full_swap_settles_with_an_interactive_maker_funding_lock() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    // The maker's own keyed wallet drives the maker's watch-only BTC funding wallet.
    core.call("createwallet", json!(["makeruser"]));
    let user = core.rpc.wallet("makeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-imaker-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-imaker-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker_interactive(&mdir, &relay, &core, &knots, &receive, &change);
    let mut taker = open_plain(&tdir, "taker", (22, 202), &relay, &core, &knots);

    // Maker locks BTC (interactively), taker locks xBTC (from its node wallet).
    let maddr = core
        .rpc
        .wallet("makerfund")
        .call("getnewaddress", json!([]))
        .unwrap();
    core.wallet()
        .call("sendtoaddress", json!([maddr, 1.0]))
        .unwrap();
    let taddr = knots
        .rpc
        .wallet("taker")
        .call("getnewaddress", json!([]))
        .unwrap();
    knots
        .wallet()
        .call("sendtoaddress", json!([taddr, 2.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);

    maker.publish(offer_btc()).unwrap();
    tick(&mut taker);
    taker
        .bid(&offer_btc(), offer_btc().maker_amount, [9; 16])
        .unwrap();

    // Drive until the maker parks its own funding lock (the maker locks first).
    let mut rounds = 0;
    let swap_id = loop {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        if let Some(id) = maker.swaps().next().map(|s| s.id) {
            if maker.pending_lock_psbt(id).is_some() {
                break id;
            }
        }
        rounds += 1;
        assert!(
            rounds < 60,
            "maker never parked: {:?}",
            maker.swaps().next().map(|s| s.phase)
        );
    };

    // The maker signs its own funding PSBT and submits it (the Role::Maker arm of submit_signed_lock).
    let parked = maker.pending_lock_psbt(swap_id).unwrap();
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    assert_eq!(signed["complete"], true);
    maker
        .submit_signed_lock(swap_id, signed["psbt"].as_str().unwrap())
        .unwrap();
    assert!(maker.pending_lock_psbt(swap_id).is_none());

    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
        || taker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
    {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "stuck: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Design 0019, #135 item 3: the user signs the parked PSBT and broadcasts it from their OWN wallet
/// while still in the funding window, instead of pasting it back. The engine must adopt the on-chain
/// lock on the next tick (clearing the prompt so the GUI stops asking) and the swap still settles.
#[test]
fn a_within_window_user_broadcast_lock_is_adopted_and_settles() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-iadopt-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-iadopt-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

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

    let (swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);

    // The user signs it, then broadcasts it themselves instead of submitting it back.
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    assert_eq!(signed["complete"], true, "the user's wallet fully signs it");
    let fin = core.call("finalizepsbt", json!([signed["psbt"].as_str().unwrap()]));
    let hex = fin["hex"].as_str().expect("the finalized funding tx hex");
    core.call("sendrawtransaction", json!([hex]));
    core.mine(1);

    // One tick adopts the on-chain lock and clears the prompt (otherwise the GUI keeps asking the user
    // to sign a lock already on chain).
    tick(&mut taker);
    assert!(
        taker.pending_lock_psbt(swap_id).is_none(),
        "the engine adopts its on-chain lock and clears the prompt, got {:?}",
        taker.pending_lock_psbt(swap_id)
    );

    // It also settles end to end.
    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
        || taker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
    {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "a user-broadcast lock was not adopted and settled: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Design 0019, #134: the user walks away while signing, the engine abandons the parked swap at the
/// funding window (clearing the prompt, as #133 intends), and the user then broadcasts the lock anyway.
/// The marker that outlives the abandon must let the engine adopt the on-chain lock and refund it with
/// self.keys, rather than strand it. The maker is not driven, so no secret is revealed and only the
/// refund path is possible.
#[test]
fn a_walked_away_swap_abandons_then_a_late_broadcast_is_refunded() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-iwalk-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-iwalk-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

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

    let (swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    let signed_psbt = signed["psbt"].as_str().unwrap().to_owned();

    // The user walks away; the engine ticks on past the funding window and abandons the parked swap.
    knots.mine(160);
    let mut r = 0;
    while taker.swaps().next().map(|s| s.phase) != Some(Phase::Abandoned) {
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        r += 1;
        assert!(
            r < 30,
            "the parked swap did not abandon: {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    }
    assert!(
        taker.pending_lock_psbt(swap_id).is_none(),
        "the prompt is cleared on abandon so the UI stops asking"
    );

    // The slow user finally broadcasts the exact lock from their own wallet.
    let fin = core.call("finalizepsbt", json!([signed_psbt]));
    let hex = fin["hex"].as_str().expect("the finalized funding tx hex");
    core.call("sendrawtransaction", json!([hex]));
    core.mine(1);

    // The watch marker outlived the abandon, so the engine adopts the lock and refunds it.
    let mut rounds = 0;
    while taker.swaps().next().map(|s| s.phase) != Some(Phase::Refunded) {
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 120,
            "a late user-broadcast lock was not adopted and refunded: taker {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Design 0019, #134's realistic path: the user pastes the signed PSBT too late, is refused
/// (`NoLongerFundable`, the prompt cleared), assumes the paste failed, and broadcasts from their own
/// wallet. The marker kept across the refusal must still let the engine adopt and refund the lock.
#[test]
fn a_refused_late_submit_then_user_broadcast_is_refunded() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-ilate2-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-ilate2-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

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

    let (swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    let signed_psbt = signed["psbt"].as_str().unwrap().to_owned();

    // Submit too late (no tick first): the maker chain runs past the taker's deadline, so the submit
    // re-decides, refuses, and clears the prompt.
    knots.mine(160);
    let err = taker.submit_signed_lock(swap_id, &signed_psbt).unwrap_err();
    assert!(
        matches!(err, EngineError::NoLongerFundable),
        "a late submit is refused, got {err:?}"
    );
    assert!(
        taker.pending_lock_psbt(swap_id).is_none(),
        "the refusal clears the prompt"
    );

    // The user, thinking the paste failed, broadcasts the lock from their own wallet anyway.
    let fin = core.call("finalizepsbt", json!([signed_psbt]));
    let hex = fin["hex"].as_str().expect("the finalized funding tx hex");
    core.call("sendrawtransaction", json!([hex]));
    core.mine(1);

    // The marker kept across the refusal lets the engine adopt and refund the lock.
    let mut rounds = 0;
    while taker.swaps().next().map(|s| s.phase) != Some(Phase::Refunded) {
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 120,
            "a lock broadcast after a refused late submit was not adopted and refunded: taker {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Design 0017 + 0018, #135 item 1: a fee-paying interactive swap. The offer carries a voluntary fee
/// with NORMAL regtest fee addresses (per 0018, interactive funding cannot build an sp1 fee output),
/// so the taker's parked PSBT includes the fee output, the maker verifies it from chain, the swap
/// settles, and `history()` reports the fee the taker paid. This exercises the production fee path
/// under interactive funding, which every prior interactive test skipped with `fee: None`.
#[test]
fn a_fee_paying_interactive_taker_swap_settles_and_reports_the_fee() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    // The project's per-chain fee addresses are normal regtest addresses (design 0018): no proof and no
    // BIP352-aware signer needed, and the counterparty verifies the fee output directly on chain.
    let btc_fee = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let xbtc_fee = knots
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let fee_offer = Offer {
        fee: Some(FeeTerms {
            maker_bps: 20,
            taker_bps: 30,
            btc_address: Some(btc_fee),
            xbtc_address: Some(xbtc_fee),
        }),
        ..offer()
    };

    let mdir = std::env::temp_dir().join(format!("sovswap-ifee-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-ifee-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

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

    // Drive to parked with the fee-bearing offer (drive_until_parked hardcodes the fee-less offer()).
    maker.publish(fee_offer.clone()).unwrap();
    tick(&mut taker);
    taker
        .bid(&fee_offer, fee_offer.maker_amount, [9; 16])
        .unwrap();
    let mut rounds = 0;
    let (swap_id, parked) = loop {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        if let Some(id) = taker.swaps().next().map(|s| s.id) {
            if let Some(psbt) = taker.pending_lock_psbt(id) {
                break (id, psbt);
            }
        }
        rounds += 1;
        assert!(
            rounds < 60,
            "taker never parked a fee'd funding lock: {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    };

    // The user signs the PSBT (which already carries the fee output) and submits it.
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    assert_eq!(signed["complete"], true, "the user's wallet fully signs it");
    taker
        .submit_signed_lock(swap_id, signed["psbt"].as_str().unwrap())
        .unwrap();

    // Both legs carry a verified fee, so the swap runs to completion.
    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
        || taker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
    {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "a fee'd interactive swap did not settle: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    // The taker locked 150_000 at 30 bps = 450, lifted to the 1_000-sat floor. history() recomputes the
    // fee from the offer terms (not from a stored proof), so an interactive swap reports it correctly:
    // this is the confirmation for #135 item 2 (no under-report for a normal fee).
    let hist = taker.history();
    assert_eq!(
        hist["totals"]["voluntary_fee_paid"]["total_sat"], 1000,
        "the interactive taker reports its 1000-sat fee: {hist}"
    );
    assert_eq!(hist["totals"]["voluntary_fee_paid"]["swaps"], 1);

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// A taker whose BTC refund/claim destination is a configured payout address (the user's own wallet),
/// otherwise identical to `open_taker`. Exercises custody: an interactive refund must return the coin
/// to an address the user controls, not to a node-generated one.
fn open_taker_payout(
    dir: &Path,
    relay: &Relay,
    core: &Node,
    knots: &Node,
    receive: &str,
    change: &str,
    btc_payout: String,
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
    let config = Config {
        btc_payout: Some(btc_payout),
        ..config()
    };
    Engine::open(dir, btc, xbtc, tp, config).unwrap()
}

/// Design 0017, #135 item 4: interactive refund custody. The taker funds BTC interactively and its
/// refund destination is a configured address in the user's own wallet. After the funding window
/// closes the user broadcasts the lock late; the engine adopts it (design 0019) and refunds with
/// self.keys, and the refunded coin must land at the user's payout address (`ismine`), not a
/// node-generated one.
#[test]
fn an_interactive_taker_refund_lands_at_the_user_payout_address() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());
    // The user's own payout address (ismine in the takeruser wallet).
    let payout = user
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();

    let mdir = std::env::temp_dir().join(format!("sovswap-icustody-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-icustody-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker_payout(
        &tdir,
        &relay,
        &core,
        &knots,
        &receive,
        &change,
        payout.clone(),
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

    let (swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    let signed_psbt = signed["psbt"].as_str().unwrap().to_owned();

    // The user walks away; the engine abandons the parked swap at the funding window.
    knots.mine(160);
    let mut r = 0;
    while taker.swaps().next().map(|s| s.phase) != Some(Phase::Abandoned) {
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        r += 1;
        assert!(
            r < 30,
            "did not abandon: {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    }

    // The user broadcasts the lock late; the engine adopts it and refunds (maker not driven).
    let fin = core.call("finalizepsbt", json!([signed_psbt]));
    let hex = fin["hex"].as_str().expect("the finalized funding tx hex");
    core.call("sendrawtransaction", json!([hex]));
    core.mine(1);
    let mut rounds = 0;
    while taker.swaps().next().map(|s| s.phase) != Some(Phase::Refunded) {
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 120,
            "the interactive refund did not complete: {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    }
    assert!(
        taker.pending_lock_psbt(swap_id).is_none(),
        "the prompt is clear after the refund"
    );

    // The refunded coin landed at the user's own payout address, not a node-generated one.
    core.mine(1);
    let received = user
        .call("getreceivedbyaddress", json!([payout, 0]))
        .unwrap();
    assert!(
        received.as_f64().unwrap_or(0.0) > 0.0,
        "the interactive refund lands at the user's payout address, got {received}"
    );

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Security (take-side fee policy): the offer's fee rate and address are chosen by the maker, who on
/// the public relay may be hostile. With the policy set (as the daemon sets it from the operator's
/// config), a taker must refuse an offer whose fee for the chain it locks exceeds the cap, or pays an
/// address the operator does not recognise, so it never pays a large "fee" to an attacker's address.
#[test]
fn a_taker_refuses_an_offer_whose_fee_is_unacceptable() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let tdir = std::env::temp_dir().join(format!("sovswap-feepolicy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tdir);
    let mut taker = open_plain(&tdir, "taker", (22, 202), &relay, &core, &knots);

    // The operator accepts only its own BTC fee address, capped at 100 bps (1%).
    let known: String = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let attacker: String = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    taker.set_fee_take_policy(100, vec![known.clone()], vec![]);

    // offer() has the maker locking xBTC, so the taker locks BTC and pays btc_address.
    let fee = |taker_bps: u16, addr: &str| Offer {
        fee: Some(FeeTerms {
            maker_bps: 20,
            taker_bps,
            btc_address: Some(addr.to_owned()),
            xbtc_address: None,
        }),
        ..offer()
    };

    // A fee to an address the operator does not recognise is refused.
    let bad_addr = fee(30, &attacker);
    assert!(
        matches!(
            taker.bid(&bad_addr, bad_addr.maker_amount, [1; 16]),
            Err(EngineError::Bid(BidError::FeeAddressNotAccepted))
        ),
        "a fee to an unknown address must be refused"
    );

    // A fee rate above the cap is refused, even to a known address.
    let high_bps = fee(200, &known);
    assert!(
        matches!(
            taker.bid(&high_bps, high_bps.maker_amount, [2; 16]),
            Err(EngineError::Bid(BidError::FeeTooHigh))
        ),
        "a taker fee above the cap must be refused"
    );

    // The accepted path (a known address within the cap passes the fee guard and the bid proceeds) is
    // covered by the swap e2e tests, which take real discovered offers; routing a Bid for a
    // hand-constructed offer has no maker to encrypt to, so we stop at the two refusals here.

    let _ = std::fs::remove_dir_all(&tdir);
}

/// Design 0019 bound (DoS): the terminal watch on a handed-out, abandoned lock is not kept forever.
/// Past the own-chain horizon the engine drops the marker, so a counterparty that bids and walks away
/// cannot leave a marker watched indefinitely. With a low cap, after the chain passes the horizon a
/// lock the user broadcasts late is NOT adopted and the swap stays Abandoned (manual rescue only,
/// since the per-swap keys are deterministic).
#[test]
fn the_adopt_watch_gives_up_past_the_horizon() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser"]));
    let user = core.rpc.wallet("takeruser");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let mdir = std::env::temp_dir().join(format!("sovswap-ihorizon-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-ihorizon-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);
    taker.set_adopt_watch_cap_blocks(5); // a short horizon for the test

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

    let (_swap_id, parked) = drive_until_parked(&mut maker, &mut taker, &core, &knots);
    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    let signed_psbt = signed["psbt"].as_str().unwrap().to_owned();

    // The user walks away. Push past the taker's lock deadline so it abandons, then drive its own
    // (BTC) chain well past the 5-block watch horizon with no lock broadcast.
    knots.mine(160);
    for _ in 0..20 {
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
    }
    assert_eq!(
        taker.swaps().next().map(|s| s.phase),
        Some(Phase::Abandoned),
        "the swap abandoned and the watch passed its horizon before any broadcast"
    );

    // The user finally broadcasts, but too late: the watch has already given up, so the lock is not
    // adopted and the swap stays Abandoned.
    let fin = core.call("finalizepsbt", json!([signed_psbt]));
    let hex = fin["hex"].as_str().expect("the finalized funding tx hex");
    core.call("sendrawtransaction", json!([hex]));
    core.mine(1);
    for _ in 0..30 {
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        assert_eq!(
            taker.swaps().next().map(|s| s.phase),
            Some(Phase::Abandoned),
            "past the horizon a late lock is not adopted; the swap stays abandoned"
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Security (fee verification, design 0010): a counterparty whose lock does not carry the agreed fee
/// must be rejected before we commit coin. A "malicious" maker is simulated with a high `min_trade_sat`
/// so its own engine deems its leg below the minimum trade and omits the fee output; the honest taker
/// (default minimum) requires it, verifies the maker's lock, sees the fee missing, and abandons WITHOUT
/// locking its own BTC - so it never pays into a swap whose agreed fee the maker dodged.
#[test]
fn an_honest_taker_abandons_a_maker_that_skips_the_fee() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let btc_fee: String = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let xbtc_fee: String = knots
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let fee_offer = Offer {
        fee: Some(FeeTerms {
            maker_bps: 20,
            taker_bps: 30,
            btc_address: Some(btc_fee),
            xbtc_address: Some(xbtc_fee),
        }),
        ..offer()
    };

    let mdir = std::env::temp_dir().join(format!("sovswap-feedodge-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-feedodge-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_plain(&mdir, "maker", (11, 101), &relay, &core, &knots);
    let mut taker = open_plain(&tdir, "taker", (22, 202), &relay, &core, &knots);
    // Malicious maker: a high minimum trade makes its engine treat its 500k xBTC leg as below-minimum,
    // so it locks WITHOUT the agreed fee output. The taker keeps the default minimum and requires it.
    maker.set_min_trade_sat(1_000_000);

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
        .call("sendtoaddress", json!([taddr, 1.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);

    maker.publish(fee_offer.clone()).unwrap();
    tick(&mut taker);
    taker
        .bid(&fee_offer, fee_offer.maker_amount, [9; 16])
        .unwrap();

    // The maker locks xBTC with no fee; the honest taker verifies, finds the agreed fee missing, and
    // abandons without locking.
    let mut rounds = 0;
    while taker.swaps().next().map(|s| s.phase) != Some(Phase::Abandoned) {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "the taker did not reject a fee-dodging maker: taker {:?}, maker {:?}",
            taker.swaps().next().map(|s| s.phase),
            maker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Security (fee verification, design 0010), maker side: the honest maker must NEVER reveal the secret
/// to a counterparty that locked without the agreed fee. A "malicious" taker is simulated with a high
/// `min_trade_sat` so its engine deems its BTC leg below-minimum and locks with no fee output; the honest
/// maker (default minimum) requires that fee, verifies the taker's lock before the claim, finds it
/// missing, and refuses to reveal - it refunds its own xBTC at the timelock instead. The griefed maker
/// loses nothing (its coin returns); the critical property is that the secret is never exposed to a
/// fee-dodger, so neither side can claim.
#[test]
fn an_honest_maker_never_reveals_to_a_taker_that_skips_the_fee() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let btc_fee: String = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let xbtc_fee: String = knots
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let fee_offer = Offer {
        fee: Some(FeeTerms {
            maker_bps: 20,
            taker_bps: 30,
            btc_address: Some(btc_fee),
            xbtc_address: Some(xbtc_fee),
        }),
        ..offer()
    };

    let mdir = std::env::temp_dir().join(format!("sovswap-mkfeedodge-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-mkfeedodge-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_plain(&mdir, "maker", (11, 101), &relay, &core, &knots);
    let mut taker = open_plain(&tdir, "taker", (22, 202), &relay, &core, &knots);
    // Malicious taker: a high minimum trade makes its engine treat its BTC leg as below-minimum, so it
    // locks WITHOUT the agreed fee. The honest maker keeps the default minimum and requires it.
    taker.set_min_trade_sat(1_000_000);

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
        .call("sendtoaddress", json!([taddr, 1.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);

    maker.publish(fee_offer.clone()).unwrap();
    tick(&mut taker);
    taker
        .bid(&fee_offer, fee_offer.maker_amount, [7; 16])
        .unwrap();

    // Drive to the maker's refund. The maker locks xBTC with its fee; the taker locks BTC without one;
    // the maker verifies the taker's lock, finds the fee missing, and never reveals. At no point may the
    // maker reach a claiming/settled phase - that would mean it exposed the secret to a fee-dodger.
    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Refunded) {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        let mp = maker.swaps().next().map(|s| s.phase);
        assert!(
            mp != Some(Phase::Claiming) && mp != Some(Phase::Done),
            "the maker revealed the secret to a fee-dodging taker: maker {mp:?}"
        );
        rounds += 1;
        assert!(
            rounds < 120,
            "the maker did not refund after refusing a fee-dodging taker: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    // The taker genuinely locked its BTC (feelessly) and got it back at its own timelock - this rules out
    // the confound where the maker refunds merely because the taker never funded. A refund is only
    // reachable from a funded lock, so reaching it proves the taker did lock.
    assert_eq!(
        taker.swaps().next().map(|s| s.phase),
        Some(Phase::Refunded),
        "the fee-dodging taker should have locked and then refunded its own coin"
    );

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Security (fee verification, design 0010/0013), wrong-address branch: a maker whose lock carries a
/// fee output of the right amount but paying a DIFFERENT address than the agreed one must be rejected.
/// The malicious maker funds its fee to a wrong (but valid) xBTC address via `fee_tamper`; the honest
/// taker verifies the maker's lock, sees the agreed fee address unpaid, and abandons WITHOUT locking
/// its own BTC. This complements the #147 missing-output tests with the wrong-address branch.
#[test]
fn an_honest_taker_abandons_a_maker_whose_fee_pays_the_wrong_address() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let btc_fee: String = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let xbtc_fee: String = knots
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    // A second, different xBTC address the cheating maker pays its fee to instead of the agreed one.
    let wrong_xbtc: String = knots
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(wrong_xbtc, xbtc_fee, "the tampered address must differ");
    let fee_offer = Offer {
        fee: Some(FeeTerms {
            maker_bps: 20,
            taker_bps: 30,
            btc_address: Some(btc_fee),
            xbtc_address: Some(xbtc_fee),
        }),
        ..offer()
    };

    let mdir = std::env::temp_dir().join(format!("sovswap-feewrong-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-feewrong-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_plain(&mdir, "maker", (11, 101), &relay, &core, &knots);
    let mut taker = open_plain(&tdir, "taker", (22, 202), &relay, &core, &knots);
    // Malicious maker: fund the agreed fee amount, but to the wrong xBTC address. The honest taker
    // keeps the default minimum and requires the fee at the agreed address.
    maker.fee_tamper = Some(FeeTamper::WrongAddress(wrong_xbtc));

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
        .call("sendtoaddress", json!([taddr, 1.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);

    maker.publish(fee_offer.clone()).unwrap();
    tick(&mut taker);
    taker
        .bid(&fee_offer, fee_offer.maker_amount, [9; 16])
        .unwrap();

    // The maker locks xBTC with the fee at the wrong address; the honest taker verifies, finds the
    // agreed fee address unpaid, and abandons without locking.
    let mut rounds = 0;
    while taker.swaps().next().map(|s| s.phase) != Some(Phase::Abandoned) {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "the taker did not reject a wrong-address fee maker: taker {:?}, maker {:?}",
            taker.swaps().next().map(|s| s.phase),
            maker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// Security (fee verification, design 0010/0013), underpaid branch, maker side: the honest maker must
/// never reveal the secret to a taker whose lock carries a fee output to the agreed address but below
/// the required amount. The malicious taker underpays its BTC fee via `fee_tamper`; the honest maker
/// verifies the taker's lock before claiming, finds the fee short, refuses to reveal, and refunds its
/// own xBTC at the timelock. A larger swap is used so the underpaid amount stays well above dust while
/// staying clearly below the required fee.
#[test]
fn an_honest_maker_never_reveals_to_a_taker_whose_fee_is_underpaid() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let btc_fee: String = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let xbtc_fee: String = knots
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    // A large swap: the taker's 3_000_000 sat leg owes a ~9_000 sat fee at 30 bps, so underpaying to
    // 1_000 sat is unmistakably short yet well above any dust limit.
    let fee_offer = Offer {
        maker_amount: Amount::from_sat(5_000_000),
        taker_amount: Amount::from_sat(3_000_000),
        min_maker_amount: Amount::from_sat(5_000_000),
        fee: Some(FeeTerms {
            maker_bps: 20,
            taker_bps: 30,
            btc_address: Some(btc_fee),
            xbtc_address: Some(xbtc_fee),
        }),
        ..offer()
    };

    let mdir = std::env::temp_dir().join(format!("sovswap-feeunder-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-feeunder-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_plain(&mdir, "maker", (11, 101), &relay, &core, &knots);
    let mut taker = open_plain(&tdir, "taker", (22, 202), &relay, &core, &knots);
    // Malicious taker: pay the agreed BTC fee address, but only 1_000 sat (far below the ~9_000 owed).
    taker.fee_tamper = Some(FeeTamper::Underpay(1_000));

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
        .call("sendtoaddress", json!([taddr, 1.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);

    maker.publish(fee_offer.clone()).unwrap();
    tick(&mut taker);
    taker
        .bid(&fee_offer, fee_offer.maker_amount, [7; 16])
        .unwrap();

    // Drive to the maker's refund. The maker locks xBTC with its honest fee; the taker locks BTC with
    // an underpaid fee; the maker verifies the taker's lock, finds the fee short, and never reveals. At
    // no point may the maker reach a claiming/settled phase, which would mean it exposed the secret.
    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Refunded) {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        let mp = maker.swaps().next().map(|s| s.phase);
        assert!(
            mp != Some(Phase::Claiming) && mp != Some(Phase::Done),
            "the maker revealed the secret to an underpaying taker: maker {mp:?}"
        );
        rounds += 1;
        assert!(
            rounds < 120,
            "the maker did not refund after refusing an underpaying taker: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    // The taker genuinely locked its BTC (with the short fee) and got it back at its own timelock, which
    // rules out the confound where the maker refunds merely because the taker never funded.
    assert_eq!(
        taker.swaps().next().map(|s| s.phase),
        Some(Phase::Refunded),
        "the underpaying taker should have locked and then refunded its own coin"
    );

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}

/// A read backend that can be made to fail `get_tx` on demand (#142). Every other read delegates to a
/// real `ChainNode`, so the swap still progresses; only `get_tx` fails while `pending` is set, which
/// makes the counterparty fee read `Pending` (engine `fee_state`). It is the deterministic seam for
/// the `NotYetFundable` branch: once a swap has parked, a plain node always reads the fee as verified
/// (parking requires it), so no real-node test can re-enter that branch without this.
struct PendableBackend {
    inner: ChainNode,
    pending: Arc<AtomicBool>,
}

impl ChainBackend for PendableBackend {
    fn network(&self) -> Network {
        self.inner.network()
    }
    fn height(&self) -> Result<u32, NodeError> {
        self.inner.height()
    }
    fn get_tx(&self, txid: Txid) -> Result<Transaction, NodeError> {
        if self.pending.load(Ordering::SeqCst) {
            return Err(NodeError::Unexpected(
                "pendable: tx not readable yet".into(),
            ));
        }
        self.inner.get_tx(txid)
    }
    fn watch_contract(&self, contract: &Contract) -> Result<(), NodeError> {
        self.inner.watch_contract(contract)
    }
    fn lock_view(
        &self,
        contract: &Contract,
        amount: Amount,
        ours: &[ScriptBuf],
    ) -> Result<Option<LockView>, NodeError> {
        self.inner.lock_view(contract, amount, ours)
    }
    fn broadcast(&self, tx: &Transaction) -> Result<(), NodeError> {
        self.inner.broadcast(tx)
    }
    fn estimate_fee_sat_vb(&self, conf_target: u16) -> Option<u64> {
        self.inner.estimate_fee_sat_vb(conf_target)
    }
}

/// #142: `submit_signed_lock` must refuse *retryably* (`NotYetFundable`), not terminally, when a parked
/// swap re-decides to not-fund while still live, keeping the parked PSBT byte-for-byte so the user's
/// signature is never stranded by a rebuild, and must then fund normally once the condition clears.
///
/// The deterministic trigger is a read backend whose `get_tx` fails on demand: with a fee-bearing
/// offer the taker's view of the maker's fee goes `Pending` (engine `fee_state`), so funding is no
/// longer decided though the phase is still `Locking`. Parking itself requires the fee verified, so a
/// plain node cannot re-enter this branch once parked, hence the injectable backend (the approach
/// captured on #142). Its sibling `NoLongerFundable` is already covered by the late-submit test.
#[test]
fn a_parked_submit_is_refused_retryably_while_the_fee_is_unreadable_then_funds_when_it_clears() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    core.call("createwallet", json!(["takeruser142"]));
    let user = core.rpc.wallet("takeruser142");
    let (receive, change) = wpkh_descriptors(&user.call("listdescriptors", json!([])).unwrap());

    let btc_fee = core
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let xbtc_fee = knots
        .wallet()
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let fee_offer = Offer {
        fee: Some(FeeTerms {
            maker_bps: 20,
            taker_bps: 30,
            btc_address: Some(btc_fee),
            xbtc_address: Some(xbtc_fee),
        }),
        ..offer()
    };

    let mdir = std::env::temp_dir().join(format!("sovswap-i142-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-i142-t-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
    let mut maker = open_maker(&mdir, &relay, &core, &knots);
    let mut taker = open_taker(&tdir, &relay, &core, &knots, &receive, &change);

    // The taker reads the maker's (xBTC) chain through a backend we can flip to fail `get_tx`. It
    // delegates to a real ChainNode on the same wallet name, so watch_contract and lock_view keep
    // working (load is idempotent); only the fee read can be made to stall.
    let pending = Arc::new(AtomicBool::new(false));
    let fake = PendableBackend {
        inner: ChainNode::open(knots.rpc.clone(), "taker").unwrap(),
        pending: pending.clone(),
    };
    taker.set_read_backend(Chain::Xbtc, Box::new(fake));

    // Fund both legs.
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

    // Drive to parked with `get_tx` working: the fee verifies and the taker parks its signed PSBT.
    maker.publish(fee_offer.clone()).unwrap();
    tick(&mut taker);
    taker
        .bid(&fee_offer, fee_offer.maker_amount, [9; 16])
        .unwrap();
    let mut rounds = 0;
    let (swap_id, parked) = loop {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
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

    let signed = user.call("walletprocesspsbt", json!([parked])).unwrap();
    assert_eq!(signed["complete"], true, "the user's wallet fully signs it");
    let signed_psbt = signed["psbt"].as_str().unwrap().to_owned();

    // The maker's fee output becomes unreadable: the parked submit must refuse RETRYABLY.
    pending.store(true, Ordering::SeqCst);
    let err = taker.submit_signed_lock(swap_id, &signed_psbt).unwrap_err();
    assert!(
        matches!(err, EngineError::NotYetFundable),
        "a parked submit whose fee is not yet readable must be NotYetFundable, got {err:?}"
    );

    // The swap stays live (not terminal), and the parked PSBT is preserved byte-for-byte so the user's
    // signature is never stranded by a rebuild.
    assert_eq!(
        taker.swaps().next().map(|s| s.phase),
        Some(Phase::Locking),
        "a retryable refusal must leave the swap live"
    );
    assert_eq!(
        taker.pending_lock_psbt(swap_id).as_deref(),
        Some(parked.as_str()),
        "the parked PSBT must survive a retryable refusal unchanged"
    );

    // Once the fee is readable again, the very same submit funds normally and the swap settles.
    pending.store(false, Ordering::SeqCst);
    taker
        .submit_signed_lock(swap_id, &signed_psbt)
        .expect("funds once the fee is readable again");

    let mut rounds = 0;
    while maker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
        || taker.swaps().next().map(|s| s.phase) != Some(Phase::Done)
    {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        rounds += 1;
        assert!(
            rounds < 80,
            "the swap did not settle after recovery: maker {:?}, taker {:?}",
            maker.swaps().next().map(|s| s.phase),
            taker.swaps().next().map(|s| s.phase)
        );
    }

    let _ = std::fs::remove_dir_all(&mdir);
    let _ = std::fs::remove_dir_all(&tdir);
}
