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

use bitcoin::Amount;
use serde_json::{json, Value};

use common::{binaries, Node};
use sovereign_swap::engine::{Config, Engine, EngineError};
use sovereign_swap::envelope::Identity;
use sovereign_swap::node::ChainNode;
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

fn tick(e: &mut Engine<Tp>) {
    let errs = e.tick();
    assert!(errs.is_empty(), "tick errors: {errs:?}");
}

/// Drive the two engines until the taker parks its funding lock awaiting the user's signature, and
/// return the swap id and the parked unsigned PSBT.
fn drive_until_parked(
    maker: &mut Engine<Tp>,
    taker: &mut Engine<Tp>,
    core: &Node,
    knots: &Node,
) -> ([u8; 16], String) {
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
