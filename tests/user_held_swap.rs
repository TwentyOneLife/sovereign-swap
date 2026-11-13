//! 0027 acceptance gate: a full two-party swap where the MAKER is user-held. The maker engine holds
//! no claim/refund key and no secret; the user is a SEPARATE `Keys` (its own seed) that the engine
//! never instantiates. The user pre-provisions a public commitment bundle (secret hash + its own
//! claim/refund pubkey hashes), the engine commits those into the contract at swap-start, parks the
//! claim for the user to sign, and the user signs it with its own key and reveals its own secret.
//!
//! This is the test that catches the custody flaw the earlier slices hid: if the engine committed its
//! OWN pubkey hashes into the contract (as it did before the commitment bundle), the user's signature
//! would be rejected by `finalize` and the swap could never settle user-held. It asserts BOTH that the
//! user's own key settles AND that the engine's own key (read back from the engine's seed file) is
//! refused. The HTTP tests stop before the engine and the htlc equivalence test signs with the
//! contract key, so neither reaches this.
//!
//! The taker is an ordinary self-hosted (local-signing) party, so this also proves wire interop: a
//! user-held node and a plain node settle on the same relay with the same messages. Routed over the
//! in-process relay. Skipped without `BTC_BITCOIND` and `XBTC_BITCOIND`.

mod common;

use std::path::Path;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::{Amount, PublicKey};

use common::{binaries, Node};
use sovereign_swap::engine::{Commitment, Config, Engine, EngineError};
use sovereign_swap::envelope::Identity;
use sovereign_swap::keys::{Keys, Use};
use sovereign_swap::policy::Policy;
use sovereign_swap::relay::{InProcessConn, Relay};
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::swap::{BidError, Chain, Offer, Phase};

type Tp = RelayTransport<InProcessConn>;

fn config(user_held: bool) -> Config {
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
        user_held_spends: user_held,
    }
}

/// The maker locks xBTC; it CLAIMS the taker's BTC lock, so the maker's claim is the user-held spend.
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

/// A plain party: both chains funded and signed from the node wallet. `user_held` only changes how the
/// engine treats its OWN claim/refund/secret, never the wire, so a plain taker and a user-held maker
/// still interoperate.
fn open(
    dir: &Path,
    name: &'static str,
    seeds: (u8, u8),
    relay: &Relay,
    core: &Node,
    knots: &Node,
    user_held: bool,
) -> Engine<Tp> {
    let tp = RelayTransport::new(
        Identity::from_seed(&[seeds.0; 32]),
        &[seeds.1; 32],
        InProcessConn::new(relay.clone()),
    );
    let btc = sovereign_swap::node::ChainNode::open(core.rpc.clone(), name).unwrap();
    let xbtc = sovereign_swap::node::ChainNode::open(knots.rpc.clone(), name).unwrap();
    Engine::open(dir, btc, xbtc, tp, config(user_held)).unwrap()
}

fn tick(e: &mut Engine<Tp>) {
    let errs = e.tick();
    assert!(errs.is_empty(), "tick errors: {errs:?}");
}

fn wait_for_confirmed_utxo(node: &Node, wallet: &str) {
    let w = node.rpc.wallet(wallet);
    for _ in 0..60 {
        let utxos = w.call("listunspent", serde_json::json!([1])).unwrap();
        if utxos.as_array().is_some_and(|a| !a.is_empty()) {
            return;
        }
        node.mine(1);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("funding wallet {wallet} never showed a confirmed UTXO");
}

/// The public commitment bundle the user derives from ITS OWN seed for swap `index`. Exactly what the
/// engine would have derived from its own seed in a self-hosted (2a) node, but here it is the user's.
fn bundle(user: &Keys, index: u32) -> Commitment {
    Commitment {
        secret_hash: sha256::Hash::hash(&user.secret(index)).to_byte_array(),
        claim_pkh: user.pkh(index, Use::Claim),
        refund_pkh: user.pkh(index, Use::Refund),
    }
}

#[test]
fn a_user_held_maker_settles_with_the_users_own_key_not_the_engines() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let mdir = std::env::temp_dir().join(format!("sovswap-uh-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-uh-t-{}", std::process::id()));
    let udir = std::env::temp_dir().join(format!("sovswap-uh-user-{}", std::process::id()));
    for d in [&mdir, &tdir, &udir] {
        let _ = std::fs::remove_dir_all(d);
    }
    std::fs::create_dir_all(&udir).unwrap();

    let mut maker = open(&mdir, "maker", (11, 101), &relay, &core, &knots, true);
    let mut taker = open(&tdir, "taker", (22, 202), &relay, &core, &knots, false);

    // The user's own keys live only here, in a seed the engine never opens. Pre-provision a window of
    // commitment bundles for the indices the maker's first swaps will use (the maker's index counter
    // starts at 0).
    let user = Keys::open(&udir).unwrap();
    let entries: Vec<(u32, Commitment)> = (0..4u32).map(|i| (i, bundle(&user, i))).collect();
    maker.provision_commitments(entries).unwrap();

    // Fund both node wallets: the maker locks xBTC from "maker" on knots, the taker locks BTC from
    // "taker" on core.
    let maddr = knots
        .rpc
        .wallet("maker")
        .call("getnewaddress", serde_json::json!([]))
        .unwrap();
    knots
        .wallet()
        .call("sendtoaddress", serde_json::json!([maddr, 1.0]))
        .unwrap();
    let taddr = core
        .rpc
        .wallet("taker")
        .call("getnewaddress", serde_json::json!([]))
        .unwrap();
    core.wallet()
        .call("sendtoaddress", serde_json::json!([taddr, 1.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);
    wait_for_confirmed_utxo(&knots, "maker");
    wait_for_confirmed_utxo(&core, "taker");

    // Publish, take, and drive until the maker parks its claim of the taker's lock for the user.
    maker.publish(offer()).unwrap();
    tick(&mut taker);
    taker.bid(&offer(), offer().maker_amount, [9; 16]).unwrap();

    let mut rounds = 0;
    let (swap_id, index, sighash) = loop {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        if let Some(s) = maker.swaps().next() {
            if let Some((is_claim, sighash)) = maker.pending_spend(s.id) {
                assert!(is_claim, "the maker's user-held spend here is a claim");
                break (s.id, s.key_index, sighash);
            }
        }
        rounds += 1;
        assert!(
            rounds < 80,
            "maker never parked a user-held claim: {:?}",
            maker.swaps().next().map(|s| s.phase)
        );
    };

    let secp = Secp256k1::new();

    // The engine's OWN key, read back from the seed the engine created, must NOT settle: the contract
    // commits to the USER's claim pubkey hash, so `finalize` rejects the engine's key. This is the
    // assertion that fails if the contract ever committed engine-derived pubkey hashes again.
    let engine_keys = Keys::open(&mdir).unwrap();
    let ekey = engine_keys.key(index, Use::Claim);
    let epub = PublicKey::new(ekey.public_key(&secp));
    let esig = secp.sign_ecdsa(&Message::from_digest(sighash), &ekey);
    assert!(
        maker
            .submit_signed_spend(swap_id, esig, epub, Some(engine_keys.secret(index)))
            .is_err(),
        "the engine's own key must not settle a user-held claim"
    );
    assert!(
        maker.pending_spend(swap_id).is_some(),
        "a rejected submission leaves the claim parked for the real user"
    );

    // The USER signs the parked sighash with its own claim key and reveals its own secret.
    let ukey = user.key(index, Use::Claim);
    let upub = PublicKey::new(ukey.public_key(&secp));
    let usig = secp.sign_ecdsa(&Message::from_digest(sighash), &ukey);
    maker
        .submit_signed_spend(swap_id, usig, upub, Some(user.secret(index)))
        .expect("the user's own key settles the claim");
    assert!(
        maker.pending_spend(swap_id).is_none(),
        "a settled claim clears the parked spend"
    );

    // The swap runs to completion: the maker's claim (with the user's revealed secret) confirms, the
    // taker learns the secret from chain and claims the maker's lock, both reach Done.
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

    for d in [&mdir, &tdir, &udir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// The mirror of the maker test: a user-held TAKER settles against a plain maker. The taker advertises
/// its bundle's pubkey hashes in the bid and claims the maker's lock with the user's own key. This is
/// the path that is broken if the bid still sends engine-derived pubkey hashes (the two sides then
/// build contracts at different addresses and the swap stalls), which the maker-only test cannot see.
#[test]
fn a_user_held_taker_settles_with_the_users_own_key_not_the_engines() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let mdir = std::env::temp_dir().join(format!("sovswap-uht-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-uht-t-{}", std::process::id()));
    let udir = std::env::temp_dir().join(format!("sovswap-uht-user-{}", std::process::id()));
    for d in [&mdir, &tdir, &udir] {
        let _ = std::fs::remove_dir_all(d);
    }
    std::fs::create_dir_all(&udir).unwrap();

    let mut maker = open(&mdir, "maker", (55, 105), &relay, &core, &knots, false);
    let mut taker = open(&tdir, "taker", (66, 206), &relay, &core, &knots, true);

    // The taker's user holds its own keys; provision a window into the taker (its index counter is 0).
    let user = Keys::open(&udir).unwrap();
    let entries: Vec<(u32, Commitment)> = (0..4u32).map(|i| (i, bundle(&user, i))).collect();
    taker.provision_commitments(entries).unwrap();

    let maddr = knots
        .rpc
        .wallet("maker")
        .call("getnewaddress", serde_json::json!([]))
        .unwrap();
    knots
        .wallet()
        .call("sendtoaddress", serde_json::json!([maddr, 1.0]))
        .unwrap();
    let taddr = core
        .rpc
        .wallet("taker")
        .call("getnewaddress", serde_json::json!([]))
        .unwrap();
    core.wallet()
        .call("sendtoaddress", serde_json::json!([taddr, 1.0]))
        .unwrap();
    core.mine(1);
    knots.mine(1);
    wait_for_confirmed_utxo(&knots, "maker");
    wait_for_confirmed_utxo(&core, "taker");

    maker.publish(offer()).unwrap();
    tick(&mut taker);
    taker.bid(&offer(), offer().maker_amount, [9; 16]).unwrap();

    // Drive until the plain maker reveals the secret and the user-held taker parks its claim of the
    // maker's lock. The taker's claim preimage is the learned secret, carried by `decide`, so the user
    // supplies no preimage; only the signature with its own key.
    let mut rounds = 0;
    let (swap_id, index, sighash) = loop {
        tick(&mut maker);
        tick(&mut taker);
        core.mine(1);
        knots.mine(1);
        if let Some(s) = taker.swaps().next() {
            if let Some((is_claim, sighash)) = taker.pending_spend(s.id) {
                assert!(is_claim, "the taker's user-held spend here is a claim");
                break (s.id, s.key_index, sighash);
            }
        }
        rounds += 1;
        assert!(
            rounds < 80,
            "taker never parked a user-held claim: {:?}",
            taker.swaps().next().map(|s| s.phase)
        );
    };

    let secp = Secp256k1::new();

    // The taker engine's OWN key must not settle: the maker's lock commits the taker's bundle claim
    // pubkey hash, advertised in the bid, so the engine's key is refused.
    let engine_keys = Keys::open(&tdir).unwrap();
    let ekey = engine_keys.key(index, Use::Claim);
    let epub = PublicKey::new(ekey.public_key(&secp));
    let esig = secp.sign_ecdsa(&Message::from_digest(sighash), &ekey);
    assert!(
        taker
            .submit_signed_spend(swap_id, esig, epub, None)
            .is_err(),
        "the engine's own key must not settle a user-held taker claim"
    );

    // The user signs with its own claim key; the learned secret comes from the engine's `decide`.
    let ukey = user.key(index, Use::Claim);
    let upub = PublicKey::new(ukey.public_key(&secp));
    let usig = secp.sign_ecdsa(&Message::from_digest(sighash), &ukey);
    taker
        .submit_signed_spend(swap_id, usig, upub, None)
        .expect("the user's own key settles the taker claim");

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

    for d in [&mdir, &tdir, &udir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A user-held node with no provisioned commitment for the index it would use refuses to bid, rather
/// than committing an engine-derived pubkey hash or stranding a half-open swap when the Accept lands.
#[test]
fn a_user_held_node_refuses_to_bid_without_a_commitment() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = Relay::new();

    let mdir = std::env::temp_dir().join(format!("sovswap-uh-nc-m-{}", std::process::id()));
    let tdir = std::env::temp_dir().join(format!("sovswap-uh-nc-t-{}", std::process::id()));
    for d in [&mdir, &tdir] {
        let _ = std::fs::remove_dir_all(d);
    }

    let mut maker = open(&mdir, "maker", (33, 103), &relay, &core, &knots, false);
    // A user-held taker that was NEVER provisioned a commitment bundle.
    let mut taker = open(&tdir, "taker", (44, 204), &relay, &core, &knots, true);

    maker.publish(offer()).unwrap();
    tick(&mut taker); // discover the offer over the relay

    let err = taker
        .bid(&offer(), offer().maker_amount, [9; 16])
        .expect_err("a user-held taker with an empty pool must refuse to bid");
    assert!(
        matches!(err, EngineError::Bid(BidError::NoCommitment)),
        "expected a NoCommitment bid refusal, got {err:?}"
    );

    for d in [&mdir, &tdir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
