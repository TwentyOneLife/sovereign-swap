//! #301: a chain reconfigured between Hot and Cold/descriptor-backed funding must not collide on one
//! bitcoind wallet name. Hot funds from a keyed wallet, cold/descriptor-backed from a watch-only one;
//! the resolver sidesteps a left-over wallet of the other mode with a dedicated `-hot`/`-cold` name
//! instead of failing (the daemon has no RPC to rename or delete a wallet). Needs BTC_BITCOIND; skips
//! otherwise.

mod common;

use serde_json::json;

use common::{binaries, Node};
use sovereign_swap::node::{resolve_funding_wallet_name, ChainNode};
use sovereign_swap::signer::InteractiveSigner;

/// The active wpkh receive (external) and change (internal) output descriptors a watch-only funding
/// wallet imports, read from a key-holding wallet's public `listdescriptors`.
fn wpkh_descriptors(node: &Node) -> (String, String) {
    node.call("createwallet", json!(["descsrc"]));
    let listed = node
        .rpc
        .wallet("descsrc")
        .call("listdescriptors", json!([]))
        .unwrap();
    let (mut receive, mut change) = (None, None);
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

/// True if the named (loaded) wallet holds private keys.
fn is_keyed(node: &Node, name: &str) -> bool {
    node.rpc
        .wallet(name)
        .call("getwalletinfo", json!([]))
        .unwrap()["private_keys_enabled"]
        .as_bool()
        .expect("private_keys_enabled is a bool")
}

/// The wallet names present on disk (loaded or not).
fn wallet_names_on_disk(node: &Node) -> Vec<String> {
    node.call("listwalletdir", json!([]))["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["name"].as_str().map(str::to_owned))
        .collect()
}

/// The trusted balance (BTC) of a keyed wallet, for the "left-over untouched" assertion.
fn trusted_balance(node: &Node, name: &str) -> f64 {
    node.rpc
        .wallet(name)
        .call("getbalances", json!([]))
        .unwrap()["mine"]["trusted"]
        .as_f64()
        .unwrap_or(0.0)
}

#[test]
fn hot_then_cold_funds_from_a_watch_only_cold_wallet() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    let (recv, change) = wpkh_descriptors(&node);
    let base = "swap-aaaa";

    // Hot first: the base wallet is created keyed and is the funding wallet.
    let hot = ChainNode::open_hot(node.rpc.clone(), base).unwrap();
    assert_eq!(
        hot.funding_wallet_name(),
        base,
        "hot funds from the base name"
    );
    assert!(is_keyed(&node, base), "the hot base wallet holds keys");

    // Reconfigure the same chain to cold/descriptor-backed: it must open without manual intervention,
    // funding from a dedicated watch-only `<base>-cold`, and leave the keyed base untouched.
    let cold = ChainNode::open_cold_from(
        node.rpc.clone(),
        base,
        &recv,
        &change,
        Box::new(InteractiveSigner),
        None,
    )
    .expect("cold opens over a keyed base left-over without manual intervention");
    assert_eq!(cold.funding_wallet_name(), format!("{base}-cold"));
    assert!(
        !is_keyed(&node, &format!("{base}-cold")),
        "the cold funding wallet is watch-only"
    );
    assert!(
        is_keyed(&node, base),
        "the keyed base left-over is untouched"
    );
}

#[test]
fn hot_leftover_balance_is_untouched_by_a_cold_open() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    let (recv, change) = wpkh_descriptors(&node);
    let base = "swap-bbbb";

    ChainNode::open_hot(node.rpc.clone(), base).unwrap();
    // Mine a matured coinbase straight into the keyed base wallet.
    let base_addr = node
        .rpc
        .wallet(base)
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    node.call("generatetoaddress", json!([101, base_addr]));
    let before = trusted_balance(&node, base);
    assert!(before > 0.0, "the hot base wallet has coins to protect");

    ChainNode::open_cold_from(
        node.rpc.clone(),
        base,
        &recv,
        &change,
        Box::new(InteractiveSigner),
        None,
    )
    .unwrap();

    // No silent coin loss: the keyed left-over still exists, is still keyed, with the same balance.
    assert!(is_keyed(&node, base));
    assert_eq!(
        trusted_balance(&node, base),
        before,
        "the hot left-over's coins are untouched"
    );
}

#[test]
fn watch_only_base_is_reused_and_no_cold_wallet_is_created() {
    // An install whose base wallet is already watch-only (a cold-first deployment). Cold must reuse
    // it, not spawn a `-cold` sibling, so working installs keep their wallet.
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    let (recv, change) = wpkh_descriptors(&node);
    let base = "swap-cccc";
    // Pre-create the base watch-only (blank descriptor wallet), as a cold-first install has it.
    node.call("createwallet", json!([base, true, true, "", false, true]));

    let cold = ChainNode::open_cold_from(
        node.rpc.clone(),
        base,
        &recv,
        &change,
        Box::new(InteractiveSigner),
        None,
    )
    .unwrap();
    assert_eq!(
        cold.funding_wallet_name(),
        base,
        "a watch-only base is reused"
    );
    assert!(
        !wallet_names_on_disk(&node).contains(&format!("{base}-cold")),
        "no `-cold` sibling is created for a watch-only base"
    );
}

#[test]
fn cold_then_hot_funds_from_a_keyed_hot_wallet() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    let (recv, change) = wpkh_descriptors(&node);
    let base = "swap-dddd";

    // Cold first: the base wallet is watch-only.
    let cold = ChainNode::open_cold_from(
        node.rpc.clone(),
        base,
        &recv,
        &change,
        Box::new(InteractiveSigner),
        None,
    )
    .unwrap();
    assert_eq!(cold.funding_wallet_name(), base);
    assert!(!is_keyed(&node, base), "the cold base wallet is watch-only");

    // Flip back to hot: a `WalletSigner` over the watch-only base could not sign (it would fail only
    // at swap time), so hot must fund from a dedicated keyed `<base>-hot` instead.
    let hot =
        ChainNode::open_hot(node.rpc.clone(), base).expect("hot opens over a watch-only base");
    assert_eq!(hot.funding_wallet_name(), format!("{base}-hot"));
    assert!(
        is_keyed(&node, &format!("{base}-hot")),
        "the hot funding wallet holds keys"
    );
    assert!(!is_keyed(&node, base), "the watch-only base is untouched");
    // The contract watch wallet stays on the base name, so in-flight swaps are never orphaned by the
    // funding-wallet rename; no `<base>-hot-watch` is ever created.
    let on_disk = wallet_names_on_disk(&node);
    assert!(
        on_disk.contains(&format!("{base}-watch")),
        "the contract watch wallet is on the base"
    );
    assert!(
        !on_disk.contains(&format!("{base}-hot-watch")),
        "the funding-wallet rename must not spawn a second watch wallet"
    );
}

#[test]
fn split_resolves_to_the_keyed_hot_wallet_after_a_cold_to_hot_flip() {
    // The split co-sign service resolves the funding wallet name exactly as the engine does, with
    // want_keyed=true. After a cold->hot flip the keyed wallet is `<base>-hot`, NOT the watch-only base;
    // split must target the former, or it would try to sign on a watch-only wallet (#301 Check 1).
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    let (recv, change) = wpkh_descriptors(&node);
    let base = "swap-eeee";

    ChainNode::open_cold_from(
        node.rpc.clone(),
        base,
        &recv,
        &change,
        Box::new(InteractiveSigner),
        None,
    )
    .unwrap();
    ChainNode::open_hot(node.rpc.clone(), base).unwrap();

    let resolved = resolve_funding_wallet_name(&node.rpc, base, true).unwrap();
    assert_eq!(
        resolved,
        format!("{base}-hot"),
        "split co-signs with the keyed hot wallet"
    );
    assert!(is_keyed(&node, &resolved));
}

#[test]
fn resolve_returns_the_base_name_when_no_wallet_exists_yet() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    // Nothing on disk under this name: both modes resolve to the base, to be created fresh.
    assert_eq!(
        resolve_funding_wallet_name(&node.rpc, "swap-ffff", true).unwrap(),
        "swap-ffff"
    );
    assert_eq!(
        resolve_funding_wallet_name(&node.rpc, "swap-ffff", false).unwrap(),
        "swap-ffff"
    );
}
