//! Silent payments (BIP352) checked against the official `send_and_receive_test_vectors.json`,
//! pinned under `tests/fixtures/` (see the provenance file). This is reference test data from the
//! BIP itself, not mock production data: it is the correctness gate for the fee-output crypto.
//!
//! Sender derivation and input eligibility are checked against every sending sub-vector. Receiver
//! scanning and address encoding are checked against the label-free receiving sub-vectors (the
//! operator publishes one plain, unlabelled address, so labels are out of scope by design 0010).

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Network, OutPoint, ScriptBuf, Txid, Witness};
use serde_json::Value;

use sovereign_swap::silentpayments::{
    create_outputs, input_pubkey, scan_outputs, InputKey, SilentPaymentAddress,
};

fn load() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bip352_send_and_receive_test_vectors.json"
    );
    let text = std::fs::read_to_string(path).expect("vector fixture present");
    serde_json::from_str(&text).expect("vector fixture is JSON")
}

fn script(hex: &str) -> ScriptBuf {
    if hex.is_empty() {
        ScriptBuf::new()
    } else {
        ScriptBuf::from_hex(hex).expect("script hex")
    }
}

fn witness(hex: &str) -> Witness {
    if hex.is_empty() {
        Witness::new()
    } else {
        deserialize_hex(hex).expect("witness hex")
    }
}

fn outpoint(vin: &Value) -> OutPoint {
    OutPoint {
        txid: Txid::from_str(vin["txid"].as_str().unwrap()).expect("txid"),
        vout: vin["vout"].as_u64().unwrap() as u32,
    }
}

fn prevout_spk(vin: &Value) -> ScriptBuf {
    script(vin["prevout"]["scriptPubKey"]["hex"].as_str().unwrap())
}

/// Classify a vector input: its outpoint, its contributed pubkey (if eligible), and taproot-ness.
fn eligible(vin: &Value) -> Option<(OutPoint, PublicKey, bool)> {
    let spk = prevout_spk(vin);
    let ss = script(vin["scriptSig"].as_str().unwrap_or(""));
    let wit = witness(vin["txinwitness"].as_str().unwrap_or(""));
    let pk = input_pubkey(&spk, &ss, &wit)?;
    Some((outpoint(vin), pk, spk.is_p2tr()))
}

fn xonly_set(values: &[Value]) -> BTreeSet<String> {
    values
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn sending_vectors_match() {
    let secp = Secp256k1::new();
    let tests = load();
    let mut checked = 0;
    for t in &tests {
        // One vector tests a reference-specific K_max DoS refusal on creating thousands of outputs
        // for a single recipient. Our fee sends exactly one output to one recipient, so that limit is
        // structurally unreachable; we do not implement it and skip this vector.
        if t["comment"].as_str().unwrap_or("").contains("K_max") {
            continue;
        }
        for sv in t["sending"].as_array().unwrap() {
            let given = &sv["given"];
            let mut inputs = Vec::new();
            let mut all_outpoints = Vec::new();
            for vin in given["vin"].as_array().unwrap() {
                all_outpoints.push(outpoint(vin));
                if let Some((_op, _pk, taproot)) = eligible(vin) {
                    let key = SecretKey::from_str(vin["private_key"].as_str().unwrap()).unwrap();
                    inputs.push(InputKey { key, taproot });
                }
            }
            let recipients: Vec<SilentPaymentAddress> = given["recipients"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| SilentPaymentAddress::parse(r["address"].as_str().unwrap()).unwrap())
                .collect();

            // expected.outputs is a list of acceptable output sets; the set we produce must be one.
            let acceptable: Vec<BTreeSet<String>> = sv["expected"]["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|group| xonly_set(group.as_array().unwrap()))
                .collect();

            let got: BTreeSet<String> =
                match create_outputs(&secp, &all_outpoints, &inputs, &recipients) {
                    Ok(outs) => outs.iter().map(|x| x.to_string()).collect(),
                    Err(_) => BTreeSet::new(), // no eligible inputs: an empty output set
                };
            assert!(
                acceptable.contains(&got),
                "sending `{}`: got {:?}, acceptable {:?}",
                t["comment"].as_str().unwrap_or(""),
                got,
                acceptable
            );
            checked += 1;
        }
    }
    assert!(
        checked > 20,
        "expected many sending sub-vectors, got {checked}"
    );
}

#[test]
fn receiving_vectors_match_without_labels() {
    let secp = Secp256k1::new();
    let tests = load();
    let mut checked = 0;
    for t in &tests {
        for rv in t["receiving"].as_array().unwrap() {
            let given = &rv["given"];
            if given
                .get("labels")
                .and_then(|l| l.as_array())
                .is_some_and(|l| !l.is_empty())
            {
                continue; // labels are out of scope (design 0010)
            }
            let km = &given["key_material"];
            let scan = SecretKey::from_str(km["scan_priv_key"].as_str().unwrap()).unwrap();
            let spend_priv = SecretKey::from_str(km["spend_priv_key"].as_str().unwrap()).unwrap();
            let spend_pub = PublicKey::from_secret_key(&secp, &spend_priv);

            let mut pubkeys = Vec::new();
            let mut all_outpoints = Vec::new();
            for vin in given["vin"].as_array().unwrap() {
                all_outpoints.push(outpoint(vin));
                if let Some((_op, pk, _)) = eligible(vin) {
                    pubkeys.push(pk);
                }
            }
            // A transaction output that is not a valid x-only key cannot be a silent payment output,
            // so decoy/non-curve outputs are simply skipped.
            let outputs: Vec<XOnlyPublicKey> = given["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|o| XOnlyPublicKey::from_str(o.as_str().unwrap()).ok())
                .collect();

            let found: BTreeSet<String> =
                scan_outputs(&secp, &scan, &spend_pub, &pubkeys, &all_outpoints, &outputs)
                    .unwrap_or_default()
                    .iter()
                    .map(|x| x.to_string())
                    .collect();
            let expected: BTreeSet<String> = rv["expected"]["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["pub_key"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(
                found,
                expected,
                "receiving `{}`",
                t["comment"].as_str().unwrap_or("")
            );

            // The plain (index 0) address encodes and parses back to these keys.
            let scan_pub = PublicKey::from_secret_key(&secp, &scan);
            let addr = SilentPaymentAddress {
                scan: scan_pub,
                spend: spend_pub,
                network: Network::Bitcoin,
            };
            let expected_addr = rv["expected"]["addresses"].as_array().unwrap()[0]
                .as_str()
                .unwrap();
            assert_eq!(addr.encode(), expected_addr, "address encode");
            let parsed = SilentPaymentAddress::parse(expected_addr).unwrap();
            assert_eq!((parsed.scan, parsed.spend), (scan_pub, spend_pub));
            checked += 1;
        }
    }
    assert!(
        checked > 15,
        "expected many label-free receiving sub-vectors, got {checked}"
    );
}
