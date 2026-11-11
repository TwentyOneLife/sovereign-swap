//! Daemon-side fee scanner (design 0013, stage 2), SCAN-ONLY.
//!
//! The operator collects its own silent-payment fees by scanning the chain with its scan key: a fee
//! paid by a third-party install goes to the operator's default address, and the DLEQ share that
//! would reveal it travels to the swap counterparty, not here. So the operator is not a party to
//! those swaps and can only find the fee outputs by scanning.
//!
//! This module walks blocks through the node RPC the daemon already holds. `getblock <hash> 3`
//! carries, per transaction, the input prevouts (for `silentpayments::input_pubkey`), the input
//! outpoints, and the output scripts; from those and the operator's scan key it re-derives the shared
//! secret and matches the fee outputs with `silentpayments::scan_outputs`. Only a `scan_outputs`
//! match counts; an arbitrary taproot output never does.
//!
//! SCAN-ONLY: it records a count and a total of sats per chain and logs each newly detected output.
//! It never spends or sweeps, and it never holds or logs a spend key (sweeping is stage 3). The scan
//! key is a secret; it lives only inside [`ScanConfig`] and never reaches a log line.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::rpc::Client;
use crate::silentpayments::{input_pubkey, scan_outputs, SilentPaymentAddress};

/// How long to sleep between catch-up passes once scanning has reached the tip.
const POLL: Duration = Duration::from_secs(30);

/// One collected fee output the operator found by scanning: where it is, and for how much.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeHit {
    pub outpoint: OutPoint,
    pub value: Amount,
}

/// Per-chain scan configuration. Built only for a chain that has both a silent payment fee address
/// and a scan key that matches it. The scan key is a secret and is never printed or logged.
pub struct ScanConfig {
    scan: SecretKey,
    spend: PublicKey,
    /// The height a first run (no persisted state) starts from. 0 means unset; the scanner then
    /// starts at the current tip rather than sweeping the whole chain.
    pub birthday: u32,
}

impl ScanConfig {
    /// Build the scan config for a chain. `Ok(None)` when the chain is not set up to scan (no scan
    /// key). `Err` with a field-free, value-free message when a scan key is present but malformed or
    /// does not match the fee address, so a misconfiguration is loud rather than silently finding
    /// nothing forever. The error text never echoes the key.
    pub fn new(
        fee_address: &str,
        scan_key_hex: &str,
        birthday: u32,
    ) -> Result<Option<ScanConfig>, String> {
        let key = scan_key_hex.trim();
        if key.is_empty() {
            return Ok(None); // no scan key, so nothing to scan for this chain
        }
        // A scan key is only meaningful for a silent payment address; a normal fee address is watched
        // in the operator's own Electrum server and needs no scanning (design 0013).
        let Ok(sp) = SilentPaymentAddress::parse(fee_address.trim()) else {
            return Err(
                "scan key set but the fee address is not a silent payment address".to_owned(),
            );
        };
        let bytes = <[u8; 32]>::from_hex(key)
            .map_err(|_| "scan key must be 64 hex characters (32 bytes)".to_owned())?;
        let scan = SecretKey::from_slice(&bytes)
            .map_err(|_| "scan key is not a valid secret key".to_owned())?;
        let secp = Secp256k1::new();
        if PublicKey::from_secret_key(&secp, &scan) != sp.scan {
            return Err(
                "scan key does not match the fee address (wrong key, or BTC and xBTC swapped)"
                    .to_owned(),
            );
        }
        Ok(Some(ScanConfig {
            scan,
            spend: sp.spend,
            birthday,
        }))
    }
}

/// One recorded fee, as persisted. The set is kept, not just a running total, so a restart resumes at
/// the right height and `/status` still reports what was already collected, and so a rescan of the
/// same block cannot double count (dedup is by outpoint).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HitRec {
    txid: String,
    vout: u32,
    sat: u64,
    height: u32,
}

/// The scanner's persisted and live state for one chain.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct State {
    /// The last height fully scanned.
    pub height: u32,
    found: Vec<HitRec>,
}

impl State {
    /// How many distinct fee outputs have been collected.
    pub fn count(&self) -> u64 {
        self.found.len() as u64
    }

    /// The total sats across the collected fee outputs.
    pub fn sats(&self) -> u64 {
        self.found.iter().map(|h| h.sat).sum()
    }
}

/// Scan one transaction for the operator's fee. `prevout_spks` are the input prevout scripts in input
/// order (from `getblock 3`), needed to recover each input's public key. Returns the matched fee
/// outputs; a transaction with no taproot output, no eligible input, or that is a coinbase, yields
/// none. Any derivation error is treated as "no match", never a scan-aborting failure.
pub fn scan_tx(
    secp: &Secp256k1<All>,
    scan: &SecretKey,
    spend: &PublicKey,
    tx: &Transaction,
    prevout_spks: &[ScriptBuf],
) -> Vec<FeeHit> {
    if tx.is_coinbase() || prevout_spks.len() != tx.input.len() {
        return Vec::new();
    }
    // The taproot outputs are the only candidates; without one there is nothing to find.
    let mut candidates: Vec<XOnlyPublicKey> = Vec::new();
    let mut info: Vec<(XOnlyPublicKey, u32, Amount)> = Vec::new();
    for (vout, o) in tx.output.iter().enumerate() {
        if o.script_pubkey.is_p2tr() {
            if let Ok(x) = XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..34]) {
                candidates.push(x);
                info.push((x, vout as u32, o.value));
            }
        }
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    // Every outpoint the transaction spends (BIP352's smallest-outpoint rule is over all inputs), and
    // the public keys of the eligible ones.
    let mut pubkeys = Vec::new();
    let mut outpoints = Vec::new();
    for (i, input) in tx.input.iter().enumerate() {
        outpoints.push(input.previous_output);
        if let Some(pk) = input_pubkey(&prevout_spks[i], &input.script_sig, &input.witness) {
            pubkeys.push(pk);
        }
    }
    if pubkeys.is_empty() {
        return Vec::new();
    }
    let found = match scan_outputs(secp, scan, spend, &pubkeys, &outpoints, &candidates) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let txid = tx.compute_txid();
    found
        .iter()
        .filter_map(|key| {
            info.iter()
                .find(|(x, _, _)| x == key)
                .map(|(_, vout, value)| FeeHit {
                    outpoint: OutPoint { txid, vout: *vout },
                    value: *value,
                })
        })
        .collect()
}

/// Scan every transaction in a `getblock <hash> 3` JSON object. Each transaction is decoded from its
/// `hex` (exact sats, exact witnesses, no float parsing); only the input prevout scripts are taken
/// from the JSON. Returns an error if the node did not return the expected shape.
pub fn scan_block(
    secp: &Secp256k1<All>,
    scan: &SecretKey,
    spend: &PublicKey,
    block: &Value,
) -> Result<Vec<FeeHit>, String> {
    let mut hits = Vec::new();
    for txj in block["tx"].as_array().into_iter().flatten() {
        let Some(hex) = txj["hex"].as_str() else {
            return Err("getblock verbosity 3 returned a transaction without hex".to_owned());
        };
        let tx: Transaction =
            deserialize_hex(hex).map_err(|e| format!("decode transaction: {e}"))?;
        if tx.is_coinbase() {
            continue;
        }
        let Some(vin) = txj["vin"].as_array() else {
            continue;
        };
        let mut prevout_spks = Vec::with_capacity(vin.len());
        for v in vin {
            match v["prevout"]["scriptPubKey"]["hex"]
                .as_str()
                .and_then(|h| ScriptBuf::from_hex(h).ok())
            {
                Some(spk) => prevout_spks.push(spk),
                None => break,
            }
        }
        if prevout_spks.len() != tx.input.len() {
            continue; // a prevout was missing; cannot derive input keys, so skip this transaction
        }
        hits.extend(scan_tx(secp, scan, spend, &tx, &prevout_spks));
    }
    Ok(hits)
}

/// Walk blocks `from_last + 1 ..= tip` over the node RPC and collect the fee hits, each paired with
/// the block height it was found in. Returns the hits and the tip height reached (the new
/// last-scanned height). Does not spend or persist; the caller records the result.
pub fn scan_range(
    client: &Client,
    cfg: &ScanConfig,
    secp: &Secp256k1<All>,
    from_last: u32,
) -> Result<(Vec<(u32, FeeHit)>, u32), String> {
    let tip = height(client)?;
    let mut hits = Vec::new();
    let mut h = from_last.saturating_add(1);
    while h <= tip {
        let hash = client
            .call("getblockhash", json!([h]))
            .map_err(|e| format!("getblockhash {h}: {e:?}"))?;
        let block = client
            .call("getblock", json!([hash, 3]))
            .map_err(|e| format!("getblock {h}: {e:?}"))?;
        let bh = block["height"].as_u64().unwrap_or(h as u64) as u32;
        for hit in scan_block(secp, &cfg.scan, &cfg.spend, &block)? {
            hits.push((bh, hit));
        }
        h += 1;
    }
    Ok((hits, tip))
}

fn height(client: &Client) -> Result<u32, String> {
    Ok(client
        .call("getblockcount", json!([]))
        .map_err(|e| format!("getblockcount: {e:?}"))?
        .as_u64()
        .unwrap_or(0) as u32)
}

fn load_state(path: &Path) -> State {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Persist the state by writing a temp file and renaming it over the old one, so a crash mid-write
/// never leaves a half-written state.
fn save_state(path: &Path, s: &State) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(s).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

/// The scanner thread for one chain: catch up to the tip, record and persist any new fee outputs,
/// then sleep and repeat. Runs forever; the daemon spawns it detached. Logs one line per newly
/// detected fee output and never logs a key.
pub fn run(
    label: &'static str,
    client: Client,
    cfg: ScanConfig,
    state_file: PathBuf,
    shared: Arc<Mutex<State>>,
) {
    let secp = Secp256k1::new();
    let mut state = load_state(&state_file);
    // First run with no saved progress: start at the birthday. An unset birthday (0) means start at
    // the current tip, so a fresh install does not sweep the whole chain by accident.
    if state.height == 0 && state.found.is_empty() {
        if cfg.birthday > 0 {
            state.height = cfg.birthday.saturating_sub(1);
        } else if let Ok(tip) = height(&client) {
            eprintln!("fee-scanner {label}: no birthday set, starting at current tip {tip}");
            state.height = tip;
        }
    } else if cfg.birthday > 0 && state.height + 1 < cfg.birthday {
        state.height = cfg.birthday.saturating_sub(1);
    }
    *shared.lock().unwrap() = state.clone();

    let mut logged_error = false;
    loop {
        match scan_range(&client, &cfg, &secp, state.height) {
            Ok((hits, tip)) => {
                logged_error = false;
                let mut changed = false;
                for (bh, hit) in hits {
                    let txid = hit.outpoint.txid.to_string();
                    let seen = state
                        .found
                        .iter()
                        .any(|r| r.txid == txid && r.vout == hit.outpoint.vout);
                    if !seen {
                        eprintln!(
                            "fee-scanner {label}: new fee output {}:{} {} sat at height {}",
                            txid,
                            hit.outpoint.vout,
                            hit.value.to_sat(),
                            bh
                        );
                        state.found.push(HitRec {
                            txid,
                            vout: hit.outpoint.vout,
                            sat: hit.value.to_sat(),
                            height: bh,
                        });
                        changed = true;
                    }
                }
                if tip > state.height {
                    state.height = tip;
                    changed = true;
                }
                if changed {
                    *shared.lock().unwrap() = state.clone();
                    if let Err(e) = save_state(&state_file, &state) {
                        eprintln!("fee-scanner {label}: could not persist state: {e}");
                    }
                }
            }
            Err(e) => {
                // Log once per error run, not on every poll, so a down node does not flood the log.
                if !logged_error {
                    eprintln!("fee-scanner {label}: {e}");
                    logged_error = true;
                }
            }
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::key::TweakedPublicKey;
    use bitcoin::transaction::Version;
    use bitcoin::{absolute, Network, Sequence, TxIn, TxOut, Txid, WPubkeyHash, Witness};

    use crate::silentpayments::{create_outputs, InputKey};

    fn sk(n: u8) -> SecretKey {
        SecretKey::from_slice(&[n; 32]).unwrap()
    }

    fn p2tr(x: XOnlyPublicKey) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(x))
    }

    #[test]
    fn scan_tx_finds_the_operator_fee_and_ignores_other_taproot_outputs() {
        let secp = Secp256k1::new();
        let in_sk = sk(0x33);
        let in_pk = PublicKey::from_secret_key(&secp, &in_sk);
        let scan = sk(0x11);
        let spend = sk(0x22);
        let recipient = SilentPaymentAddress {
            scan: PublicKey::from_secret_key(&secp, &scan),
            spend: PublicKey::from_secret_key(&secp, &spend),
            network: Network::Regtest,
        };

        // The fee output a payer would place for this operator, from one P2WPKH input.
        let prevout = OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: 1,
        };
        let inputs = [InputKey {
            key: in_sk,
            taproot: false,
        }];
        let fee_xonly = create_outputs(&secp, &[prevout], &inputs, &[recipient]).unwrap()[0];

        // The P2WPKH spend: its witness ends in the input public key (what `input_pubkey` reads).
        let wpkh = WPubkeyHash::from_byte_array(
            bitcoin::hashes::hash160::Hash::hash(&in_pk.serialize()).to_byte_array(),
        );
        let mut witness = Witness::new();
        witness.push([0u8; 72]); // placeholder signature
        witness.push(in_pk.serialize());

        // An unrelated taproot output in the same transaction: must not count.
        let decoy = PublicKey::from_secret_key(&secp, &sk(0x99))
            .x_only_public_key()
            .0;

        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prevout,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(2_000),
                    script_pubkey: p2tr(fee_xonly),
                },
                TxOut {
                    value: Amount::from_sat(9_999),
                    script_pubkey: p2tr(decoy),
                },
            ],
        };
        let prevout_spks = vec![ScriptBuf::new_p2wpkh(&wpkh)];

        let hits = scan_tx(&secp, &scan, &recipient.spend, &tx, &prevout_spks);
        assert_eq!(hits.len(), 1, "exactly the operator fee output is found");
        assert_eq!(hits[0].outpoint.vout, 0);
        assert_eq!(hits[0].value, Amount::from_sat(2_000));

        // A different operator key finds nothing in the same transaction.
        let none = scan_tx(
            &secp,
            &sk(0xAB),
            &PublicKey::from_secret_key(&secp, &sk(0xCD)),
            &tx,
            &prevout_spks,
        );
        assert!(none.is_empty(), "an unrelated key collects no fee");
    }

    #[test]
    fn scan_config_matches_key_to_address_and_rejects_mismatch() {
        let secp = Secp256k1::new();
        let scan = sk(0x44);
        let spend = sk(0x55);
        let addr = SilentPaymentAddress {
            scan: PublicKey::from_secret_key(&secp, &scan),
            spend: PublicKey::from_secret_key(&secp, &spend),
            network: Network::Regtest,
        }
        .encode();
        let key_hex = {
            use bitcoin::hex::DisplayHex;
            scan.secret_bytes().to_lower_hex_string()
        };
        // An empty key means "not scanning", not an error.
        assert!(ScanConfig::new(&addr, "", 0).unwrap().is_none());
        // The right key for the address builds a config.
        assert!(ScanConfig::new(&addr, &key_hex, 100).unwrap().is_some());
        // A valid but wrong key is refused, and the message never contains the key.
        let wrong = {
            use bitcoin::hex::DisplayHex;
            sk(0x66).secret_bytes().to_lower_hex_string()
        };
        // ScanConfig deliberately has no Debug (it holds a scan key), so match rather than unwrap_err.
        let err = match ScanConfig::new(&addr, &wrong, 0) {
            Err(e) => e,
            Ok(_) => panic!("a valid but wrong key must be refused"),
        };
        assert!(err.contains("does not match"));
        assert!(!err.contains(&wrong));
        // A non-hex key is refused.
        assert!(ScanConfig::new(&addr, "nothex", 0).is_err());
    }
}
