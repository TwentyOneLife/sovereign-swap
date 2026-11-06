//! Silent payments (BIP352), in-tree, for the voluntary fee output (design 0010).
//!
//! Only what the fee needs: parse and encode a `sp1` address, classify the inputs a transaction
//! spends, derive the sender's fresh output(s) for a set of recipients, and scan a transaction's
//! taproot outputs for a recipient (the operator finding its own fee). No labels: the operator
//! publishes one plain address, so the label machinery of BIP352 is deliberately left out.
//!
//! The primitives are the ones already in the tree: `secp256k1` from the `bitcoin` crate, tagged
//! SHA256, and bech32m. The correctness gate is the official BIP352 test vectors (see
//! `tests/silentpayments_vectors.rs`); this module invents no cryptography, it composes audited
//! operations to the specification.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bech32::{Bech32m, Fe32, Hrp};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{
    Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey,
};
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, TxOut, Witness};

use crate::dleq;

/// Taproot NUMS point H (BIP341). A taproot input spent via a script path that reveals H as the
/// internal key is not eligible (BIP352): the output key is provably not a normal key.
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The address is not valid bech32m, or not a silent payment address.
    Address,
    /// A key in the address or an input was not a valid point.
    Key,
    /// No input was eligible, so there is no shared secret to derive.
    NoEligibleInputs,
    /// A scalar landed outside the curve order (negligible; treated as a hard error, never guessed).
    Scalar,
    /// The DLEQ proof could not be produced (a degenerate input).
    Dleq,
}

/// secp256k1's generator G, compressed, for the DLEQ proofs over the input-key sum.
fn generator() -> PublicKey {
    PublicKey::from_slice(&[
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ])
    .expect("valid secp256k1 generator")
}

/// What a payer puts on its lock to pay the fee, and reveals so a counterparty can check it.
#[derive(Clone, Debug)]
pub struct FeePayment {
    /// The P2TR scriptPubKey of the fee output (a fresh silent payment output).
    pub output: ScriptBuf,
    /// The ECDH share `a * B_scan`, compressed: revealed over the swap channel.
    pub share: [u8; 33],
    /// A BIP374 proof that `share` shares the input-key sum's discrete log, so the counterparty can
    /// trust it and the operator can locate the output.
    pub proof: [u8; 64],
}

/// The fee the operator receives (index 0) always; a single fee output per lock.
const FEE_OUTPUT_INDEX: u32 = 0;

fn p2tr(out_key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(out_key))
}

/// Payer side: the fee output to add to this lock, plus the share and DLEQ proof to send the
/// counterparty. `inputs` are the lock's eligible inputs (with their keys), `all_outpoints` every
/// input it spends, `recipient` the operator's silent payment address, `aux` fresh randomness for
/// the proof. Needs the input keys, so it runs in the signer.
pub fn pay_fee<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    inputs: &[InputKey],
    all_outpoints: &[OutPoint],
    recipient: &SilentPaymentAddress,
    aux: &[u8; 32],
) -> Result<FeePayment, Error> {
    let (a, a_pub) = sum_input_keys(secp, inputs)?;
    let smallest = all_outpoints
        .iter()
        .map(outpoint_bytes)
        .min()
        .ok_or(Error::NoEligibleInputs)?;
    let ih = input_hash(&smallest, &a_pub)?;
    let ecdh = ecdh_point(secp, &a, &ih, &recipient.scan)?;
    let out_key = output_key(secp, &ecdh, &recipient.spend, FEE_OUTPUT_INDEX)?;
    let share = recipient
        .scan
        .mul_tweak(secp, &scalar_of(&a)?)
        .map_err(|_| Error::Scalar)?
        .serialize();
    let proof =
        dleq::prove(secp, &generator(), &a, &recipient.scan, aux, None).ok_or(Error::Dleq)?;
    Ok(FeePayment {
        output: p2tr(out_key),
        share,
        proof,
    })
}

/// Counterparty side: does `outputs` (the payer's lock outputs) contain the operator's fee output of
/// at least `required_fee`? Verifies the DLEQ proof against `A` rebuilt from the lock's eligible
/// input public keys, derives the expected output from the revealed `share`, and looks for it. Pure
/// public-data computation: no secret, so it lives outside the signer.
#[allow(clippy::too_many_arguments)]
pub fn verify_fee<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    input_pub_keys: &[PublicKey],
    all_outpoints: &[OutPoint],
    recipient: &SilentPaymentAddress,
    share: &[u8; 33],
    proof: &[u8; 64],
    outputs: &[TxOut],
    required_fee: Amount,
) -> bool {
    let Ok(a_pub) = sum_pubkeys(input_pub_keys) else {
        return false;
    };
    let Ok(c) = PublicKey::from_slice(share) else {
        return false;
    };
    if !dleq::verify(secp, &generator(), &a_pub, &recipient.scan, &c, proof, None) {
        return false;
    }
    let Some(smallest) = all_outpoints.iter().map(outpoint_bytes).min() else {
        return false;
    };
    let Ok(ih) = input_hash(&smallest, &a_pub) else {
        return false;
    };
    // The counterparty's shared point is input_hash * share == (a * input_hash) * B_scan.
    let Ok(ecdh) = c.mul_tweak(secp, &ih) else {
        return false;
    };
    let Ok(out_key) = output_key(secp, &ecdh, &recipient.spend, FEE_OUTPUT_INDEX) else {
        return false;
    };
    let expected = p2tr(out_key);
    outputs
        .iter()
        .any(|o| o.script_pubkey == expected && o.value >= required_fee)
}

/// A parsed silent payment address: the recipient's scan and spend public keys, and its network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    pub scan: PublicKey,
    pub spend: PublicKey,
    pub testnet: bool,
}

impl SilentPaymentAddress {
    /// Parses a `sp1`/`tsp1` address. Only version 0 (a 66-byte scan||spend payload) is accepted;
    /// a higher version, wrong length, or a bad point is rejected rather than guessed.
    pub fn parse(s: &str) -> Result<SilentPaymentAddress, Error> {
        let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|_| Error::Address)?;
        let testnet = match checked.hrp().as_str() {
            "sp" => false,
            "tsp" => true,
            _ => return Err(Error::Address),
        };
        let mut fes = checked.fe32_iter::<core::iter::Empty<u8>>();
        let version = fes.next().ok_or(Error::Address)?;
        if version != Fe32::Q {
            return Err(Error::Address); // only v0
        }
        let payload: Vec<u8> = fes.fes_to_bytes().collect();
        if payload.len() != 66 {
            return Err(Error::Address);
        }
        Ok(SilentPaymentAddress {
            scan: PublicKey::from_slice(&payload[..33]).map_err(|_| Error::Key)?,
            spend: PublicKey::from_slice(&payload[33..]).map_err(|_| Error::Key)?,
            testnet,
        })
    }

    /// The bech32m string form, the inverse of `parse`.
    pub fn encode(&self) -> String {
        let hrp = Hrp::parse(if self.testnet { "tsp" } else { "sp" }).expect("static hrp");
        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&self.scan.serialize());
        payload.extend_from_slice(&self.spend.serialize());
        core::iter::once(Fe32::Q)
            .chain(payload.into_iter().bytes_to_fes())
            .with_checksum::<Bech32m>(&hrp)
            .chars()
            .collect()
    }
}

/// One eligible input a transaction spends, as the sender knows it: the private key for the pubkey
/// the input contributes, and whether it is a taproot spend (which needs the even-Y rule). The
/// outpoints are passed separately and in full, because BIP352's `input_hash` is keyed by the
/// smallest outpoint among *all* inputs, eligible or not.
pub struct InputKey {
    pub key: SecretKey,
    pub taproot: bool,
}

fn scalar_of(k: &SecretKey) -> Result<Scalar, Error> {
    Scalar::from_be_bytes(k.secret_bytes()).map_err(|_| Error::Scalar)
}

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(data);
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// The 36-byte consensus serialization of an outpoint (txid in internal order, then vout LE), the
/// form BIP352 orders inputs by.
fn outpoint_bytes(o: &OutPoint) -> [u8; 36] {
    let mut v = [0u8; 36];
    v[..32].copy_from_slice(&o.txid.to_byte_array());
    v[32..].copy_from_slice(&o.vout.to_le_bytes());
    v
}

/// `input_hash = tagged(Inputs, smallest_outpoint || A)`, where `A` is the summed input public key.
fn input_hash(smallest_outpoint: &[u8; 36], a_pub: &PublicKey) -> Result<Scalar, Error> {
    let mut data = Vec::with_capacity(36 + 33);
    data.extend_from_slice(smallest_outpoint);
    data.extend_from_slice(&a_pub.serialize());
    Scalar::from_be_bytes(tagged_hash("BIP0352/Inputs", &data)).map_err(|_| Error::Scalar)
}

/// `t_k = tagged(SharedSecret, ecdh || ser32(k))`, the per-output tweak.
fn output_tweak(ecdh: &PublicKey, k: u32) -> [u8; 32] {
    let mut data = Vec::with_capacity(33 + 4);
    data.extend_from_slice(&ecdh.serialize());
    data.extend_from_slice(&k.to_be_bytes());
    tagged_hash("BIP0352/SharedSecret", &data)
}

/// The sender's summed key `a`, with taproot inputs negated to even Y, and the matching public sum.
fn sum_input_keys<C: Signing>(
    secp: &Secp256k1<C>,
    inputs: &[InputKey],
) -> Result<(SecretKey, PublicKey), Error> {
    if inputs.is_empty() {
        return Err(Error::NoEligibleInputs);
    }
    let mut pending: Vec<SecretKey> = inputs
        .iter()
        .map(|inp| {
            let k = inp.key;
            if inp.taproot && k.x_only_public_key(secp).1 == Parity::Odd {
                k.negate()
            } else {
                k
            }
        })
        .collect();
    // Fold with deferral: `add_tweak` fails when a partial sum would be zero, which BIP352 allows as
    // an intermediate even when the final sum is valid (the "intermediate sum is zero" vector). On
    // such a step we defer the term and add it later; a valid total guarantees a working order.
    let mut acc: Option<SecretKey> = None;
    loop {
        let before = pending.len();
        let mut deferred = Vec::new();
        for k in pending.drain(..) {
            match &acc {
                None => acc = Some(k),
                Some(a) => match a.add_tweak(&scalar_of(&k)?) {
                    Ok(s) => acc = Some(s),
                    Err(_) => deferred.push(k),
                },
            }
        }
        if deferred.is_empty() {
            break;
        }
        if deferred.len() == before {
            return Err(Error::Scalar); // no progress: the whole sum is zero
        }
        pending = deferred;
    }
    let a = acc.ok_or(Error::NoEligibleInputs)?;
    let a_pub = PublicKey::from_secret_key(secp, &a);
    Ok((a, a_pub))
}

/// The ECDH point for a recipient scan key: `(a * input_hash) * B_scan`.
fn ecdh_point<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    a: &SecretKey,
    input_hash: &Scalar,
    scan: &PublicKey,
) -> Result<PublicKey, Error> {
    let partial = a.mul_tweak(input_hash).map_err(|_| Error::Scalar)?;
    scan.mul_tweak(secp, &scalar_of(&partial)?)
        .map_err(|_| Error::Scalar)
}

/// Derives the output x-only key for recipient `scan`/`spend` at index `k` from an ECDH point.
fn output_key<C: Signing>(
    secp: &Secp256k1<C>,
    ecdh: &PublicKey,
    spend: &PublicKey,
    k: u32,
) -> Result<XOnlyPublicKey, Error> {
    let t = SecretKey::from_slice(&output_tweak(ecdh, k)).map_err(|_| Error::Key)?;
    let t_point = PublicKey::from_secret_key(secp, &t);
    Ok(spend
        .combine(&t_point)
        .map_err(|_| Error::Key)?
        .x_only_public_key()
        .0)
}

/// Sender side: the fresh P2TR output keys this transaction pays to `recipients`. Recipients that
/// repeat a scan key get consecutive indices `k`; a single recipient (our fee) is just `k = 0`.
pub fn create_outputs<C: Signing + bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    all_outpoints: &[OutPoint],
    inputs: &[InputKey],
    recipients: &[SilentPaymentAddress],
) -> Result<Vec<XOnlyPublicKey>, Error> {
    if recipients.is_empty() {
        return Ok(Vec::new());
    }
    let (a, a_pub) = sum_input_keys(secp, inputs)?;
    let smallest = all_outpoints
        .iter()
        .map(outpoint_bytes)
        .min()
        .ok_or(Error::NoEligibleInputs)?;
    let input_hash = input_hash(&smallest, &a_pub)?;

    // Group by scan key so repeated recipients share one ECDH and count up k; preserve input order.
    let mut groups: Vec<(PublicKey, Vec<PublicKey>)> = Vec::new();
    for r in recipients {
        match groups.iter_mut().find(|(scan, _)| *scan == r.scan) {
            Some((_, spends)) => spends.push(r.spend),
            None => groups.push((r.scan, vec![r.spend])),
        }
    }
    let mut outputs = Vec::with_capacity(recipients.len());
    for (scan, spends) in &groups {
        let ecdh = ecdh_point(secp, &a, &input_hash, scan)?;
        for (k, spend) in spends.iter().enumerate() {
            outputs.push(output_key(secp, &ecdh, spend, k as u32)?);
        }
    }
    Ok(outputs)
}

/// Receiver side (the operator): which of `tx_outputs` pay this scan/spend key, given the public
/// keys of the transaction's eligible inputs and `all_outpoints` (every input the transaction
/// spends, for the smallest-outpoint rule). No scan key reveals here: the operator holds `scan`
/// (its scan private key) and scans its own incoming fees.
pub fn scan_outputs<C: Signing + bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    scan: &SecretKey,
    spend: &PublicKey,
    input_pub_keys: &[PublicKey],
    all_outpoints: &[OutPoint],
    tx_outputs: &[XOnlyPublicKey],
) -> Result<Vec<XOnlyPublicKey>, Error> {
    let a_pub = sum_pubkeys(input_pub_keys)?;
    let smallest = all_outpoints
        .iter()
        .map(outpoint_bytes)
        .min()
        .ok_or(Error::NoEligibleInputs)?;
    let input_hash = input_hash(&smallest, &a_pub)?;
    // ecdh = (scan * input_hash) * A
    let partial = scan.mul_tweak(&input_hash).map_err(|_| Error::Scalar)?;
    let ecdh = a_pub
        .mul_tweak(secp, &scalar_of(&partial)?)
        .map_err(|_| Error::Scalar)?;

    let mut remaining: Vec<XOnlyPublicKey> = tx_outputs.to_vec();
    let mut found = Vec::new();
    let mut k = 0u32;
    loop {
        let candidate = output_key(secp, &ecdh, spend, k)?;
        match remaining.iter().position(|o| *o == candidate) {
            Some(pos) => {
                remaining.remove(pos);
                found.push(candidate);
                k += 1;
            }
            None => break,
        }
    }
    Ok(found)
}

/// Sum eligible input public keys, deferring any step that lands on the point at infinity (the
/// mirror of the sender's zero intermediate; same reasoning, same guarantee from a valid total).
fn sum_pubkeys(pubkeys: &[PublicKey]) -> Result<PublicKey, Error> {
    if pubkeys.is_empty() {
        return Err(Error::NoEligibleInputs);
    }
    let mut pending: Vec<PublicKey> = pubkeys.to_vec();
    let mut acc: Option<PublicKey> = None;
    loop {
        let before = pending.len();
        let mut deferred = Vec::new();
        for pk in pending.drain(..) {
            match &acc {
                None => acc = Some(pk),
                Some(a) => match a.combine(&pk) {
                    Ok(s) => acc = Some(s),
                    Err(_) => deferred.push(pk),
                },
            }
        }
        if deferred.is_empty() {
            break;
        }
        if deferred.len() == before {
            return Err(Error::Key); // no progress: the whole sum is the point at infinity
        }
        pending = deferred;
    }
    acc.ok_or(Error::NoEligibleInputs)
}

/// The compressed public key an input contributes to the shared secret, or `None` if the input is
/// not eligible (BIP352). `spk` is the prevout script, `script_sig`/`witness` the spend data.
pub fn input_pubkey(spk: &Script, script_sig: &Script, witness: &Witness) -> Option<PublicKey> {
    if spk.is_p2tr() {
        if taproot_internal_is_nums(witness) {
            return None;
        }
        let xonly = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).ok()?;
        return Some(PublicKey::from_x_only_public_key(xonly, Parity::Even));
    }
    if spk.is_p2wpkh() {
        return compressed(witness.last()?);
    }
    if spk.is_p2sh() {
        // Eligible only as P2SH-P2WPKH: the redeem script pushed in scriptSig is `OP_0 <20-byte>`.
        let redeem = single_push(script_sig)?;
        if redeem.len() == 22 && redeem[0] == 0x00 && redeem[1] == 0x14 {
            return compressed(witness.last()?);
        }
        return None;
    }
    if spk.is_p2pkh() {
        let hash = &spk.as_bytes()[3..23];
        // The eligible key is the compressed push in scriptSig whose hash160 matches.
        for push in pushes(script_sig) {
            let h = bitcoin::hashes::hash160::Hash::hash(push);
            if push.len() == 33 && h.to_byte_array().as_slice() == hash {
                return compressed(push);
            }
        }
        return None;
    }
    None
}

fn compressed(bytes: &[u8]) -> Option<PublicKey> {
    if bytes.len() == 33 {
        PublicKey::from_slice(bytes).ok()
    } else {
        None // uncompressed keys are not eligible (BIP352)
    }
}

/// True if a taproot spend reveals the NUMS point H as its internal key (script path, so ineligible).
fn taproot_internal_is_nums(witness: &Witness) -> bool {
    let mut items: Vec<&[u8]> = witness.iter().collect();
    // Drop the annex if present (a final item starting with 0x50).
    if items.len() >= 2 && items.last().is_some_and(|a| a.first() == Some(&0x50)) {
        items.pop();
    }
    // Key-path spend is a single element (the signature); no internal key revealed, so not NUMS.
    if items.len() < 2 {
        return false;
    }
    // Script path: the last element is the control block; internal key is bytes 1..33.
    match items.last() {
        Some(cb) if cb.len() >= 33 => cb[1..33] == NUMS_H,
        _ => false,
    }
}

/// The data pushes of a script, in order (ignoring opcodes), for pubkey extraction.
fn pushes(script: &Script) -> Vec<&[u8]> {
    script
        .instructions()
        .filter_map(|i| match i {
            Ok(bitcoin::script::Instruction::PushBytes(b)) => Some(b.as_bytes()),
            _ => None,
        })
        .collect()
}

/// The single data push of a script, or `None` if there is not exactly one.
fn single_push(script: &Script) -> Option<&[u8]> {
    let p = pushes(script);
    if p.len() == 1 {
        Some(p[0])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;

    fn sk(n: u8) -> SecretKey {
        SecretKey::from_slice(&[n; 32]).unwrap()
    }

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: n as u32,
        }
    }

    // The operator's address, two eligible inputs, and the fee the payer should pay.
    fn fixture(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
    ) -> (
        SilentPaymentAddress,
        SecretKey,
        Vec<InputKey>,
        Vec<PublicKey>,
        Vec<OutPoint>,
    ) {
        let scan = sk(11);
        let spend = sk(12);
        let recipient = SilentPaymentAddress {
            scan: PublicKey::from_secret_key(secp, &scan),
            spend: PublicKey::from_secret_key(secp, &spend),
            testnet: false,
        };
        let keys = [sk(21), sk(22)];
        let inputs: Vec<InputKey> = keys
            .iter()
            .map(|k| InputKey {
                key: *k,
                taproot: false,
            })
            .collect();
        let pubs: Vec<PublicKey> = keys
            .iter()
            .map(|k| PublicKey::from_secret_key(secp, k))
            .collect();
        let outpoints = vec![outpoint(1), outpoint(2)];
        (recipient, scan, inputs, pubs, outpoints)
    }

    #[test]
    fn payer_pays_counterparty_verifies_operator_scans() {
        let secp = Secp256k1::new();
        let (recipient, scan, inputs, pubs, outpoints) = fixture(&secp);
        let fee = Amount::from_sat(1_000);

        let pay = pay_fee(&secp, &inputs, &outpoints, &recipient, &[7u8; 32]).unwrap();
        let lock = [TxOut {
            value: fee,
            script_pubkey: pay.output.clone(),
        }];

        // The counterparty, from public data plus the revealed share and proof, finds the fee.
        assert!(verify_fee(
            &secp, &pubs, &outpoints, &recipient, &pay.share, &pay.proof, &lock, fee
        ));

        // The operator, scanning with its scan key, locates the same output as its own.
        let out_key = XOnlyPublicKey::from_slice(&pay.output.as_bytes()[2..34]).unwrap();
        let found = scan_outputs(
            &secp,
            &scan,
            &recipient.spend,
            &pubs,
            &outpoints,
            &[out_key],
        )
        .unwrap();
        assert_eq!(found, vec![out_key]);
    }

    #[test]
    fn verify_rejects_a_short_missing_or_tampered_fee() {
        let secp = Secp256k1::new();
        let (recipient, _scan, inputs, pubs, outpoints) = fixture(&secp);
        let fee = Amount::from_sat(1_000);
        let pay = pay_fee(&secp, &inputs, &outpoints, &recipient, &[7u8; 32]).unwrap();
        let lock = [TxOut {
            value: fee,
            script_pubkey: pay.output.clone(),
        }];

        let v = |s: &[u8; 33], p: &[u8; 64], out: &[TxOut], req: Amount| {
            verify_fee(&secp, &pubs, &outpoints, &recipient, s, p, out, req)
        };
        // Requiring more than was paid, or an empty lock, fails.
        assert!(!v(&pay.share, &pay.proof, &lock, Amount::from_sat(1_001)));
        assert!(!v(&pay.share, &pay.proof, &[], fee));
        // A tampered share makes the DLEQ fail.
        let mut bad_share = pay.share;
        bad_share[1] ^= 1;
        assert!(!v(&bad_share, &pay.proof, &lock, fee));
        // A tampered proof fails.
        let mut bad_proof = pay.proof;
        bad_proof[0] ^= 1;
        assert!(!v(&pay.share, &bad_proof, &lock, fee));
        // A fee output to a different address is not found.
        let other = SilentPaymentAddress {
            scan: PublicKey::from_secret_key(&secp, &sk(31)),
            spend: PublicKey::from_secret_key(&secp, &sk(32)),
            testnet: false,
        };
        let elsewhere = pay_fee(&secp, &inputs, &outpoints, &other, &[7u8; 32]).unwrap();
        let wrong = [TxOut {
            value: fee,
            script_pubkey: elsewhere.output,
        }];
        assert!(!v(&pay.share, &pay.proof, &wrong, fee));
    }
}
