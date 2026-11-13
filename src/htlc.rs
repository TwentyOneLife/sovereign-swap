//! Secret-hash contract in a P2WSH output, see `docs/design/0001-htlc-and-replay-guard.md`.

use bitcoin::blockdata::opcodes::all::{
    OP_CHECKSIG, OP_CSV, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_HASH160, OP_IF,
    OP_SHA256, OP_SIZE,
};
use bitcoin::blockdata::script::{read_scriptint, Builder, Instruction, PushBytes};
use bitcoin::ecdsa;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, Signing};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, Amount, OutPoint, PubkeyHash, PublicKey, Script, ScriptBuf, SegwitV0Sighash,
    Sequence, Transaction, TxIn, TxOut, Witness,
};

pub const PREIMAGE_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Contract {
    pub secret_hash: [u8; 32],
    pub claim_pkh: PubkeyHash,
    pub refund_pkh: PubkeyHash,
    /// Relative lock in blocks of the chain the contract is on.
    pub lock_blocks: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ContractMismatch {
    NotTemplate,
    SecretHash,
    ClaimKey,
    RefundKey,
    LockBlocks,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LockError {
    NoOutputToContract,
    WrongAmount { expected: Amount, found: Amount },
}

#[derive(Debug, PartialEq, Eq)]
pub enum SpendError {
    FeeExceedsValue,
    OutputBelowDust,
    WrongPreimage,
    WrongKey,
}

/// What a claim or refund spends and where it pays.
#[derive(Clone, Debug)]
pub struct Spend {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub destination: ScriptBuf,
    pub fee: Amount,
}

fn push(bytes: &[u8]) -> &PushBytes {
    <&PushBytes>::try_from(bytes).expect("contract pushes are at most 32 bytes")
}

impl Contract {
    pub fn script(&self) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_IF)
            .push_opcode(OP_SIZE)
            .push_int(PREIMAGE_LEN as i64)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(push(&self.secret_hash))
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(push(self.claim_pkh.as_byte_array()))
            .push_opcode(OP_ELSE)
            .push_int(i64::from(self.lock_blocks))
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(push(self.refund_pkh.as_byte_array()))
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2wsh(&self.script().wscript_hash())
    }

    /// Reads a script that must be exactly the template, byte for byte, as `script()` builds it.
    pub fn from_script(script: &Script) -> Result<Contract, ContractMismatch> {
        let ins: Vec<Instruction> = script
            .instructions()
            .collect::<Result<_, _>>()
            .map_err(|_| ContractMismatch::NotTemplate)?;
        if ins.len() != 20 {
            return Err(ContractMismatch::NotTemplate);
        }
        let bytes = |i: usize, len: usize| match ins[i] {
            Instruction::PushBytes(b) if b.len() == len => Ok(b.as_bytes()),
            _ => Err(ContractMismatch::NotTemplate),
        };
        let lock = match ins[11] {
            Instruction::PushBytes(b) => read_scriptint(b.as_bytes()).ok(),
            Instruction::Op(op) => {
                let n = i64::from(op.to_u8()) - 0x50;
                (1..=16).contains(&n).then_some(n)
            }
        }
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or(ContractMismatch::NotTemplate)?;
        let contract = Contract {
            secret_hash: bytes(5, 32)?.try_into().expect("length checked"),
            claim_pkh: PubkeyHash::from_byte_array(
                bytes(9, 20)?.try_into().expect("length checked"),
            ),
            refund_pkh: PubkeyHash::from_byte_array(
                bytes(16, 20)?.try_into().expect("length checked"),
            ),
            lock_blocks: lock,
        };
        // Rebuilding and comparing rejects every other opcode and any non-minimal push.
        if contract.script() != *script {
            return Err(ContractMismatch::NotTemplate);
        }
        Ok(contract)
    }

    /// Checks a script received from the counterparty against the contract we expect.
    pub fn check_script(&self, received: &Script) -> Result<(), ContractMismatch> {
        let got = Contract::from_script(received)?;
        if got.secret_hash != self.secret_hash {
            return Err(ContractMismatch::SecretHash);
        }
        if got.claim_pkh != self.claim_pkh {
            return Err(ContractMismatch::ClaimKey);
        }
        if got.refund_pkh != self.refund_pkh {
            return Err(ContractMismatch::RefundKey);
        }
        if got.lock_blocks != self.lock_blocks {
            return Err(ContractMismatch::LockBlocks);
        }
        Ok(())
    }

    /// Returns the index of the output that locks exactly `amount` in this contract.
    pub fn find_lock_output(&self, tx: &Transaction, amount: Amount) -> Result<u32, LockError> {
        let spk = self.script_pubkey();
        let mut found = None;
        for (i, out) in tx.output.iter().enumerate() {
            if out.script_pubkey != spk {
                continue;
            }
            if out.value == amount {
                return Ok(i as u32);
            }
            found.get_or_insert(out.value);
        }
        match found {
            Some(found) => Err(LockError::WrongAmount {
                expected: amount,
                found,
            }),
            None => Err(LockError::NoOutputToContract),
        }
    }

    pub fn sighash(&self, tx: &Transaction, input: usize, value: Amount) -> SegwitV0Sighash {
        SighashCache::new(tx)
            .p2wsh_signature_hash(input, &self.script(), value, EcdsaSighashType::All)
            .expect("input index is within the transaction")
    }

    pub fn claim<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        spend: &Spend,
        key: &SecretKey,
        preimage: &[u8; PREIMAGE_LEN],
    ) -> Result<Transaction, SpendError> {
        self.claim_unsigned(spend)?
            .sign_with(secp, key, Some(*preimage))
    }

    /// Build the claim spend WITHOUT signing it, and WITHOUT the preimage (0027): the unsigned tx plus
    /// the sighash a signer signs with the claim key. The preimage is supplied later to
    /// [`UnsignedSpend::finalize`] (by the engine for a local claim, by the user for a user-held one),
    /// so a built claim carries only the `secret_hash` and never the secret. The local-key
    /// [`claim`](Self::claim) is this followed by `sign_with` with the preimage.
    pub fn claim_unsigned(&self, spend: &Spend) -> Result<UnsignedSpend, SpendError> {
        self.build_unsigned(
            spend,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            self.claim_pkh,
            WitnessKind::Claim {
                secret_hash: self.secret_hash,
            },
        )
    }

    pub fn refund<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        spend: &Spend,
        key: &SecretKey,
    ) -> Result<Transaction, SpendError> {
        self.refund_unsigned(spend)?.sign_with(secp, key, None)
    }

    /// Build the refund spend WITHOUT signing it (0027); see [`claim_unsigned`](Self::claim_unsigned).
    pub fn refund_unsigned(&self, spend: &Spend) -> Result<UnsignedSpend, SpendError> {
        self.build_unsigned(
            spend,
            Sequence::from_height(self.lock_blocks),
            self.refund_pkh,
            WitnessKind::Refund,
        )
    }

    fn build_unsigned(
        &self,
        spend: &Spend,
        sequence: Sequence,
        expected_pubkey_hash: PubkeyHash,
        witness: WitnessKind,
    ) -> Result<UnsignedSpend, SpendError> {
        let tx = unsigned_spend(spend, sequence)?;
        let sighash = self.sighash(&tx, 0, spend.value).to_byte_array();
        Ok(UnsignedSpend {
            tx,
            sighash,
            expected_pubkey_hash,
            witness,
            script: self.script(),
        })
    }

    /// A claim spend with a DUMMY witness of the real signed size, for fee estimation only (0027
    /// user-held spends, which cannot sign to measure vsize). NOT valid to broadcast; feed it to
    /// `rate_spend` to fee the eventual user-signed claim by its real vsize.
    pub fn claim_probe(&self, spend: &Spend) -> Result<Transaction, SpendError> {
        self.probe(spend, Sequence::ENABLE_RBF_NO_LOCKTIME, true)
    }

    /// A refund spend with a dummy witness of the real signed size, for fee estimation (see
    /// [`claim_probe`](Self::claim_probe)).
    pub fn refund_probe(&self, spend: &Spend) -> Result<Transaction, SpendError> {
        self.probe(spend, Sequence::from_height(self.lock_blocks), false)
    }

    fn probe(
        &self,
        spend: &Spend,
        sequence: Sequence,
        claim: bool,
    ) -> Result<Transaction, SpendError> {
        let mut tx = unsigned_spend(spend, sequence)?;
        // Dummy items at the maximum real sizes: a 72-byte DER signature + the sighash-type byte (73),
        // a 33-byte compressed pubkey, and for a claim the 32-byte preimage + the 1-byte branch
        // selector. The script is real. A real signature is no larger, so the fee never underpays;
        // `rate_spend` adds a further +1 vB for signature-length variance.
        let mut items = vec![vec![0u8; 73], vec![0u8; 33]];
        if claim {
            items.push(vec![0u8; 32]);
            items.push(vec![1u8]);
        } else {
            items.push(Vec::new());
        }
        items.push(self.script().into_bytes());
        tx.input[0].witness = Witness::from_slice(&items);
        Ok(tx)
    }
}

/// The non-signature half of a claim/refund witness: a claim pushes the preimage and the branch
/// selector `OP_1`; a refund pushes the empty selector. Carried by [`UnsignedSpend`]. A claim holds only
/// the `secret_hash`, not the preimage: the preimage is supplied to `finalize` (by the engine for a
/// local claim, by the user for a user-held one, 0027), and `finalize` checks it against this hash. So a
/// built claim never carries the secret, which is what lets the secret stay with the user.
enum WitnessKind {
    Claim { secret_hash: [u8; 32] },
    Refund,
}

/// An HTLC claim or refund that is built but not yet signed (0027): the unsigned transaction and the
/// sighash an external signer signs with the claim/refund key. The engine builds this and either signs
/// locally ([`sign_with`](Self::sign_with), today's path) or hands the digest to a user-held signer and
/// assembles the result with [`finalize`](Self::finalize). The spend is a single P2WSH input, so a
/// generic PSBT wallet cannot finalize it; the signer only produces a signature over `sighash`, and the
/// witness is assembled here.
pub struct UnsignedSpend {
    pub tx: Transaction,
    /// The SegWit v0 SIGHASH_ALL digest over input 0, the bytes to sign with the claim/refund key.
    pub sighash: [u8; 32],
    /// The signer's key must hash to this; `sign_with`/`finalize` refuse any other key, so a wrong key
    /// can never assemble a spendable transaction.
    pub expected_pubkey_hash: PubkeyHash,
    witness: WitnessKind,
    script: ScriptBuf,
}

impl UnsignedSpend {
    /// Sign locally with `key` (today's engine path): sign `sighash` and assemble the witness. For a
    /// claim, `preimage` is the secret (the engine provides it locally); for a refund it is `None`.
    pub fn sign_with<C: Signing>(
        self,
        secp: &Secp256k1<C>,
        key: &SecretKey,
        preimage: Option<[u8; PREIMAGE_LEN]>,
    ) -> Result<Transaction, SpendError> {
        let pubkey = PublicKey::new(key.public_key(secp));
        if pubkey.pubkey_hash() != self.expected_pubkey_hash {
            return Err(SpendError::WrongKey);
        }
        let sig = secp.sign_ecdsa(&Message::from_digest(self.sighash), key);
        self.finalize(sig, pubkey, preimage)
    }

    /// Assemble the broadcastable transaction from a signature over `sighash` by `pubkey`, plus the
    /// `preimage` for a claim (0027, the user-held path). Refuses a `pubkey` that does not hash to
    /// `expected_pubkey_hash`, and a claim whose `preimage` is missing or does not hash to the
    /// contract's `secret_hash` - so a wrong key or a wrong/absent secret can never assemble a spendable
    /// transaction. A refund ignores `preimage`.
    pub fn finalize(
        mut self,
        sig: bitcoin::secp256k1::ecdsa::Signature,
        pubkey: PublicKey,
        preimage: Option<[u8; PREIMAGE_LEN]>,
    ) -> Result<Transaction, SpendError> {
        if pubkey.pubkey_hash() != self.expected_pubkey_hash {
            return Err(SpendError::WrongKey);
        }
        let sig = ecdsa::Signature {
            signature: sig,
            sighash_type: EcdsaSighashType::All,
        };
        let mut items = match &self.witness {
            WitnessKind::Claim { secret_hash } => {
                let preimage = preimage.ok_or(SpendError::WrongPreimage)?;
                if sha256::Hash::hash(&preimage).to_byte_array() != *secret_hash {
                    return Err(SpendError::WrongPreimage);
                }
                vec![sig.to_vec(), pubkey.to_bytes(), preimage.to_vec(), vec![1]]
            }
            WitnessKind::Refund => vec![sig.to_vec(), pubkey.to_bytes(), vec![]],
        };
        items.push(self.script.into_bytes());
        self.tx.input[0].witness = Witness::from_slice(&items);
        Ok(self.tx)
    }
}

/// Fee a claim or refund by its real vbytes (F6). `build` signs the spend for a given fee; we build
/// once at the current lower bound to learn the exact vsize, then settle the fee. The vsize is taken
/// +1 vB because the rebuild's signature may sign one byte longer (the sighash commits to the output
/// value, so `r`/`s` length can differ), so a spend aimed at a rate never lands a hair under it.
///
/// `prior` is the fee of a transaction already in the mempool for this spend (`None` on the first
/// spend). The returned fee is:
/// - first spend (`prior` is `None`): `max(floor, rate * vsize)`;
/// - a rebuild (`prior` is `Some(p)`): the new rate `rate * vsize` **only when it clears the BIP125
///   increment** `p + incremental_relay_feerate * vsize` (1 sat/vB), otherwise exactly `p`. So a
///   rebuild is either an identical, already-accepted transaction (a no-op rebroadcast) or a valid
///   fee-bump replacement - never a replacement the node rejects for an insufficient fee.
///
/// Returns the signed spend and the fee it pays. Propagates `OutputBelowDust` when the leg is too
/// small to pay the fee, exactly as a plain spend would.
pub fn spend_at_rate(
    build: impl Fn(Amount) -> Result<Transaction, SpendError>,
    rate_sat_vb: u64,
    floor: Amount,
    prior: Option<Amount>,
) -> Result<(Transaction, Amount), SpendError> {
    let lower = prior.unwrap_or(floor).max(floor);
    let probe = build(lower)?;
    let vsize = probe.vsize() as u64 + 1;
    let raw = vsize.saturating_mul(rate_sat_vb);
    let fee = match prior {
        None => Amount::from_sat(raw.max(floor.to_sat())),
        Some(p) => {
            let p = p.to_sat();
            // Bump to the new rate only if it clears p + 1 sat/vB * vsize (BIP125), else reuse p.
            if raw >= p + vsize {
                Amount::from_sat(raw)
            } else {
                Amount::from_sat(p)
            }
        }
    };
    if fee == lower {
        Ok((probe, fee))
    } else {
        Ok((build(fee)?, fee))
    }
}

/// A one-input, one-output version 2 transaction spending the contract, without witness.
pub fn unsigned_spend(spend: &Spend, sequence: Sequence) -> Result<Transaction, SpendError> {
    let value = spend
        .value
        .checked_sub(spend.fee)
        .ok_or(SpendError::FeeExceedsValue)?;
    if value < spend.destination.minimal_non_dust() {
        return Err(SpendError::OutputBelowDust);
    }
    Ok(Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: spend.outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: spend.destination.clone(),
        }],
    })
}

/// Finds the secret in a transaction that claimed this contract.
pub fn extract_preimage(tx: &Transaction, contract: &Contract) -> Option<[u8; PREIMAGE_LEN]> {
    let script = contract.script();
    tx.input.iter().find_map(|input| {
        let w = &input.witness;
        if w.len() != 5 || w.nth(4)? != script.as_bytes() || w.nth(3)? != [1u8].as_slice() {
            return None;
        }
        let preimage: [u8; PREIMAGE_LEN] = w.nth(2)?.try_into().ok()?;
        (sha256::Hash::hash(&preimage).to_byte_array() == contract.secret_hash).then_some(preimage)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::FromHex;
    use bitcoin::Txid;

    fn contract() -> Contract {
        Contract {
            secret_hash: sha256::Hash::hash(&[1u8; 32]).to_byte_array(),
            claim_pkh: PubkeyHash::from_byte_array([0x11; 20]),
            refund_pkh: PubkeyHash::from_byte_array([0x22; 20]),
            lock_blocks: 144,
        }
    }

    // Bytes laid out as BasicSwap's `atomic_swap_1.buildContractScript` builds them.
    const BASICSWAP_VECTOR: &str =
        "6382012088a82072cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9\
        d521f0153637938876a914111111111111111111111111111111111111111167029000b27576a9142222222222\
        2222222222222222222222222222226888ac";

    #[test]
    fn script_matches_basicswap_layout() {
        let expected = Vec::<u8>::from_hex(&BASICSWAP_VECTOR.replace(' ', "")).unwrap();
        assert_eq!(contract().script().as_bytes(), expected.as_slice());
    }

    #[test]
    fn script_round_trips() {
        for lock_blocks in [1, 16, 17, 127, 128, 144, 288, u16::MAX] {
            let c = Contract {
                lock_blocks,
                ..contract()
            };
            assert_eq!(Contract::from_script(&c.script()), Ok(c));
        }
    }

    #[test]
    fn check_script_names_the_wrong_field() {
        let c = contract();
        let other = |f: fn(&mut Contract)| {
            let mut x = contract();
            f(&mut x);
            x.script()
        };
        assert_eq!(c.check_script(&c.script()), Ok(()));
        assert_eq!(
            c.check_script(&other(|x| x.secret_hash[0] ^= 1)),
            Err(ContractMismatch::SecretHash)
        );
        assert_eq!(
            c.check_script(&other(
                |x| x.claim_pkh = PubkeyHash::from_byte_array([0x33; 20])
            )),
            Err(ContractMismatch::ClaimKey)
        );
        assert_eq!(
            c.check_script(&other(
                |x| x.refund_pkh = PubkeyHash::from_byte_array([0x33; 20])
            )),
            Err(ContractMismatch::RefundKey)
        );
        assert_eq!(
            c.check_script(&other(|x| x.lock_blocks = 143)),
            Err(ContractMismatch::LockBlocks)
        );
    }

    #[test]
    fn from_script_rejects_anything_but_the_template() {
        let good = contract().script().into_bytes();
        // Preimage size 33 instead of 32.
        let mut size = good.clone();
        size[3] = 33;
        assert_eq!(
            Contract::from_script(Script::from_bytes(&size)),
            Err(ContractMismatch::NotTemplate)
        );
        // OP_SHA256 replaced by OP_HASH256.
        let mut hash_op = good.clone();
        hash_op[5] = 0xaa;
        assert_eq!(
            Contract::from_script(Script::from_bytes(&hash_op)),
            Err(ContractMismatch::NotTemplate)
        );
        // Trailing opcode.
        let mut longer = good.clone();
        longer.push(0x75);
        assert_eq!(
            Contract::from_script(Script::from_bytes(&longer)),
            Err(ContractMismatch::NotTemplate)
        );
        // Lock value 144 pushed non-minimally as three bytes.
        let (before_lock, after_lock) = (&good[..64], &good[67..]);
        let mut non_minimal = before_lock.to_vec();
        non_minimal.extend_from_slice(&[0x03, 0x90, 0x00, 0x00]);
        non_minimal.extend_from_slice(after_lock);
        assert_eq!(
            Contract::from_script(Script::from_bytes(&non_minimal)),
            Err(ContractMismatch::NotTemplate)
        );
        // Zero and negative locks.
        for lock in [0i64, -1] {
            let mut b = Builder::from(before_lock.to_vec())
                .push_int(lock)
                .into_script()
                .into_bytes();
            b.extend_from_slice(after_lock);
            assert_eq!(
                Contract::from_script(Script::from_bytes(&b)),
                Err(ContractMismatch::NotTemplate)
            );
        }
    }

    fn lock_tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: outputs,
        }
    }

    #[test]
    fn find_lock_output_checks_amount_and_index() {
        let c = contract();
        let to = |value, script_pubkey| TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        };
        let change = ScriptBuf::new_p2wsh(&ScriptBuf::new().wscript_hash());
        let tx = lock_tx(vec![
            to(5_000, change.clone()),
            to(100_000, c.script_pubkey()),
        ]);
        assert_eq!(c.find_lock_output(&tx, Amount::from_sat(100_000)), Ok(1));
        assert_eq!(
            c.find_lock_output(&tx, Amount::from_sat(100_001)),
            Err(LockError::WrongAmount {
                expected: Amount::from_sat(100_001),
                found: Amount::from_sat(100_000)
            })
        );
        let elsewhere = lock_tx(vec![to(100_000, change)]);
        assert_eq!(
            c.find_lock_output(&elsewhere, Amount::from_sat(100_000)),
            Err(LockError::NoOutputToContract)
        );
    }

    fn spend() -> Spend {
        Spend {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            value: Amount::from_sat(100_000),
            destination: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x44; 20])),
            fee: Amount::from_sat(1_000),
        }
    }

    #[test]
    fn claim_and_extract_preimage() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let preimage = [9u8; 32];
        let c = Contract {
            secret_hash: sha256::Hash::hash(&preimage).to_byte_array(),
            claim_pkh: PublicKey::new(key.public_key(&secp)).pubkey_hash(),
            ..contract()
        };
        let tx = c.claim(&secp, &spend(), &key, &preimage).unwrap();
        assert_eq!(extract_preimage(&tx, &c), Some(preimage));
        assert_eq!(tx.output[0].value, Amount::from_sat(99_000));
        assert_eq!(
            c.claim(&secp, &spend(), &key, &[8u8; 32]),
            Err(SpendError::WrongPreimage)
        );
        let other_key = SecretKey::from_slice(&[6u8; 32]).unwrap();
        assert_eq!(
            c.claim(&secp, &spend(), &other_key, &preimage),
            Err(SpendError::WrongKey)
        );
        let refund = c.refund(&secp, &spend(), &key);
        assert_eq!(refund, Err(SpendError::WrongKey));
    }

    #[test]
    fn build_then_finalize_equals_the_local_key_claim_and_refund() {
        // 0027: claim_unsigned/refund_unsigned + finalize must produce the exact transaction the
        // local-key claim/refund does, so moving the signature to a user-held signer changes nothing on
        // chain. (ECDSA signing here is deterministic, so the bytes match.)
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pubkey = PublicKey::new(key.public_key(&secp));
        let preimage = [9u8; 32];
        let c = Contract {
            secret_hash: sha256::Hash::hash(&preimage).to_byte_array(),
            claim_pkh: pubkey.pubkey_hash(),
            refund_pkh: pubkey.pubkey_hash(),
            ..contract()
        };

        let local_claim = c.claim(&secp, &spend(), &key, &preimage).unwrap();
        let unsigned = c.claim_unsigned(&spend()).unwrap();
        let sig = secp.sign_ecdsa(&Message::from_digest(unsigned.sighash), &key);
        assert_eq!(
            unsigned.finalize(sig, pubkey, Some(preimage)).unwrap(),
            local_claim,
            "finalized claim (preimage at finalize) equals the local-key claim"
        );

        let local_refund = c.refund(&secp, &spend(), &key).unwrap();
        let unsigned_r = c.refund_unsigned(&spend()).unwrap();
        let sig_r = secp.sign_ecdsa(&Message::from_digest(unsigned_r.sighash), &key);
        assert_eq!(
            unsigned_r.finalize(sig_r, pubkey, None).unwrap(),
            local_refund,
            "finalized refund equals the local-key refund"
        );

        // finalize refuses a wrong key, so a bad signer cannot assemble a spendable transaction.
        let wrong = SecretKey::from_slice(&[6u8; 32]).unwrap();
        let wrong_pub = PublicKey::new(wrong.public_key(&secp));
        let unsigned2 = c.claim_unsigned(&spend()).unwrap();
        let sig2 = secp.sign_ecdsa(&Message::from_digest(unsigned2.sighash), &wrong);
        assert_eq!(
            unsigned2.finalize(sig2, wrong_pub, Some(preimage)),
            Err(SpendError::WrongKey)
        );
        // finalize refuses a claim with a missing or wrong preimage (0027: the secret is checked at
        // finalize now, not at build).
        let unsigned3 = c.claim_unsigned(&spend()).unwrap();
        let sig3 = secp.sign_ecdsa(&Message::from_digest(unsigned3.sighash), &key);
        assert_eq!(
            unsigned3.finalize(sig3, pubkey, None),
            Err(SpendError::WrongPreimage),
            "a claim with no preimage is refused"
        );
        let unsigned4 = c.claim_unsigned(&spend()).unwrap();
        let sig4 = secp.sign_ecdsa(&Message::from_digest(unsigned4.sighash), &key);
        assert_eq!(
            unsigned4.finalize(sig4, pubkey, Some([0u8; 32])),
            Err(SpendError::WrongPreimage),
            "a claim with the wrong preimage is refused"
        );
    }

    #[test]
    fn the_fee_probe_matches_the_signed_spend_size() {
        // 0027: the dummy-witness probe used to rate a user-held spend's fee must be at least the real
        // signed size (so the fee never underpays) and within ~1 vB of it (so it does not overpay).
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pubkey = PublicKey::new(key.public_key(&secp));
        let preimage = [9u8; 32];
        let c = Contract {
            secret_hash: sha256::Hash::hash(&preimage).to_byte_array(),
            claim_pkh: pubkey.pubkey_hash(),
            refund_pkh: pubkey.pubkey_hash(),
            ..contract()
        };
        let signed_claim = c.claim(&secp, &spend(), &key, &preimage).unwrap();
        let probe_claim = c.claim_probe(&spend()).unwrap();
        assert!(
            probe_claim.vsize() >= signed_claim.vsize(),
            "claim probe {} must not underpay the real claim {}",
            probe_claim.vsize(),
            signed_claim.vsize()
        );
        assert!(probe_claim.vsize() <= signed_claim.vsize() + 1);
        let signed_refund = c.refund(&secp, &spend(), &key).unwrap();
        let probe_refund = c.refund_probe(&spend()).unwrap();
        assert!(probe_refund.vsize() >= signed_refund.vsize());
        assert!(probe_refund.vsize() <= signed_refund.vsize() + 1);
    }

    #[test]
    fn extract_preimage_ignores_refunds_and_foreign_inputs() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let c = Contract {
            refund_pkh: PublicKey::new(key.public_key(&secp)).pubkey_hash(),
            ..contract()
        };
        let refund = c.refund(&secp, &spend(), &key).unwrap();
        assert_eq!(refund.input[0].sequence, Sequence::from_height(144));
        assert_eq!(extract_preimage(&refund, &c), None);
        assert_eq!(extract_preimage(&lock_tx(vec![]), &c), None);
    }

    #[test]
    fn spend_at_rate_fees_by_vbytes_with_a_floor() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let preimage = [9u8; 32];
        let c = Contract {
            secret_hash: sha256::Hash::hash(&preimage).to_byte_array(),
            claim_pkh: PublicKey::new(key.public_key(&secp)).pubkey_hash(),
            ..contract()
        };
        let base = |fee| {
            let s = Spend { fee, ..spend() };
            c.claim(&secp, &s, &key, &preimage)
        };
        // First spend, rate wins: at 50 sat/vB a ~142 vB claim pays well above the 500-sat floor.
        let (tx, fee) = spend_at_rate(base, 50, Amount::from_sat(500), None).unwrap();
        assert!(
            fee > Amount::from_sat(500),
            "the rate, not the floor, should win"
        );
        assert!(
            fee.to_sat() >= 50 * tx.vsize() as u64,
            "fee {fee} must cover 50 sat/vB * vsize {}",
            tx.vsize()
        );
        assert_eq!(
            tx.output[0].value,
            spend().value - fee,
            "output = value - fee"
        );
        // First spend, floor wins: at 1 sat/vB (~143 sat) the 2000-sat floor dominates.
        let (_t, fee2) = spend_at_rate(base, 1, Amount::from_sat(2_000), None).unwrap();
        assert_eq!(fee2, Amount::from_sat(2_000));

        // Rebuild (prior in the mempool): a higher rate that clears the BIP125 increment bumps.
        let prior = Amount::from_sat(2_000);
        let (_t, bumped) = spend_at_rate(base, 50, Amount::from_sat(500), Some(prior)).unwrap();
        assert!(
            bumped > prior,
            "a big rate rise bumps the fee: {bumped} > {prior}"
        );
        // A rate that does NOT clear the increment reuses the exact prior fee (no rejected replace).
        let (_t, same) = spend_at_rate(base, 1, Amount::from_sat(500), Some(prior)).unwrap();
        assert_eq!(same, prior, "a sub-increment rate keeps the prior fee");
    }

    #[test]
    fn spend_refuses_fee_and_dust_errors() {
        let mut s = spend();
        s.fee = Amount::from_sat(100_001);
        assert_eq!(
            unsigned_spend(&s, Sequence::MAX),
            Err(SpendError::FeeExceedsValue)
        );
        s.fee = Amount::from_sat(99_900);
        assert_eq!(
            unsigned_spend(&s, Sequence::MAX),
            Err(SpendError::OutputBelowDust)
        );
    }
}

/// Cross-implementation test vectors for the browser (0027 user-held) signer. The hosted browser must
/// port `Contract::script`, the P2WSH `script_pubkey`, the BIP143 sighash, and ECDSA signing to JS and
/// produce byte-identical results, or a user-held claim/refund it signs will not spend. These vectors
/// are the byte-exact target: this Rust test asserts the engine reproduces every field of the committed
/// `tests/fixtures/htlc_vectors.json`, and the browser test reads the same file. The engine signs the
/// raw sighash (no extra hashing) with RFC6979 + low-S; so must the browser, so the deterministic DER
/// signature is included and must match across the two implementations.
#[cfg(test)]
mod test_vectors {
    use super::*;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hex::DisplayHex;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Txid, WPubkeyHash};
    use serde_json::{json, Value};

    // Fixed, deterministic inputs. Real secret keys (valid scalars) so the committed pubkey hashes are
    // genuine hash160s and the signature + finalized-tx vectors exercise the whole signing path.
    const CLAIM_SK: [u8; 32] = [0x11; 32];
    const REFUND_SK: [u8; 32] = [0x22; 32];
    const PREIMAGE: [u8; PREIMAGE_LEN] = [0x07; PREIMAGE_LEN];
    const PREVOUT_VOUT: u32 = 1;
    const VALUE_SAT: u64 = 100_000;
    const FEE_SAT: u64 = 2_000;
    const DEST_WPKH: [u8; 20] = [0x33; 20];
    // Number-encoding boundaries for the CSV lock value: minimal push (1), the OP_1..OP_16 edge
    // (16/17), the one-byte/two-byte edge (127/128, where 128 needs a sign byte), a realistic value,
    // and the two-byte/three-byte edges (32767/32768) up to the u16 max.
    const LOCK_VECTORS: [u16; 9] = [1, 16, 17, 127, 128, 144, 32767, 32768, 65535];

    // Prevout txid internal bytes 0x00..0x1f: `Txid::from_byte_array` takes the raw (consensus /
    // little-endian) order, which is what the serialized tx carries. Deliberately NOT a palindrome,
    // so the explorer DISPLAY string (`Txid` reverses to big-endian) differs visibly from the raw
    // bytes and the browser port is forced to get the byte order right, the classic JS bug. The
    // fixture records both forms so the relationship is pinned.
    fn prevout_txid_internal() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    fn pkh(sk: &[u8; 32]) -> PubkeyHash {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(sk).unwrap();
        PublicKey::new(key.public_key(&secp)).pubkey_hash()
    }

    fn contract(lock_blocks: u16) -> Contract {
        Contract {
            secret_hash: sha256::Hash::hash(&PREIMAGE).to_byte_array(),
            claim_pkh: pkh(&CLAIM_SK),
            refund_pkh: pkh(&REFUND_SK),
            lock_blocks,
        }
    }

    fn spend() -> Spend {
        Spend {
            outpoint: OutPoint::new(Txid::from_byte_array(prevout_txid_internal()), PREVOUT_VOUT),
            value: Amount::from_sat(VALUE_SAT),
            destination: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(DEST_WPKH)),
            fee: Amount::from_sat(FEE_SAT),
        }
    }

    /// One claim/refund branch: the unsigned tx + sighash the browser must reproduce, then the
    /// deterministic signature and the finalized spendable tx it must match.
    fn branch(
        unsigned: UnsignedSpend,
        signed: Transaction,
        sk: &[u8; 32],
        preimage: Option<[u8; PREIMAGE_LEN]>,
    ) -> Value {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(sk).unwrap();
        // The bare DER signature over the sighash (no trailing sighash-type byte): what the browser's
        // `sign()` returns. The engine/finalize appends SIGHASH_ALL (0x01).
        let der = secp
            .sign_ecdsa(&Message::from_digest(unsigned.sighash), &key)
            .serialize_der()
            .to_lower_hex_string();
        json!({
            "sequence": unsigned.tx.input[0].sequence.to_consensus_u32(),
            "sighash": unsigned.sighash.to_lower_hex_string(),
            "unsigned_tx_hex": serialize_hex(&unsigned.tx),
            "der_signature": der,
            "pubkey": PublicKey::new(key.public_key(&secp)).to_bytes().to_lower_hex_string(),
            "preimage": preimage.map(|p| p.to_lower_hex_string()),
            "signed_tx_hex": serialize_hex(&signed),
        })
    }

    /// Signatures whose canonical DER encoding exercises each branch of a hand-rolled DER encoder
    /// (what the browser signer uses): an `r` with the high bit set (DER prepends a 0x00 sign byte),
    /// an `r` with a leading zero byte, and an `s` with a leading zero byte (both stripped to minimal
    /// form). Under low-S, `s` never has its high bit set, so that pad case cannot arise and is not
    /// listed. Each case signs sha256(counter) with the claim key and records the counter, the digest,
    /// and the canonical DER the browser must reproduce from the raw (r, s). RFC6979 makes these
    /// deterministic, so a browser with a broken encoder fails on every retry, which is why a vector
    /// per branch matters, not just the two plain spend signatures above.
    fn der_edge_cases() -> Vec<Value> {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&CLAIM_SK).unwrap();
        // A predicate over the signature's (r, s) big-endian halves, one per DER-encoder branch.
        type RsPred = fn(&[u8], &[u8]) -> bool;
        let wanted: [(&str, RsPred); 3] = [
            ("r_high_bit_set", |r, _s| r[0] >= 0x80),
            ("r_leading_zero", |r, _s| r[0] == 0x00),
            ("s_leading_zero", |_r, s| s[0] == 0x00),
        ];
        let mut found = [false; 3];
        let mut out: Vec<Value> = Vec::new();
        for counter in 0u32.. {
            let digest = sha256::Hash::hash(&counter.to_be_bytes()).to_byte_array();
            let sig = secp.sign_ecdsa(&Message::from_digest(digest), &key);
            let compact = sig.serialize_compact();
            let (r, s) = compact.split_at(32);
            for (idx, (case, pred)) in wanted.iter().enumerate() {
                if !found[idx] && pred(r, s) {
                    found[idx] = true;
                    out.push(json!({
                        "case": case,
                        "counter": counter,
                        "digest": digest.to_lower_hex_string(),
                        "der_signature": sig.serialize_der().as_ref().to_lower_hex_string(),
                    }));
                }
            }
            if found.iter().all(|&f| f) {
                break;
            }
        }
        out
    }

    /// Build the full vector set from the engine's own code paths.
    fn build() -> Value {
        let secp = Secp256k1::new();
        let scripts: Vec<Value> = LOCK_VECTORS
            .iter()
            .map(|&lock_blocks| {
                let c = contract(lock_blocks);
                json!({
                    "lock_blocks": lock_blocks,
                    "witness_script_hex": c.script().as_bytes().to_lower_hex_string(),
                    "script_pubkey_hex": c.script_pubkey().as_bytes().to_lower_hex_string(),
                })
            })
            .collect();

        let c = contract(144);
        let s = spend();
        let claim_unsigned = c.claim_unsigned(&s).unwrap();
        let refund_unsigned = c.refund_unsigned(&s).unwrap();
        let claim_signed = c
            .claim(
                &secp,
                &s,
                &SecretKey::from_slice(&CLAIM_SK).unwrap(),
                &PREIMAGE,
            )
            .unwrap();
        let refund_signed = c
            .refund(&secp, &s, &SecretKey::from_slice(&REFUND_SK).unwrap())
            .unwrap();

        json!({
            "_note": "Cross-implementation vectors for the 0027 browser signer. Generated by the \
                sovereign-swap engine; the browser port must reproduce every field byte-for-byte. \
                Regenerate with REGEN_HTLC_VECTORS=1 cargo test test_vectors.",
            "contract": {
                "secret_hash": c.secret_hash.to_lower_hex_string(),
                "preimage": PREIMAGE.to_lower_hex_string(),
                "claim_pkh": c.claim_pkh.to_string(),
                "refund_pkh": c.refund_pkh.to_string(),
                "lock_blocks": c.lock_blocks,
            },
            "spend": {
                "prevout_txid_internal_hex": prevout_txid_internal().to_lower_hex_string(),
                "prevout_txid_display": s.outpoint.txid.to_string(),
                "prevout_vout": PREVOUT_VOUT,
                "value_sat": VALUE_SAT,
                "fee_sat": FEE_SAT,
                "output_value_sat": VALUE_SAT - FEE_SAT,
                "destination_script_pubkey_hex": s.destination.as_bytes().to_lower_hex_string(),
                "tx_version": 2,
                "locktime": 0,
                "sighash_type": "SIGHASH_ALL (0x01)",
            },
            "scripts": scripts,
            "claim": branch(claim_unsigned, claim_signed, &CLAIM_SK, Some(PREIMAGE)),
            "refund": branch(refund_unsigned, refund_signed, &REFUND_SK, None),
            "der_signatures": der_edge_cases(),
        })
    }

    const FIXTURE: &str = include_str!("../tests/fixtures/htlc_vectors.json");

    #[test]
    fn test_vectors_match_the_committed_fixture() {
        let built = build();
        if std::env::var("REGEN_HTLC_VECTORS").is_ok() {
            let mut out = serde_json::to_string_pretty(&built).unwrap();
            out.push('\n');
            std::fs::write("tests/fixtures/htlc_vectors.json", out).unwrap();
            return;
        }
        let committed: Value = serde_json::from_str(FIXTURE)
            .expect("committed htlc_vectors.json parses; regenerate with REGEN_HTLC_VECTORS=1");
        assert_eq!(
            built, committed,
            "engine no longer reproduces the committed HTLC vectors; if this change is intended, \
             regenerate the fixture and update the browser signer to match"
        );
    }
}
