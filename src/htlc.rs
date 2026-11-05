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

#[derive(Clone, Debug, PartialEq, Eq)]
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
        if sha256::Hash::hash(preimage).to_byte_array() != self.secret_hash {
            return Err(SpendError::WrongPreimage);
        }
        self.sign(
            secp,
            spend,
            key,
            &self.claim_pkh,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            |sig, pk| vec![sig, pk, preimage.to_vec(), vec![1]],
        )
    }

    pub fn refund<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        spend: &Spend,
        key: &SecretKey,
    ) -> Result<Transaction, SpendError> {
        let sequence = Sequence::from_height(self.lock_blocks);
        self.sign(secp, spend, key, &self.refund_pkh, sequence, |sig, pk| {
            vec![sig, pk, vec![]]
        })
    }

    fn sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        spend: &Spend,
        key: &SecretKey,
        expected_pkh: &PubkeyHash,
        sequence: Sequence,
        witness_items: impl FnOnce(Vec<u8>, Vec<u8>) -> Vec<Vec<u8>>,
    ) -> Result<Transaction, SpendError> {
        let pubkey = PublicKey::new(key.public_key(secp));
        if pubkey.pubkey_hash() != *expected_pkh {
            return Err(SpendError::WrongKey);
        }
        let mut tx = unsigned_spend(spend, sequence)?;
        let digest = self.sighash(&tx, 0, spend.value);
        let sig = ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(digest.to_byte_array()), key),
            sighash_type: EcdsaSighashType::All,
        };
        let mut items = witness_items(sig.to_vec(), pubkey.to_bytes());
        items.push(self.script().into_bytes());
        tx.input[0].witness = Witness::from_slice(&items);
        Ok(tx)
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
