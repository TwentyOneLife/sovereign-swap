//! Refuse to sign a transaction whose inputs also exist, unspent, on the other chain.
//!
//! Legacy signatures are valid on both BTC and xBTC, so such a transaction would be valid on both
//! and could be replayed. See `docs/design/0001-htlc-and-replay-guard.md`.

use bitcoin::{OutPoint, Transaction};

pub trait UtxoLookup {
    type Error;

    /// Whether the outpoint exists unspent on this chain, mempool included.
    fn is_unspent(&self, outpoint: &OutPoint) -> Result<bool, Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError<E> {
    Lookup(E),
    SpendableOnOtherChain(OutPoint),
}

pub fn check_inputs<L: UtxoLookup>(
    tx: &Transaction,
    other_chain: &L,
) -> Result<(), ReplayError<L::Error>> {
    for input in &tx.input {
        if other_chain
            .is_unspent(&input.previous_output)
            .map_err(ReplayError::Lookup)?
        {
            return Err(ReplayError::SpendableOnOtherChain(input.previous_output));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{absolute, ScriptBuf, Sequence, TxIn, Txid, Witness};
    use std::collections::HashSet;

    struct Stub(HashSet<OutPoint>);

    impl UtxoLookup for Stub {
        type Error = ();
        fn is_unspent(&self, outpoint: &OutPoint) -> Result<bool, ()> {
            Ok(self.0.contains(outpoint))
        }
    }

    struct Unreachable;

    impl UtxoLookup for Unreachable {
        type Error = &'static str;
        fn is_unspent(&self, _: &OutPoint) -> Result<bool, &'static str> {
            Err("node unreachable")
        }
    }

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: u32::from(n),
        }
    }

    fn spending(outpoints: &[OutPoint]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: outpoints
                .iter()
                .map(|o| TxIn {
                    previous_output: *o,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![],
        }
    }

    #[test]
    fn replay_guard_passes_inputs_unique_to_this_chain() {
        let other = Stub(HashSet::from([outpoint(9)]));
        assert_eq!(
            check_inputs(&spending(&[outpoint(1), outpoint(2)]), &other),
            Ok(())
        );
    }

    #[test]
    fn replay_guard_refuses_an_input_spendable_on_the_other_chain() {
        let other = Stub(HashSet::from([outpoint(2)]));
        assert_eq!(
            check_inputs(&spending(&[outpoint(1), outpoint(2)]), &other),
            Err(ReplayError::SpendableOnOtherChain(outpoint(2)))
        );
    }

    #[test]
    fn replay_guard_fails_closed_when_the_other_chain_cannot_be_asked() {
        assert_eq!(
            check_inputs(&spending(&[outpoint(1)]), &Unreachable),
            Err(ReplayError::Lookup("node unreachable"))
        );
    }
}
