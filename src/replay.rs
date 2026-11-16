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

/// The funding view's prediction of the runtime guard (design 0001, #312): each funding UTXO
/// classified by the SAME predicate `check_inputs` uses, so the view and the backstop can never
/// disagree. An outpoint still unspent on the OTHER chain is replayable; one already spent there is
/// safe. Fails closed like the guard: a lookup error marks the survey `unverified` and the coin is
/// counted as NEITHER safe nor replayable, so `safe_sat` never over-counts (the caller treats
/// unverified as not-safe).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReplaySurvey {
    /// The replayable funding UTXOs (outpoint + value in sats), i.e. still unspent on the other chain.
    pub replayable: Vec<(OutPoint, u64)>,
    pub replayable_sat: u64,
    /// Sum of UTXOs proven spent on the other chain (safe to fund a lock from).
    pub safe_sat: u64,
    /// True if any lookup errored; those coins are in neither total, so `safe_sat` stays conservative.
    pub unverified: bool,
}

/// Survey funding UTXOs for cross-chain replay risk against `other_chain`, using the guard's own
/// `is_unspent` predicate. `utxos` is `(outpoint, value_sat)`.
pub fn survey_replay<L: UtxoLookup>(utxos: &[(OutPoint, u64)], other_chain: &L) -> ReplaySurvey {
    let mut s = ReplaySurvey::default();
    for (outpoint, value) in utxos {
        match other_chain.is_unspent(outpoint) {
            Ok(true) => {
                s.replayable.push((*outpoint, *value));
                s.replayable_sat += value;
            }
            Ok(false) => s.safe_sat += value,
            // Fail closed and stop: once a lookup errors the survey is already `unverified` (the caller
            // treats that as not-safe), so there is nothing to gain from more lookups, and a node that
            // hangs rather than refuses would otherwise cost one timeout per remaining UTXO.
            Err(_) => {
                s.unverified = true;
                break;
            }
        }
    }
    s
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

    #[test]
    fn survey_splits_replayable_from_safe_by_the_guards_predicate() {
        // outpoint(2) is still unspent on the other chain (replayable); outpoint(1) is not (safe).
        let other = Stub(HashSet::from([outpoint(2)]));
        let s = survey_replay(&[(outpoint(1), 1000), (outpoint(2), 2500)], &other);
        assert_eq!(s.replayable, vec![(outpoint(2), 2500)]);
        assert_eq!(s.replayable_sat, 2500);
        assert_eq!(s.safe_sat, 1000);
        assert!(!s.unverified);
    }

    #[test]
    fn survey_fails_closed_marking_unverified_and_never_counting_safe() {
        // A lookup error must not let a coin be counted as safe; it is unverified, in neither total.
        let s = survey_replay(&[(outpoint(1), 1000), (outpoint(2), 2500)], &Unreachable);
        assert!(s.unverified);
        assert_eq!(s.safe_sat, 0);
        assert_eq!(s.replayable_sat, 0);
        assert!(s.replayable.is_empty());
    }

    #[test]
    fn survey_of_coins_unique_to_this_chain_is_all_safe() {
        let other = Stub(HashSet::from([outpoint(9)]));
        let s = survey_replay(&[(outpoint(1), 500), (outpoint(2), 700)], &other);
        assert_eq!(s.safe_sat, 1200);
        assert_eq!(s.replayable_sat, 0);
        assert!(!s.unverified);
    }
}
