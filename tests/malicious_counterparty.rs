//! Malicious-counterparty harness.
//!
//! A swap peer is untrusted: it can break the protocol in ways a fuzzer (byte-level, see `fuzz/` and
//! `fuzz_parsers.rs`) does not reach, by sending well-formed messages in a hostile *order*, *count*,
//! or *content*. This file gives the reusable primitive for that: a `Tamper` transport that wraps a
//! real transport and rewrites what the peer sends, so a test can put an honest engine against a peer
//! that duplicates, drops, reorders, or substitutes messages and assert the honest side stays safe
//! (never panics, never builds a swap from nothing, always keeps its funds recoverable).
//!
//! Enhance during live real-funds testing: add a strategy for each new attack (below), and drive it
//! against the two-party regtest harness in `tests/swap.rs` by giving one party a `Tamper` wrapping
//! its `Memory` instead of the bare `Memory`. The honest party is the one under test.
//!
//! Attack ideas to add: lock-and-vanish (drop everything after the lock), replay an old `Accept`,
//! send an `Accept` with a mismatched `secret_hash`, flood `FeeProof` for unknown swaps, send a `Bid`
//! for an offer that was never made, race two `Accept`s for one swap.

use std::sync::Arc;

use sovereign_swap::swap::Message;
use sovereign_swap::transport::{memory_pair, Memory, Transport};

/// What the peer actually puts on the wire for one message it tries to send.
type Rewrite = Arc<dyn Fn(&Message) -> Vec<Message> + Send + Sync>;

/// A transport that applies `rewrite` to every message the peer tries to send. `rewrite` returns the
/// messages actually put on the wire: `[m]` is honest, `[]` drops, `[m, m]` duplicates, `[other]`
/// substitutes, `[a, b]` injects. Receiving is untouched. Clonable (the engine clones its transport).
#[derive(Clone)]
pub struct Tamper {
    inner: Memory,
    rewrite: Rewrite,
}

impl Tamper {
    pub fn new(
        inner: Memory,
        rewrite: impl Fn(&Message) -> Vec<Message> + Send + Sync + 'static,
    ) -> Tamper {
        Tamper {
            inner,
            rewrite: Arc::new(rewrite),
        }
    }

    /// Send each message twice (replay / duplicate attack).
    pub fn duplicate(inner: Memory) -> Tamper {
        Tamper::new(inner, |m| vec![m.clone(), m.clone()])
    }

    /// Drop every outgoing message (a peer that goes silent mid-swap; the honest side must refund).
    pub fn silent(inner: Memory) -> Tamper {
        Tamper::new(inner, |_| Vec::new())
    }

    /// Drop messages for which `pred` is true, pass the rest (selective griefing).
    pub fn drop_if(
        inner: Memory,
        pred: impl Fn(&Message) -> bool + Send + Sync + 'static,
    ) -> Tamper {
        Tamper::new(
            inner,
            move |m| {
                if pred(m) {
                    Vec::new()
                } else {
                    vec![m.clone()]
                }
            },
        )
    }
}

impl Transport for Tamper {
    fn send(&self, message: &Message) {
        for m in (self.rewrite)(message) {
            self.inner.send(&m);
        }
    }

    fn receive(&self) -> Vec<Message> {
        self.inner.receive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::PubkeyHash;

    fn a_message() -> Message {
        Message::Accept {
            swap_id: [1u8; 16],
            secret_hash: [2u8; 32],
            maker_claim_pkh: PubkeyHash::from_byte_array([3u8; 20]),
            maker_refund_pkh: PubkeyHash::from_byte_array([4u8; 20]),
        }
    }

    #[test]
    fn duplicate_puts_two_on_the_wire() {
        let (attacker, honest) = memory_pair();
        let attacker = Tamper::duplicate(attacker);
        attacker.send(&a_message());
        assert_eq!(
            honest.receive().len(),
            2,
            "duplicate attack should send twice"
        );
    }

    #[test]
    fn silent_drops_everything() {
        let (attacker, honest) = memory_pair();
        let attacker = Tamper::silent(attacker);
        attacker.send(&a_message());
        assert!(
            honest.receive().is_empty(),
            "silent attack should send nothing"
        );
    }

    #[test]
    fn drop_if_is_selective() {
        let (attacker, honest) = memory_pair();
        // Drop Accepts, keep the rest: a peer that will not commit.
        let attacker = Tamper::drop_if(attacker, |m| matches!(m, Message::Accept { .. }));
        attacker.send(&a_message());
        assert!(
            honest.receive().is_empty(),
            "the Accept should have been dropped"
        );
    }
}
