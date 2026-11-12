//! Hostile-input fuzzing of the parsers that read data from a counterparty or the chain, see
//! `docs/design/0003-adversarial-testing.md`. A counterparty controls the bytes of the contract
//! script it sends and of the witnesses it puts on chain, so these functions must never panic,
//! loop forever or accept something that does not round-trip, whatever the input.
//!
//! Deterministic: a seeded xorshift PRNG, so a failure reprints the seed to reproduce it. Raise the
//! iteration counts with SOVSWAP_FUZZ_ITERS for a longer soak.

use bitcoin::blockdata::transaction::Version;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{
    absolute, Amount, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use sovereign_swap::htlc::{extract_preimage, Contract};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*; fixed, so a seed reproduces a run exactly.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        self.next() as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max + 1);
        (0..len).map(|_| self.byte()).collect()
    }
}

fn iters(default: u64) -> u64 {
    std::env::var("SOVSWAP_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn contract(rng: &mut Rng) -> Contract {
    Contract {
        secret_hash: std::array::from_fn(|_| rng.byte()),
        claim_pkh: PubkeyHash::from_byte_array(std::array::from_fn(|_| rng.byte())),
        refund_pkh: PubkeyHash::from_byte_array(std::array::from_fn(|_| rng.byte())),
        lock_blocks: (rng.next() as u16) | 1,
    }
}

/// Builds bytes that are usually close to a real contract script, so the parser's branches are
/// reached, not just rejected at byte 0.
fn scriptish(rng: &mut Rng) -> Vec<u8> {
    let mut bytes = contract(rng).script().into_bytes();
    for _ in 0..rng.below(6) {
        if bytes.is_empty() {
            break;
        }
        match rng.below(4) {
            0 => {
                let at = rng.below(bytes.len());
                bytes[at] = rng.byte();
            }
            1 => {
                let at = rng.below(bytes.len() + 1);
                bytes.insert(at, rng.byte());
            }
            2 => {
                let at = rng.below(bytes.len());
                bytes.remove(at);
            }
            _ => bytes.truncate(rng.below(bytes.len() + 1)),
        }
    }
    bytes
}

#[test]
fn from_script_never_panics_and_only_accepts_round_tripping_scripts() {
    let mut rng = Rng(0x5A17_C01E);
    for i in 0..iters(2_000_000) {
        let bytes = if i % 3 == 0 {
            rng.bytes(140)
        } else {
            scriptish(&mut rng)
        };
        let script = ScriptBuf::from_bytes(bytes.clone());
        // The contract is held to the exact template, so anything it accepts must rebuild byte for
        // byte; otherwise an attacker could craft a lock the engine misreads.
        if let Ok(parsed) = Contract::from_script(&script) {
            assert_eq!(
                parsed.script().into_bytes(),
                bytes,
                "seed 0x5A17C01E iter {i}: accepted a script that does not round-trip"
            );
        }
    }
}

#[test]
fn check_script_never_panics_on_a_hostile_counterparty_script() {
    let mut rng = Rng(0xC0DE_F00D);
    let expected = contract(&mut rng);
    for _ in 0..iters(1_000_000) {
        let script = ScriptBuf::from_bytes(scriptish(&mut rng));
        // Accepting it means it matched the expected contract exactly, so it must round-trip too.
        if expected.check_script(&script).is_ok() {
            assert_eq!(
                ScriptBuf::from_bytes(expected.script().into_bytes()),
                script
            );
        }
    }
}

fn hostile_witness(rng: &mut Rng) -> Witness {
    let items = rng.below(7);
    let mut w = Witness::new();
    for _ in 0..items {
        w.push(rng.bytes(40));
    }
    w
}

#[test]
fn extract_preimage_never_panics_and_only_returns_the_real_secret() {
    let mut rng = Rng(0xBEEF_1234);
    let preimage: [u8; 32] = std::array::from_fn(|_| rng.byte());
    let c = Contract {
        secret_hash: sha256::Hash::hash(&preimage).to_byte_array(),
        ..contract(&mut rng)
    };
    for _ in 0..iters(1_000_000) {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: (0..rng.below(4))
                .map(|_| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::all_zeros(),
                        vout: rng.next() as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(rng.next() as u32),
                    witness: hostile_witness(&mut rng),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(rng.next() % 1_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        if let Some(found) = extract_preimage(&tx, &c) {
            assert_eq!(
                found, preimage,
                "extract_preimage returned a value whose hash is not the secret"
            );
        }
    }
}

mod envelope_fuzz {
    use super::{iters, Rng};
    use sovereign_swap::envelope::{open, read_broadcast_payload, verify_broadcast, Identity};

    #[test]
    fn read_broadcast_payload_never_panics_on_random_bytes() {
        let mut rng = Rng(0x0DE1_2345);
        for _ in 0..iters(200_000) {
            // Lengths spanning below and above the header + the two fixed-size signature fields.
            let len = rng.below(5200);
            let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            // The relay decodes attacker bytes here WITHOUT verifying, so this must never panic and
            // must only ever return a sub-slice of its input (never fabricate or over-read).
            if let Some(payload) = read_broadcast_payload(&bytes) {
                assert!(payload.len() <= bytes.len());
            }
        }
    }

    #[test]
    fn open_and_verify_never_panic_on_random_bytes() {
        let alice = Identity::from_seed(&[1; 32]);
        let bob = Identity::from_seed(&[2; 32]);
        let mut rng = Rng(0xEE11_2233);
        for _ in 0..iters(200_000) {
            // Lengths around the real header/key sizes so the length checks and slicing are exercised.
            let len = rng.below(3400);
            let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            // Must only ever return Err, never panic, on bytes we did not seal.
            assert!(open(&bob, alice.public(), &bytes).is_err());
            assert!(verify_broadcast(alice.public(), &bytes).is_err());
        }
    }
}

mod nostr_fuzz {
    use super::{iters, Rng};
    use sovereign_swap::nostr::Event;

    #[test]
    fn event_from_json_never_panics_on_random_bytes() {
        let mut rng = Rng(0x4059_1234);
        for _ in 0..iters(300_000) {
            let len = rng.below(400);
            let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            // Must only ever return Err, never panic.
            let _ = Event::from_json(&bytes);
        }
    }
}

/// A hostile maker's fee address reaches `SilentPaymentAddress::parse` (via the engine's fundability
/// and fee-dest checks). It must never panic on arbitrary input, and anything it DOES accept must
/// round-trip through `encode`/`parse`. Iteration count overridable via `SOVSWAP_FUZZ_ITERS`.
#[test]
fn silent_payment_parse_never_panics_and_round_trips() {
    use sovereign_swap::silentpayments::SilentPaymentAddress;
    let mut rng = Rng(0x0A11_CE5E_EDF0_0D11_u64);
    let prefixes = ["sp1", "tsp1", "sprt1", "bc1", "x1", ""];
    let bech = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    for _ in 0..iters(40_000) {
        let raw = rng.bytes(130);
        let _ = SilentPaymentAddress::parse(&String::from_utf8_lossy(&raw));
        let p = prefixes[rng.below(prefixes.len())];
        let body: String = (0..rng.below(120))
            .map(|_| bech[rng.below(bech.len())] as char)
            .collect();
        if let Ok(addr) = SilentPaymentAddress::parse(&format!("{p}{body}")) {
            let enc = addr.encode();
            let enc2 = SilentPaymentAddress::parse(&enc)
                .expect("re-parse of an encoded address")
                .encode();
            assert_eq!(enc, enc2, "silent payment parse/encode must be inverse");
        }
    }
}
