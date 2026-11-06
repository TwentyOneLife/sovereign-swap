//! Property tests of the state machine: whatever a counterparty and the chains do, `Swap::decide`
//! must stay safe. See `docs/design/0003-adversarial-testing.md`.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, PubkeyHash, Txid};

use sovereign_swap::htlc::Contract;
use sovereign_swap::policy::Depths;
use sovereign_swap::swap::{
    Action, Chain, ChainView, FeeState, LockView, Offer, Phase, Role, SpendView, Swap,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
}

fn contract(byte: u8) -> Contract {
    Contract {
        secret_hash: [byte; 32],
        claim_pkh: PubkeyHash::from_byte_array([byte; 20]),
        refund_pkh: PubkeyHash::from_byte_array([byte.wrapping_add(1); 20]),
        lock_blocks: 20,
    }
}

fn swap(role: Role) -> Swap {
    let offer = Offer {
        id: [1; 16],
        maker_chain: Chain::Xbtc,
        maker_amount: Amount::from_sat(1_000_000),
        taker_amount: Amount::from_sat(300_000),
        min_maker_amount: Amount::ZERO,
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 2,
        taker_lock_depth: 2,
        margin_blocks: 3,
        fee: None,
    };
    Swap {
        id: [2; 16],
        role,
        offer,
        key_index: 0,
        maker_part: Amount::from_sat(1_000_000),
        taker_part: Amount::from_sat(300_000),
        maker_contract: contract(3),
        taker_contract: contract(5),
        depths: Depths {
            maker_lock: 2,
            taker_lock: 2,
            maker_final: 3,
            taker_final: 3,
        },
        lock_deadline: 50,
        learned_secret: None,
        phase: match role {
            Role::Maker => Phase::Locking,
            Role::Taker => Phase::Waiting,
        },
    }
}

/// A lock that may be unconfirmed, confirmed, or spent, with random but self-consistent fields.
fn random_lock(rng: &mut Rng, n: u8, height: u32) -> Option<LockView> {
    if rng.chance(4) {
        return None;
    }
    let confirmed_height = if rng.chance(3) {
        None
    } else {
        Some(height.saturating_sub(rng.below(50) as u32))
    };
    let spend = if confirmed_height.is_some() && rng.chance(3) {
        Some(SpendView {
            preimage: if rng.chance(2) { Some([9; 32]) } else { None },
            depth: rng.below(10) as u32,
            ours: rng.chance(2),
        })
    } else {
        None
    };
    Some(LockView {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        },
        value: Amount::from_sat(1_000_000),
        amount_ok: !rng.chance(4),
        confirmed_height,
        spend,
        // Arbitrary fee state too, so the gate is fuzzed for the never-panic / never-both invariant.
        fee: if rng.chance(4) {
            FeeState::Failed
        } else if rng.chance(3) {
            FeeState::Pending
        } else {
            FeeState::Verified
        },
    })
}

const TERMINAL: [Phase; 3] = [Phase::Done, Phase::Refunded, Phase::Abandoned];

/// `decide` must never panic, never both claim and refund the same lock in one call, and never
/// resurrect a swap once it has settled. Arbitrary, even self-inconsistent, chain views.
#[test]
fn decide_is_safe_on_arbitrary_chain_views() {
    for seed in 1..=400u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for role in [Role::Maker, Role::Taker] {
            let mut s = swap(role);
            let mut height = 0u32;
            for _ in 0..200 {
                height += rng.below(3) as u32;
                let view = ChainView {
                    maker_chain_height: height,
                    taker_chain_height: height.saturating_sub(rng.below(2) as u32),
                    maker_lock: random_lock(&mut rng, 10, height),
                    taker_lock: random_lock(&mut rng, 11, height),
                };
                let secret = (role == Role::Maker).then_some([9u8; 32]);
                let before = s.phase;
                let actions = s.decide(&view, secret);

                let claims: Vec<_> = actions
                    .iter()
                    .filter_map(|a| matches!(a, Action::Claim { .. }).then_some(lock_of(a)))
                    .collect();
                let refunds: Vec<_> = actions
                    .iter()
                    .filter_map(|a| matches!(a, Action::Refund { .. }).then_some(lock_of(a)))
                    .collect();
                for c in &claims {
                    assert!(
                        !refunds.contains(c),
                        "seed {seed} {role:?}: claimed and refunded the same lock {c:?}"
                    );
                }
                if TERMINAL.contains(&before) {
                    assert_eq!(
                        s.phase, before,
                        "seed {seed} {role:?}: left terminal phase {before:?}"
                    );
                    assert!(
                        actions.is_empty(),
                        "seed {seed} {role:?}: acted after settling"
                    );
                }
            }
        }
    }
}

fn lock_of(a: &Action) -> OutPoint {
    match a {
        Action::Claim { lock, .. } | Action::Refund { lock, .. } => *lock,
        Action::Fund => OutPoint::null(),
    }
}

/// A small monotonic chain simulator: the engine's own actions land on chain and deepen each block,
/// the counterparty eventually reveals the secret, and the taker must settle and stay settled.
#[derive(Clone, Copy, Default)]
struct SimLock {
    outpoint: OutPoint,
    confirmed: Option<u32>,
    /// (ours, has_secret, depth); set once the lock is spent.
    spend: Option<(bool, bool, u32)>,
}

impl SimLock {
    fn view(&self) -> Option<LockView> {
        let confirmed = self.confirmed?;
        Some(LockView {
            outpoint: self.outpoint,
            value: Amount::from_sat(1_000_000),
            amount_ok: true,
            confirmed_height: Some(confirmed),
            spend: self.spend.map(|(ours, has_secret, depth)| SpendView {
                preimage: has_secret.then_some([9; 32]),
                depth,
                ours,
            }),
            fee: FeeState::NotRequired,
        })
    }
    fn spend_once(&mut self, ours: bool, has_secret: bool) {
        if self.confirmed.is_some() && self.spend.is_none() {
            self.spend = Some((ours, has_secret, 0));
        }
    }
    fn deepen(&mut self) {
        if let Some((_, _, d)) = &mut self.spend {
            *d += 1;
        }
    }
}

#[test]
fn a_monotonic_chain_drives_the_taker_to_a_terminal_phase() {
    for seed in 1..=300u64 {
        let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
        let mut s = swap(Role::Taker);
        let mut maker = SimLock {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([10; 32]),
                vout: 0,
            },
            confirmed: Some(1),
            spend: None,
        };
        let mut taker = SimLock {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([11; 32]),
                vout: 0,
            },
            ..SimLock::default()
        };
        let mut taker_funded_at: Option<u32> = None;
        let reveal_delay = 1 + rng.below(30) as u32;

        let mut terminal_at = None;
        for h in 2..500u32 {
            let view = ChainView {
                maker_chain_height: h,
                taker_chain_height: h,
                maker_lock: maker.view(),
                taker_lock: taker.view(),
            };
            for a in s.decide(&view, None) {
                match a {
                    Action::Fund if taker.confirmed.is_none() => {
                        taker.confirmed = Some(h + 1);
                        taker_funded_at = Some(h + 1);
                    }
                    Action::Claim { lock, .. } if lock == maker.outpoint => {
                        maker.spend_once(true, false)
                    }
                    Action::Refund { lock, .. } if lock == taker.outpoint => {
                        taker.spend_once(true, false)
                    }
                    _ => {}
                }
            }
            // The counterparty reveals the secret by claiming our lock, some blocks after we lock.
            if let Some(f) = taker_funded_at {
                if h >= f + reveal_delay {
                    taker.spend_once(false, true);
                }
            }
            maker.deepen();
            taker.deepen();

            if TERMINAL.contains(&s.phase) && terminal_at.is_none() {
                terminal_at = Some(h);
            }
            if let Some(t) = terminal_at {
                assert!(
                    TERMINAL.contains(&s.phase),
                    "seed {seed}: left terminal (reached at {t}), now {:?} at {h}",
                    s.phase
                );
            }
        }
        // Done when the secret came in time, Refunded when it came too late; always one or the other.
        assert!(
            terminal_at.is_some(),
            "seed {seed}: never settled, stuck in {:?}",
            s.phase
        );
    }
}
