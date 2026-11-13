//! The engine actor: a thread owns the Engine and runs its tick loop, driven by commands over a
//! channel, and builds the JSON views the API returns.
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::hex::{Case, DisplayHex};
use bitcoin::Amount;
use serde_json::{json, Value};

use crate::engine::{Commitment, Config as EngineConfig, Engine};
use crate::htlc::PREIMAGE_LEN;
use crate::policy::Policy;
use crate::routing::RelayTransport;
use crate::swap::{
    Chain as SwapChain, ChainView, LockView, Offer as SwapOffer, Phase, Role, Side, Swap,
};
use crate::ws::WsConn;

use super::types::Settings;
use super::wire::random16;

pub(crate) const TICK_INTERVAL: Duration = Duration::from_secs(3);

/// How long a daemon API call waits for the engine's reply (`engine_call_on`'s `recv_timeout`).
pub(crate) const ENGINE_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// A `Publish` or `Take` dequeued later than this after it was created is dropped unrun (#176): by then
/// the caller has given up (or is about to, at `ENGINE_CALL_TIMEOUT`), and running a trade it abandoned
/// would double-trade on its retry. Both commands mint a fresh random id per request, so a retry shares
/// nothing with the original and the engine cannot dedupe it; not running the abandoned one is the only
/// safe server-side guard. Kept strictly below `ENGINE_CALL_TIMEOUT` so a dropped command's reply
/// channel disconnects before the caller's wait expires, turning the wait into a definite "not applied"
/// rather than an ambiguous timeout. `Withdraw`/`Abort`/`SubmitSignedLock` are never dropped: running
/// them late is what the operator wants, and a repeat is harmless (refused or idempotent).
pub(crate) const ENGINE_CMD_DEADLINE: Duration = Duration::from_secs(7);

/// A command plus the wall-clock point past which it must not run if it is a double-trade risk.
pub(crate) struct Dispatch {
    pub cmd: EngineCmd,
    pub deadline: Instant,
}

/// Admit a dequeued command, or drop it. A `Publish`/`Take` whose deadline has passed is dropped (the
/// caller gave up; running it would double-trade). Every other command runs regardless of its age:
/// late reads are harmless, and late `Withdraw`/`Abort`/`SubmitSignedLock` are wanted and safe to
/// repeat. Pure (clock passed in) so it is unit-testable.
pub(crate) fn admit(d: Dispatch, now: Instant) -> Option<EngineCmd> {
    if now >= d.deadline && d.cmd.is_double_trade_risk() {
        None
    } else {
        Some(d.cmd)
    }
}

/// Default per-leg timelocks for a new offer, in blocks (the engine clamps to policy regardless).
pub(crate) const MAKER_LOCK_BLOCKS: u16 = 40;

pub(crate) const TAKER_LOCK_BLOCKS: u16 = 20;

/// A command to the engine thread. The engine never leaves that thread; only these messages cross it,
/// so none of the engine's internals need to be shared or `Send` across a lock.
pub(crate) enum EngineCmd {
    Publish(SwapOffer, Sender<Result<(), String>>),
    Offers(Sender<Vec<(SwapOffer, Option<u64>)>>),
    /// Our own live offers, for the "My offers" view so the maker can withdraw them (#211).
    OwnOffers(Sender<Vec<SwapOffer>>),
    Swaps(Sender<Vec<SwapView>>),
    /// Full detail of one swap: the static view plus the live chain view. `None` if no such swap.
    Detail([u8; 16], Sender<Option<Value>>),
    /// The operator reporting ledger (#67): per-swap history plus aggregate totals.
    History(Sender<Value>),
    Take {
        offer_id: [u8; 16],
        maker_part: Amount,
        reply: Sender<Result<[u8; 16], String>>,
    },
    /// Take one of our offers off the market.
    Withdraw {
        offer_id: [u8; 16],
        reply: Sender<Result<(), String>>,
    },
    /// Abandon a swap that has not locked yet (operator teardown).
    Abort {
        swap_id: [u8; 16],
        reply: Sender<Result<(), String>>,
    },
    /// E2 (design 0017): the user submits the signed funding PSBT for a swap parked awaiting it.
    SubmitSignedLock {
        swap_id: [u8; 16],
        psbt: String,
        reply: Sender<Result<(), String>>,
    },
    /// 0027: the user submits the signature over a parked claim/refund's sighash for a user-held swap.
    /// `preimage` carries the maker's secret for a user-held maker claim (the user holds it); `None`
    /// for a refund or a taker claim.
    SubmitSignedSpend {
        swap_id: [u8; 16],
        sig: bitcoin::secp256k1::ecdsa::Signature,
        pubkey: bitcoin::PublicKey,
        preimage: Option<[u8; PREIMAGE_LEN]>,
        reply: Sender<Result<(), String>>,
    },
    /// 0027: the user's browser pre-provisions public commitment bundles for upcoming swap indices
    /// (user-held mode). Public data only; the engine commits one per swap and never reuses it.
    ProvisionCommitments {
        entries: Vec<(u32, Commitment)>,
        reply: Sender<Result<(), String>>,
    },
    /// 0027: the next swap index and the pool's provisioned indices, so the browser knows what to top
    /// up. Read-only, public data.
    CommitmentStatus(Sender<Value>),
}

impl EngineCmd {
    /// Commands whose late execution would double-trade: `Publish` (a duplicate offer) and `Take` (a
    /// second swap against an offer). These are the ones `admit` drops once their caller has given up.
    fn is_double_trade_risk(&self) -> bool {
        matches!(self, EngineCmd::Publish(..) | EngineCmd::Take { .. })
    }
}

/// The slice of a swap the API exposes: id, phase, our role, the direction and amounts, and whether
/// the secret is out. Live on-chain detail (confirmations, txids, refund countdown) follows once the
/// engine surfaces per-swap chain views.
pub struct SwapView {
    id: [u8; 16],
    phase: Phase,
    role: Role,
    maker_chain: SwapChain,
    maker_part: Amount,
    taker_part: Amount,
    secret_revealed: bool,
    started_at: Option<u64>,
}

impl SwapView {
    pub(crate) fn of(s: &Swap) -> SwapView {
        SwapView {
            id: s.id,
            phase: s.phase,
            role: s.role,
            maker_chain: s.offer.maker_chain,
            maker_part: s.maker_part,
            taker_part: s.taker_part,
            secret_revealed: s.learned_secret.is_some(),
            started_at: s.started_at,
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        !matches!(self.phase, Phase::Done | Phase::Refunded | Phase::Abandoned)
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "id": self.id.to_hex_string(Case::Lower),
            "phase": format!("{:?}", self.phase).to_lowercase(),
            "role": match self.role { Role::Maker => "maker", Role::Taker => "taker" },
            "maker_chain": chain_str(self.maker_chain),
            "taker_chain": chain_str(self.maker_chain.other()),
            "maker_amount_sat": self.maker_part.to_sat(),
            "taker_amount_sat": self.taker_part.to_sat(),
            "secret_revealed": self.secret_revealed,
            "started_at": self.started_at,
        })
    }
}

/// Owns the engine, drives it forward on a timer, and serves commands. Ends when the daemon drops its
/// sender (all senders gone => `Disconnected`).
pub(crate) fn run_engine(
    mut engine: Engine<RelayTransport<WsConn>>,
    rx: Receiver<Dispatch>,
    events: Arc<Mutex<Vec<Sender<String>>>>,
) {
    let mut last_phase: std::collections::BTreeMap<[u8; 16], Phase> = Default::default();
    let mut last_offers = 0usize;
    loop {
        match rx.recv_timeout(TICK_INTERVAL) {
            // Drop a Publish/Take whose caller has already given up (#176); run everything else.
            Ok(d) => {
                if let Some(cmd) = admit(d, Instant::now()) {
                    handle_engine_cmd(cmd, &mut engine);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let _ = engine.tick();
        // Broadcast what changed so the GUI updates without polling: a swap whose phase moved, and a
        // change in the number of discovered offers.
        for s in engine.swaps() {
            if last_phase.insert(s.id, s.phase) != Some(s.phase) {
                broadcast(&events, &SwapView::of(s).to_json().to_string());
            }
        }
        let offers = engine.seen_offers().len();
        if offers != last_offers {
            last_offers = offers;
            broadcast(
                &events,
                &json!({"type": "offers", "count": offers}).to_string(),
            );
        }
    }
}

/// Sends one SSE data line to every subscriber, dropping any whose receiver is gone.
pub(crate) fn broadcast(events: &Arc<Mutex<Vec<Sender<String>>>>, line: &str) {
    events
        .lock()
        .unwrap()
        .retain(|tx| tx.send(line.to_owned()).is_ok());
}

pub(crate) fn handle_engine_cmd(cmd: EngineCmd, engine: &mut Engine<RelayTransport<WsConn>>) {
    match cmd {
        EngineCmd::Publish(offer, reply) => {
            let _ = reply.send(engine.publish(offer).map_err(|e| format!("{e:?}")));
        }
        EngineCmd::Offers(reply) => {
            let _ = reply.send(engine.seen_offers_with_time());
        }
        EngineCmd::OwnOffers(reply) => {
            let _ = reply.send(engine.own_offers().to_vec());
        }
        EngineCmd::Swaps(reply) => {
            let views = engine.swaps().map(SwapView::of).collect();
            let _ = reply.send(views);
        }
        EngineCmd::Detail(id, reply) => {
            // Static view first (ends the swaps() borrow), then the live chain view.
            let base = engine.swaps().find(|s| s.id == id).map(|s| {
                (
                    SwapView::of(s).to_json(),
                    s.own_side(),
                    s.offer.maker_lock_blocks,
                    s.offer.taker_lock_blocks,
                    s.key_index,
                )
            });
            // E2 (0017): if the swap is parked awaiting the user's funding signature, surface the
            // unsigned PSBT so the user can sign it and POST it back to /swaps/{id}/signed-psbt.
            let pending = engine.pending_lock_psbt(id);
            // 0027: if a user-held swap is parked awaiting the user's claim/refund signature, surface
            // which spend it is and the sighash to sign, for POST /swaps/{id}/signed-spend.
            let pending_spend = engine.pending_spend(id);
            let detail = base.map(|(mut j, side, mlb, tlb, key_index)| {
                if let Some(psbt) = &pending {
                    j["pending_lock_psbt"] = json!(psbt);
                }
                if let Some((claim, sighash)) = pending_spend {
                    j["pending_spend"] = json!({
                        "claim": claim,
                        "sighash": sighash.to_lower_hex_string(),
                    });
                    // 0027: the swap's key index, so a user-held browser knows which key derived from
                    // its seed to sign the parked spend with. Public data (an index, not a key).
                    j["key_index"] = json!(key_index);
                }
                match engine.chain_view(id) {
                    Some(Ok(view)) => j["chain"] = chain_view_json(&view, side, mlb, tlb),
                    Some(Err(e)) => j["chain_error"] = json!(format!("{e:?}")),
                    None => {}
                }
                j
            });
            let _ = reply.send(detail);
        }
        EngineCmd::History(reply) => {
            let _ = reply.send(engine.history());
        }
        EngineCmd::Take {
            offer_id,
            maker_part,
            reply,
        } => {
            let found = engine
                .seen_offers()
                .iter()
                .find(|o| o.id == offer_id)
                .cloned();
            let res = match found {
                Some(o) => {
                    let id = random16();
                    engine
                        .bid(&o, maker_part, id)
                        .map(|_| id)
                        .map_err(|e| format!("{e:?}"))
                }
                None => Err("no such offer".to_owned()),
            };
            let _ = reply.send(res);
        }
        EngineCmd::Withdraw { offer_id, reply } => {
            let _ = reply.send(engine.withdraw(offer_id).map_err(|e| format!("{e:?}")));
        }
        EngineCmd::Abort { swap_id, reply } => {
            let _ = reply.send(engine.abort(swap_id).map_err(|e| format!("{e:?}")));
        }
        EngineCmd::SubmitSignedLock {
            swap_id,
            psbt,
            reply,
        } => {
            let _ = reply.send(
                engine
                    .submit_signed_lock(swap_id, &psbt)
                    .map_err(|e| format!("{e:?}")),
            );
        }
        EngineCmd::SubmitSignedSpend {
            swap_id,
            sig,
            pubkey,
            preimage,
            reply,
        } => {
            let _ = reply.send(
                engine
                    .submit_signed_spend(swap_id, sig, pubkey, preimage)
                    .map_err(|e| format!("{e:?}")),
            );
        }
        EngineCmd::ProvisionCommitments { entries, reply } => {
            let _ = reply.send(
                engine
                    .provision_commitments(entries)
                    .map_err(|e| format!("{e:?}")),
            );
        }
        EngineCmd::CommitmentStatus(reply) => {
            let (next_index, provisioned) = engine.commitment_status();
            let _ = reply.send(json!({ "next_index": next_index, "provisioned": provisioned }));
        }
    }
}

pub(crate) fn engine_config(s: &Settings) -> EngineConfig {
    let mut policy = Policy::standard();
    policy.funding_minconf_btc = s.btc_conf;
    policy.funding_minconf_xbtc = s.xbtc_conf;
    let payout = |a: &str| (!a.trim().is_empty()).then(|| a.trim().to_owned());
    EngineConfig {
        // Floor on the claim/refund fee (F6); the real fee is the live estimate x vsize, never below
        // this. Min-relay-safe (~2.8 sat/vB for a ~142 vB claim) so a spend still confirms when the
        // mempool is empty, while a quiet mempool no longer forces the old flat 2000-sat overpay.
        min_spend_fee: Amount::from_sat(400),
        fee_rate_sat_vb: 2,
        policy,
        btc_payout: payout(&s.btc_payout_address),
        xbtc_payout: payout(&s.xbtc_payout_address),
        user_held_spends: s.user_held_spends,
    }
}

pub(crate) fn offer_to_json(o: &SwapOffer, seen_at: Option<u64>) -> Value {
    json!({
        "id": o.id.to_hex_string(Case::Lower),
        "sell_chain": chain_str(o.maker_chain),
        "taker_chain": chain_str(o.maker_chain.other()),
        "amount_sat": o.maker_amount.to_sat(),
        "counter_amount_sat": o.taker_amount.to_sat(),
        "min_amount_sat": o.min_maker_amount.to_sat(),
        "maker_lock_blocks": o.maker_lock_blocks,
        "taker_lock_blocks": o.taker_lock_blocks,
        // When this node last saw the offer on its market (#88), for the time column.
        "seen_at": seen_at,
        // Maker-set expiry (design 0026, #212): unix seconds, or null for no explicit expiry.
        "valid_until": o.valid_until,
    })
}

/// The live chain view for the swap-detail screen: heights, each lock's txid and confirmations, and
/// the countdown until our own lock can be refunded.
pub(crate) fn chain_view_json(
    view: &ChainView,
    own_side: Side,
    maker_lock_blocks: u16,
    taker_lock_blocks: u16,
) -> Value {
    let (own_lock, own_height, own_lock_blocks) = match own_side {
        Side::Maker => (&view.maker_lock, view.maker_chain_height, maker_lock_blocks),
        Side::Taker => (&view.taker_lock, view.taker_chain_height, taker_lock_blocks),
    };
    // Refundable at confirmed_height + lock_blocks - 1; negative means it is already available.
    let refund_in = own_lock
        .as_ref()
        .and_then(|l| l.confirmed_height)
        .map(|h| i64::from(h) + i64::from(own_lock_blocks) - 1 - i64::from(own_height));
    json!({
        "maker_height": view.maker_chain_height,
        "taker_height": view.taker_chain_height,
        "maker_lock": lock_json(&view.maker_lock, view.maker_chain_height),
        "taker_lock": lock_json(&view.taker_lock, view.taker_chain_height),
        "refund_in_blocks": refund_in,
    })
}

pub(crate) fn lock_json(lock: &Option<LockView>, height: u32) -> Value {
    match lock {
        Some(l) => json!({
            "txid": l.outpoint.txid.to_string(),
            "vout": l.outpoint.vout,
            "confirmations": l.confirmed_height.map(|h| height.saturating_sub(h) + 1),
            "amount_ok": l.amount_ok,
            "spent": l.spend.is_some(),
        }),
        None => Value::Null,
    }
}

pub(crate) fn chain_str(c: SwapChain) -> &'static str {
    match c {
        SwapChain::Btc => "btc",
        SwapChain::Xbtc => "xbtc",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;
    use std::sync::mpsc;

    fn test_offer() -> SwapOffer {
        SwapOffer {
            id: [0u8; 16],
            maker_chain: SwapChain::Btc,
            maker_amount: Amount::from_sat(1000),
            taker_amount: Amount::from_sat(1000),
            min_maker_amount: Amount::from_sat(1000),
            maker_lock_blocks: 40,
            taker_lock_blocks: 20,
            maker_lock_depth: 1,
            taker_lock_depth: 1,
            margin_blocks: 6,
            fee: None,
            valid_until: None,
        }
    }

    #[test]
    fn admit_drops_only_a_stale_publish_or_take() {
        let past = Instant::now() - Duration::from_secs(1);
        let future = Instant::now() + Duration::from_secs(60);
        let now = Instant::now();

        // A stale Publish or Take is a double-trade risk: drop it.
        let (tx, _rx) = mpsc::channel();
        let publish = Dispatch {
            cmd: EngineCmd::Publish(test_offer(), tx),
            deadline: past,
        };
        assert!(
            admit(publish, now).is_none(),
            "stale Publish must be dropped"
        );

        let (tx, _rx) = mpsc::channel();
        let take = Dispatch {
            cmd: EngineCmd::Take {
                offer_id: [0u8; 16],
                maker_part: Amount::from_sat(0),
                reply: tx,
            },
            deadline: past,
        };
        assert!(admit(take, now).is_none(), "stale Take must be dropped");

        // A stale Withdraw/Abort/SubmitSignedLock still runs (operator brakes, funding window).
        let (tx, _rx) = mpsc::channel();
        let withdraw = Dispatch {
            cmd: EngineCmd::Withdraw {
                offer_id: [0u8; 16],
                reply: tx,
            },
            deadline: past,
        };
        assert!(
            admit(withdraw, now).is_some(),
            "a stale Withdraw must still run"
        );

        // A stale read still runs (harmless; its reply goes to a receiver that may be gone).
        let (tx, _rx) = mpsc::channel();
        let offers = Dispatch {
            cmd: EngineCmd::Offers(tx),
            deadline: past,
        };
        assert!(admit(offers, now).is_some(), "a stale read must still run");

        // A fresh Take (deadline not reached) runs.
        let (tx, _rx) = mpsc::channel();
        let fresh = Dispatch {
            cmd: EngineCmd::Take {
                offer_id: [0u8; 16],
                maker_part: Amount::from_sat(0),
                reply: tx,
            },
            deadline: future,
        };
        assert!(admit(fresh, now).is_some(), "a fresh Take must run");
    }

    #[test]
    fn chain_detail_reports_confirmations_and_refund_countdown() {
        let lock = LockView {
            outpoint: OutPoint::null(),
            value: Amount::from_sat(500_000),
            amount_ok: true,
            confirmed_height: Some(100),
            spend: None,
            fee: crate::swap::FeeState::NotRequired,
        };
        let view = ChainView {
            maker_chain_height: 105,
            taker_chain_height: 50,
            maker_lock: Some(lock),
            taker_lock: None,
            own_funded: false,
        };
        // We are the maker, so our lock is on the maker chain with 40 lock blocks.
        let j = chain_view_json(&view, Side::Maker, 40, 20);
        assert_eq!(j["maker_lock"]["confirmations"], 6); // 105 - 100 + 1
        assert_eq!(j["refund_in_blocks"], 34); // 100 + 40 - 1 - 105
        assert_eq!(j["taker_lock"], Value::Null);
        assert_eq!(j["maker_lock"]["spent"], false);
    }
}
