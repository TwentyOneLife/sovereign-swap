//! The engine actor: a thread owns the Engine and runs its tick loop, driven by commands over a
//! channel, and builds the JSON views the API returns.
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::hex::{Case, DisplayHex};
use bitcoin::Amount;
use serde_json::{json, Value};

use crate::engine::{Config as EngineConfig, Engine};
use crate::policy::Policy;
use crate::routing::RelayTransport;
use crate::swap::{
    Chain as SwapChain, ChainView, LockView, Offer as SwapOffer, Phase, Role, Side, Swap,
};
use crate::ws::WsConn;

use super::types::Settings;
use super::wire::random16;

pub(crate) const TICK_INTERVAL: Duration = Duration::from_secs(3);

/// Default per-leg timelocks for a new offer, in blocks (the engine clamps to policy regardless).
pub(crate) const MAKER_LOCK_BLOCKS: u16 = 40;

pub(crate) const TAKER_LOCK_BLOCKS: u16 = 20;

/// A command to the engine thread. The engine never leaves that thread; only these messages cross it,
/// so none of the engine's internals need to be shared or `Send` across a lock.
pub(crate) enum EngineCmd {
    Publish(SwapOffer, Sender<Result<(), String>>),
    Offers(Sender<Vec<SwapOffer>>),
    Swaps(Sender<Vec<SwapView>>),
    /// Full detail of one swap: the static view plus the live chain view. `None` if no such swap.
    Detail([u8; 16], Sender<Option<Value>>),
    Take {
        offer_id: [u8; 16],
        maker_part: Amount,
        reply: Sender<Result<[u8; 16], String>>,
    },
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
        })
    }
}

/// Owns the engine, drives it forward on a timer, and serves commands. Ends when the daemon drops its
/// sender (all senders gone => `Disconnected`).
pub(crate) fn run_engine(
    mut engine: Engine<RelayTransport<WsConn>>,
    rx: Receiver<EngineCmd>,
    events: Arc<Mutex<Vec<Sender<String>>>>,
) {
    let mut last_phase: std::collections::BTreeMap<[u8; 16], Phase> = Default::default();
    let mut last_offers = 0usize;
    loop {
        match rx.recv_timeout(TICK_INTERVAL) {
            Ok(cmd) => handle_engine_cmd(cmd, &mut engine),
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
            let _ = reply.send(engine.seen_offers().to_vec());
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
                )
            });
            let detail = base.map(|(mut j, side, mlb, tlb)| {
                match engine.chain_view(id) {
                    Some(Ok(view)) => j["chain"] = chain_view_json(&view, side, mlb, tlb),
                    Some(Err(e)) => j["chain_error"] = json!(format!("{e:?}")),
                    None => {}
                }
                j
            });
            let _ = reply.send(detail);
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
    }
}

pub(crate) fn engine_config(s: &Settings) -> EngineConfig {
    let mut policy = Policy::standard();
    policy.funding_minconf_btc = s.btc_conf;
    policy.funding_minconf_xbtc = s.xbtc_conf;
    EngineConfig {
        spend_fee: Amount::from_sat(2_000),
        fee_rate_sat_vb: 2,
        policy,
    }
}

pub(crate) fn offer_to_json(o: &SwapOffer) -> Value {
    json!({
        "id": o.id.to_hex_string(Case::Lower),
        "sell_chain": chain_str(o.maker_chain),
        "amount_sat": o.maker_amount.to_sat(),
        "counter_amount_sat": o.taker_amount.to_sat(),
        "min_amount_sat": o.min_maker_amount.to_sat(),
        "maker_lock_blocks": o.maker_lock_blocks,
        "taker_lock_blocks": o.taker_lock_blocks,
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
        };
        // We are the maker, so our lock is on the maker chain with 40 lock blocks.
        let j = chain_view_json(&view, Side::Maker, 40, 20);
        assert_eq!(j["maker_lock"]["confirmations"], 6); // 105 - 100 + 1
        assert_eq!(j["refund_in_blocks"], 34); // 100 + 40 - 1 - 105
        assert_eq!(j["taker_lock"], Value::Null);
        assert_eq!(j["maker_lock"]["spent"], false);
    }
}
