//! Periodic offer re-announcement (design 0020 decision 2). The relay's bounded store (phase 1) can
//! evict a live offer under a flood; nothing re-publishes it on reconnect (that only re-subscribes),
//! so `Engine::tick` re-announces our own live offers on a timer and eviction becomes self-healing.
//!
//! This file holds the transport-level guarantee the engine relies on: a repeated broadcast of the
//! same `Offer` is a NEW event each time (fresh id and `created_at`), so a relay's id-dedupe does not
//! drop the re-send and a reconnecting peer's `since` watermark does not hide it. The engine-side
//! timer and `own_offers` selection are covered in `tests/relay_swap.rs` (regtest-gated).

use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::Amount;

use sovereign_swap::envelope::Identity;
use sovereign_swap::relay::{InProcessConn, Relay};
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::swap::{Chain, Message, Offer};
use sovereign_swap::transport::Transport;

fn offer() -> Offer {
    Offer {
        id: [7; 16],
        maker_chain: Chain::Xbtc,
        maker_amount: Amount::from_sat(500_000),
        taker_amount: Amount::from_sat(150_000),
        min_maker_amount: Amount::from_sat(500_000),
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 1,
        taker_lock_depth: 1,
        margin_blocks: 2,
        fee: None,
    }
}

/// A routing key that is not the maker's, so the relay returns the maker's broadcasts to it.
fn other_key() -> bitcoin::secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    Keypair::from_seckey_slice(&secp, &[9u8; 32])
        .unwrap()
        .x_only_public_key()
        .0
}

#[test]
fn re_broadcasting_one_offer_produces_a_distinct_event_each_time() {
    let relay = Relay::new();
    let maker = RelayTransport::new(
        Identity::from_seed(&[11; 32]),
        &[101; 32],
        InProcessConn::new(relay.clone()),
    );

    // The same offer, broadcast twice, exactly as the periodic re-announce does.
    maker.send(&Message::Offer(offer()));
    maker.send(&Message::Offer(offer()));

    // The relay dedupes by event id and keeps both, so the two sends are distinct events: a re-send is
    // not silently dropped, and its fresh timestamp keeps it above a reconnecting peer's `since`.
    let (events, _) = relay.query(0, &other_key());
    assert_eq!(events.len(), 2, "both re-sends must be stored, not deduped");
    assert_ne!(
        events[0].id, events[1].id,
        "each re-announce must be a new event id"
    );
    assert!(
        events[1].created_at >= events[0].created_at,
        "a re-announce carries a fresh created_at"
    );
}
