//! Multi-peer routing over the in-process relay: an offer reaches every taker, a bid reaches only
//! the maker it is addressed to. No chain, no nodes. See docs/design/0006.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, PubkeyHash};

use sovereign_swap::envelope::Identity;
use sovereign_swap::relay::Relay;
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::swap::{Chain, Message, Offer};
use sovereign_swap::transport::Transport;

fn party(relay: &Relay, id_seed: u8, routing_seed: u8) -> RelayTransport {
    RelayTransport::new(
        Identity::from_seed(&[id_seed; 32]),
        &[routing_seed; 32],
        relay.clone(),
    )
}

fn offer() -> Offer {
    Offer {
        id: [42; 16],
        maker_chain: Chain::Xbtc,
        maker_amount: Amount::from_sat(1_000_000),
        taker_amount: Amount::from_sat(300_000),
        min_maker_amount: Amount::from_sat(1_000_000),
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 1,
        taker_lock_depth: 1,
        margin_blocks: 2,
    }
}

fn bid(swap_id: [u8; 16]) -> Message {
    Message::Bid {
        offer_id: offer().id,
        swap_id,
        maker_part: offer().maker_amount,
        taker_claim_pkh: PubkeyHash::from_byte_array([1; 20]),
        taker_refund_pkh: PubkeyHash::from_byte_array([2; 20]),
    }
}

#[test]
fn an_offer_reaches_every_taker_and_a_bid_reaches_only_the_maker() {
    let relay = Relay::new();
    let maker = party(&relay, 1, 10);
    let taker1 = party(&relay, 2, 20);
    let taker2 = party(&relay, 3, 30);

    maker.send(&Message::Offer(offer()));

    // Both takers see the broadcast offer; the maker does not receive its own.
    assert!(matches!(taker1.receive().as_slice(), [Message::Offer(o)] if o.id == offer().id));
    assert!(matches!(taker2.receive().as_slice(), [Message::Offer(o)] if o.id == offer().id));
    assert!(maker.receive().is_empty());

    // Taker 1 bids; only the maker receives it, not taker 2.
    taker1.send(&bid([7; 16]));
    assert!(
        matches!(maker.receive().as_slice(), [Message::Bid { swap_id, .. }] if *swap_id == [7; 16])
    );
    assert!(
        taker2.receive().is_empty(),
        "a directed bid must not reach another taker"
    );

    // The maker can now address the taker it heard from.
    maker.send(&Message::Accept {
        swap_id: [7; 16],
        secret_hash: [9; 32],
        maker_claim_pkh: PubkeyHash::from_byte_array([3; 20]),
        maker_refund_pkh: PubkeyHash::from_byte_array([4; 20]),
    });
    assert!(
        matches!(taker1.receive().as_slice(), [Message::Accept { swap_id, .. }] if *swap_id == [7; 16])
    );
    assert!(taker2.receive().is_empty());
}

#[test]
fn a_forged_event_from_the_relay_is_dropped() {
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use sovereign_swap::nostr::Event;

    let relay = Relay::new();
    let taker = party(&relay, 2, 20);
    // Anyone can publish a kind-4859 event with garbage content; its envelope will not verify.
    let secp = Secp256k1::new();
    let forger = Keypair::from_seckey_slice(&secp, &[99; 32]).unwrap();
    relay.publish(Event::build(
        &secp,
        &forger,
        1,
        vec![],
        b"not a valid frame",
    ));
    assert!(
        taker.receive().is_empty(),
        "an event whose envelope does not verify must be dropped"
    );
}
