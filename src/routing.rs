//! Routes `Message`s to peers over a relay: offers are broadcast, bids and swap steps are addressed
//! to one peer by its routing key and sealed to its identity. Peers are learned from the signed
//! offers and bids that arrive, so two parties who never met can complete a swap through an
//! untrusted relay. See `docs/design/0006-nostr-client-and-relay.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::secp256k1::{All, Keypair, Secp256k1, XOnlyPublicKey};

use crate::envelope::{
    open, seal, sign_broadcast, verify_broadcast, Identity, PublicIdentity, PUBLIC_IDENTITY_LEN,
};
use crate::nostr::{p_tag, Event};
use crate::swap::Message;
use crate::transport::Transport;

/// A peer as this party has learned it: its relay routing key and its envelope identity.
type Peer = (XOnlyPublicKey, PublicIdentity);

/// A connection to one or more relays. An in-process `Relay` and a real WebSocket relay both
/// implement it, so the routing below is written once and runs over either.
pub trait RelayConn {
    fn publish(&self, event: Event);
    /// Events newly arrived for `subscriber` (addressed to it or broadcast, never its own), deduped.
    fn poll(&self, subscriber: &XOnlyPublicKey) -> Vec<Event>;
}

pub struct RelayTransport<C: RelayConn> {
    me: Identity,
    routing: Keypair,
    routing_key: XOnlyPublicKey,
    conn: C,
    secp: Secp256k1<All>,
    /// offer id -> the maker of that offer.
    offers: Mutex<HashMap<[u8; 16], Peer>>,
    /// swap id -> the counterparty of that swap.
    swaps: Mutex<HashMap<[u8; 16], Peer>>,
}

impl<C: RelayConn> RelayTransport<C> {
    pub fn new(me: Identity, routing_seed: &[u8; 32], conn: C) -> RelayTransport<C> {
        let secp = Secp256k1::new();
        let routing = Keypair::from_seckey_slice(&secp, routing_seed).expect("valid scalar");
        RelayTransport {
            routing_key: routing.x_only_public_key().0,
            me,
            routing,
            conn,
            secp,
            offers: Mutex::new(HashMap::new()),
            swaps: Mutex::new(HashMap::new()),
        }
    }

    /// The content of an event: an unauthenticated sender-identity hint, then the envelope. The hint
    /// is only a hint; the envelope's own signature is verified against it, so a wrong hint fails.
    fn frame(&self, envelope: Vec<u8>) -> Vec<u8> {
        let mut f = self.me.public().to_bytes().to_vec();
        f.extend_from_slice(&envelope);
        f
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn os_random<const N: usize>() -> [u8; N] {
        use std::io::Read;
        let mut buf = [0u8; N];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .expect("OS randomness");
        buf
    }
}

impl<C: RelayConn> Transport for RelayTransport<C> {
    fn send(&self, message: &Message) {
        let payload = serde_json::to_vec(message).expect("a Message serializes");
        let (tags, envelope) = match message {
            Message::Offer(_) => (
                Vec::new(),
                sign_broadcast(&self.me, &payload, Self::os_random()),
            ),
            Message::Bid {
                offer_id, swap_id, ..
            } => {
                let peer = self
                    .offers
                    .lock()
                    .unwrap()
                    .get(offer_id)
                    .cloned()
                    .expect("bidding on a seen offer");
                self.swaps.lock().unwrap().insert(*swap_id, peer.clone());
                (
                    vec![p_tag(&peer.0)],
                    seal(&self.me, &peer.1, &payload, &Self::os_random()),
                )
            }
            Message::Accept { swap_id, .. } => {
                let peer = self
                    .swaps
                    .lock()
                    .unwrap()
                    .get(swap_id)
                    .cloned()
                    .expect("accepting a known swap");
                (
                    vec![p_tag(&peer.0)],
                    seal(&self.me, &peer.1, &payload, &Self::os_random()),
                )
            }
            // The fee proof is directed to the swap's counterparty, sealed like an Accept.
            Message::FeeProof { swap_id, .. } => {
                let peer = self
                    .swaps
                    .lock()
                    .unwrap()
                    .get(swap_id)
                    .cloned()
                    .expect("fee proof for a known swap");
                (
                    vec![p_tag(&peer.0)],
                    seal(&self.me, &peer.1, &payload, &Self::os_random()),
                )
            }
        };
        let event = Event::build(
            &self.secp,
            &self.routing,
            Self::now(),
            tags,
            &self.frame(envelope),
        );
        self.conn.publish(event);
    }

    fn receive(&self) -> Vec<Message> {
        let events = self.conn.poll(&self.routing_key);
        let mut out = Vec::new();
        for event in events {
            if event.verify(&self.secp).is_err() {
                continue;
            }
            let Ok(frame) = event.envelope() else {
                continue;
            };
            if frame.len() < PUBLIC_IDENTITY_LEN {
                continue;
            }
            let (hint, env) = frame.split_at(PUBLIC_IDENTITY_LEN);
            let Ok(sender) = PublicIdentity::from_bytes(hint) else {
                continue;
            };
            let payload = if event.recipient().is_none() {
                verify_broadcast(&sender, env)
            } else {
                open(&self.me, &sender, env)
            };
            let Ok(payload) = payload else { continue };
            let Ok(message) = serde_json::from_slice::<Message>(&payload) else {
                continue;
            };
            match &message {
                Message::Offer(offer) => {
                    self.offers
                        .lock()
                        .unwrap()
                        .insert(offer.id, (event.pubkey, sender));
                }
                Message::Bid { swap_id, .. } => {
                    self.swaps
                        .lock()
                        .unwrap()
                        .insert(*swap_id, (event.pubkey, sender));
                }
                Message::Accept { .. } => {}
                // The counterparty is already known for the swap; no routing bookkeeping needed.
                Message::FeeProof { .. } => {}
            }
            out.push(message);
        }
        out
    }
}
