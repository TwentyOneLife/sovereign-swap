//! Routes `Message`s to peers over a relay: offers are broadcast, bids and swap steps are addressed
//! to one peer by its routing key and sealed to its identity. Peers are learned from the signed
//! offers and bids that arrive, so two parties who never met can complete a swap through an
//! untrusted relay. See `docs/design/0006-nostr-client-and-relay.md`.

use std::collections::{HashMap, HashSet};
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

/// One relay's connection status, for display ("connected sovereign-relays").
#[derive(Clone, Debug)]
pub struct RelayStatus {
    pub url: String,
    pub connected: bool,
}

/// A connection to one or more relays. An in-process `Relay` and a real WebSocket relay both
/// implement it, so the routing below is written once and runs over either.
pub trait RelayConn {
    fn publish(&self, event: Event);
    /// Events newly arrived for `subscriber` (addressed to it or broadcast, never its own), deduped.
    fn poll(&self, subscriber: &XOnlyPublicKey) -> Vec<Event>;
    /// Per-relay connection status, for the client to show which relays (markets) it is connected to.
    /// Default empty (an in-process or statusless conn reports nothing); `WsConn` and `MultiConn`
    /// report real entries.
    fn status(&self) -> Vec<RelayStatus> {
        Vec::new()
    }
}

/// Connects to SEVERAL relays at once and presents them as one (design 0029, client-side federation):
/// an offer published by anyone on ANY connected relay is discoverable here, so separate
/// sovereign-relays become one combined market. Publishes to every relay; polls all and dedups by
/// event id (the same event seen on two relays is delivered once). The swap itself is unchanged and
/// trustless, so pooling discovery across relays you do not trust cannot cost funds (see 0029).
pub struct MultiConn<C: RelayConn> {
    conns: Vec<C>,
    seen: Mutex<HashSet<[u8; 32]>>,
}

impl<C: RelayConn> MultiConn<C> {
    pub fn new(conns: Vec<C>) -> MultiConn<C> {
        MultiConn {
            conns,
            seen: Mutex::new(HashSet::new()),
        }
    }
}

impl<C: RelayConn> RelayConn for MultiConn<C> {
    fn publish(&self, event: Event) {
        for c in &self.conns {
            c.publish(event.clone());
        }
    }

    fn poll(&self, subscriber: &XOnlyPublicKey) -> Vec<Event> {
        let mut seen = self.seen.lock().unwrap();
        let mut out = Vec::new();
        for c in &self.conns {
            for e in c.poll(subscriber) {
                if seen.insert(e.id) {
                    out.push(e);
                }
            }
        }
        out
    }

    fn status(&self) -> Vec<RelayStatus> {
        self.conns.iter().flat_map(|c| c.status()).collect()
    }
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
    fn relay_status(&self) -> Vec<RelayStatus> {
        self.conn.status()
    }

    fn send(&self, message: &Message) {
        let payload = serde_json::to_vec(message).expect("a Message serializes");
        let (tags, envelope) = match message {
            // Both are unaddressed, broadcast to everyone: an offer and its later withdrawal.
            Message::Offer(_) | Message::Withdraw { .. } => (
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
                // Only the author of an offer may withdraw it (#71): the sender must match the pubkey
                // that published that offer. Fail closed if the offer is unknown - its author cannot
                // be verified (also the case after a relay restart clears this in-memory map, where a
                // withdraw then simply does not propagate, which is acceptable).
                Message::Withdraw { offer_id } => {
                    let authentic = self
                        .offers
                        .lock()
                        .unwrap()
                        .get(offer_id)
                        .is_some_and(|(pk, _)| *pk == event.pubkey);
                    if !authentic {
                        continue;
                    }
                }
            }
            out.push(message);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::Event;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn a_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7u8; 32]).unwrap())
            .x_only_public_key()
            .0
    }

    fn ev(id: u8) -> Event {
        Event {
            id: [id; 32],
            pubkey: a_key(),
            created_at: 0,
            kind: 4859,
            tags: vec![],
            content: String::new(),
            sig: [0u8; 64],
        }
    }

    /// A relay that returns a fixed set of events (the per-relay poll + subscriber filter are the real
    /// conns' job; this isolates `MultiConn`'s union + dedup).
    struct Fixed(Vec<Event>);
    impl RelayConn for Fixed {
        fn publish(&self, _: Event) {}
        fn poll(&self, _: &XOnlyPublicKey) -> Vec<Event> {
            self.0.clone()
        }
    }

    #[test]
    fn multiconn_unions_offers_and_dedups_across_relays() {
        // Relay A carries events {1,2}, relay B carries {2,3}: the combined market is {1,2,3} with the
        // event seen on both relays delivered once (design 0029).
        let mc = MultiConn::new(vec![Fixed(vec![ev(1), ev(2)]), Fixed(vec![ev(2), ev(3)])]);
        let ids: Vec<u8> = mc.poll(&a_key()).iter().map(|e| e.id[0]).collect();
        assert_eq!(
            ids,
            vec![1, 2, 3],
            "union across relays, deduped by event id"
        );
        assert!(
            mc.poll(&a_key()).is_empty(),
            "an event already delivered from any relay is not returned again"
        );
    }

    #[test]
    fn multiconn_status_concatenates_each_relay() {
        struct One(&'static str);
        impl RelayConn for One {
            fn publish(&self, _: Event) {}
            fn poll(&self, _: &XOnlyPublicKey) -> Vec<Event> {
                vec![]
            }
            fn status(&self) -> Vec<RelayStatus> {
                vec![RelayStatus {
                    url: self.0.into(),
                    connected: true,
                }]
            }
        }
        let mc = MultiConn::new(vec![One("ws://a"), One("ws://b")]);
        let s = mc.status();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].url, "ws://a");
        assert_eq!(s[1].url, "ws://b");
    }
}
