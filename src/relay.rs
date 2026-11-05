//! An in-process Nostr relay for tests: store events and serve subscriptions by kind and `p` tag.
//! A real relay (M3b-3) is a remote WebSocket service; this models its store-and-forward semantics
//! so the multi-peer routing runs in CI with no network. See `docs/design/0006-nostr-client-and-relay.md`.

use std::sync::{Arc, Mutex};

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::nostr::Event;

/// Shared by cloning: every clone talks to the same event log.
#[derive(Clone, Default)]
pub struct Relay {
    events: Arc<Mutex<Vec<Event>>>,
}

impl Relay {
    pub fn new() -> Relay {
        Relay::default()
    }

    /// Stores an event unless one with the same id is already present (dedup).
    pub fn publish(&self, event: Event) {
        let mut events = self.events.lock().unwrap();
        if !events.iter().any(|e| e.id == event.id) {
            events.push(event);
        }
    }

    /// Events stored at or after `from`, that `subscriber` should see: broadcasts (no `p` tag) and
    /// events addressed to `subscriber`, never the subscriber's own. Returns them and the new cursor.
    pub fn query(&self, from: usize, subscriber: &XOnlyPublicKey) -> (Vec<Event>, usize) {
        let events = self.events.lock().unwrap();
        let matched = events
            .iter()
            .skip(from)
            .filter(|e| e.pubkey != *subscriber)
            .filter(|e| match e.recipient() {
                Some(to) => to == *subscriber,
                None => true,
            })
            .cloned()
            .collect();
        (matched, events.len())
    }
}

use crate::routing::RelayConn;

/// A `RelayConn` over the in-process `Relay`, tracking this party's read cursor.
pub struct InProcessConn {
    relay: Relay,
    cursor: Mutex<usize>,
}

impl InProcessConn {
    pub fn new(relay: Relay) -> InProcessConn {
        InProcessConn {
            relay,
            cursor: Mutex::new(0),
        }
    }
}

impl RelayConn for InProcessConn {
    fn publish(&self, event: crate::nostr::Event) {
        self.relay.publish(event);
    }
    fn poll(&self, subscriber: &bitcoin::secp256k1::XOnlyPublicKey) -> Vec<crate::nostr::Event> {
        let mut cursor = self.cursor.lock().unwrap();
        let (events, next) = self.relay.query(*cursor, subscriber);
        *cursor = next;
        events
    }
}
