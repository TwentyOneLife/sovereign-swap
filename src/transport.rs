//! How protocol messages travel. Nostr with the post-quantum envelope replaces the in-memory pair.

use std::sync::{Arc, Mutex};

use crate::swap::Message;

pub trait Transport {
    fn send(&self, message: &Message);
    fn receive(&self) -> Vec<Message>;
}

/// One end of a pair: what one end sends, the other receives.
#[derive(Clone)]
pub struct Memory {
    inbox: Arc<Mutex<Vec<Message>>>,
    outbox: Arc<Mutex<Vec<Message>>>,
}

pub fn memory_pair() -> (Memory, Memory) {
    let (a, b) = (Arc::default(), Arc::default());
    (
        Memory {
            inbox: Arc::clone(&a),
            outbox: Arc::clone(&b),
        },
        Memory {
            inbox: b,
            outbox: a,
        },
    )
}

impl Transport for Memory {
    fn send(&self, message: &Message) {
        self.outbox.lock().unwrap().push(message.clone());
    }

    fn receive(&self) -> Vec<Message> {
        std::mem::take(&mut *self.inbox.lock().unwrap())
    }
}
