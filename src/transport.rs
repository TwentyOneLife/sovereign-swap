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

use crate::envelope::{open, seal, sign_broadcast, verify_broadcast, Identity, PublicIdentity};

/// Moves opaque frames between two ends. A real one is a Nostr relay; `MemoryBytes` is the test pair.
pub trait ByteTransport {
    fn send_frame(&self, frame: Vec<u8>);
    fn receive_frames(&self) -> Vec<Vec<u8>>;
}

#[derive(Clone, Default)]
pub struct MemoryBytes {
    inbox: Arc<Mutex<Vec<Vec<u8>>>>,
    outbox: Arc<Mutex<Vec<Vec<u8>>>>,
}

type Frames = Arc<Mutex<Vec<Vec<u8>>>>;

pub fn memory_bytes_pair() -> (MemoryBytes, MemoryBytes) {
    let (a, b): (Frames, Frames) = Default::default();
    (
        MemoryBytes {
            inbox: Arc::clone(&a),
            outbox: Arc::clone(&b),
        },
        MemoryBytes {
            inbox: b,
            outbox: a,
        },
    )
}

impl ByteTransport for MemoryBytes {
    fn send_frame(&self, frame: Vec<u8>) {
        self.outbox.lock().unwrap().push(frame);
    }
    fn receive_frames(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.inbox.lock().unwrap())
    }
}

/// Carries `Message`s as payload-format-3 envelopes over an inner frame transport: offers are
/// broadcast-signed, every other message is sealed to the peer. A frame that does not verify or
/// decrypt is dropped, so a hostile relay cannot inject a message. Routing to more than one peer is
/// M3b (the Nostr client); here one `EnvelopeTransport` talks to one known peer.
pub struct EnvelopeTransport<B: ByteTransport> {
    me: Arc<Identity>,
    peer: PublicIdentity,
    inner: B,
}

const FRAME_BROADCAST: u8 = 0;
const FRAME_DIRECT: u8 = 1;

impl<B: ByteTransport> EnvelopeTransport<B> {
    pub fn new(me: Arc<Identity>, peer: PublicIdentity, inner: B) -> EnvelopeTransport<B> {
        EnvelopeTransport { me, peer, inner }
    }
}

impl<B: ByteTransport> Transport for EnvelopeTransport<B> {
    fn send(&self, message: &Message) {
        let payload = serde_json::to_vec(message).expect("a Message serializes");
        let frame = match message {
            Message::Offer(_) => {
                let mut f = vec![FRAME_BROADCAST];
                f.extend_from_slice(&sign_broadcast(&self.me, &payload, os_random()));
                f
            }
            _ => {
                let mut f = vec![FRAME_DIRECT];
                f.extend_from_slice(&seal(&self.me, &self.peer, &payload, &os_random()));
                f
            }
        };
        self.inner.send_frame(frame);
    }

    fn receive(&self) -> Vec<Message> {
        self.inner
            .receive_frames()
            .into_iter()
            .filter_map(|frame| {
                let (kind, env) = frame.split_first()?;
                let payload = match *kind {
                    FRAME_BROADCAST => verify_broadcast(&self.peer, env).ok()?,
                    FRAME_DIRECT => open(&self.me, &self.peer, env).ok()?,
                    _ => return None,
                };
                serde_json::from_slice(&payload).ok()
            })
            .collect()
    }
}

/// Fresh bytes from the operating system for ephemeral keys and signing coins.
fn os_random<const N: usize>() -> [u8; N] {
    use std::io::Read;
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("the OS provides randomness");
    buf
}
