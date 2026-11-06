#![no_main]
//! Fuzz the swap wire-message deserializer (serde_json -> Message). A counterparty's message arrives
//! as untrusted bytes over the relay; deserializing must never panic, only reject.
use libfuzzer_sys::fuzz_target;
use sovereign_swap::swap::Message;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Message>(data);
});
