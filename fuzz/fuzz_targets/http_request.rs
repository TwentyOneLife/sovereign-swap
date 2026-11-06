#![no_main]
//! Fuzz the daemon HTTP request reader. It parses fully untrusted client bytes from the onion, so a
//! panic here is a remote denial of service. The reader must only ever return Ok or an error code.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sovereign_swap::daemon::fuzz_read_request(data);
});
