# 0005 Nostr transport and the post-quantum envelope (M3)

Status: design, not implemented.

## Goal

Replace the in-memory `Transport` with a real one: offers, bids and swap messages travel over Nostr
relays, end-to-end encrypted and signed with a hybrid classical + post-quantum envelope. The relay
is untrusted; every guarantee rests on the envelope. Default transport is Tor; clearnet optional.

## Where it plugs in

The engine already talks to a `Transport` trait (`send`, `receive`) and carries no keys in its
messages beyond public key hashes and the secret hash. M3 adds a `NostrTransport` implementing that
trait; the engine does not change. The `Message` enum gains nothing; it is serialised, encrypted and
wrapped in a Nostr event.

```
 engine ── Message ──► envelope (encrypt + hybrid-sign) ──► Nostr event (kind 4859) ──► relay(s) over Tor
 engine ◄─ Message ─── envelope (verify + decrypt)      ◄── Nostr event             ◄── relay(s)
```

## Envelope (payload format 3)

Per `xbtc-swap-spec.md` section 5. Suite 0x01, NIST category 5, hybrid so an attacker must break both
the classical and the post-quantum scheme:

| Function | Primitive |
|---|---|
| Key agreement | X25519 + ML-KEM-1024 (FIPS 203), both secrets into the KDF |
| Signature | secp256k1 Schnorr (BIP340) + ML-DSA-87 (FIPS 204), both must verify |
| AEAD | AES-256-GCM |
| KDF | HKDF-SHA-512 |

- Offers are broadcast: not encrypted, but hybrid-signed, and the offer body carries the maker's PQ
  public keys. Bids and later messages are encrypted to the keys in the signed offer; a bid carries
  the taker's keys for the replies. Per-offer keys by default.
- A message is rejected unless both signatures verify; the session key needs both shared secrets;
  the suite is inside the signed header, so there is no downgrade. Duplicates and expired messages
  (`created + ttl`) are dropped.

## Library choice (verify before coding)

Rust post-quantum support must be picked on provenance, not convenience, per GUARDRAILS 4:
- Candidates: `libcrux-ml-kem` / `libcrux-ml-dsa` (formally verified) or `aws-lc-rs`. Pin exactly,
  verify the source, prefer the formally verified one for the KEM and signature.
- Classical pieces reuse the `bitcoin`/`secp256k1` crates already in the tree (Schnorr) plus
  `x25519`, `aes-gcm`, `hkdf`, `sha2`, each pinned.
- The envelope is specified byte-for-byte with published test vectors, so the Rust engine and the
  Rust coordinator (and any Python reference) agree. Fuzz the decoder (design 0003 Layer B).

## Nostr client

A minimal client (no heavy framework): connect to a relay over a SOCKS proxy (Tor), publish kind-4859
events, subscribe by kind and recipient tag, dedupe by event id. List several relays; a dead or
censoring relay must not endanger a swap (the client retries others). No account, no metadata beyond
what a swap needs.

## Milestone split

- M3a: the envelope (format 3) with test vectors and decoder fuzzing, behind the `Transport` trait,
  still over the in-memory pair, so the two-engine tests run unchanged on the encrypted envelope.
- M3b: the Nostr client and Tor transport; a relay (`sovereign-swap-relay`) for tests.
- M3c (then): Layer C of design 0003, DoS and protocol-fuzz the relay from the homelab Kali VM.

## Test plan

- Round-trip and tamper: a message with either signature broken, a swapped suite byte, a replayed
  envelope, or a truncated frame is rejected; a valid one round-trips.
- Harvest-now: no swap secret or private key ever appears in an envelope's cleartext (asserted over
  every message type).
- The existing two-engine swap and load tests pass with the real envelope substituted for the
  in-memory messages.
