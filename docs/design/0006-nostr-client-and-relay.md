# 0006 Nostr client and relay (M3b)

Status: design; built in increments.

## Goal

Deliver the format-3 envelopes (design 0005) over Nostr relays so swaps work between parties who have
never met, over Tor by default. The relay is untrusted: it only stores and forwards opaque events.

## How a swap maps onto Nostr

Every swap message is already an envelope (bytes). M3b wraps each in a Nostr event of our kind and
routes it:

- **Offer** (broadcast): a kind-4859 event whose content is the broadcast-signed envelope. Any taker
  subscribing to the kind sees it and learns the maker's public identity from inside the signed
  offer.
- **Bid, accept, swap steps** (directed): a kind-4859 event tagged with the recipient's routing id
  (`p` tag), content is the sealed envelope. Only the addressed peer processes it; others ignore it.

The envelope already provides confidentiality and authenticity; the Nostr layer provides delivery,
addressing and discovery. A relay that drops or forges events cannot break a swap: forged content
fails the envelope, and a dead relay is replaced by another the client also lists.

## The event (NIP-01)

An event is `{id, pubkey, created_at, kind, tags, content, sig}`.
- `id` = SHA-256 of the canonical serialization `[0, pubkey, created_at, kind, tags, content]`
  (compact JSON, NIP-01 escaping).
- `sig` = secp256k1 Schnorr (BIP340) over `id`, under `pubkey` (x-only). We already have Schnorr in
  the tree.
- The event `pubkey` is a per-swap routing key, **not** a party's long-term identity; the real
  identities live inside the envelope. So the relay sees only throwaway routing keys.

## Increments

- **M3b-1 (this doc's first PR): the event layer.** `src/nostr.rs`: build, serialize, id, sign, and
  verify an event; parse one from the wire; NIP-01 canonical escaping. Pure, tested, no network.
- **M3b-2: an in-process relay and a routing client. Done.** `src/relay.rs` (store-and-forward,
  dedup, filter by kind and `p` tag, never your own events) and `src/routing.rs`
  (`RelayTransport`: broadcast offers, route bids/steps to the peer learned from the signed offer,
  seal to its identity). Tests: an offer reaches two takers, a bid reaches only the maker, a forged
  event is dropped, and a full swap routes over the relay. Original note: A `Relay` that stores events and serves REQ
  subscriptions (by kind and by `p` tag) with dedup, and a `RelayTransport` implementing
  `ByteTransport` over it: publish our events, subscribe for ours, dedupe by event id. Routing: a
  taker subscribes to the kind to find offers; a bid is addressed to the maker's routing key from the
  signed offer. This runs the multi-peer offer/bid flow in CI with no network.
- **M3b-3: the real wire. Done (code).** `src/ws.rs`: `WsConn`, a `RelayConn` over a real relay via
  WebSocket. Decision taken: **tungstenite** (pinned `=0.30.0`, blocking, no TLS, `handshake`
  feature) for the RFC 6455 framing, plus a hand-rolled SOCKS5 connector (~40 lines, no dependency)
  so an `.onion` is dialed inside Tor. Tor-first means plain `ws://` inside the Tor circuit (content
  is end-to-end encrypted by the envelope); clearnet `wss://` (rustls) is a later option. One owner
  thread holds the socket, draining publishes and buffering a `REQ` subscription's events; routing
  is the same generic code as the in-process relay (`RelayConn`). Tested in CI against a localhost
  toy relay (`tests/ws_relay.rs`): the tungstenite handshake, NIP-01 framing and multi-peer routing
  over real WebSocket frames. Tor interop against a live relay is a manual check (the relay address
  is operator config, never in this repo).
- **M3c: DoS and protocol-fuzz** the relay from the homelab Kali VM (design 0003 Layer C, issue #58).

## Test plan

- M3b-1: an event round-trips (build, serialize, id, sign, verify); a tampered content, id or sig is
  rejected; the canonical serialization escapes per NIP-01; a fuzz test parses random bytes without
  panicking.
- M3b-2: a maker's offer reaches two subscribed takers; a bid addressed to the maker reaches only the
  maker; duplicate events are delivered once; the full two-engine swap runs over the relay.
- M3b-3: interop against a real relay; a swap over Tor; a dead relay is tolerated.
