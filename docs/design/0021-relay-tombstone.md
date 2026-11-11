# 0021 Relay-side tombstone for retired offers (defence in depth, #117)

Status: implemented, 2026-11-11 (proposed 2026-11-10). Addresses #117 (split from #65). Builds on
[0006](0006-nostr-client-and-relay.md) (Nostr transport), [0007](0007-abuse-deterrence-no-fund-freezing.md),
and [0020](0020-store-flood-admission-and-proof-of-work.md) (store partition and retention). The client
replay watermark (0015, `ws.rs` `since`) remains the PRIMARY guard against a retired offer re-animating;
this is a secondary, relay-side layer.

## Problem

A maker withdraws an offer by broadcasting a `Message::Withdraw { offer_id }` (0006). Receivers drop it
from discovery and remember the id as withdrawn. But the relay keeps the ORIGINAL `Offer` event in its
store until retention expires (0020: 7 days for the offer class). So:

- A client that connects fresh (or without a watermark) during that window still backfills the dead
  offer from the relay.
- The relay re-serves an offer whose maker has already withdrawn it, wasting discovery and inviting a
  bid the maker will not honour.

The client watermark makes this harmless for an up-to-date peer, but a relay that actively forgot a
withdrawn offer would stop serving dead offers to everyone, which is the point of #117.

## The constraint that gates the mechanism (resolved)

0020 flagged that the relay may not be able to tell an `Offer` from a `Withdraw`, because the message
type sits inside an envelope the relay does not open. VERIFIED (2026-11-10) against `src/envelope.rs`:
**broadcasts are signed, not encrypted** (`sign_broadcast`: `[VERSION, SUITE, schnorr, dsa, payload]`,
with `payload` the plaintext `serde_json` of the `Message`). Directed messages (`seal`) ARE encrypted,
but withdrawals are broadcasts. So the relay CAN read a broadcast's payload and distinguish an `Offer`
from a `Withdraw` without any key and without a wire change.

The event `content` is `hex(public_identity || envelope)`. To read a broadcast the relay strips the
`PUBLIC_IDENTITY_LEN` prefix, then `verify_broadcast(sender, envelope)` both authenticates the broadcast
and returns the payload bytes, which parse as `Message`. This couples the relay to the envelope and
message formats, but the relay already knows the kind (4859) and the `p`-tag convention (0006,
`is_directed`), so reading the broadcast body is a small step further, inside the same crate.

## Mechanism (no wire change)

In `accept_event` (`src/relay_server.rs`), after an event is validated and it is a broadcast (not
`p`-tagged), parse its payload:

- **`Withdraw { offer_id }`**: evict from the offers `Store` every `Offer` event whose payload offer id
  equals `offer_id` AND whose author key (`event.pubkey`, the routing key) equals this Withdraw's
  author key, then record the pair in a bounded tombstone set. The author check is the same authenticity
  rule the client uses (`routing.rs`: only the offer's author may withdraw it); it stops a third party
  from evicting someone else's offer by replaying a forged withdrawal id. The Withdraw event itself is
  still stored and fanned out (peers need it), under the directed/offer budget as today.
- **`Offer`**: if `(offer_id, author_key)` is in the tombstone set, refuse to store it (a replay of an
  offer the author already withdrew), mirroring the client's `withdrawn` guard.

### Tombstone set bounds

The set must not grow without bound (that would be a new memory vector). Bound it like the stores: a
`max_tombstones` count and a retention equal to the offer retention (a tombstone older than the offer it
guards is pointless, since the offer would have aged out anyway). Evict oldest first. Keyed by
`(offer_id, author_key)` so one author cannot tombstone another's ids.

### What this is NOT

- Not a consume-on-settlement for directed swap-step events. Those are encrypted, the relay cannot read
  them, and they already age out on the short directed retention (0020). #117 is only about retiring a
  withdrawn OFFER early.
- Not a replacement for the client watermark. A relay is untrusted; a hostile relay can ignore all of
  this. The watermark is what actually protects a client. This only makes an HONEST relay stop serving
  offers their makers retired.

## Cost and recommendation

Cost: one payload parse per accepted broadcast (cheap relative to signature verification already done),
a bounded tombstone map, and an eviction scan of the offers store per withdrawal (the offers store is
already scanned on each REQ). No wire change, no protocol bump, no client change. Coupling: the relay
gains a dependency on `envelope::verify_broadcast` + `swap::Message`, both in-crate.

Recommendation: implement the focused mechanism above (withdraw-evicts-offer + replay-tombstone),
relay-side, with unit tests in `tests/relay_server.rs`:

1. an authentic Withdraw evicts the matching stored Offer and a later REQ no longer returns it;
2. a Withdraw whose author key does not match the Offer's author does NOT evict it;
3. a replayed Offer for a tombstoned `(id, author)` is refused;
4. the tombstone set honours its count/retention bound.

It is defence in depth, so it is not urgent; but it is cheap and needs no wire change, which is why it is
worth doing rather than deferring to the fidelity-bond or PoW work. Treat the implementation as the next
step on #117; this note resolves the open question (broadcasts are readable, so no wire change) that
blocked it.

## Implementation notes (2026-11-11)

Three refinements made while implementing the mechanism in `src/relay_server.rs`, none changing the wire
or the client:

- **A tombstone is recorded only when the withdrawal actually evicted a stored offer.** The count bound
  alone would let anyone mint routing keys and flood withdrawals for random ids, pushing genuine
  tombstones out of a full set. Requiring a real eviction first means a flooder must pay the offers
  store's own (already bounded, 0020) budget before any tombstone is created, so the tombstone set
  cannot be churned by forged withdrawals.
- **The offer id is cached in the store at insert.** Each stored event carries its parsed offer id, so a
  withdrawal evicts matching offers by a cheap compare on the id and the routing key, never re-reading or
  re-verifying an envelope (an ML-DSA verify) while holding the store lock. The payload is parsed exactly
  once, when the event is first accepted.
- **Tombstone timestamps are relay-local**, not the withdrawal's `created_at`, since the acceptance path
  admits a wide range of author-supplied timestamps and the author's clock must not set a tombstone's
  lifetime.

Tests: the four cases above live in `tests/relay_server.rs` as black-box checks over the WebSocket (an
authentic withdraw evicts and a later REQ drops the offer; a foreign-author withdraw does not evict and
records no tombstone; a replayed withdrawn offer is refused; the count bound lets the oldest retired
offer reappear). The retention expiry and the author-keying are unit-tested on the tombstone set
directly. Every assertion was mutation-verified (eviction, the author check, the tombstone insert, the
membership check, the count bound, retention pruning, and the evict-first guard each fail exactly one
test when neutered).
