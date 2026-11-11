# Transport and privacy

Coordination messages (offers, bids, swap steps) travel over **Nostr** relays, dialed **through Tor** by
default. The transport is untrusted by design: it cannot move a coin, cannot read a directed message, and
cannot tie a trade to your IP address.

## Why Nostr

Nostr is a minimal relay protocol: clients publish signed events to relays, and subscribe to events by
filter. Sovereign Swap uses it purely as store-and-forward plumbing for the
[post-quantum envelope](/guide/envelope). Each protocol message becomes one Nostr event of a dedicated
kind (**4859**), whose content is the sealed/signed envelope in hex.

<img class="diagram" src="/diagrams/transport-and-privacy-1.svg" alt="Why Nostr (diagram)" loading="lazy" />

- **Offers** are broadcast events (no recipient); any subscriber can see and verify them.
- **Bids, accepts, swap steps, fee proofs** are directed events tagged to one recipient and sealed to it;
  the relay forwards opaque ciphertext.
- Peers are identified only by a **throwaway routing key**, learned from the offers and bids that arrive.
  Two people who have never met can complete a swap through a relay they both happen to use.

## Tor first

<img class="diagram" src="/diagrams/transport-and-privacy-2.svg" alt="Tor first (diagram)" loading="lazy" />

By default the client dials relays (and can dial nodes) as **`.onion`** services through a Tor SOCKS5
proxy. Because the envelope already encrypts and authenticates end to end, no TLS is layered on the Tor
path. The effect:

- a relay never learns your IP address;
- a network observer sees only Tor traffic, not that you are trading or with whom;
- you do not need to expose any inbound port.

Node connection over Tor is specified in [design 0011](/design/).

## What the relay can and cannot do

| The relay **can** | The relay **cannot** |
|---|---|
| store and forward kind-4859 events | move, hold, or freeze any coin |
| read a public **offer** (it is only signed) | read a **directed** message (it is encrypted) |
| drop, delay, or reorder messages | forge a message (signatures are end-to-end) |
| see routing keys and timing | learn your IP (Tor) or your real identity |

The worst a hostile or broken relay can do is **withhold or delay** messages. That cannot cost a coin: a
swap that cannot make progress simply refunds at its timelock (see [lifecycle](/guide/lifecycle)). For
resilience you can connect to more than one relay.

## Hardening against a flooded relay

Because a relay is public and anyone can publish, the relay is hardened against flooding: per-connection
rate limits on both publishing and subscribing, a cap on how many events one request can return, a
byte-bounded event store split so a flood of directed messages cannot evict open offers, and idle- or
stalled-connection reclamation. The full analysis is in
[design 0007](/design/) and [design 0020](/design/). None of this can affect custody; it only protects
the relay's availability.

## Re-announcement so discovery self-heals

A busy or flooded relay may evict an old offer from its store. Makers **re-announce** their live offers on
a short timer, so an evicted offer returns on its own and a taker who connects later can still find it. A
re-announced offer is a fresh event, so it is never confused with a stale one, and the maker's withdrawal
still retires it everywhere (see [design 0020](/design/) and [0021](/design/)).
