# 0029 Relay federation: connecting sovereign-relays into shared markets

Status: concept / design sketch, 2026-11-13. NOT scheduled; captured because it is the natural next
evolution of the discovery layer and the question "can my market connect to other people's markets?"
has a clean answer in this architecture. No code yet.

## The question

Today one `sovereign-swap-relay` is one market: a maker and a taker who both point at it can find each
other. If other people run their own open-source relay, each is a separate island. Can relays connect,
so a user can choose which market(s) to trade in, or see a combined book?

## Why this is tractable here (and safe)

Two properties of the design make federation easy and low-risk, unlike a custodial exchange:

1. **The relay is dumb discovery, not a coordinator.** It is a Nostr-style relay: makers publish offer
   events, peers subscribe and discover, and the actual swap is a peer-to-peer, envelope-encrypted
   exchange routed through it. The relay never holds funds, keys, or swap state.
2. **The swap is trustless regardless of where the offer was found.** Settlement is the non-custodial
   HTLC with per-offer verification (amount, voluntary fee, timelocks, and under 2b the user-held keys).
   An offer discovered on a stranger's relay is validated exactly like one on your own before you lock a
   satoshi. So merging markets cannot introduce a theft vector; the worst a hostile relay can do is
   withhold or spam offers (a DoS / availability problem) or observe who subscribes (a privacy problem,
   mitigated by Tor). It can never make you lose funds.

That second property is the crux: because the money leg is trustless, **market size and market trust are
decoupled**. You can safely pool discovery with relays you do not trust at all.

## Where the code already is

`Settings.relays` is a `Vec<String>`, and `RelayConn` is documented as "a connection to one or more
relays". But the daemon currently connects to only `settings.relays.first()` (`daemon/mod.rs`), and
`RelayTransport` holds a single `conn`. So the model anticipates many relays; only the connection layer
is single today. Federation is an additive build, not a redesign.

## Two paths

### A. Client-side aggregation (the Nostr way; recommended first)
The client connects to N relays at once and the market it sees is the UNION of their offers; it publishes
its own offers to the relays it chooses, and routes a swap's messages over whichever relay the
counterparty is reachable on. This is how Nostr clients already work.
- Build: a multi-connection transport (a `Vec<WsConn>`), publish to the selected set, poll+merge+dedup
  across all (offers already carry a stable id, so dedup is by id), and remember which relay a
  counterparty was seen on for the swap's direct messages.
- "Which marketplace" becomes "which relays am I subscribed to", a user choice in the config/UI. A relay
  directory (a NIP-65-style published relay list, or a curated list in the app) lets users discover other
  sovereign-relays to add.
- No protocol change, no relay change, no new trust. This alone gives shared/combined markets.

### B. Relay gossip / mesh (later, optional)
Relays forward events to peer relays, so a client on one relay transparently sees a merged book. More
powerful (a thin client needs only one connection) but more complex: loop prevention, dedup, spam and
flood control across operators, and a peering policy. Path A makes B unnecessary for a while, and B can
be added under the same offer-event format when scale demands it.

## Design constraints federation must keep

- **Per-offer verification stays mandatory** and unchanged; a federated offer is a stranger's offer.
- **Offer-event dedup by id** across relays (the client must not show or double-count the same offer
  seen on two relays).
- **Withdrawal/expiry must propagate per relay** (design 0021/0026): a withdraw or a TTL is relative to
  where the offer was published; the client ages each out per its source.
- **Privacy:** more relays means more operators observing your subscriptions and offers; keep Tor the
  default and let the user scope which relays see their own offers vs. which they only read.
- **No global order matching:** there is no central book; each client aggregates its own view. That is a
  feature (sovereignty), not a gap.

## Recommendation

Path A (client-side multi-relay aggregation) is the right first step: additive, safe by construction,
and it directly delivers "choose your market(s)" by choosing your relay set. A relay directory for
discovery is the companion UX. Path B (relay mesh) is a later scale option. File as an issue when
scheduled; this note is the reference for the decision.
