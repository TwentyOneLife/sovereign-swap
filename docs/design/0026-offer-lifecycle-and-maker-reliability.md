# 0026 Offer lifecycle and maker reliability without penalties

Status: design, proposed 2026-11-12. Not yet fully implemented. Extends the safe-swap lifecycle
([0015](0015-safe-swap-lifecycle.md)), the abuse-deterrence stance ([0007](0007-abuse-deterrence-no-fund-freezing.md)),
and the relay tombstone ([0021](0021-relay-tombstone.md)). Tracked in issues #211 (withdraw in the GUI)
and #212 (maker-set expiry).

## The question

A maker can post an offer it cannot or will not fill: it never funds, its funding gets spent elsewhere,
or it simply vanishes. Should the system penalize such a maker, for example by removing or pausing its
offers, slashing a bond, or banning it?

## Why penalties do not fit this system

A penalty needs one of two things the design deliberately does not have:

- **Custody.** There is nothing of the maker's to slash. The service holds no maker funds; every coin
  stays in the user's own wallet until the atomic swap moves it (0014, 0015). A slashing bond would
  reintroduce custody, the exact thing the product exists to avoid.
- **Identity.** Peers are throwaway routing keys, no account, no KYC (0005, 0006). There is nothing to
  ban: a "penalized" maker makes a fresh key and reappears. A persistent reputation key would force
  identity on makers and leak a graph of their activity.

[0007](0007-abuse-deterrence-no-fund-freezing.md) already settled the broader version of this: no
fund-freezing, no blacklists. Penalizing a maker is the same move in a smaller costume, and is rejected
for the same reasons.

## The real goal: a dead offer is cheap and self-cleaning

Reframe from "punish the bad maker" to "make an unbacked offer cost the taker nothing and disappear on
its own." Most of this already holds:

1. **The taker risks nothing against an unfunded maker.** The maker locks first; the taker only locks
   after verifying the maker's on-chain lock (0001, 0015). An unfunded maker never locks, so the taker
   never locks: no principal at risk, only time.
2. **The maker self-abandons.** `decide_maker` abandons at the `lock_deadline` cutoff (`swap.rs`), so a
   maker that cannot reach funding depth in time gives up instead of arming a late lock. Shipped.
3. **Prune-on-fill.** A taken offer is removed so it cannot be re-taken (M1). Shipped.
4. **Relay admission control.** Store-flood admission + proof of work + per-connection rate limits
   ([0020](0020-store-flood-admission-and-proof-of-work.md)) bound how many offers a maker can spam.

The residual harm from a flaky maker is **wasted taker time and relay clutter**, not lost funds. Two
lifecycle levers close most of that gap, and are the sanctioned direction:

### L1. Withdraw / pause an offer (#211)
The daemon already supports it end to end (`POST /offers/{id}/withdraw`, the `Withdraw` Nostr message,
the relay tombstone 0021); it is simply not in the GUI. Surface a "My offers" view with a Withdraw
button so a maker can remove an offer it can no longer back. Pausing is withdraw + re-post later.

### L2. Maker-set expiry (#212)
Let the maker stamp an offer "valid for N days". Carry a `valid_until` on the offer, honored client-side
(do not show or take an expired offer) and, where the relay parses offers, tombstoned at expiry. Make it
a backward-compatible optional field: an old peer that ignores it falls back to the existing 7-day
re-announce TTL, so this needs no hard protocol break. This also shortens the orphan-offer window (an
un-withdrawable offer from a retired identity ages out at its expiry instead of the full TTL).

## The only accountability lever that fits: optional proof-of-funding

If, later, takers want a stronger signal than "the offer exists", the one mechanism compatible with the
model is **opt-in proof-of-funding**: the maker attaches a proof it controls a funded UTXO (a signed
message over the offer, or a commitment to an outpoint), and takers filter for "backed" offers. Its
limits are honest and must be stated in the UI:

- it **reveals** the maker's UTXO, a privacy cost the maker opts into per offer;
- the funds can still be **moved afterward**, so it is a *soft signal at post time*, never a guarantee;
- it is **optional** - an offer without it is still valid, just less assuring.

This is a filter takers may prefer, not a gate or a penalty. Design only; not scheduled.

## What we explicitly will NOT build

- No bond/escrow/slashing (needs custody).
- No ban-list, no persistent maker reputation imposed by the system (needs identity; leaks the graph).
- No automated "removal" of another maker's offer: a peer can only tombstone its **own** offer
  (`NotYourOffer` guards this today); the relay TTL handles the rest.

## Constraints this leaves behind

- Taker-side time cost against a flaky maker is bounded by `lock_deadline`, not by any maker penalty;
  keep that deadline the primary protection.
- Any "backed offer" proof is advisory; the UI must never present it as a guarantee of settlement.
- Expiry is defence in depth over the re-announce TTL, not a replacement; both must agree that an
  unseen/expired offer is gone.
