# 0018 Interactive funding and the fee output: keep the normal address as the default

Status: design, decision approved 2026-11-10. Extends [0010](0010-fee-output-and-silent-payments.md),
revises the default stated in [0013](0013-fee-collection-and-address-choice.md), and is constrained by
[0017](0017-user-held-signing-psbt-handoff.md). Not yet implemented. Tracked in issue #110; it informs
the fee'd Interactive end-to-end test in #135.

## Context: why silent payment and Interactive collide

0010 made the voluntary fee a BIP352 silent payment output, and 0013 added a per-chain choice between a
silent payment (`sp1...`) address and a normal address, with silent payment named as the default
"because it does not tag swaps on chain" (`FeeTerms.btc_address` / `xbtc_address`, `FeeDest`).

0017 introduced Interactive funding: the engine builds the unsigned funding PSBT and the user signs it
in their own wallet, so no key that can move the user's coin ever reaches the operator.

A silent payment output is not a fixed script: per BIP352 the sender derives it from the private keys
of the inputs being spent (an ECDH with those keys), which is why `sign_with_silent_fee` is the
signer's job and why a signer that is not BIP352-aware is refused. In Interactive mode the engine holds
no input keys, and a wallet without BIP352 and BIP375 support cannot be handed the derivation either,
so an `sp1` fee output cannot be produced. (BIP375 defines the PSBT fields that carry a silent payment
recipient, the ECDH share and the DLEQ proof; a future BIP352-and-BIP375-aware user wallet could do it,
but we assume nothing about any specific wallet today.) A normal address has no such requirement: the
engine places the output's scriptPubKey directly in the PSBT, the user signs it, and the counterparty
verifies it pays the agreed address on chain.

## Current state (so the decision is on the real facts)

The operator's configured per-chain fee addresses are **normal Taproot (P2TR) addresses, not silent
payment**, and the fee is currently off by default (0010: off until a legal opinion; the client fee
address defaults are presently empty). Two consequences:

- Interactive funding and the operator's intended fee **already work together** with no change: a
  normal address is exactly what Interactive can produce. There is no blocker here to enabling
  Interactive with the current fee configuration.
- `sp1` is therefore the privacy **upgrade** that #110 proposes to adopt, not the status quo. The
  collision above is the reason that upgrade cannot become the universal default.

## What is, and is not, at stake

A normal fee address, per 0013, **tags every swap lock that pays it**: the lock transaction, its inputs
and its change are marked on chain as a sovereign-swap lock paying a known address. So the privacy cost
is not only the operator's (clustering fee receipts and revealing total fee revenue); it also falls on
the **user's** funding transaction. Silent payment is the only fee shape that avoids this tagging, and
it is precisely the shape Interactive cannot build with ordinary wallets.

What is not affected: user funds, custody, and the trustlessness of the swap. The fee is voluntary and
opt-out (0010), so a privacy-sensitive Interactive user can decline the fee rather than accept the
tagging.

## Options

1. **Normal fee address as the universal default (optionally rotated).** Works in every funding mode
   including Interactive, simplest, no proof machinery. Cost: the on-chain tagging above, for both
   sides.
2. **Keep `sp1` as the default, forbid Interactive whenever a fee applies on the funded side.** Keeps
   the no-tagging property. Cost: the flagship sovereign mode either cannot charge a fee or needs a
   "fundable depends on mode and fee-type and which chain you lock" matrix, likely losing
   Interactive-mode revenue.
3. **Hybrid.** Normal is the universal default so the fee works everywhere including Interactive; `sp1`
   stays available as opt-in for operators funding hot or cold with a BIP352-aware signer who accept
   its constraints.

## Decision: option 3

Interactive is the flagship sovereign mode (0017, #46 Model 2a) and must be able to charge the
voluntary fee, so the default fee shape has to be one every funding mode can produce. Normal is already
the operator's configured choice, so this ratifies the real state rather than changing it. `sp1` keeps
its value as an opt-in no-tagging option for operators whose signer can build it, and the
`sign_with_silent_fee` machinery from 0010 and 0013 is retained for them. This revises 0013's
"silent payment is the default" to: **normal is the default; silent payment is an opt-in for a
BIP352-aware signer.**

## Fundability must be decided at publish and take time, not only at funding

The maker sets the fee address in the offer, but each side chooses its own funding mode at runtime. If
an offer carries an `sp1` fee for a chain and the side locking that chain then funds interactively, a
"fail loudly at funding time" guard can fire **after** the counterparty has already locked, leaving the
counterparty to wait out a refund timelock. So an opt-in `sp1` fee needs compatibility decided earlier:

- A maker must not publish an `sp1` fee for a chain it intends to fund interactively.
- A taker in Interactive mode must filter out, or refuse at take time, any offer whose fee address for
  the chain it will lock is `sp1`.
- The `sign_with_silent_fee` refuse-by-default guard stays as the last line, so an `sp1` fee can never
  silently degrade into a no-fee swap.

This is a Sprint 1 test to add when the `sp1` opt-in path is exercised.

## Rotation of the normal fee address (later, with an open distribution question)

Rotation can blunt the operator-side clustering of a normal fee address, though it does not help the
per-lock tagging of the user's transaction and it does not hide the address, which is public anyway.
The operator has confirmed (2026-11-10) that rotation **is required** for obfuscation; the open item is
the distribution mechanism below, not whether to rotate. It is still sequenced after enabling
Interactive, since it is not needed to run the fee'd end-to-end test or to turn Interactive on.

- **Time-based.** Rotate the configured BTC and xBTC fee addresses on a randomized interval of 25 to 40
  days. **Open sub-decision: distribution.** The default fee address ships inside third-party installs,
  so rotation means either (a) a client release per window, with every old address watched forever
  because stale installs keep paying it, or (b) a signed remote fetch of the current address, where the
  fetch must be authenticated (for example by the release key) or a spoofed source can redirect fees.
- **Per-swap derivation (stronger, deferred).** Derive a fresh fee address per offer from the
  operator's fee xpub. Caveat: an xpub shipped in a public package lets anyone derive every fee
  address, so this is not private against someone who reads the package; it only unlinks addresses from
  each other on chain.

Honest limit of any rotation: the fee address is public via offers on the relay and via the package and
its release history, so rotation limits passive chain-analysis aggregation, not linkage by anyone
watching those sources. `sp1` remains the only form that is unlinkable against them, and the one
Interactive cannot produce.

## Cross-references

- Issue #110 (adopt silent payment addresses so collection is anonymised): this note is its resolution.
- Issue #135 (verify before enabling Interactive): this note sets the fee shape its fee'd end-to-end
  test uses (a normal fee), and confirms there is no fee-address blocker to enabling Interactive.
- Designs 0010 (fee output and silent payments), 0013 (fee collection and address choice), 0017
  (user-held signing via PSBT handoff).
