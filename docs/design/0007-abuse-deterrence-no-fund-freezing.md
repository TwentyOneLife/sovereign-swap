# 0007 Abuse deterrence, and why funds are never frozen

Status: decision, 2026-11-05.

## The question

Can a verified attacker be penalised by freezing their funds until they contact us (email, Nostr) to
have them released manually?

## Decision: no. Funds are never frozen, by anyone, including the operator.

It is not an implementation gap; it is a boundary the design will not cross.

### Why it cannot be done

- **We hold nothing to freeze.** Coins live in the user's own wallet and, during a swap, in HTLCs
  that only the two counterparties can spend (claim with the preimage, or refund after the timeout).
  There is no operator key in that path. The engine's own wallet is the user's, planned cold (M2b).
- **Bitcoin and Bitcoin Blake2b have no freeze primitive.** No one can prevent another party's UTXO
  from being spent; only the holder of the keys, or the chain's consensus, can. We are neither.
- **A relay-level "attacker" has no funds in view.** Relay abuse (flooding, malformed events, DoS)
  comes from throwaway routing keys and connections, not from an on-chain identity tied to coins.

### Why it must not be done, even if it could

A freeze-and-release switch would require taking custody of user funds and giving the operator a
lever to seize or withhold them pending an out-of-band message. That turns a sovereign, non-custodial
tool into a bank with a honeypot and a censor's switch, the precise thing this project exists to
avoid (self-custody, no permission required; see the manifesto and ADRs on no custody). It also
re-creates the regulated posture (custody, discretionary control of client assets) that keeps the
service non-custodial and low-regulation.

## What we do instead: make abuse expensive and ineffective

Deterrence without custody, in layers:

1. **Relay controls** (`src/relay_server.rs`): verify every event, serve one kind, cap event size,
   rate-limit per connection, bound the store with a TTL, cap connections, and drop or ban abusive
   connections and IPs. This stops relay abuse at the door.
2. **Proof of work on messages**: a small per-message PoW (BasicSwap already carries one) makes
   flooding cost the attacker CPU; the relay can raise the required difficulty under load.
3. **Several relays**: no single relay is a chokepoint; a censoring or dead relay is replaced by the
   client, so taking one down buys an attacker nothing.
4. **Reputation, opt-in**: standing earned from completed swaps, so a key that grieves loses it and
   honest peers refuse to trade with it. Social, soft, and never touches funds.
5. **Forfeitable bonds, optional and heavier**: a time-locked fidelity bond a party posts and
   forfeits if it misbehaves, in the spirit of Bisq's bonded reputation. It is non-custodial (the
   operator never holds it) but adds protocol complexity, so it is a later option, not v1.

## The structural backstop

A denial-of-service attacker can cost the network time, never a trader a coin: an interrupted swap
always resolves to claim-or-refund (design 0002, 0003). So there is nothing to be gained by seizing
an attacker's money, and nothing we are able or willing to seize.
