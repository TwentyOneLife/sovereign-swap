# How it works: the atomic swap

A Sovereign Swap is a classic **hash time-locked contract (HTLC)** atomic swap, run across two chains at
once. This page explains why it is trustless: at no point can one side take both coins, and the worst
case for an honest party is getting their own coin back.

## The idea in one sentence

Both sides lock their coin into a contract that can be claimed only by revealing the **same secret**, and
the person who holds the secret has to reveal it on-chain to claim, which hands the secret to the other
side so they can claim too.

## The two contracts

One side is the **maker** (posts the offer) and the other is the **taker** (accepts it). Say the maker
sells **xBTC** for the taker's **BTC**. The maker picks a random secret `s` and computes `H = SHA256(s)`.

- **HTLC #1, on xBTC, funded by the maker:** claimable by the **taker** if they present `s`; refundable
  by the **maker** after a long timelock (40 blocks by default).
- **HTLC #2, on BTC, funded by the taker:** claimable by the **maker** if they present `s`; refundable
  by the **taker** after a shorter timelock (20 blocks by default).

The timelocks are deliberately unequal: the taker's refund comes **first**, so the maker must claim (and
reveal `s`) while the taker is still committed, which leaves the taker enough time to claim with the
revealed `s`.

## The sequence

```
 Maker (sells xBTC)                      Taker (sells BTC)                 On chain
 ──────────────────                      ─────────────────                ────────
 pick secret s, H = SHA256(s)
 publish Offer  ─────────────────────────────────────────────► (over Nostr)
                          ◄───────────────── Bid (swap id, taker key hashes)
 Accept (H, maker key hashes) ────────────────────────────────►
 fund HTLC #1 on xBTC ─────────────────────────────────────────────────► xBTC: locked
      (claim: taker+s / refund: maker after 40)
                          taker reads and verifies HTLC #1
                          fund HTLC #2 on BTC ─────────────────────────► BTC: locked
                               (claim: maker+s / refund: taker after 20)
 maker reads and verifies HTLC #2
 claim BTC with s ─────────────────────────────────────────────────────► BTC: s now public
                          taker reads s from the BTC claim
                          claim xBTC with s ───────────────────────────► xBTC: taker paid
 ✅ maker now holds BTC, taker now holds xBTC
```

**Reading the diagram, step by step:**

1. The maker makes an **offer** and the taker **bids**; they exchange public key hashes so each contract
   names who can claim and who can refund. These messages travel over [Nostr](/guide/transport-and-privacy),
   not on chain.
2. The **maker funds HTLC #1** on xBTC. It can be spent by the taker with `s`, or refunded by the maker
   after 40 blocks.
3. The taker **verifies HTLC #1 is really on the xBTC chain** (correct amount, correct hash, correct
   refund path) before risking anything, then **funds HTLC #2** on BTC, spendable by the maker with `s`
   or refunded by the taker after 20 blocks.
4. The maker **verifies HTLC #2 on BTC**, then **claims it by revealing `s`**. The claim transaction puts
   `s` on the BTC chain in public.
5. The taker **reads `s`** from that transaction and **claims HTLC #1** on xBTC.

Both sides end with the coin they wanted. The secret tied the two claims together.

## Why no one can cheat

```
                  if the swap stalls at any point, the timelocks resolve it
                  ───────────────────────────────────────────────────────
   maker funds, taker never funds   ─►  maker refunds HTLC #1 after 40 blocks
   both fund, maker never claims    ─►  taker refunds HTLC #2 after 20 blocks,
                                        then maker refunds HTLC #1 after 40
   maker claims (reveals s), taker  ─►  taker claims HTLC #1 with s (has until 40)
     tries to skip paying                 there is no "skip": claiming IS paying
```

- **The maker cannot take the taker's BTC without paying.** To claim HTLC #2 the maker must reveal `s`
  on chain, which immediately lets the taker claim HTLC #1.
- **The taker cannot take the maker's xBTC without paying.** HTLC #1 is only claimable with `s`, and the
  taker only learns `s` after the maker has claimed HTLC #2 (so the maker has already been paid).
- **A party that walks away loses nothing but time.** Every unfinished state ends in a refund of your own
  coin at your own timelock. This is the key property: *an interrupted swap always resolves to
  claim-or-refund.* See the [safe swap lifecycle](/guide/lifecycle) for how the engine guarantees it.

## The replay guard

Each swap uses **fresh, per-swap keys** and binds its signatures to that swap. A lock, signature, or
secret from one swap cannot be replayed into another swap or onto the other chain to claim something it
was not meant for. This is covered by the HTLC-and-replay-guard decision
([0001](/design/0001-htlc-and-replay-guard)).

## What is on chain vs off chain

- **On chain:** the two HTLCs and their claim/refund spends. These are the only things that move coins,
  and they are enforced by each chain's own consensus, not by this software.
- **Off chain (over Nostr):** the offer, the bid, the acceptance, and the fee proof. These coordinate the
  swap but cannot move a coin. If a message is lost or a relay misbehaves, the worst case is a stalled
  swap that refunds. See [transport and privacy](/guide/transport-and-privacy).
