# Safe swap lifecycle

The engine drives every swap through a small state machine. Its one invariant: **a swap can always reach
claim-or-refund**, no matter what the counterparty, relay, or network does. This page shows the phases
and the rules that keep a swap from ever stranding a coin.

## The phases

```
                 ┌──────────┐
                 │ Offered  │  maker posted an offer / taker is bidding
                 └────┬─────┘
                      ▼
                 ┌──────────┐  a lock is being funded on chain
                 │ Locking  │
                 └────┬─────┘
            ┌─────────┼───────────────┐
            ▼         ▼               ▼
      ┌──────────┐ ┌──────────┐  ┌───────────┐
      │ Claiming │ │Refunding │  │ Abandoned │  (never funded, safe to drop)
      └────┬─────┘ └────┬─────┘  └───────────┘
           ▼            ▼
      ┌──────────┐ ┌──────────┐
      │   Done   │ │ Refunded │
      └──────────┘ └──────────┘
```

- **Offered** - the offer is live or a bid is in flight. No coin is committed.
- **Locking** - a lock is being funded. The engine will only move forward once it sees the required
  confirmations on chain.
- **Claiming** - the counterparty's lock is verified and the engine is spending it with the secret.
- **Refunding / Refunded** - a timelock was reached; the engine reclaims its own lock.
- **Done** - both legs settled.
- **Abandoned** - the swap ended before any coin was committed (so there is nothing to refund).

## The rules that make it safe

These come from the operator review recorded in [design 0015](/design/) and the funding-handoff designs
[0017](/design/)/[0019](/design/):

- **Verify on chain before committing.** The engine funds its lock only after the counterparty's lock is
  really on chain with the agreed amount, hash, refund path, and fee output. A message is never enough.
- **Never reveal the secret to a cheat.** The maker (secret-holder) claims the taker's lock only after
  verifying it fully, including the fee. If anything is wrong, it refuses and refunds; the secret stays
  secret, so neither side can claim and the taker gets its coin back.
- **A maker that cannot fund gives up on time.** An unfunded maker stops arming and abandons *before* the
  taker's lock window could close, so it never funds a lock against a swap the taker already walked away
  from.
- **Timelocks are ordered.** The taker's refund comes before the maker's, so the maker must reveal the
  secret while the taker is still committed, leaving the taker time to claim.
- **Restart-safe.** The engine's state is persisted; a crash and restart resume the same swap, re-verify
  against a fresh chain view, and never rebuild a parked funding transaction (which could strand a
  signature).
- **Adopt a late lock.** For interactive funding, if you broadcast your signed lock late, the engine will
  still recognise and drive it (within a bounded window) rather than lose track of it ([0019](/design/)).

## Operator teardown without surgery

Earlier builds needed hand-editing of state to clear a stuck swap; that is gone. The engine exposes
first-class primitives:

- **Withdraw an offer** - take it off the market and tell peers to drop it.
- **Abort a swap** - mark a not-yet-locked swap abandoned. Refused once a lock is funded, because a
  funded lock must go through the timelock refund, never a forced abandon that could strand the coin.

So an operator can always wind a swap down to a safe state through the API, never by touching files.

## What a stall looks like

```
   maker funds, taker never funds   ─►  Locking ─► (40 blocks) ─► Refunding ─► Refunded
   both fund, maker never claims    ─►  taker:  (20 blocks) ─► Refunded
                                        maker:  (40 blocks) ─► Refunded
   relay drops a message            ─►  swap cannot progress ─► refund at timelock
```

In every case the coins come home. That is the property the whole design protects.
