# 0002 Swap engine: state machine, swap wallet, persistence

Status: accepted for implementation, 2026-11-05.

## Problem

0001 gives the contract and the replay guard. A swap is a sequence of steps over hours on two chains
and with a counterparty who may vanish, lie or race. The engine has to drive each swap to one of two
safe ends, both sides claimed or both sides refunded, survive crashes and reorgs, and never miss a
refund deadline.

## Roles and flow

The **maker** publishes an offer and knows the secret; the **taker** accepts it. The maker locks first
on its chain (`T_maker` blocks), the taker locks second on the other chain (`T_taker` blocks, shorter
in time). The maker claims the taker's lock, which reveals the secret; the taker reads it and claims
the maker's lock.

```
 maker                                   taker
 Offer ───────────────────────────────►
       ◄─────────────────────────────── Bid (taker's keys)
 Accept (maker's keys, secret hash) ──►
 lock A on chain A
                                         wait N_A confirmations, verify lock A
                                         lock B on chain B
 wait N_B confirmations, verify lock B
 claim B (reveals secret)
                                         read secret from chain B, claim A
```

## State machine

A pure function `step(state, event) -> (state, actions)`; a driver feeds it events (peer messages,
chain observations, block heights) and carries out the actions (broadcast, send message). **The new
state is written to disk before any action runs**, so a crash repeats an action rather than losing
one, and every action is safe to repeat (broadcasting a known transaction again, resending a message).

```
 maker:  Offered ─bid─► Accepted ─lock A sent─► LockedA ─lock B ok─► Claiming ─B claimed (deep)─► Done
            │              │                       │                     │
            ▼              ▼                       ▼ T_maker reached      ▼ (claim keeps being
         Expired        Abandoned              RefundingA ─────────► Refunded    rebroadcast)

 taker:  BidSent ─accepted─► WaitLockA ─lock A ok─► LockedB ─secret seen─► ClaimingA ─(deep)─► Done
                                │                     │
                                ▼ deadline            ▼ T_taker reached
                             Abandoned            RefundingB ───────────► Refunded
```

Rules taken over from BasicSwap's failure handling (`docs/edge-cases.md`):
- Deadlines are counted from **confirmation** of a lock, not from its broadcast (row 11): CSV already
  does this on chain; the engine's own "lock not confirmed in time" deadline uses the same rule.
- A broadcast transaction is **watched until it is N blocks deep**; if it is not in the mempool or a
  block, it is broadcast again (rows 12, 13). A reorg that removes a claim sends the swap back to
  re-broadcasting, never to "done".
- **The taker locks only while enough of `T_maker` remains**: remaining blocks of lock A, converted to
  time, must exceed `N_B` confirmations plus `T_taker` plus a safety margin. Otherwise a maker whose
  lock confirmed late could claim B after `T_maker` has passed and refund A as well. If the condition
  fails, the taker abandons and the maker refunds.
- The maker reveals the secret only after the taker's lock is verified and N_B deep, and only while
  `T_taker` minus a safety margin has not passed; otherwise it refunds instead.
- The taker claims as soon as the secret is seen, and refunds when `T_taker` is reached without one.
- A failed step ends in the refund branch, never in an unknown state (row 18).
- An offer cannot be taken by the engine that made it (row 14).
- Amounts are integers in satoshis; a partial bid converts at the offer's rate rounding down for the
  side that receives, and bids that round to below dust are refused (row 15).

## Confirmation policy

Depths are not the maker's to choose: the maker writes the offer, and the depth that protects the
taker cannot be left to the maker. Each engine applies its own `Policy`, by chain and by the swap's
BTC-side amount, and uses the larger of the policy and the offer. A spend counts as final, and stops
being watched, only at the policy depth of its chain, so a reorg on xBTC cannot undo a claim we
already stopped watching. Offers whose timelocks cannot fit these depths are refused, and so are
amounts above the policy's limit. Lock inputs need `minconf` confirmations. The standard table
(xBTC 6 / 12 / 36, BTC 1 / 2 / 3 up to 0.01 / 0.1 / 1 BTC) is provisional until a reorg-cost
study of xBTC.

## Swap wallet

Funding goes through a dedicated wallet on the user's own node of each chain (`walletcreatefundedpsbt`,
then `walletprocesspsbt`). The node keeps the keys of the user's balance, chooses coins and, on
xBTC, signs with the replay-protected signature hash. **Every funded transaction passes the replay
guard before it is signed.** The engine itself holds only per-swap keys for the contracts, derived
from its own seed by hardened BIP32 derivation at a per-swap index. Each secret is the SHA-256 of a
separate hardened derived private key, so no public key ever reveals it, and a restored seed recovers
every swap. Claims and refunds pay to fresh addresses of the same node wallets.
Running BTC through Electrum instead of a node needs an engine-side wallet: milestone M2b. The same
wallet is what makes silent payment fee outputs possible, because a BIP352 sender needs its inputs'
private keys and neither node wallet can send to a silent payment address.

## Persistence

One file per swap, JSON, replaced atomically (write to a temporary file, fsync, rename, fsync the
directory). No database dependency. Encryption at rest comes with the user-facing package.

## Transport

A `Transport` trait carries the protocol messages. Tests use an in-memory pair; Nostr with the
post-quantum envelope comes in the next milestone. Messages carry no keys beyond public key hashes
and the secret hash; the secret itself never travels.

## Test plan

Two engines on regtest (Core and Knots BLAKE2b), connected by the in-memory transport:
- success in both directions (maker sells BTC, maker sells xBTC);
- taker never locks: maker refunds after `T_maker`;
- maker never claims: taker refunds after `T_taker`, maker refunds after `T_maker`;
- wrong lock amount or script from the counterparty: no further step, refund;
- maker's lock confirms so late that too little of `T_maker` remains: taker refuses to lock, maker refunds;
- slow lock confirmation, dropped first claim broadcast, claim reorged out (`invalidateblock`);
- self bid refused; partial bid rounding;
- restart: the engine is dropped and rebuilt from its files after every state change of a full swap,
  and the swap still completes;
- replay: funding from a coin that also exists on the other chain is refused before signing.
