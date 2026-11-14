# 0031 Watchtower broadcast, refined: refund-first and secret-safe

Status: design, 2026-11-14. Refines the watchtower sketch in
[0027](0027-user-held-claim-refund-and-watchtower.md) section 3 for a HOSTED engine (model 2b of
[0014](0014-non-custodial-rearchitecture.md)). It keeps the one invariant that the operator holds
nothing that can move a user's coin, and corrects a case where the 0027 sketch would have broken it.
Builds on the user-held claim/refund path (0027), the safe lifecycle ([0015](0015-safe-swap-lifecycle.md))
and the payout destinations (F5, implemented). No code yet; this is the spec the optional watchtower
slice follows.

## Why a watchtower at all

The timelock constraint (0014) says someone holding the user's key must be online to claim in time and
to refund if a swap stalls. A 2a self-hosted node keeps its client running. A 2b user runs in a browser
that they will close. An optional, operator-run **watchtower** removes the online-presence requirement
WITHOUT custody: it only ever broadcasts transactions the user has already signed, to outputs the user
fixed. It is optional; without one, a 2b user keeps the browser open for the swap, exactly as 2a does.

## The invariant this must not break

From 0014 and 0027, unchanged: the operator's infrastructure (the hosted engine and the watchtower)
never holds anything that can move a user's coin, and specifically **no spend key, no seed, and no
secret**. A watchtower may hold only public data and fully user-signed transactions whose outputs are
fixed to the user's own addresses.

## The problem with the 0027 section 3 sketch

The 0027 sketch says "the maker pre-signs its claim with `s` already embedded (the maker holds `s`)" and
hands it to the watchtower. That breaks the invariant: a maker claim carries the secret `s` in its
witness, so handing it to the watchtower hands the operator `s` BEFORE it is public. The secret `s` is
the value that unlocks BOTH legs of the swap; the atomicity of the swap depends on `s` becoming known
only at the moment the maker claims on chain. An operator that learns `s` early holds swap-moving power
the invariant forbids, even though the pre-signed transaction's own outputs are fixed. So a pre-signed
claim that embeds a not-yet-public `s` must never be entrusted to a watchtower.

The resolution below keeps every safe case and drops only that one.

## What a watchtower may hold

Three cases, by role and by whether the secret is already public:

1. **Any refund: always safe.** A refund spends the user's OWN lock back to the user's own refund
   address after the lock's timelock. Its witness is a plain signature over a fixed output plus the
   timelock branch; it carries NO secret. A pre-signed refund leaks nothing and gives the watchtower no
   power beyond broadcasting the user's own refund once the timelock has expired and the swap did not
   complete. This is the first slice, and it is fully non-custodial.
2. **The taker's claim, pre-signed WITHOUT the secret: safe, gated on the public reveal.** A signature
   does not cover the separate `s` witness element, so the taker can pre-sign its claim of the maker's
   lock before `s` is known, with the `s` slot left empty and the output fixed to the taker's payout.
   The watchtower fills `s` and broadcasts ONLY AFTER it has observed the maker reveal `s` on chain (the
   maker's own claim of the taker's lock). At that moment `s` is already public, so the watchtower learns
   nothing non-public and gains no early power. This is a later slice, gated by an on-chain
   counterparty-lock-and-reveal check (the same class of check as the funding-time counterparty
   verification).
3. **The maker's claim: never.** A maker claim embeds a private `s`. The maker is also the party whose
   on-chain claim is what reveals `s` in the first place, so a maker that goes offline before claiming
   simply does not reveal `s`, and both sides refund. The maker therefore never needs a
   watchtower-broadcast claim; it needs only a watchtower-broadcast REFUND (case 1). The maker's claim
   stays with the online maker and is never given to the watchtower.

So: refunds for everyone, taker claims gated on the public reveal, and no maker claim ever. The
watchtower never holds a secret that is not already on chain.

## Non-custody argument

- The watchtower holds no key and no seed; it cannot produce or alter a signature.
- Every transaction it holds is fully user-signed with outputs fixed to the user's own payout or refund
  address; a changed output invalidates the signature and is un-broadcastable.
- For a refund it holds no secret at all; for a gated taker claim it only ever supplies an `s` that is
  already public on chain. It chooses WHICH of the user's own pre-signed transactions to broadcast and
  WHEN, nothing more. It can never redirect, forge, or move a coin to anywhere but the user's address.

## Storage of the pre-signed transactions

- Per swap and per role the watchtower stores: the user's pre-signed refund (always); and, for a taker
  under the later slice, the pre-signed-without-`s` claim plus the public contract data needed to
  recognise the on-chain reveal (the lock outpoint, the witness script, the expected `s` hash). It stores
  NO private key and NO not-yet-public secret.
- Entries are per swap, bounded, and expire: an entry is dropped once the swap settles (the lock is spent
  by claim or refund, observed on chain) or once its timelock plus a finality margin has passed with the
  swap already terminal. The store is capped and aged so it cannot grow without bound.
- Encryption at rest: the stored transactions are, by construction, broadcastable only to the user's own
  addresses, so they are not funds-bearing secrets; nonetheless the store should be encrypted at rest and
  access-controlled, because it reveals swap metadata (amounts, addresses, timing) that a user expects an
  operator to protect. The encryption key is the operator's, not a user secret.

## Broadcast trigger

The watchtower follows the same on-chain conditions the engine's `decide` uses, so it broadcasts exactly
the transaction the user would have, at the moment the user would have:

- **Refund:** broadcast once the lock's refund timelock height is reached AND the swap has not completed
  (the counterparty's expected claim/lock has not confirmed). It must NOT broadcast a refund early: before
  the timelock the refund is invalid and would be rejected, and broadcasting a refund while the swap could
  still complete would race the user's own claim. The watchtower waits for the timelock height and for the
  swap to be in a refundable terminal condition.
- **Gated taker claim (later slice):** broadcast only after observing the maker's on-chain reveal of `s`
  on the taker's lock, confirmed to the engine's funding/finality depth, and while the taker claim is
  still within its own timelock window. Fill the observed `s` into the pre-signed claim and broadcast.
- The watchtower broadcasts at most ONE of {claim, refund} per lock, gated on the same mutually exclusive
  on-chain conditions, so it can never double-spend the user's funds.

## Interaction with the refund timelock and finality depths

- The watchtower does not change any timelock or depth; it reuses the swap's existing per-leg timelocks
  (maker longer than taker, so the maker's lock is claimable first) and the chain finality depths the
  engine already waits.
- Because the watchtower only automates the broadcast the user would have made, the claim/refund race
  bounds of the core state machine (0015) are unchanged. A watchtower shortens the user's required online
  window to zero; it does not widen any safety margin.

## Failure modes and scope

First slice (refund-only):
- Watchtower offline or missing: degrades to today's behaviour, the user must be online to refund, and if
  neither acts the funds remain locked until the user refunds later (a refund has no deadline past the
  timelock). No loss, only a liveness cost.
- Watchtower broadcasts a refund that races a late user claim: the mutually exclusive on-chain gate and
  the single-broadcast rule prevent a double spend; the first to confirm wins, both are the user's own
  signed transactions to the user's own addresses, so either outcome is safe for the user.

Out of scope for the first slice:
- The gated taker claim (case 2) is a later slice; it needs the on-chain reveal observation and the
  confirmed-counterparty-lock gate, which are the more delicate parts.
- Multi-watchtower redundancy, watchtower payment/accounting, and cross-operator watchtowers are future
  work. The first slice is a single operator-run watchtower for its own hosted users.

## Security requirements and tests (per 0003)

- Assert the watchtower holds NO key, NO seed, and NO not-yet-public secret: for a refund the store
  contains no secret; for a gated taker claim the `s` slot is empty until the on-chain reveal is observed.
- A broadcast transaction's outputs are byte-identical to the user's pre-signed one; a tampered output
  fails signature verification and is un-broadcastable. Test it.
- The watchtower never broadcasts a refund before its timelock height, and never broadcasts both a claim
  and a refund for the same lock. Test both.
- The gated taker claim is broadcast ONLY after a confirmed on-chain reveal of `s`; a claim offered
  without a matching public reveal is refused. Test the refusal.
- A maker claim is never accepted into the watchtower store. Test the refusal.
- Re-run the existing abandon/refund adversarial tests with the watchtower automating the broadcast, and
  confirm the outcomes match a user that acted manually.
