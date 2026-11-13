# 0028 Signed-spend persistence (user-held claim/refund survives eviction without a re-sign)

Status: design, 2026-11-13. A precondition for enabling the 2b gate (`#226`), building on
[0027](0027-user-held-claim-refund-and-watchtower.md). No code yet; this is the spec the build follows.

## The gap

For a user-held swap (0027) the engine holds no claim/refund key, so `submit_signed_spend` broadcasts
the user's signed claim/refund and then clears `pending_spend` and stores **nothing**. If that
transaction later leaves the node's view before confirming, the engine's `decide` re-issues
`Action::Claim`/`Action::Refund` and the user-held park re-parks (`pending_spend` set again), forcing the
user to sign a second time.

A transaction leaves the view when the node's mempool is lost (a StartOS package/daemon restart without
a persisted mempool, the common case), or on a reorg that un-mines the spend and then drops it as an
orphan, or on a true mempool eviction. For a **claim** this is not just friction: the maker's secret is
public on chain the instant the first claim broadcasts, so any window where the engine sits re-parked
waiting for a re-sign is a race the counterparty can exploit with the now-public secret. The local
(non-user-held) path does not have this gap: it holds the key and re-signs + rebroadcasts on every tick.

This is an asymmetry with the FUNDING leg, which 0017 already persists: `submit_signed_lock` stores the
signed lock in `Record::funding`, and `Action::Fund` rebroadcasts the stored tx on every tick
(`engine.rs`: `Action::Fund => match record.funding { Some(tx) => rebroadcast, None => build/park }`).
0028 brings the claim/refund leg to the same footing.

## The one invariant (unchanged from 0014/0027)

The operator's engine holds no spend key, seed, or secret. A fully-signed spend transaction is PUBLIC
data (it is about to be, or already has been, broadcast; a claim's witness carries the secret, which is
public the moment the claim hits the chain). Storing it on the same host that already parked and
broadcast it reveals nothing new and moves no coin anywhere but the output the user already signed. So
persistence is non-custodial by construction.

## Design

1. **Store the signed spend.** Add `#[serde(default)] pub spent_tx: Option<Transaction>` to `Record`
   (public data, rides `save`). In `submit_signed_spend`, after a successful broadcast, set
   `spent_tx = Some(tx)` in place of simply clearing state (and clear `pending_spend`: a swap is either
   awaiting a signature or already signed-and-broadcast, never both, exactly like
   `pending_lock_psbt` vs `funding`).

2. **Rebroadcast instead of re-park.** In the user-held `Action::Claim` and `Action::Refund` arms of the
   tick, before parking, check `record.spent_tx`: if it is present AND matches this action's lock (point
   3), REBROADCAST it and return; otherwise park a fresh unsigned spend for the user to sign. This
   mirrors `Action::Fund`'s `match record.funding`, with the lock-match guard added.

3. **Rebroadcast only the stored spend that matches the current action's lock (the regression gate).**
   The stored tx is NOT rebroadcast blindly. A claim and a refund spend DIFFERENT outpoints (on
   different chains), so the engine rebroadcasts `spent_tx` only when its `input[0].previous_output`
   equals the `lock` of the action the arm was entered on; otherwise the stored tx is stale, is dropped,
   and the new action is parked as today.

   Why this is required, not just defensive: it is tempting to argue `decide` already keeps claim and
   refund apart, but that holds only for the MAKER. `decide_maker`'s refund branch is gated on
   `phase != Claiming`, so once it claims it never switches to refund. The TAKER has no such gate:
   `decide_taker` yields a learned-secret `Action::Claim` with no phase check, and `decide`
   short-circuits only on `Done | Refunded | Abandoned`, not `Refunding`. So a user-held taker can
   legitimately switch refund -> claim: its refund opens at `taker_lock_blocks` and is signed and stored;
   a late maker claim of the taker's lock wins the race, making the stored refund a dead, conflicted tx;
   the taker learns `s` from that claim and `decide_taker` yields `Action::Claim` on the MAKER's lock.
   Without the outpoint guard the Claim arm would rebroadcast the dead refund and return without parking
   the claim, and the taker would lose BOTH legs, a regression over today (which stores nothing and parks
   the claim correctly). With the guard, the stale refund is dropped and the claim is parked for the
   user. When the lock DOES match, the rebroadcast is still further guarded by `decide` only yielding the
   action when the lock is unspent and that spend is the right move (the funding-rebroadcast / #74
   guarantee).

   The match/mismatch decision is a small pure function, e.g.
   `fn reusable_spend(spent: Option<&Transaction>, lock: OutPoint) -> Option<&Transaction>` returning the
   tx iff `input[0].previous_output == lock`, so it is unit-testable with no nodes and mutation-checkable
   (drop the outpoint compare and the mismatch test goes red).

4. **Scope: user-held only.** The local path re-signs and rebroadcasts every tick (it has the key via
   `rate_spend` + `build`), so it needs no stored tx. `spent_tx` is set and consulted only on the
   user-held branch; the local path is byte-identical to today.

5. **Clearing.** Clear `spent_tx` the moment the current action's lock does NOT match the stored tx's
   input (the kind/outpoint switch of point 3): the stored tx is dead and must never be rebroadcast
   again. This is the clearing that matters. Separately, `spent_tx` is harmlessly left until the swap
   reaches a terminal phase (`Done`/`Refunded`/`Abandoned`) otherwise; a terminal swap is never
   re-decided, so that clearing is only housekeeping.

## Interaction with fee-bumping (out of scope here)

`spent_tx` is rebroadcast verbatim, at the fee it was signed at. If the mempool's min-relay fee has
risen past that, the rebroadcast may not relay; RBF/CPFP of a user-signed spend is a separate concern
(the user would re-sign a higher-fee spend). 0028 only closes the re-sign race for a spend that is still
relayable, which is the eviction/restart case. This matches the funding leg, which also rebroadcasts at
its signed fee.

## Adversarial tests (per 0003)

- **Durability (deterministic, restart-based).** A user-held swap settles its claim via
  `submit_signed_spend`; reopen the engine from the same dir (the `reopen` harness) and assert
  `spent_tx` survived the reload, so a rebroadcast is possible after a package restart. Mirrors
  `interactive_swap::a_parked_funding_lock_survives_an_engine_restart`.
- **Rebroadcast, not re-park (deterministic, mock-backend).** Using a `ChainBackend` test seam in the
  style of `interactive_swap::PendableBackend`, make `lock_view` report the counterparty lock as
  UNSPENT on demand (hiding the already-broadcast claim). Because the REAL node still holds the claim, a
  verbatim rebroadcast would otherwise error ("already in mempool", or "already in block chain" if
  mined) and trip the `errs.is_empty()` assert in `tick()`; so the seam's `broadcast` records the txid
  and returns `Ok` while hiding. Tick: assert the recorded txid is the stored claim's (it was
  rebroadcast) and that `pending_spend` stays `None` (no re-sign demanded). Flip the seam off: the spend
  is seen again and the swap settles. No reorg needed, so the test is deterministic.
- **Kind-switch regression test (the real gate for point 3).** A user-held TAKER whose refund is signed
  and stored, then a maker claim reveals `s` so `decide_taker` yields `Action::Claim` on the maker's
  lock: assert the engine DROPS the stale refund and PARKS the claim (it does NOT rebroadcast the
  refund), and that the swap then settles via the user-signed claim. Plus a `reusable_spend` unit test
  over the match / mismatch / none cases, mutation-checked by dropping the outpoint compare. Neither of
  the two tests above exercises a kind switch, so this is what guards the two-leg-loss regression. (The
  custody line itself, that the engine cannot produce the spend, is already covered by 0027's
  separate-seed acceptance tests.)

## Alternatives considered

- **Re-sign on re-park (today's behaviour).** Rejected: the re-sign window is a race once the claim's
  secret is public.
- **Store only the sighash / rebuild on demand.** Insufficient: the engine cannot re-sign (no key), so
  it must keep the whole signed tx.
- **Rebroadcast from a separate watchtower only.** That is 0027 section 3 (slice 4) and is optional;
  persistence belongs in the engine so even a browser that reconnects after a restart does not re-sign.

## Out of scope

Fee-bumping / RBF of a user-signed spend; the watchtower (0027 section 3); any custodial fallback.
