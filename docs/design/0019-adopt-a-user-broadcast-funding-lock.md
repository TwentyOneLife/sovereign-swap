# 0019 Adopt a user-broadcast funding lock (Interactive)

Status: implemented 2026-11-10 (red tests then fix, engine `advance()`). Builds on
[0017](0017-user-held-signing-psbt-handoff.md) (Interactive funding) and the late-submit guard in PR
#133. Resolves issue #134 and the self-broadcast item of #135 (item 3). The red tests corrected the
severity hypothesis below: see "Current behaviour (pinned by the red tests)".

## Problem

In Interactive funding the engine hands the user an unsigned funding PSBT, parks the swap
(`record.pending_lock_psbt`), and waits for the signed PSBT via `POST /swaps/{id}/signed-psbt`. The
engine never broadcasts in this mode. But the user's wallet has a Broadcast button, so the user can put
the lock on chain themselves, within the funding window (#135 item 3) or after the swap abandoned
(#134). The engine currently acts on neither.

## Root cause (narrower than it first looks)

`Engine::view` already calls `lock_view` on both `maker_contract` and `taker_contract` every tick, so
the engine already observes our own lock on chain (for a taker that is `taker_lock`, for a maker
`maker_lock`), and `start()` registers both contracts with `watch_contract`, so the observation is live
while the swap is parked. The gap is one line: `own_funded` is wired to `record.funding.is_some()`
(pure bookkeeping), not to that observation. Because the engine never recorded a funding tx in
Interactive mode, `own_funded` stays false even when our lock is confirmed on chain.

Detection also already has an exact key. A segwit txid is fixed by the unsigned transaction (the witness
does not change it), and `submit_signed_lock` already matches on same-txid, so the parked PSBT gives the
engine the exact expected lock txid. The own-side `LockView.outpoint` carries the txid actually seen on
chain.

## Current behaviour (pinned by the red tests)

The red tests (`a_within_window_user_broadcast_lock_is_adopted_and_settles`,
`a_post_window_user_broadcast_lock_is_adopted_and_refunded`) corrected the feared "taker loses the
coin" hypothesis. What actually happens on the pre-fix code:

- **Within the funding window:** the swap settles to `Done`. The maker claims the on-chain lock and
  reveals the secret, and the taker claims the maker's lock with it. The only defect is cosmetic: the
  parked PSBT lingers until the terminal phase, so the GUI keeps asking the user to sign a lock that is
  already on chain. Not a loss.
- **A lock on chain before the swap goes terminal:** already refunded or claimed. `decide` reaches the
  claim/refund paths off the on-chain `taker_lock`/`maker_lock` in the view, not off `record.funding`,
  so the on-chain lock is driven regardless of the `own_funded` bookkeeping.
- **The one genuine loss path is the abandon-then-forget order:** if the engine ticks the parked swap
  past the funding window with no lock yet, `decide` abandons it and `advance()` drops the PSBT; since
  `tick()` skips terminal swaps, a lock the user broadcasts *after that* is never observed and is
  stranded in an HTLC only `self.keys` can refund. This is the #134 hazard, reproduced by the
  post-window test.

So the fix is narrower than first written: not "wire `own_funded` to the observation" (claim/refund
already work), but (1) clear the parked PSBT when the own lock is observed, and (2) stop terminalising
and forgetting a parked, handed-out swap.

## Decision: adopt the lock (resolves #134 alternative (a))

Of #134's alternatives, (a) watch and adopt is chosen over (b) a manual runbook and (c) a pre-signed
refund. It adds no user step, reuses the observation the engine already makes, and needs no new state.

### Mechanism

In `advance()` (which is `&mut`, unlike `view`), while `pending_lock_psbt` is set, two changes:

- **Adopt.** If the own-side `lock_view` (`taker_lock` for a taker, `maker_lock` for a maker) shows a
  lock, set `record.funding = get_tx(own_lock.outpoint.txid)` and clear `pending_lock_psbt`. `get_tx`
  returns the full signed transaction including witnesses (read from the watch wallet that
  `watch_contract` populated), so the existing reorg path ("the same funding transaction goes out
  again") rebroadcasts unchanged, and the GUI stops asking for a signature. The same `view` is then
  passed to `decide`: the lock is present in it, so `decide` takes the on-chain-lock path regardless of
  `own_funded`.
- **Keep watching.** If no lock was adopted and `decide` moved the swap to `Abandoned`, revert the
  phase to its value at entry and keep `pending_lock_psbt`, returning without acting. This keeps the
  swap non-terminal so `tick()` keeps advancing it; when the user's lock later appears it is adopted on
  that tick.

**No forced `Phase::Refunding` is needed.** `decide` already handles claim vs refund by the same
deadline logic a normally funded swap uses: `decide_maker` only reveals the secret while `time_left`
holds (the #74 margin), and `decide_taker` only claims with a learned secret, so post-window adoption
cannot trigger the one-side-gets-both race. The earlier "refund-only" plan was unnecessary.

### Deferred (not in this change)

- **Stop condition.** The current code keeps watching for as long as the PSBT is parked; a swap the
  user never acts on therefore stays non-terminal rather than abandoning. The precise "can never
  confirm" signal (any PSBT input spent by another transaction) would let it give up and drop the PSBT,
  but it needs a backend outpoint-spent query that does not exist yet. Watching longer is the safe
  default (it never strands); the per-swap keys are deterministic from `key_index`, so a manual rescue
  stays possible regardless. Tracked as a follow-up.
- **Look-alike txid** (our contract funded by a transaction other than the expected one, for example
  missing the fee output): adopted the same way, since it is still our HTLC; a stricter refund-only
  treatment is a possible refinement.
- **Fee bookkeeping.** Deriving `record.fee` from the adopted transaction (which also closes the #135
  `submit_signed_lock` fee under-report) is a separate #135 item, not this change.

## Tests

- `a_within_window_user_broadcast_lock_is_adopted_and_settles`: one tick after the lock confirms clears
  the parked PSBT (prompt adoption), and the swap still settles to `Done`.
- `a_post_window_user_broadcast_lock_is_adopted_and_refunded`: the engine keeps watching a handed-out
  PSBT past the window, and when the user broadcasts late the lock is adopted and refunded by
  `self.keys` (the maker is not driven, so no secret is revealed and only the refund path is possible).
- The four existing interactive tests and the full suite stay green.

## Cross-references

Issues #134 (recover a user-broadcast abandoned lock) and #135 (verify before enabling Interactive,
item 3, and the `record.fee` under-report). Designs 0017 (PSBT handoff), 0018 (fee address), 0010 (fee
proof).
