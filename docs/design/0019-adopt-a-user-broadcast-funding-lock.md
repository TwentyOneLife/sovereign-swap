# 0019 Adopt a user-broadcast funding lock (Interactive)

Status: design, revised 2026-11-10 after an adversarial review rejected a first implementation (the
"revert the abandon" approach below). The split-prompt-from-watch design is the one to implement. Builds on
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

### Mechanism: split the prompt from the watch

A first attempt reverted every abandon and kept `pending_lock_psbt` set to keep watching. An adversarial
review killed it: that re-introduces the #133 GUI-stuck (a walked-away user is asked to sign a dead swap
forever), it overrides abandons that mean the counterparty is broken (wrong amount, already spent, fee
`Failed`), it leaves un-terminating zombie swaps ticked forever, and, worst, it does not even close
#134's real path, because `submit_signed_lock` still sets `Abandoned` and `tick()` skips terminal swaps,
so a user who pastes late (refused) and then broadcasts is stranded exactly as before.

The fix is to separate the two jobs `pending_lock_psbt` was doing:

- **`pending_lock_psbt`** (existing): the prompt. Drives the GUI and `submit_signed_lock`. Cleared the
  moment the swap stops awaiting a signature (adopted, settled, or abandoned), so the GUI never asks the
  user to sign a dead or already-funded swap. This keeps the #133 behaviour.
- **`expected_lock_txid`** (new, persisted, `#[serde(default)]`): the watch. Set when parking, from the
  unsigned PSBT's txid (segwit fixes it, and `submit_signed_lock` already matches on it). Outlives
  abandon so the engine can still recognise the user's lock if it lands after the swap went terminal.

On park (`act` AwaitingSignature arm) set both. On abandon, from either `advance()`'s tick re-decision
or `submit_signed_lock`'s refusal, clear `pending_lock_psbt` (prompt gone, phase `Abandoned`) and KEEP
`expected_lock_txid`.

Adoption then happens in two places:

- **While parked (non-terminal), in `advance()`:** if the own-side `lock_view` shows the expected lock,
  set `record.funding = get_tx(txid)` (full signed tx incl. witnesses, read from the watch wallet
  `watch_contract` populated, so the reorg rebroadcast path works), clear both `pending_lock_psbt` and
  `expected_lock_txid`, and let `decide` run on the same `view`. Within the window it settles; near or
  after the window it refunds. Refund-safe for both roles: `decide_maker` only reveals while `time_left`
  holds (the #74 margin) or it is already `Claiming`; `decide_taker` only claims with a learned secret.
- **After abandon, in `tick()`:** a swap that is `Abandoned` but still carries `expected_lock_txid` is
  NOT skipped. The engine checks the own-side `lock_view`; on the expected lock it adopts (set funding),
  transitions explicitly to `Phase::Refunding` (decide refuses to reconsider a terminal swap, so the
  transition is explicit here), clears the marker, and drives the `self.keys` refund. This closes
  #134's real path.

### Bound: when to give up the watch

Drop `expected_lock_txid` when the expected lock is not on chain and a PSBT input has been spent by
another transaction (the precise "can never confirm" signal), checked with `gettxout` on the funding
node's `rpc` (which `ChainNode` already holds, so no new backend trait), with a block-height cap as a
backstop. After that the swap is a plain `Abandoned`; the deterministic per-swap keys keep a manual
rescue possible even then.

### Deferred (not in this change)

- **Look-alike txid** (our contract funded by a transaction other than the expected one, for example
  missing the fee output): adopted the same way, since it is still our HTLC; a stricter refund-only
  treatment is a possible refinement.
- **Fee bookkeeping.** Deriving `record.fee` from the adopted transaction (which also closes the #135
  `submit_signed_lock` fee under-report) is a separate #135 item, not this change.

## Tests

Red first, then the split-design fix makes them green:

- Within-window self-broadcast: one tick after the lock confirms clears the parked PSBT (prompt
  adoption) and the swap still settles to `Done`.
- Walk-away: past the window with no lock, the prompt (`pending_lock_psbt`) is cleared and the phase is
  `Abandoned` (the #133 behaviour is preserved), but the `expected_lock_txid` marker is kept.
- Post-window broadcast after abandon: with the swap already `Abandoned`, a late user broadcast is
  adopted off the marker, transitioned to `Refunding`, and refunded by `self.keys`.
- Late-submit-then-broadcast (#134's real path): after `submit_signed_lock` refuses
  (`NoLongerFundable`) and clears the prompt, the user broadcasts the lock; it is adopted off the marker
  and refunded.
- The four existing interactive tests and the full suite stay green.

## Cross-references

Issues #134 (recover a user-broadcast abandoned lock) and #135 (verify before enabling Interactive,
item 3, and the `record.fee` under-report). Designs 0017 (PSBT handoff), 0018 (fee address), 0010 (fee
proof).
