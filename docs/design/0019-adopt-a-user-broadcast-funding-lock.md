# 0019 Adopt a user-broadcast funding lock (Interactive)

Status: design, 2026-11-10. Builds on [0017](0017-user-held-signing-psbt-handoff.md) (Interactive
funding) and the late-submit guard in PR #133. Resolves issue #134 and the self-broadcast item of #135
(item 3). Not yet implemented; the current behaviour is to be pinned by red tests first (see below).

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

## Current behaviour: pin it with red tests before any fix

Three outcomes are possible for a within-window self-broadcast and the difference sets the severity:

1. GUI stalls only, swap still completes.
2. Swap stalls and then abandons harmlessly.
3. The taker loses the coin: `own_funded` stays false, `decide_taker` returns a no-op `Fund` until its
   deadline, the swap abandons and `advance()` drops the PSBT, while the maker sees the real lock,
   claims it and reveals the secret, and the abandoned taker never claims back.

Outcome 3 is a real loss path, so the first task is red tests that reproduce today's behaviour:
`drive_until_parked`, sign with the simulated user signer, `sendrawtransaction` out of band instead of
submitting, tick, and assert what happens, for both the within-window and post-abandon cases.
Interactive is OFF on the live nodes, so this is inert, but the result is recorded.

## Decision: adopt the lock (resolves #134 alternative (a))

Of #134's alternatives, (a) watch and adopt is chosen over (b) a manual runbook and (c) a pre-signed
refund. It adds no user step, reuses the observation the engine already makes, and needs no new state.

### Mechanism

In `advance()` (which is `&mut`, unlike `view`), when the swap has no `record.funding` yet and the
own-side `lock_view` shows a confirmed lock:

- **Adopt.** Set `record.funding = get_tx(own_lock.outpoint.txid)`. `get_tx` returns the full signed
  transaction including witnesses, so the existing reorg path ("the same funding transaction goes out
  again") rebroadcasts unchanged; there is no need to re-park on a reorg. Clear `pending_lock_psbt`.
  Then re-take the view so `own_funded` is true, and let `decide` run.
- **Within the funding window:** the swap proceeds exactly as a normally funded swap. This removes the
  outcome-3 loss path.
- **After the window (the swap would otherwise abandon):** transition straight to `Phase::Refunding`
  and only then run `decide`. It must be refund-only: reviving into a normal phase could let
  `decide_maker` reveal the secret or either side claim with margins the deadline logic already judged
  unsafe (the one-side-gets-both race). The refund is the `self.keys` refund at the HTLC timelock. Part
  of the fix is a check that the `Refunding` arms of `decide_maker`/`decide_taker` never claim and never
  reveal.

### Txid match

- Expected txid seen on chain: adopt as above.
- Our contract funded by a different txid (a look-alike, for example one missing the fee output): it is
  still our HTLC and still only refundable by `self.keys`, so adopt it refund-only rather than strand
  it, regardless of window.

### Stop condition (bound)

The funding window and the refund timelock do not bound when the user can broadcast; the PSBT can
confirm any time its inputs are unspent. The precise "can never confirm" signal is any PSBT input spent
by another transaction. Use that as the stop condition: when an input is spent elsewhere, truly abandon
and drop `pending_lock_psbt`. Keep a long horizon only as a backstop cap. Because the per-swap keys are
deterministic from `key_index`, a manual rescue stays possible even after the engine gives up.

### Fee bookkeeping

Under [0018](0018-interactive-funding-and-the-fee-output.md) the default fee address is Normal, so the
fee output sits on chain in the adopted transaction and can be matched against the offer's fee address.
Derive `record.fee` from the adopted tx rather than marking it unknown. The same derivation closes the
separate #135 gap where `submit_signed_lock` never sets `record.fee`, so one change covers both.

## Tests (Sprint 1)

- Red first: current behaviour for within-window and post-abandon self-broadcast (pin outcome 1, 2 or
  3).
- Within-window self-broadcast: adopt, pending cleared, swap drives to Done.
- Post-abandon self-broadcast: adopt refund-only, `self.keys` refund at the timelock, never a claim or
  reveal.
- Look-alike txid (missing fee output): adopt refund-only.
- Input spent elsewhere: abandon and drop the PSBT.
- Reorg of an adopted lock: the existing rebroadcast path re-sends the adopted transaction.
- Fee derived from an adopted Normal-fee tx matches the offer address.

## Cross-references

Issues #134 (recover a user-broadcast abandoned lock) and #135 (verify before enabling Interactive,
item 3, and the `record.fee` under-report). Designs 0017 (PSBT handoff), 0018 (fee address), 0010 (fee
proof).
