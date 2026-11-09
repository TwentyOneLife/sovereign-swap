# 0017 User-held signing via PSBT handoff (E2), and the watch-only view (E3)

## Context
E1 (design 0016) lets the engine read chain data and broadcast over an Electrum server, so a swap needs
no full node for **reads**. E2 and E3 remove the remaining full-node / hot-wallet requirement: the
**user's own wallet funds and signs**, and the operator's side never holds a spendable key. This is the
heart of the thin client and the hosted service (#46, Model 2a/2b), and it is the mechanism the owner
described: the site builds unsigned PSBTs, the user signs in their own wallet (Sparrow for BTC, Shrike
for xBTC, both speak PSBT today), and submits the signed PSBT back.

Builds on 0012 (the cold-signer seam: `FundingSigner`, watch-only funding wallet, `RemoteSigner` ->
`signer_server`) and 0014 (the custody line). The one invariant: **no key that can move a user's coin
ever reaches the operator.**

## E3 first, because E1 mostly delivered it
E3 is "build and monitor each swap against read-only data, never a shared spendable wallet." The read
half is **already done by E1**: `ElectrumBackend` queries by scripthash and needs no wallet, and
`watch_contract` is a no-op (query-based). What remains for a fully watch-only hosted side is the
**funding** half: today funding uses a node wallet (hot) or a watch-only wallet plus an automated
signer (cold, 0012). E2 moves funding to the user, which is what makes the hosted side watch-only end
to end. So E3 = "E1 reads + E2 funding," with no spendable wallet anywhere the operator runs.

## E2: the signing seam

### What exists
`FundingSigner::sign(unsigned_psbt) -> signed_psbt` is **synchronous**: `WalletSigner` signs on the
spot, `RemoteSigner` RPCs an always-on `signer_server` that signs on the spot. The engine builds the
unsigned funding PSBT, calls `sign`, and broadcasts, all in one tick.

### What changes: signing becomes interactive (asynchronous)
A human signer is not available within a tick. Blocking `sign()` on a person would stall the engine, so
funding (and the claim) must **park and resume**:

1. **Propose.** When the engine would fund (or claim), it builds the unsigned PSBT, stores it on the
   swap record as a *pending signature*, and transitions the swap to an awaiting-signature checkpoint
   (e.g. `AwaitingUserLock` / `AwaitingUserClaim`). It does **not** broadcast; it emits an event.
2. **Hand off.** The web UI / API surfaces the pending unsigned PSBT (text, file, or QR). The user signs
   it in their own wallet. Nothing secret leaves the user's device.
3. **Submit.** The user returns the signed PSBT via a new action (`POST /swaps/{id}/signed-psbt`). The
   engine validates it (the same-unsigned-tx check `RemoteSigner` already does, so the signer cannot
   rewrite destination/amount), broadcasts it over the E1 Electrum backend, and advances the swap.

This is the `signer_server` seam turned inside out: instead of the daemon calling an automated signer,
the daemon *publishes* the unsigned PSBT and *waits* for the user to call back. The validation and the
same-txid guard are reused verbatim.

### CORRECTION (verified against the code): only the funding lock is user-signed
An earlier draft of this design assumed the user also signs the **claim** and **refund** in their own
wallet, which would create a claim-liveness problem (the user must return to sign the claim when the
secret appears). **That is wrong for this architecture.** The claim and refund are HTLC spends signed by
the engine's own per-swap keys (`self.keys`, derived from the user's seed; `engine.rs` uses
`self.keys.key(index, Use::Claim)` / `Use::Refund`), **automatically**, and broadcast over E1. Only the
**funding lock** uses the user's big-balance wallet, which is what E2 moved to PSBT handoff.

Consequences:
- There is **no refund-liveness problem** and **no pre-signed-refund step (the old E2b)**: the thin
  client signs the refund itself when the timelock passes.
- There is **no interactive-claim step or watcher (the old E2c)** for the self-hosted thin client: the
  thin client signs the claim itself when the secret appears. It only needs to keep running, as any swap
  daemon does; the user is never prompted to sign a claim.
- The self-hosted thin client is therefore **complete with E1 + E2 funding + `self.keys` claim/refund**.
  The only remaining work is the UI (select Interactive mode; the GUI PSBT handoff).

Interactive/user-held claim and refund keys become relevant only in a **hosted multi-tenant** model
(#46), where each session's HTLC keys must be the user's, not the operator's. That is out of scope here.

### Watch-only funding input
The daemon builds the unsigned funding PSBT from the user's **watch-only descriptors / xpub** (0012
already provisions a watch-only funding wallet for cold mode) or from a user-supplied UTXO set. The
operator never imports a spendable key. This is the E3 funding half.

### Transport of the PSBT
- **Self-hosted client (open):** the daemon GUI shows the pending unsigned PSBT and accepts the signed
  one (copy/paste, file, or QR). This is the manual handoff, which works for both chains today.
- **Hosted service (private, #46):** the same handshake per session in the proprietary web frontend;
  for xBTC the signer is Shrike (no browser extension exists). A slicker one-click connector is a later
  upgrade, not a launch blocker (the manual PSBT round-trip works now).

## What stays out of scope (the custody line)
- No spendable wallet, seed, or private key on the operator's side, ever.
- No automated signing of a user's funding on the operator's behalf.
- The operator only builds unsigned PSBTs, broadcasts signed ones, and reads chain data.

## Build order (each a separate design/PR, after this design)
1. **E3a watch-only funding input , ALREADY DELIVERED by 0012.** The cold path already builds the
   unsigned funding PSBT on a watch-only funding wallet (`open_cold`: `disable_private_keys=true`,
   imported from account descriptors; it refuses a keyed wallet), and `fund()` uses
   `walletcreatefundedpsbt` there with no spendable key on the host. Proven by
   `tests/cold_signer.rs` (`the_engine_wallet_holds_no_keys_and_an_external_signer_funds_the_lock`,
   `a_cold_lock_is_funded_end_to_end_through_a_remote_signer`). The only thin-client difference is that
   the descriptors are the user's and the signer is the user, which is E2, not new funding code. So the
   first genuinely new step is E2a.
2. **E2a interactive funding signer + the awaiting-signature swap state , DONE** (#128, #129, #130).
   The park/resume state machine for the funding lock, the `signed-psbt` submit action, broadcast via
   E1, the same-txid validation, and `FundingMode::Interactive`, all regtest-proven.
3. ~~**E2b pre-signed refund.**~~ **MOOT** (see the correction above): the refund is signed by the thin
   client's own `self.keys` automatically; the user never signs it, so there is nothing to pre-sign.
4. ~~**E2c interactive claim + watcher.**~~ **MOOT for the self-hosted thin client**: the claim is signed
   by `self.keys` automatically when the secret appears. Relevant only to the hosted multi-tenant model
   (#46), where the per-session HTLC keys would be user-held.
5. **GUI handoff + Interactive config** in the open client (show the unsigned PSBT, accept the signed
   one; a funding-mode option). The last remaining usability bit for the self-hosted thin client.
6. **(#46) multi-tenant + proprietary web frontend** on top, per the private spec.

## Risks (ranked)
1. **State-machine correctness** , parking/resuming a half-funded swap across restarts must never fund
   twice, never broadcast a stale PSBT, and must survive the replay guards (handled in E2a: a pending
   PSBT is never rebuilt, funding and pending are mutually exclusive).
2. **xBTC signing UX** , manual PSBT via Shrike works; a smooth flow is a later upgrade, not a blocker.
3. **Hosted multi-tenant claim/refund keys** , only for #46: the per-session HTLC keys must be the
   user's, not the operator's. Out of scope for the self-hosted thin client.

## Relationship to the hosted service
E2 is the per-session signing model the hosted multi-tenant engine uses (#46, Model 2b). Everything here
is open-core protocol/engine work; the commercial frontend and multi-tenant layer stay private
(`_internal/designs/xbtc-swap-hosted-commercial-spec-2026-11.md`). A public hosted launch is gated on
the #104 compliance read.
