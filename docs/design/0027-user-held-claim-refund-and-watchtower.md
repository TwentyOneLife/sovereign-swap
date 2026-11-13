# 0027 User-held claim/refund signing and watchtower broadcast (hosted engine, 2b)

Status: design, 2026-11-13. Addresses the remaining non-custodial gap for a HOSTED engine (model 2b of
[0014](0014-non-custodial-rearchitecture.md)). Extends [0017](0017-user-held-signing-psbt-handoff.md)
(which moved the FUNDING signature to the user) to the claim and refund spends and the maker's secret,
and adds an optional watchtower so a 2b user can be offline mid-swap without custody. Builds on
[0012](0012-cold-signer-wiring.md), [0016](0016-electrum-chain-backend.md), the payout destinations
(F5, implemented), and the custody line of 0014. No code yet; this is the spec the 2b build follows.

## The gap this closes

0017 parks the funding PSBT for the user to sign, so the engine holds no funding key. But today the
CLAIM and REFUND spends are still built and signed by the engine with keys derived from `identity_seed`
(`engine.rs`: `self.keys.key(index, Use::Claim)`, `Use::Refund`), and the maker's secret is engine
derived (`self.keys.secret(index)`). On a self-hosted client (2a) that is fine: the engine runs on the
USER's device, so those keys are the user's. On a HOSTED engine (2b) it is NOT: the operator's engine
would hold every user's claim/refund keys and secret, which is custody (model 3, rejected by 0014).

So 2b requires three things to leave the hosted engine: the claim signature, the refund signature, and
the maker's secret.

## The one invariant (unchanged from 0014)

The operator's infrastructure never holds anything that can move a user's coin: no spend key, no seed,
no secret, no funded-and-signable wallet. The hosted engine may hold only public data (hashes, heights,
confirmations, spend templates) and watch-only descriptors.

## Design

### 1. Generalise the park/resume handoff to claim and refund

0017 already parks funding at an `AwaitingSignature` checkpoint and resumes via
`POST /swaps/{id}/signed-psbt` + `submit_signed_lock`. Generalise the same mechanism to the two other
spends, gated on an "interactive signer" for the chain (never for a local hot/engine signer, so 2a and
the current product are untouched):

- When `decide` yields `Action::Claim` or `Action::Refund` under an interactive signer, the engine
  builds the unsigned spend TEMPLATE (input = the lock outpoint, output = the user's **payout address**
  (F5), locktime/sequence as the contract requires) and parks it as a pending signature at a new
  checkpoint (`AwaitingUserClaim` / `AwaitingUserRefund`), emitting an event. It does NOT sign and does
  NOT broadcast.
- The UI surfaces the unsigned template; the user signs it in their own wallet (or the browser signer);
  the signed spend returns via a submit action (generalise `submit_signed_lock` to
  `submit_signed_spend`, or add parallel `claim`/`refund` arms). The engine validates it against the
  template it built (same-tx check, same as `RemoteSigner` and `submit_signed_lock` already do), then
  broadcasts.

The template output is always the user's payout address, so even a malicious engine cannot redirect the
coin; the user's wallet is the verification point (it shows what it signs).

### 2. The maker's secret becomes user-held

The maker's secret must be generated and held client-side (browser/wallet device), not by the hosted
engine. The engine orchestrates on the hash `H(s)` only:

- The offer/commit carries `H(s)` as today; the engine never needs `s` until it is on chain.
- When the maker is to claim the taker's lock, the engine builds the claim template committing to
  `H(s)`; the client signs AND inserts the preimage `s` into the witness. `s` reaches the chain only
  inside that witness, never the engine.
- The taker learns `s` by reading the maker's claim from chain data (as today, `learned_secret`), and
  uses it to sign-and-fill its own claim client-side.

This moves `self.keys.secret` off the hosted engine. On a self-hosted engine (2a) nothing changes: the
local engine still derives `s` from the local seed.

### 3. Watchtower broadcast (optional, for 2b liveness)

The timelock constraint (0014) says someone holding the user's key must be online to claim or refund in
time. For a 2b user who closes the browser, an optional operator-run **watchtower** removes the
online-presence requirement WITHOUT custody, because it only ever broadcasts transactions the user has
already signed to fixed outputs:

- At each step the browser PRE-signs the next spend (claim and refund), with outputs fixed to the user's
  payout address, and hands the signed transactions to the watchtower.
- A signature does not cover the separate `s` witness element, so the taker's claim can be pre-signed
  before `s` is known; the watchtower, on seeing the counterparty reveal `s` on chain, inserts `s` into
  the pre-signed taker claim and broadcasts. The maker pre-signs its claim with `s` already embedded
  (the maker holds `s`).
- The watchtower broadcasts the claim when the counterparty lock is confirmed and claimable, and the
  refund once the timelock expires and the swap did not complete. It chooses WHICH fixed, user-signed
  transaction to broadcast and WHEN; it can never change an output, forge a signature, or move the coin
  anywhere but the user's payout address. So it is non-custodial by construction.

A watchtower is optional: without one, a 2b user must keep the browser open for the swap, exactly as 2a
keeps its client running.

## Security requirements and adversarial tests (per 0003)

- The hosted engine and the watchtower hold NO spend key, seed, or secret: assert `s` and
  `Use::Claim`/`Use::Refund` keys never leave the client in the 2b path.
- A watchtower cannot redirect: a broadcast transaction's outputs are byte-identical to the user's
  pre-signed one; a tampered output fails signature verification and is un-broadcastable. Test it.
- The user's wallet rejects a template whose output is not the user's payout address (the verification
  point). Test a malicious-template case.
- Claim/refund race bounds are unchanged from the core state machine; the watchtower only automates the
  broadcast the user would have made. Re-run the existing abandon/refund adversarial tests with the
  interactive claim/refund path.
- No double-spend of the user's funds: the watchtower broadcasts at most one of {claim, refund} per
  lock, gated on the same on-chain conditions `decide` uses.

## OSS keeps working, and interop

- Every change is ADDITIVE and gated on the interactive signer; the local hot/engine signer path (the
  current product and 2a) is untouched, with defaults equal to today's behaviour.
- No wire/protocol change: the handoff is local (engine <-> UI), and the watchtower is a new optional
  service that broadcasts standard transactions. A hosted-2b user and a self-hosted node therefore
  trade on the SAME relay and market with the SAME protocol; add an interop test asserting a 2b-signed
  order and a self-hosted order match and settle.

## Scope and sequencing

- In scope: the claim/refund handoff (section 1), the user-held secret (section 2), and the watchtower
  (section 3), each behind the interactive signer.
- The multi-tenant web orchestration (per-session engine state, the browser signing UX, session and
  identity management) is the hosted PRODUCT layer, not this protocol change, and is tracked
  separately.
- Build order: (1) claim/refund handoff first, reusing the 0017 machinery and tests; (2) user-held
  secret; (3) watchtower last, as an optional add-on once (1) and (2) are adversarially tested.

## Out of scope

Any custodial path (operator-held keys, seed, or secret; operator-initiated spends to anywhere but the
user's payout address). A watchtower that can sign. These cross the custody line and are not this note.
