# 0032 Output-only funding: run the client without a funding wallet

Status: design, proposed 2026-11-14. Builds on [0017](0017-user-held-signing-psbt-handoff.md)
(Interactive funding), [0018](0018-interactive-funding-and-the-fee-output.md) (the fee output under
Interactive) and [0019](0019-adopt-a-user-broadcast-funding-lock.md) (adopting a user-broadcast lock).
Not yet implemented.

## Problem

The client cannot start as a pure front-end. In Interactive (and Cold) funding the daemon **refuses to
start without both account descriptors**, and at boot it opens a watch-only funding wallet from them:

- `validate_funding` (`src/daemon/types.rs`): *"cold and interactive modes need a receive and a change
  account descriptor"* - a hard startup error.
- `ChainNode::open_cold` (`src/node.rs`): imports `descriptor_receive` + `descriptor_change` so
  `walletcreatefundedpsbt` can **select the user's coins and add change** when it builds the funding
  PSBT (`src/node.rs` ~601).

So "run the website" is coupled to "configure a funding wallet". That is the wrong shape for the model
we actually want: the client is a **front-end that holds nothing**, and funding is a **per-trade**
act - the user locks coins when they make an offer, or signs a PSBT when they take one. The descriptors
are needed only so the daemon can pick inputs *for* the user, a convenience the user does not need and
that forces wallet state onto a node that should have none.

## Proposal: an output-only funding template

Add a funding path where the engine emits a PSBT that contains **only the swap's required outputs** (the
HTLC lock output, plus the fee output when enabled) and **no inputs**. The user's own wallet (Sparrow
for BTC, Shrike for xBTC) adds the inputs and change, signs, and the lock is broadcast (by the daemon on
submit, or by the user per 0019). The daemon never holds, imports, or selects from the user's wallet.

Consequences:

- **No funding descriptors anywhere.** The daemon needs none at startup or at fund-time. The website
  runs with zero funding config; the only funding input is the signed PSBT a user hands back per swap.
- **Watch-only is per-contract, not per-wallet.** The daemon already tracks each swap contract in the
  `-watch` wallet (`start()` -> `watch_contract`) and derives the exact expected lock txid from the
  parked PSBT (0019). Confirmation detection, claim and refund are unchanged: they drive off the
  on-chain `lock_view`, not off any funding wallet.
- **Balance is the user's concern.** The daemon cannot pre-check that the user has the coins (it has no
  view of their wallet). Instead it validates the **returned** PSBT before broadcast: the HTLC output
  script and amount are exactly the committed ones, the fee output (if any) matches the agreed address
  and amount, and the transaction is final and fully signed. A wrong or underfunded PSBT is rejected,
  not broadcast - no worse a failure mode than the user signing a wrong PSBT today.

### Mode shape

Keep `FundingMode::Interactive` and make the descriptors **optional**, selecting the builder by their
presence:

- **Interactive, descriptors set (status quo, 0017):** the daemon builds a fully-funded PSBT
  (`walletcreatefundedpsbt` over the watch-only wallet). Convenient for a single-operator market-maker
  who funds from one known account.
- **Interactive, descriptors empty (new, this design):** the daemon builds an **output-only** PSBT
  (`createpsbt` with the HTLC + fee outputs, empty input list). The user's wallet funds and signs it.

This keeps one mode, one `/signed-psbt` endpoint, and one claim/refund path; only the builder and the
startup validation branch on whether descriptors are present. (`Cold` is untouched: an always-on
external signer still needs descriptors and an endpoint.)

## Code changes (sketch)

1. **`src/daemon/types.rs` `validate_funding`:** for `Interactive`, descriptors become optional. Require
   them still for `Cold`. Drop the "interactive needs ... descriptor" push when mode is `Interactive`.
2. **`src/daemon/mod.rs` `open_chain` + `src/node.rs` `open_cold`:** when `Interactive` **and**
   descriptors are empty, open only the `-watch` contract wallet; skip creating/importing the funding
   wallet. Factor the funding-wallet import out of `open_cold` so the watch-only-contract path can stand
   alone (`open_watch_only(name)` -> opens `-watch`, no funding wallet).
3. **Funding-PSBT builder (`src/node.rs`):** add an output-only builder used when there is no funding
   wallet - `createpsbt([], [{lock}, {fee?}])` returning the unsigned template - in place of
   `walletcreatefundedpsbt`. The HTLC and fee outputs are already computed by the engine; this just
   omits input selection and change.
4. **`post_signed_psbt` (`src/daemon/mod.rs` ~1607):** generalise validation to not assume the daemon
   chose the inputs: verify the submitted tx contains the committed HTLC output (script + amount) and
   the agreed fee output, and is final/complete, before broadcast. The same-txid match (0019) still
   anchors adoption of a user-broadcast lock.
5. **`FundingMode::Interactive` doc comment + `FundingConfig`:** note descriptors are optional and what
   their absence selects.

## Fee output

Unchanged from 0018: a **normal (P2TR) fee address** is placed directly in the template as an output,
and the user signs it - this works with output-only funding exactly as it works today. A **silent
payment (`sp1`) fee** still cannot be built here (BIP352 derives the output from the spending inputs'
keys, which only the user's wallet holds), the same constraint 0017/0018 already record. So output-only
funding is fully compatible with the fee **on**, as long as the fee address is a normal address - which
is the current default.

## Claim and refund destinations are required in this mode (critical)

`Engine::destination` (`src/engine.rs:1545`) picks the claim/refund address as: the configured
`btc_payout`/`xbtc_payout` address **if set**, otherwise `self.nodes[chain].new_destination()` - a fresh
address drawn **from the node's funding wallet**. With output-only funding there **is no funding
wallet**, so the fallback has no source: the received coins (the taker's claimed xBTC, a maker's claimed
BTC) and a refund would have nowhere valid to land, or would land on the node - exactly the "funds on the
node" outcome this design exists to prevent (and the xBTC-interactive correction of 2026-11-14 depended
on the claim landing cold).

Therefore, in output-only mode the **per-chain payout addresses are mandatory**: the daemon refuses to
start output-only (or refuses the offer/take) unless a claim destination for the receiving chain and a
refund destination for the funding chain are configured (the existing `*_payout_address` fields, or a
per-trade address supplied at offer-create / take time). This ties into F5 (operator-configured
claim/refund destinations) and 0027's user-held destinations. Validation must assert
`new_destination()` is never reached when there is no funding wallet.

## What this is not

This is **not** the hosted browser-custody layer (0023): there is still exactly one operator identity
per client daemon, and the user and operator are the same person on a standalone node. It only removes
the funding **wallet** from that daemon. The multi-user, per-identity orchestration remains the separate
`sovereign-swap-web` concern.

## Description/doc changes that follow

- `sovereign-swap-client-startos` `startos/actions/config.ts`, Funding action: Interactive's description
  should say the descriptors are **optional** - *"leave them empty to fund entirely from your own wallet
  (the client gives you a PSBT with just the swap output; your wallet adds the inputs, change and
  signs)"* - and drop "refuses to start" for Interactive.
- `docs/guide/run-your-own.md` and `docs/guide/architecture.md`: Interactive no longer needs descriptors;
  the client can run as a pure front-end and fund per trade.
- This file's decision, once approved, supersedes the "Interactive needs both descriptors" statement in
  0017's config surface (the engine-built-PSBT path stays as the descriptors-present variant).

## Open questions

1. **Coin selection UX in the user wallet.** Sparrow/Shrike can fund a PSBT that has a fixed output
   (add inputs + change). Confirm the exact import path we document per wallet, and whether a
   round-trip through "Add Inputs" preserves the HTLC output untouched.
2. **Minimum-viability check.** Without a wallet view, should the GUI surface the required amount
   prominently (it must, since the user sizes the funding) and should `post_signed_psbt` reject an
   over-large fee or a dust change the user accidentally created?
3. **Interaction with 0019 adoption.** The output-only template changes who selects inputs but not the
   txid-anchored adoption; confirm the red tests in 0019 still hold when the inputs are user-chosen.
