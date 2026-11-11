# 0022 Silent-payment (sp1) fee and donation collection (#110)

Status: proposal, 2026-11-10; corrected 2026-11-11 (see "Correction" below). Addresses #110 and the
finding in runbook `bb2c478` ("fees use plain taproot, not sp1"). Builds on
[0010](0010-fee-output-and-silent-payments.md) (fee output and silent payments) and
[0013](0013-fee-collection-and-address-choice.md) (fee collection and address choice), and is bounded
by the later, merged [0018](0018-interactive-funding-and-the-fee-output.md) (normal taproot is the
universal fee default; sp1 is opt-in).

## Correction (2026-11-11): the PAYING side needs a BIP352-aware signer

This note (drafted before 0018 and #166 landed) said configuring an sp1 fee address "just works today".
That is true only for a **hot, BIP352-aware signer** (the regtest `WalletSigner`). It is NOT true for
the production paths:

- The production **cold** signer (`RemoteSigner`, `src/signer.rs`) is not BIP352-aware; `node.rs`
  `sign_with_silent_fee` refuses by default, so a cold-funded lock cannot build an sp1 fee output.
- **Interactive** funding (0017, the non-custodial path) structurally cannot build one: the engine
  holds no input private keys, and a silent-payment output is derived from them.

Design 0018 therefore makes normal taproot the universal fee default and sp1 an opt-in for a hot or
BIP352-aware signer only, and the fundability guard (#166) now REFUSES, at publish and at bid, an sp1
fee for a chain the party funds interactively or with a non-BIP352 cold signer, so it can never strand
a swap. Consequences for #110:

- **Beta stays on taproot** (owner decision). sp1 paying is simply unavailable on the interactive path,
  and unavailable on the cold path until a BIP352-aware cold signer exists.
- #110 is therefore **not purely ops/key**. Two tracks: (a) the PAYING side for cold-mode operators
  needs a BIP352-aware cold signer (a signer feature, the `sovereign-swap-signer` milestone); (b) the
  project's own RECEIVING side is the ops/key task below (its scan half shipped scan-only in the fee
  scanner, #168; the sweep and the offline key material remain).

The rest of this note (the receiving-side plan) stands; read "just works today" as "works with a
BIP352-aware signer".

## The important correction this note records

#110 is framed as "implement sp1 fee addresses". VERIFIED (2026-11-10): **the sp1 fee path is already
implemented and tested end to end.** The work is NOT an engine feature, it is a configuration and
key-management change. Evidence:

- `FeeDest::parse` (`src/node.rs`) returns `FeeDest::SilentPayment` for any `sp1...` fee address.
- `ChainNode::fund` builds the silent-payment fee output and returns a `FeeProof` for a
  `FeeDest::SilentPayment` dest (`src/node.rs`, `pay_fee` + `place_fee_output_and_sign`).
- `Engine::fee_state`'s `FeeDest::SilentPayment` arm verifies the counterparty's sp1 fee output against
  the DLEQ proof (`src/engine.rs`, design 0010).
- The regtest test `a_lowered_min_trade_lets_the_fee_apply_to_a_small_swap` (`tests/swap.rs`) already
  drives a full swap whose BOTH fee addresses are `SilentPaymentAddress`es, to `Phase::Done`.

So the protocol already carries an sp1 fee output plus its DLEQ proof, and both sides already fund and
verify it. Configuring an `sp1...` fee address "just works" **with a hot or otherwise BIP352-aware
signer** (see the Correction above: the production cold and interactive paths cannot build one).

## What is actually unfinished (the real #110)

The PROJECT's own fee and donation collection uses **plain, reused taproot addresses**: the client bakes
`fee_btc_address`/`fee_xbtc_address` as `bc1p...` taproot defaults (`settings.json.ts`), and the
published donation address is a single receiving address. Reusing one on-chain address deanonymises the
project's receipts (every fee and donation is linkable on chain). Fixing that means the project collects
to sp1 instead, which requires:

1. **A project silent-payment key.** sp1 is a scan key plus a spend key. The project must generate this
   key material offline and keep the spend key cold (the same discipline as any receiving key). The sp1
   ADDRESS (derived from the public scan + spend keys) is what gets published and baked, and is safe to
   publish, exactly like the current taproot address.
2. **A scanning and claiming procedure.** sp1 outputs are unlinkable, so the project cannot just watch
   one address: it must scan each relevant chain with the scan key to find the per-swap outputs destined
   to it, then spend them with the spend key. This is the operational cost sp1 trades for privacy. A
   scanning tool (or a wallet that supports BIP352 receiving on both BTC and the BLAKE2b chain) is
   required before switching, so receipts are not stranded.
3. **Switching the configured addresses.** Once 1 and 2 exist, change the baked DEFAULT
   `fee_btc_address`/`fee_xbtc_address` in the client (`settings.json.ts`) and the published donation
   address to the project's sp1 addresses. The daemon needs no change. Remember the per-chain rule
   (0013): the BTC sp1 and the xBTC sp1 address must each stay on their own chain, and this chain shares
   Bitcoin's address format, so a published sp1 address still needs the note that coin sent there is a
   different asset.

## Compatibility and the "off by default" question

- **No wire change, no protocol bump.** The sp1 fee output and DLEQ proof are already in the protocol
  (0010). A counterparty running today's code already funds-and-verifies an sp1 fee when the offer's fee
  address is sp1. Switching the project's addresses changes only what the fee pays to, which is already
  a per-offer value the counterparty reads.
- **Off by default is already true.** The owner asked for sp1 "behind an off-by-default flag". That
  property holds without a new flag: the default configured addresses are plain taproot, and sp1 is
  opt-in purely by configuring an `sp1...` address. There is nothing to gate in the engine, because the
  engine already does the right thing for whichever address type it is given. Adding an engine flag
  would be redundant with the address field that already selects the behaviour.
- **Optional safeguard (only if wanted).** If an operator wants to guarantee they never collect to a
  reusable address by accident, a small `fee_require_private` daemon setting (default false) could
  refuse a `FeeDest::Normal` fee address when set. This is a convenience guard, not required for #110,
  and is the only engine code this issue could justify. Recommend deferring it unless an operator asks.

## Recommendation

1. Reframe #110 from "implement sp1 fee" (done) to "adopt sp1 for the project's own fee and donation
   collection", an ops/key task: generate the project sp1 key offline, stand up scanning, then switch
   the baked defaults and the published donation address.
2. Make no engine or wire change for #110. The optional `fee_require_private` guard is the only code it
   could justify, and only on request.
3. Keep the plain-taproot defaults until scanning exists, so no fee or donation is ever sent to an sp1
   address the project cannot yet find and spend.

This note is the owner's decision point: the key generation and the choice to switch the baked and
published addresses are owner actions (they touch the project's receiving keys), not something a coding
session should do unattended.
