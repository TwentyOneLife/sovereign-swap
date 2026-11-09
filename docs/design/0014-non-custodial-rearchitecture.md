# 0014 Non-custodial re-architecture: thin client, Electrum backend, user-held signing

Status: design, strategic. This is the full specification for turning sovereign-swap from a
single-operator client that needs two full nodes into something a user can run with a wallet and a
thin client against shared chain data, without anyone custodying their funds. It exists to support a
go-forward decision for the project (see the decision section at the end). No code yet.

## Goal and non-goals

Goal: a user swaps with **a BTC wallet, an xBTC wallet, and a thin client**, using hosted chain data
(our Fulcrum/Shulcrum) and the relay, while **holding their own keys and signing their own swaps**. No
operator custody, so no KYC.

Non-goals: custodial operation (rejected, it is a regulated business); changing the swap protocol
itself (the wire protocol and the state machine stay); a general-purpose wallet (we integrate existing
wallets, we do not build one).

## What the current architecture actually is (verified in source)

- **The protocol core is already pure and backend-agnostic.** `Swap::decide(view: &ChainView, secret)`
  (`swap.rs`) is a state machine over a `ChainView` snapshot (heights, confirmations, lock status). It
  returns `Action`s and touches no node. This is the valuable, audited part, and it does not change.
- **The bitcoind coupling is only at the engine-to-node boundary.** The engine builds the `ChainView`
  from `ChainNode` (`node.rs`, bitcoind RPC) and executes `Action`s against it: it funds with
  `walletcreatefundedpsbt`, signs through the `FundingSigner` trait, and broadcasts with
  `sendrawtransaction`.
- **Signing is already behind a trait.** `FundingSigner` (`node.rs`) abstracts signing; `WalletSigner`
  is the hot bitcoind impl, and `ChainNode::with_signer` can swap in an external one (design 0012,
  unwired).
- **Funding and chain data are not abstracted.** `ChainNode` is a concrete bitcoind wallet client.
  Coin selection and PSBT construction are done by bitcoind's wallet, not by us.
- **The daemon is single-tenant.** One `identity_seed` and one `routing_seed` per data dir; every
  swap's keys come from that one seed.

The practical meaning: the hard part of the swap (the protocol state machine) is reusable as-is. The
re-architecture is a bounded change at the node boundary plus key custody, not a rewrite.

## The custody line (the one invariant)

Non-custodial means the operator's infrastructure never holds anything that can move a user's coin:
no spend key, no seed, no funded-and-signable wallet. The operator may hold, and serve, only:

- chain data (read) and transaction broadcast,
- the relay (encrypted messages),
- watch-only descriptors to monitor a user's swap.

Every design choice below is checked against this line.

> **IMPLEMENTED (F5): operator-owned payout destinations.** A node's claimed proceeds and its refunds
> land at an operator-configured payout address per chain (`btc_payout` / `xbtc_payout`, engine config;
> network-checked in `node.rs`), or, when none is set, a fresh address from the node's own funding
> wallet. Directing proceeds to an external operator-owned address keeps claimed coin from accumulating
> in the node's hot funding wallet, consistent with the custody line above. A payout address is a
> destination only; it confers no control over a user's in-flight swap.

## The re-architecture

### 1. A chain backend trait

Introduce `ChainBackend`: the data and broadcast surface the engine needs, with no wallet in it.
Methods, drawn from what the engine uses today: tip height; confirmations for a txid; fetch a
transaction; is-an-output-spent / find-spend; broadcast a raw transaction; register a watch-only
script and report its transactions. `ChainNode` becomes one impl (bitcoind); an `ElectrumBackend`
(Fulcrum for BTC, Shulcrum for xBTC) becomes another. The engine depends on the trait, not on bitcoind.

This is what removes the user's full-node requirement: the thin client points `ChainBackend` at our
Electrum endpoints.

### 2. Funding and signing move to the user's wallet

Electrum servers have no wallet, so coin selection and PSBT construction cannot sit on the backend.
They move client-side, to the user's own wallet:

- The engine computes the **lock specification** (output script, amount, locktime) from the swap, as
  it does now, but no longer funds it itself.
- The user's wallet **selects coins, builds the funded PSBT, and signs** it. This is the natural job
  of Sparrow (BTC) / Shrike (xBTC) and of the `FundingSigner`/`with_signer` seam generalised: a
  `WalletBackendSigner` that hands the lock spec to the user's wallet and gets back a signed, funded
  transaction.
- The backend only **broadcasts** it and then **watches** the resulting outputs.

The claim and refund transactions are the same shape: the engine builds the spend template, the user's
wallet (holding the per-swap keys) signs, the backend broadcasts.

### 3. Where the per-swap keys live, and the timelock constraint

The swap's claim/refund/secret keys must be the user's and must be available to sign **within the
timelock window** when the state machine says to act. This is the real constraint and it forks the
product:

- **2a, thin client (recommended first).** The user runs the client (desktop or StartOS app). The
  per-swap keys are derived from the user's own seed, held locally, and the local engine signs when
  `decide` says to. The backend (our Electrum) and the relay are shared; keys and signing are local.
  No full node, fully non-custodial, and the online-presence requirement is just "the user's client is
  running," the same as any swap today.
- **2b, hosted web service (later, optional).** We host the engine and the UI; the user connects a
  wallet in the browser and signs each step there. This needs everything in 2a plus (i) multi-tenant
  engine state and per-session key isolation, (ii) a browser-wallet signing flow for lock/claim/refund,
  and (iii) the user's browser (or a signer they control) present during the swap, because we must not
  hold the key that signs a refund. A watchtower we host can monitor and alert, but it cannot sign.

There is no non-custodial way to let a user go fully offline mid-swap: someone holding their key must
be online to claim or refund in time. 2a makes that someone the user's own client; 2b makes it the
user's browser/signer. Only custody removes it, and custody is out.

### 4. Multi-tenancy (2b only)

For a hosted engine, isolate per user: separate engine state, separate relay identity/routing seed per
session, no shared swap store, strict separation so one user cannot see or affect another's swaps. For
2a this is free, because each user runs their own client.

## Security requirements

- The operator's Electrum/Fulcrum/Shulcrum endpoints expose **no wallet RPC**, only chain data and
  broadcast. A user must never be able to reach `walletcreatefundedpsbt` or spend anything.
- Watch-only descriptors only on any shared node.
- The relay stays hardened and public-safe (caps, NIP-11, monitoring; issue #45).
- 2b web surface keeps the Basic-auth + token boundary and the fail-closed default, per session, with
  login rate-limiting.
- Package sandbox isolation so a web/relay compromise cannot reach a wallet or a key.

## Effort and risk, by piece

- **ChainBackend trait + refactor the engine onto it:** medium. Mechanical but touches the engine's
  node calls; the pure state machine is untouched, which caps the blast radius. Strong test coverage
  exists to catch regressions.
- **ElectrumBackend (Fulcrum/Shulcrum):** medium-large. New network code (Electrum protocol, over Tor
  and TLS), confirmation and spend lookups, watch-only subscriptions. Reuses the transport work.
- **Client-side funding + `WalletBackendSigner`:** large. This is the real shift: moving coin selection
  and PSBT construction to the user's wallet, and defining the wallet-signing handoff for lock, claim,
  and refund. Generalises 0012.
- **2b multi-tenancy + browser signing:** large, separate phase, only if demand justifies it.

## Impact on the current project

This does not throw the current project away; it builds on it. The protocol, the state machine, the
relay, the fee design (0010/0013), and the security hardening all carry forward unchanged. What changes
is the node boundary and where keys/funding live. The current single-node sovereign client remains a
valid product (model 1) and, in fact, becomes the reference implementation the thin client is derived
from.

## Go-forward decision (for the user)

Three coherent directions, not mutually exclusive over time:

- **A. Finish and ship the sovereign client (model 1).** Complete the per-chain fee (0013), the
  release-readiness gates, the public hardened relay, and 0013 monetisation. Smallest path to a
  shipped, non-custodial product, for people who already run both nodes. Lowest risk, narrow audience.
- **B. Then build 2a (this spec).** The ChainBackend trait, the Electrum backend, and client-side
  signing, so a user needs only wallets and a thin client. Largest single audience unlock per unit of
  effort, still non-custodial, and it reuses everything in A.
- **C. Then build 2b (hosted web service).** Multi-tenant hosted engine with browser signing. Broadest
  reach, largest effort, defer until A and B prove demand.

Recommendation: **A now, B next, C only on demand.** A is close and gives a real product; B is the
strategic re-architecture and should be a deliberate milestone, not a detour mid-release; C waits.
Custody (a fourth option) stays rejected.

**Decided 2026-11-07: A.** Finish the current sovereign release (per-chain fee 0013, release-readiness
gates, public hardened relay), then make 2a (B) the next milestone. The fee work (stage 1 of 0013)
resumes. B is specified here and tracked for after the release; C waits on demand.

## Out of scope

Building a wallet, and any custodial path.
