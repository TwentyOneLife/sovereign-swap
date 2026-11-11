# 0023 Hosted non-custodial swap service (#46)

Status: proposal, 2026-11-11. Addresses #46. Scopes a hosted deployment of the swap where the operator
hosts only the safe-to-share parts and never custodies user funds. Builds on
[0014](0014-non-custodial-rearchitecture.md) (thin-client direction),
[0016](0016-electrum-chain-backend.md) (Electrum ChainBackend),
[0017](0017-user-held-signing-psbt-handoff.md) (user-held signing) and
[0012](0012-cold-signer-wiring.md) (funding modes). This note is design only: the build is gated on the
compliance read (#104, see "Custody/KYC boundary") and on the owner's go decision.

## Goal and the custody line

Let a user swap without running their own full nodes, while the operator never holds or can move user
funds and no KYC obligation attaches. The hard line: the operator hosts chain data and relays (public
by nature); the user keeps their keys and signs their own locks. Anything that would let the operator
move a user's coin (a shared spendable wallet, operator-held signing keys, pooled balances) is out of
scope by definition, because it would make the service custodial.

## Two models

- **2a. Thin self-hosted client against hosted chain data.** The user still runs the client (StartOS
  package or binary), but points its reads at the operator's Electrum endpoints instead of a local full
  node, and funds via interactive (user-held) signing. The operator hosts only Electrum + relay. This is
  the near-term model and is mostly already possible (see Enablers).
- **2b. Hosted multi-tenant web service.** The operator also hosts the client/GUI for many users at
  once. This needs per-session isolation and browser-wallet signing and is explicitly later.

## Enablers and their current state (on main)

- **Electrum read backend (0016).** `src/electrum.rs` `ElectrumBackend` implements `ChainBackend`;
  `tests/electrum_swap.rs` drives a swap whose BTC side reads/broadcasts through a real Fulcrum. So a
  client can already read a chain without a local full node for that chain. Remaining for 2a: an
  operator-facing deployment note (which Electrum/Fulcrum endpoints to expose, over Tor and/or clearnet
  LAN) and client config to point both chains at Electrum.
- **User-held signing (0017).** Interactive funding parks an unsigned PSBT the user signs out of band;
  the engine holds no spending key. Non-custodial by construction. Available today.
- **Watch-only chain view (0012).** The funding wallet is watch-only from the user's account
  descriptors; no spending key on the host. Available today. Enforcement gap for a hosted node: no user
  may reach wallet RPC on it (operator firewalls the RPC; the daemon API is token-gated and loopback by
  default).
- **Public relay.** The relay is non-custodial already. A clearnet endpoint + NIP-11 + tuned anti-abuse
  caps + monitoring (overlaps #45, now largely shipped) make it usable by hosted clients. Independent of
  the rest of this note and the smallest shippable slice. OUTWARD-FACING, so an owner go decision.
- **Multi-tenant engine (2b only).** The engine is single-seed, single-tenant today. 2b needs per-user
  state and keys with no cross-user leakage, and browser-wallet (e.g. PSBT via WebUSB/paste) signing.
  NOT started; the largest piece.

## Custody/KYC boundary (depends on #104)

Whether even the non-custodial 2a/2b posture triggers a registration or KYC obligation is a
legal/compliance question, not a protocol one. This note does not assert the boundary; it records the
design so that **once #104 (the compliance read) returns**, the operator can decide which model, if any,
to run and what notices to show. The engineering keeps the operator non-custodial regardless; #104
decides whether that is sufficient in the target jurisdiction.

## Recommendation / sequencing

1. Treat the **public clearnet relay slice** as the one independently-shippable, non-custodial piece;
   gate it only on the owner's outward-exposure decision (not on #104 or 2b).
2. For **2a**, write the operator deployment note (hosted Electrum endpoints + client config) and a
   "non-custodial, your keys" product notice; ship after #104.
3. Defer **2b** (multi-tenant + browser signing) as a separate milestone; do not start it until 2a has
   run and #104 is settled.
4. No engine or wire change is required for 2a; it is deployment + config + docs on top of the Electrum
   backend and interactive signing that already exist.

## Out of scope

Any custodial variant (operator-held keys, pooled funds, operator-initiated spends). Building a hosted
wallet. These change the custody line and are not this note.
