# 0012 Wiring the cold funding signer into the daemon and package (M2b)

Status: implemented (2026-11-11). Stage 1 (daemon) and stage 2 (StartOS package actions + store
wiring) are both built; `funding_mode` resolves per chain in `Daemon::connect` to hot (`ChainNode::open`),
cold (`open_cold` + `RemoteSigner`), or interactive (`open_cold` + `InteractiveSigner`, design 0017),
with the config surface in `sovereign-swap-client-startos` (`startos/actions/config.ts` funding fields,
`startos/fileModels/settings.json.ts` shape). Tested in `tests/cold_signer.rs` (regtest cold lock end
to end through a mock signer; refusal when the funding wallet holds keys; refusal when the signer is
unreachable) and `tests/remote_signer.rs` (the RemoteSigner protocol: sign, refuse, timeout, TLS).

Three things remain, each a deliberate boundary rather than unfinished wiring, and together the
blocking points for running COLD mode specifically (see "Remaining boundaries" at the end):

- a reference signer product (`sovereign-swap-signer`) is not built; cold mode needs the operator to
  run any service that speaks the `RemoteSigner` protocol below. Building that signer is out of scope
  here (see "Out of scope"), a separate milestone;
- a hot-to-cold migration path: a funding wallet that already ran hot (so holds keys) is refused in
  cold mode; switching an existing hot install to cold needs a documented key-rotation/new-wallet step;
- a rescan/birthday for a pre-funded cold account: the watch-only import uses `timestamp: "now"`, so an
  account funded BEFORE it is configured needs a rescan; the operator guidance is to fund the cold
  account AFTER switching.

INTERACTIVE mode (the user signs each funding lock in their own wallet, design 0017) is the
non-custodial path that is fully usable today with NO external signer and needs none of the three
above; it is the recommended way to fund real value now. The signer seam
exists in the library (0008); this note designs how the daemon and the StartOS package select and
reach an external signer, so a user's balance keys never sit on the engine host.

Stage 1 landed the daemon wiring: a per-chain `funding_mode` (`hot` default, or `cold` with a signer
endpoint and account descriptors) in `Settings`; a `RemoteSigner` that forwards the unsigned PSBT to
the signer over the existing node transport and finalises nothing itself; watch-only funding wallet
provisioning (`ChainNode::open_cold`) that imports the account descriptors and refuses a wallet that
holds keys; and `funding_mode` resolution in `Daemon::connect` that probes the signer and refuses to
start rather than ever silently funding hot. The `RemoteSigner` wire protocol is documented in
`src/signer.rs`. Stage 2 then landed the StartOS package action fields and store wiring (per chain:
`funding_mode`, and for cold the signer endpoint, auth, Root CA and the account descriptors). What
remains are the two deliberate boundaries called out in the status above: a hot-to-cold migration
path (an existing keyed funding wallet under the same name is refused) and a rescan/birthday for a
pre-funded account (import uses `timestamp: "now"`), plus the separate reference-signer milestone.

## The gap

Design 0008 built the seam: `FundingSigner` (src/node.rs), `ChainNode::open` creates a hot
`WalletSigner` from the node wallet, and `ChainNode::with_signer` swaps in an external signer and
leaves the funding wallet watch-only. `tests/cold_signer.rs` proves an external signer funds a valid
lock while the funding wallet has `private_keys_enabled=false`.

What is missing is the wiring: the daemon always calls `ChainNode::open(client, &wallet)`, so it
always runs hot, and the StartOS package exposes no way to choose cold funding or to reach a signer.
Today, funding a swap spends from the node's own bitcoind wallet. That is fine for a dust test and
unacceptable for a real balance.

## What this note decides

How the daemon picks a signer, what a cold signer looks like for a StartOS deployment, how the
watch-only funding wallet is provisioned, and the config surface, so M2b can be built without
re-opening 0008.

## Signer selection in the daemon

`Daemon::connect` (src/daemon/mod.rs) resolves each chain's signer from config before opening the
engine:

```
let node = ChainNode::open(client, &wallet)?;      // creates <wallet> + <wallet>-watch
let node = match funding_mode(chain, &settings) {
    FundingMode::Hot      => node,                 // WalletSigner, unchanged default
    FundingMode::Cold(ep) => node.with_signer(RemoteSigner::new(ep)?),
};
```

`funding_mode` is per chain, because BTC and xBTC can run different signers (a user may cold-store
BTC on a hardware device and keep xBTC hot, or the reverse). Default stays `Hot` so nothing changes
for existing installs and for regtest.

## What a cold signer is here

0008 is explicit that an air-gapped human cannot sign inside a timelock, so "cold" means
key-separated, not offline. For a StartOS node the realistic forms are, cheapest first:

1. **A second service on the node (or an adjacent box)** that holds the funding descriptors and
   exposes a narrow "sign this PSBT" endpoint over the local network, reachable the same way the
   daemon reaches bitcoind (HTTPS to a node Root CA, or a Tor onion through the SOCKS proxy). The
   engine host never has the keys; a compromise of the engine cannot move the balance, only propose
   PSBTs the signer may reject.
2. **A hardware wallet behind an automated approver** that enforces a policy (amount ceilings,
   address allow-list, rate limit) and signs without a human in the loop.
3. **An HSM** with the same policy envelope.

All three implement one interface from the daemon's side: take an unsigned, fully-described PSBT,
return it signed or refuse. That is `RemoteSigner`, a new `FundingSigner` impl that forwards the PSBT
to a configured endpoint and finalises nothing itself (the engine finalises through the node, as it
already does for `WalletSigner`).

`RemoteSigner` transport reuses what the daemon already has: the same WS/HTTPS-over-SOCKS and Root CA
machinery used for nodes and relays (0011), so onion-addressed signers work with no new network code.

## The watch-only funding wallet

For cold funding, the funding wallet itself (`<wallet>`, not just `<wallet>-watch`) must be watch-only
and track the user's balance from an account descriptor, so the engine can build funded PSBTs without
any private key. `ChainNode::open` currently creates `<wallet>` with private keys enabled. M2b adds a
provisioning step: when a chain is in cold mode, create `<wallet>` with `private_keys_enabled=false`
and `importdescriptors` the user's account `xpub`/output descriptors (external and change), so
`fundrawtransaction`/`walletcreatefundedpsbt` can select coins and produce a PSBT the external signer
can sign.

The descriptor import is the one new node interaction; everything downstream (replay guard on the
PSBT inputs, hand to signer, finalise) is unchanged from 0008.

## Fee output

The fee output (0010) rides in the funding transaction, so cold funding forces 0008's fee-address
choice. Ship the xpub-derived default (the engine derives a fresh fee address per swap from a
watch-only xpub, works with any signer); offer silent payments only when the signer is BIP352-aware.
This note does not re-decide it, it records that `RemoteSigner` must carry enough of the PSBT (the
inputs and their descriptors) for a BIP352-aware signer to compute the fee output itself.

## Config surface (package actions, never the web UI)

Per our earlier decision, config lives only in the StartOS package actions. M2b adds, per chain, to
the existing node action:

- `funding_mode`: `hot` (default) or `cold`.
- when `cold`: `signer_endpoint` (URL or onion, same shape as a node endpoint), its auth, its Root CA
  if TLS, and the account descriptor(s) / `xpub` for the watch-only funding wallet.

These are node-operator secrets and follow the same rule as RPC credentials: entered through the
action, stored in the package store, never served to the web layer, never logged.

## Security properties and the limits

- The user's balance keys never reach the engine host. A full compromise of the daemon can propose
  funding PSBTs but cannot sign them; the signer's policy (ceilings, allow-list, rate limit) is the
  backstop, so the signer must validate independently and not blind-sign.
- Unchanged and inherent: per-swap claim/refund keys are online (derived from the engine seed),
  exposing only in-flight value, transiently. A missed claim falls back to refund. 0008 covers why.
- The replay guard already runs on the PSBT inputs before signing; keep that ordering (guard, then
  sign) so the signer is never asked to sign a replayable input.

## Testing

- `cold_signer.rs` already proves the seam with an in-process signer. Add:
  - a `RemoteSigner` integration test against a mock HTTP signer endpoint (sign, refuse, timeout,
    malformed response), reusing the transport test harness from `rpc_transport.rs`.
  - a regtest test that funds a lock in cold mode end to end: watch-only funding wallet imported from
    a descriptor, engine builds the PSBT, mock signer signs, lock confirms.
  - a package action config test (valid/invalid endpoint, missing descriptor, hot/cold per chain).
- Negative: assert the daemon refuses to start a swap in cold mode if the funding wallet is not
  watch-only (private keys present means misconfiguration), and refuses if the signer endpoint is
  unreachable, rather than silently falling back to hot.

## Rollout

1. `RemoteSigner` + watch-only descriptor provisioning + `funding_mode` resolution in `connect`.
2. Package action fields and store wiring.
3. Tests above, CI green.
4. Docs: a cold-funding setup guide (operator side) and the clear statement that real funds require
   cold mode; hot stays the regtest/dust default.
5. Only after this lands does the "not for real funds" status become eligible to flip (with the other
   release-readiness gates).

## Out of scope

Building a signer product. M2b targets the generic `RemoteSigner` interface and documents the
contract a signer must meet; which device or service a user runs behind it is their choice, and a
reference signer can be a later, separate milestone.

## Remaining boundaries (the blocking points for cold mode)

The wiring is complete; what gates running COLD mode for real value is deliberate scope, not missing
code. None of these block INTERACTIVE mode, which is non-custodial and usable today.

1. **No reference signer ships.** Cold mode points the daemon at an endpoint that speaks the
   `RemoteSigner` protocol; no such service is built here (see Out of scope). Until a
   `sovereign-swap-signer` (or any conforming signer) exists, cold mode has nothing to point at. The
   config help text in the client package names `sovereign-swap-signer` as the intended reference;
   that package does not yet exist, so either it is built as its own milestone or the help text should
   stop implying it is available. Blocking point: an owner decision to build (or not) the reference
   signer; it is a separate product with its own policy engine (ceilings, allow-list, rate limit) and
   must validate independently, never blind-sign.
2. **Hot-to-cold migration.** An install that already ran hot holds keys in its funding wallet and is
   refused in cold mode by design. Switching needs a documented procedure (new watch-only wallet from
   the cold account descriptors, sweep the old hot balance to the cold account). Blocking point: write
   and test that procedure; no engine change is required.
3. **Pre-funded rescan.** The watch-only import uses `timestamp: "now"`, so coins sent to the cold
   account before it is configured are invisible until a rescan. Operator guidance is to fund after
   switching; a birthday/rescan input would lift the restriction. Blocking point: a small config/import
   enhancement, only if funding-before-configuring must be supported.

Recommendation: for real value now, use interactive funding (design 0017), which needs none of the
above. Treat the reference signer as a separate, owner-gated milestone.
