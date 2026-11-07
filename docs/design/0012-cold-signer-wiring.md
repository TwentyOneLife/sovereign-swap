# 0012 Wiring the cold funding signer into the daemon and package (M2b)

Status: design. The signer seam exists in the library (0008); this note designs how the daemon and
the StartOS package select and reach an external signer, so a user's balance keys never sit on the
engine host. No code yet.

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
