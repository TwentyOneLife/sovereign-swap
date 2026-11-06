# 0010 Fee output, static and voluntary, to a silent payment address (M2b)

Status: design. Supersedes the open fee question in [0008](0008-cold-funding-and-fees.md) and records
the owner decisions of 2026-11-05 (spec sections 7.5 and 7.5a). The mechanism here ships **off by
default** and stays off until a legal opinion; this document plans every element so the switch, when
it is turned on, flips working code and not a stub.

## What was decided, and what this changes

The spec left two things to the owner. Both are now decided:

- **Fee shape (7.5): a single static rate, voluntary, opt-out.** Not volume tiers. There is no
  coordinator, no account key, no 31-day ledger, and no linkage between a user's trades. Defaults:
  maker 0.20 %, taker 0.30 %, a floor of 1,000 sat per fee output, and a minimum trade of 0.001 BTC.
  Each side pays its fee **in the coin it locks**, as one extra output in its own lock transaction, so
  no price oracle is ever needed.
- **Fee address (7.5a): one published silent payment address (BIP352).** Every swap pays a fresh,
  unlinkable on-chain output derived from that address and the payer's own inputs. No single address
  tags our swaps on chain, there is no xpub for a third party to cluster, and there is no coordinator
  to watch addresses. The cost is that the payer's signer must be BIP352-aware (below).

This removes, for the client, the coordinator and the "chain view / Fulcrum" question that 0008 and
the infra plan carried: with a static fee and silent payments there is nothing for a coordinator to
quote, verify or watch. The operator detects and spends its own fee outputs with the silent payment
scan key, off the swap path entirely.

## Off by default

`Settings.fee_enabled` defaults to `false`. When it is false the engine builds lock transactions
exactly as today: no fee output, no BIP352 code on the path, no new failure mode. The real-proof
milestone (v0.2.0, a real atomic swap over the deployed relay) runs with fees off, so the swap it proves
is unaffected by anything here. Turning the switch on is a deliberate, separately gated act.

The fee is **voluntary** in the honest sense the spec already states (7.3): in open-source P2P
software the fee is enforced by the clients and the relay, not by cryptography. Two modified clients
on another relay can trade without it. That is accepted. The fee pays for the relay, the operator and
development; it is opt-out in advanced settings, not a toll the protocol can force.

## The fee output

For a lock of `locked` in the coin a side is locking, at rate `r` (basis points):

```
fee = max(floor, locked * r / 10_000)          // floor = 1_000 sat
```

The fee output is **extra**: it is funded from the payer's wallet alongside the HTLC output and the
change, never carved out of `locked`. The counterparty receives the full agreed amount; the fee is
the payer's own cost. A trade below the 0.001 BTC minimum is refused before any transaction is built.

Dust and sanity: `floor` (1,000 sat) is far above any dust limit, so a fee output is always
spendable. The fee is checked to be a small fraction of `locked` (a sanity band, same spirit as the
rate band in 0009 layer 2), so a mis-set rate cannot produce a fee larger than the trade.

## Silent payments on the funding path

A silent payment address `sp1...` carries two public keys, scan and spend. The payer, who holds the
inputs it is spending, computes a shared secret from (sum of the eligible input private keys) and the
recipient's scan key, and derives a fresh P2TR output from it. Anyone who holds the address and sees
the transaction's inputs can recompute that same output script and recognise the payment; only the
holder of the scan key can detect it as theirs, and only the spend key can spend it. This is exactly
the property we want: the payer needs no interaction, the counterparty can verify (below), and the
output links to nothing.

The difficulty is that the output script depends on the inputs, and the inputs are chosen by
`walletcreatefundedpsbt`, and the shared secret needs the inputs' private keys, which in production
are at the cold signer. So the fee output cannot be a plain address handed to `fund()` up front. The
flow is two-step:

1. **Select inputs.** Call `walletcreatefundedpsbt` with the HTLC output and a **placeholder P2TR
   output** of value `fee` (P2TR so the vsize, and therefore the miner fee, matches the final tx).
   This fixes the input set and the change.
2. **Resolve and sign.** Hand the PSBT and the silent payment address to the signer. The signer, which
   holds the input keys, computes the BIP352 output script from the chosen inputs and replaces the
   placeholder output's script with it (the value is unchanged, so nothing else moves), then signs.

This is the "BIP352-aware signer" the decision named, and it is not built yet. It is a new method on
the funding seam, not a change to the existing one:

```rust
pub trait FundingSigner: Send + Sync {
    fn sign(&self, unsigned_psbt: &str) -> Result<String, NodeError>;
    /// Replace the placeholder fee output at `vout` with the BIP352 output for `sp_address`,
    /// derived from this PSBT's inputs, then sign. Only called when fees are enabled.
    fn sign_with_silent_fee(
        &self,
        unsigned_psbt: &str,
        sp_address: &str,
        fee_vout: u32,
    ) -> Result<String, NodeError> { /* default: Err(Unsupported) */ }
}
```

`WalletSigner` (the hot regtest default) implements it directly from the node wallet's keys. A cold
signer that is not BIP352-aware returns `Unsupported`, and the daemon refuses to enable fees against
it with a clear message rather than silently dropping the fee. So the signer's capability gates the
feature; it never corrupts a transaction.

## The counterparty check

Spec 7.3 requires that each client verify the other side's lock transaction carries the fee output
before continuing, and otherwise take the refund path, which is always safe. Silent payments make
this checkable without any secret: the counterparty sees the other lock's inputs (public) and holds
the published silent payment address, so it recomputes the expected output script the same way the
payer did and checks that an output with that script and value at least the required `fee` is present.
If it is missing or short, the client does not proceed to its own lock; it stops, and the swap unwinds
through the normal refund. No funds are ever at risk from a missing fee, because the check happens
before this side commits.

This verification is pure public-data computation, so it lives in the engine (not the signer) and is
covered by BIP352 test vectors.

## Settings

Added to `daemon::Settings` (snake_case, persisted, `serde(default)` so old config still loads):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `fee_enabled` | bool | `false` | Master switch. Off keeps the engine on today's path. |
| `fee_sp_address` | string | `""` | The operator's published silent payment address. Required when enabled; validated as a well-formed `sp1` address for the right network. |
| `fee_maker_bps` | u16 | `20` | Maker rate, basis points (0.20 %). |
| `fee_taker_bps` | u16 | `30` | Taker rate, basis points (0.30 %). |

Validation (0009 layer 2, authoritative in the daemon): if `fee_enabled`, then `fee_sp_address` must
parse for the configured network and the signer must report BIP352 support; rates must be within a
sane band (0 to a small cap) so a fat-finger cannot set a punitive fee. The engine enforces the
floor and the "fee is extra, never from the swap amount" invariant regardless of settings, the same
way it enforces confirmations and timelocks (0009 layer 3).

This is **not** the node RPC connection, which is unchanged and already present (`btc_node`,
`xbtc_node`, credentials, confirmations). One unrelated gap noted while here: the 0009 settings
mockup shows cookie auth for the node, but `Settings` only has user/pass. Cookie auth is tracked
separately (it belongs with the StartOS dependency-wired node selection, M4c), not in this document.

## BIP352 dependency

We need a BIP352 implementation for output derivation and the counterparty check. Options: a
reviewed Rust silent-payments crate pinned by `Cargo.lock` hash, or a minimal in-tree implementation
of just sender-side output derivation and receiver-side scanning against the published test vectors.
The input-eligibility rules (which input types contribute to the shared secret) follow BIP352
exactly. Decision deferred to the implementation PR, where the dependency can be weighed against the
sovereign-code preference in GUARDRAILS; either way it is pinned and verified.

## Build order

1. **Settings + validation + off-switch** (this PR's code): the four fields, layer-2 validation, and
   the engine wiring that does nothing when `fee_enabled` is false. Ships in v0.2.0.
2. **Fee amount + placeholder output**: `FeePolicy` computing `fee` from amount, side and rate with
   the floor and the min-trade refusal; `fund()` adds the placeholder P2TR output when enabled.
3. **BIP352 derivation**: the `sign_with_silent_fee` seam, `WalletSigner`'s implementation, and the
   engine-side counterparty check, all against BIP352 test vectors.
4. **Regtest end to end with fees on**: a full swap that pays both fee outputs and verifies each side,
   plus the refund path when a fee output is absent.

Steps 1 and 2 are mechanical and safe. Step 3 is the real cryptographic work and sits on the
funding-PSBT path the cold signer approves, so it is the one that needs the test vectors and careful
review before fees are ever switched on in anger.

## Test plan

- **Unit**: fee amount (rate, floor, rounding), min-trade refusal, the sanity band, and that a
  disabled fee adds no output and changes no byte of today's path.
- **BIP352 vectors**: sender output derivation and receiver scanning match the BIP352 test vectors.
- **Counterparty check**: accepts a correct fee output, rejects a missing one, rejects a short one,
  rejects one to the wrong script, and in each rejection the swap takes the safe refund path.
- **Signer capability**: enabling fees against a non-BIP352 signer is refused at validation, not at
  transaction build.
- **Regtest e2e**: a full swap with fees on pays and verifies both outputs; the operator scans and
  finds its two fresh outputs; nothing links them.

## What this deliberately does not add

No coordinator, no fee quote request or response, no account key, no volume ledger, no address
watching, no Fulcrum or Shulcrum Electrum connection for fees. The static voluntary model needs none
of them. If volume tiers ever return (they were considered and set aside in 7.5), they are a
coordinator service and a separate design, not a change to this path.
