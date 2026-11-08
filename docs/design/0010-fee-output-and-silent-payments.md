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

> **REVISED 2026-11-08 (owner decision): on by default for a fresh install.** `Settings::default()`
> now ships `fee_enabled: true` with the project's per-chain fee addresses, reversing the original
> "off until a legal opinion" stance below. The reversal is scoped so no existing install is migrated:
> a config that never set the key still deserializes to `false` via `serde(default)`, and an explicit
> `false` is never changed. Only a truly fresh default is on. The rest of this section documents the
> original stance for context.

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
the payer's own cost. A trade below the minimum trade is refused before any transaction is built.

The minimum trade is **configurable** (daemon setting `min_trade_sat`, default 100,000 sat = 0.001
BTC), threaded into both the funding path and the counterparty's verify path so the two sides agree.
Lowering it lets the fee apply to a small real-rate leg (xBTC is far cheaper than BTC, so a realistic
swap's BTC side is tiny). It travels in the settings, not in the offer's `FeeTerms`, so both operators
must set the same value; a mismatch fails safely (the verifier marks the fee `Failed`, or funding
errors loudly, before anything commits) and never loses funds. The floor (1,000 sat) is **not**
configurable: it guards Bitcoin's dust limit.

Dust and sanity: `floor` (1,000 sat) is far above any dust limit, so a fee output is always
spendable. The fee is checked to be a small fraction of `locked` (a sanity band, same spirit as the
rate band in 0009 layer 2), so a mis-set rate cannot produce a fee larger than the trade.

> **IMPLEMENTED 2026-11-08 (F3).** The band is `fee_exceeds_band(fee, locked)`:
> `fee > MAX_FEE_FRACTION_BPS (50%) of locked`. It is enforced **only locally** - a maker at publish
> (`post_offer`) and a taker before it takes (`bid`) - and never in counterparty fee verification, so
> an old and a new peer never disagree over an offer. Under today's constants it **cannot fire**: the
> swap minimum (`MIN_SWAP_FLOOR_SAT`, 3,000) keeps the 1,000-sat floor to at most ~33% of the smallest
> leg. It is belt-and-braces, guarding only against a later lowering of the swap minimum or a raising
> of the floor/bps cap. It does NOT cap dust-fee economics; that would be a different, lower threshold.

## Silent payments on the funding path

A silent payment address `sp1...` carries two public keys, scan and spend. The payer, who holds the
inputs it is spending, computes a shared secret from (the sum `a` of the eligible input private keys)
and the recipient's scan key `B_scan`, and derives a fresh P2TR output from it. By the ECDH identity
`a * B_scan = b_scan * A` (where `A = a*G` is the public input sum), the output can be computed by the
payer (who knows `a`) or the recipient (who knows the scan private key `b_scan`), **and by no one
else**: a third party sees only `A` and cannot recover the shared secret. Only the scan key detects
the output, only the spend key can spend it. This third-party unlinkability is the property we want on
chain; it is also, deliberately, why the counterparty cannot by itself verify the payment (see below).

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

## The counterparty check (open owner decision)

Spec 7.3 requires that each client verify the other side's lock transaction carries the fee output
before continuing, and otherwise take the refund path, which is always safe. That mutual check is
what makes 7.3's claim true, that skipping the fee takes *two* modified clients: without it, one
modified client can omit its own fee while trading against a stock client that still pays.

An earlier draft of this document claimed the counterparty could recompute the expected fee output
from public data. **That was wrong**, and it is wrong for the exact reason silent payments are
private: the output needs either the payer's input-key sum `a` or the operator's scan key `b_scan`,
and the counterparty holds neither. So the check cannot be a silent recomputation. Three ways to
restore it, a decision for the owner (as 7.5a was):

- **(A) The payer reveals its ECDH share.** The payer sends, over the already encrypted swap channel,
  the point `S = a * B_scan` for its lock, optionally with a DLEQ proof (BIP374) that `S` matches the
  lock's public input sum `A`. The counterparty rebuilds `A` from the lock's inputs, (verifies the
  proof,) derives `B_spend + hash(S‖k)*G`, and checks that output is present with value at least
  `fee`. Without the DLEQ proof a dishonest payer can at most send a wrong `S` and so burn its own
  fee to an output the operator cannot find by scanning; it cannot redirect the counterparty's funds,
  because every candidate output is still `B_spend + t*G`, spendable only with the operator's spend
  key. So the cheap no-proof variant is safe for the counterparty and only weakens "the operator can
  always find its fee"; DLEQ can be added later. This is the recommended path and matches the
  direction hardware signers are taking (BIP375, silent payments in PSBTs). It adds **one versioned
  field to the swap message** (the share, and later the proof).
- **(B) Drop the check.** Accept that a fee is one-sided-skippable by a modified client and amend spec
  7.3. Simplest, and defensible given the fee is already voluntary and unenforceable against two
  modified clients; the cost is that it is now unenforceable against *one*.
- **(C) Xpub with a deterministic per-swap index.** The only mechanism that needs no reveal: both
  sides derive the same fee address from the operator's xpub at an index fixed by the swap id, so the
  counterparty recomputes it directly. It costs exactly the on-chain linkability (one xpub clusters
  all fees) that 7.5a chose silent payments to avoid.

Whatever is chosen, no funds are ever at risk from a missing or wrong fee: the check runs before this
side commits its own lock, and a failure takes the always-safe refund path.

Until the owner decides, this document specifies only the parts every option shares (below): the
BIP352 core and the fee output. The counterparty check and any new swap-message field are held, and
the swap message format is versioned when the field is added.

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

## BIP352 implementation

Decided (2026-11-06): a **minimal in-tree** implementation, not an external crate. The primitives it
needs (`secp256k1`, tagged SHA256, bech32m) are already in the dependency tree via the `bitcoin`
crate, so an external silent-payments crate would add no capability we lack while pulling its own,
possibly mismatched, `bitcoin`/`secp256k1` versions (a second `secp256k1` in a wallet is a real
footgun) and an unaudited dependency onto the money path. In-tree keeps the one pinned `secp256k1`,
matches the sovereign-code preference in GUARDRAILS, and is bounded: address parse and encode, tagged
hashes, sender output derivation, and receiver scanning, roughly a few hundred lines. Its correctness
gate is the official BIP352 `send_and_receive_test_vectors.json`, checked in under `tests/fixtures/`
pinned to a bips commit with a recorded SHA256. The input-eligibility rules (which input types
contribute to the shared secret) follow BIP352 exactly.

## Build order

1. **Settings + validation + off-switch** (done, PR #27): the four fields, layer-2 validation, and no
   engine change while `fee_enabled` is false. Ships in v0.2.0.
2. **Fee amount + placeholder output**: `FeePolicy` computing `fee` from amount, side and rate with
   the floor and the min-trade refusal; `fund()` adds the placeholder P2TR output when enabled.
3. **BIP352 core (in-tree)**: address parse/encode, tagged hashes, sender derivation and receiver
   scanning, all against the pinned test vectors. Needed by every counterparty-check option, so it is
   built before that decision; the `sign_with_silent_fee` signer seam uses it.
4. **Counterparty check**: held until the owner decides (A/B/C above). When it is A, this adds the
   revealed ECDH share (and later the DLEQ proof) as a versioned swap-message field, plus the
   verifier; when B, nothing; when C, the xpub derivation replaces the SP path here.
5. **Regtest end to end with fees on**: a full swap that pays both fee outputs, the operator scans and
   finds them, and the refund path when a fee output is absent or (under A) its share fails to verify.

Steps 1 and 2 are mechanical and safe. Steps 3 and 4 are the real cryptographic work and sit on the
funding-PSBT path the cold signer approves, so they need the test vectors and careful review before
fees are ever switched on in anger.

## Test plan

- **Unit**: fee amount (rate, floor, rounding), min-trade refusal, the sanity band, and that a
  disabled fee adds no output and changes no byte of today's path.
- **BIP352 vectors**: sender output derivation and receiver scanning match the BIP352 test vectors.
- **Counterparty check** (once the owner picks A/B/C): under A, a correct revealed share verifies and
  locates the output; a missing output, a short one, or a share that fails its proof is rejected and
  the swap takes the safe refund path.
- **Signer capability**: enabling fees against a non-BIP352 signer is refused at validation, not at
  transaction build.
- **Regtest e2e**: a full swap with fees on pays and verifies both outputs; the operator scans and
  finds its two fresh outputs; nothing links them.

## What this deliberately does not add

No coordinator, no fee quote request or response, no account key, no volume ledger, no address
watching, no Fulcrum or Shulcrum Electrum connection for fees. The static voluntary model needs none
of them. If volume tiers ever return (they were considered and set aside in 7.5), they are a
coordinator service and a separate design, not a change to this path.

## Addendum (2026-11-06): wiring the fee onto the live swap

Review of the wiring plan surfaced four points that change the integration (not the crypto, which is
built and vector-tested). They are recorded here before the state machine is touched.

### 1. Fee terms travel in the Offer, not in each side's Settings

`verify_fee` must check against terms both sides agreed, not against the verifier's local `Settings`.
If the taker verified against its own `fee_*` settings, an opted-out maker, a different rate, or a
fork with another address would fail the taker's check **after the maker has already locked**,
stranding the maker's coins until the timelock. So the Offer carries the terms:

```
Offer { ..., fee: Option<FeeTerms { maker_bps: u16, taker_bps: u16, sp_address: String }> }
```

The maker fills `fee` from its own settings when it publishes; the taker accepts those terms by
bidding; both sides pay and verify against the **offer's** terms. `Settings.fee_*` become the
operator's defaults for the offers this client creates, not an input to verification. The Offer (and
the new `FeeProof` message, below) are a wire-format change and are versioned together.

Fee-less offers (owner decision 2026-11-06): a default client **publishes fee-bearing offers but
accepts fee-less ones too**, surfacing or down-ranking them. Liquidity is never blocked; the fee
stays voluntary and is avoidable by anyone posting a fee-less offer, which is accepted. The verifier
treats `fee: None` as "no fee output expected" (no check); `fee: Some` requires the output. Until
fees are enabled (pending the legal opinion) every offer is fee-less in any case.

### 2. The counterparty gate has three states, and never wraps the claim-continuation path

A boolean `fee_ok` conflates "proof not yet arrived" with "fee missing", which would either abandon a
good swap the instant the lock gets deep, or (worse) gate a claim. The gate is three-valued:

- `Failed`  -> abandon, alongside `!amount_ok` (before this side commits its own lock).
- `Pending` -> do nothing this tick; the existing `lock_deadline` already bounds the wait.
- `Verified` -> proceed.

Placement is exact:
- Taker, before funding: fund only on `Verified`; `Failed` abandons; `Pending` waits. The taker's
  `learned_secret` claim path (swap.rs) gets **no** fee gate.
- Maker, before claiming: the fee is one term of the pre-claim conjunction only,
  `go = phase == Claiming || (amount_ok && fee == Verified && deep && time_left)`. It must never wrap
  the whole expression: once the secret is public the maker keeps re-claiming regardless, or the
  taker can take both legs.

Unit tests must cover: proof arrives after the lock is deep (no abandon); proof never arrives
(abandon at the deadline); proof arrives after the maker entered `Claiming` (claim continues).

### 3. Verification needs prevout scriptPubKeys, so the payer ships the prevout transactions

`input_pubkey` reads the prevout scriptPubKey, which a lock transaction does not contain (a taproot
key-path witness is only a signature). Rather than require `-txindex` on the verifier's node, the
payer includes the **full prevout transactions** in the `FeeProof` message; the verifier checks each
hashes to its outpoint's txid, then classifies eligibility from the prevout it just authenticated.
Trustless, and works on any node. On the payer side, `NoEligibleInputs` at fund time is a hard error
(never fund without the fee, or the counterparty abandons); coin selection is restricted to eligible
input types (P2WPKH / P2TR) so this does not arise in practice.

### 4. The fee proof is persisted and re-sent

The `FeePayment` (share, proof, prevouts) is written in the same atomic `Record` as the signed
`funding`, before the first broadcast, so a restart resends the same share rather than asking a cold
signer to regenerate it. The `FeeProof` message is re-sent each tick until the counterparty's lock
appears, since the relay may drop it; receiving it twice is harmless.

### Regtest notes

- `WalletSigner` key access: recent Bitcoin Core has no legacy wallets, so not `dumpprivkey`. Derive
  each input key from `listdescriptors true` plus `getaddressinfo(addr).hdkeypath`, reusing the bip32
  code in `keys.rs`; or fund the e2e from an imported known single-key descriptor.
- Silent payment address network: regtest uses the `sprt` HRP, which `parse` and `looks_like_sp_address`
  must accept, and the parsed network is checked against the chain on both BTC and xBTC.

### Order of work

1. This addendum.
2. Step-1 plumbing: `fund(.., fee: Option<(Amount, &SilentPaymentAddress)>)`, the BIP352-aware signer
   seam returning the signed PSBT and the `FeePayment`, and persistence in `Record`.
3. The `FeeProof` message (with prevouts) and the three-state gate in `decide`.
4. Regtest end to end, with the key-access and HRP points above.
