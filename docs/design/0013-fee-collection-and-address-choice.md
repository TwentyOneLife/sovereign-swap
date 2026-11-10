# 0013 Fee collection: silent payment or normal address, with daemon-side chain scanning

Status: partly implemented. The default stated below (silent payment) is revised by
[0018](0018-interactive-funding-and-the-fee-output.md): normal is the default so the fee works under
Interactive funding (0017), with silent payment kept as an opt-in for a BIP352-aware signer. Extends
0010 (which made the fee a silent-payment-only output). The
per-chain fee address choice (silent payment or normal: `FeeTerms.btc_address`/`xbtc_address`,
`FeeDest`, `fee_state`) is implemented and released; the daemon-side chain scanner for silent-payment
collection is open in a separate PR. The per-chain fee address decision was tracked in issue #45.

This note adds two things the operator asked for: a choice, per chain, between a silent payment
address and a normal address for the fee, and a daemon-side way to detect and collect silent-payment
fees by scanning the chain through the node the daemon already uses, so collection does not depend on
an external silent-payments indexer.

## Why

0010 made the fee a BIP352 silent payment output: private and unlinkable, but collecting it needs a
wallet that can scan for silent payments, which needs an Electrum server that indexes them. Our own
servers (Fulcrum for BTC, Shulcrum for xBTC) do not implement that index, and upstream Fulcrum has
none to borrow. So today the fee can be built but not easily collected.

The operator's goal is that an install left on the default fee address pays the project, and the
project receives it. The project is not a party to those third-party swaps, so it cannot learn the
per-swap data; it must find the outputs by scanning the chain with its scan key. That is the core of
this note. A normal-address option is also offered for operators who would rather watch one address in
the Fulcrum/Shulcrum they already run and accept the privacy cost.

## The choice, per chain

The fee destination for a chain is one of:

- **Silent payment address** (`sp1...`, the default): the fee output is a fresh, unlinkable silent
  payment output (0010), carried with its DLEQ share and proof. Collected by daemon-side chain
  scanning (below). This stays the default because it does not tag swaps on chain.
- **Normal address** (for example `bc1q...` / `bc1p...`, opt-in): the fee output is that address's
  scriptPubKey, paid directly. Trivial to collect (watch it in any wallet served by the operator's own
  Fulcrum/Shulcrum), but it tags every swap lock that pays it.

The kind is inferred from the address: an `sp`/`tsp`/`sprt` HRP is a silent payment address, anything
else that parses as a valid address is normal. BTC and xBTC are configured independently.

## Output construction and counterparty verification

The fee is still an extra output the payer funds on its own lock, never carved out of the swap amount.

- **Silent payment (unchanged from 0010).** The payer derives the fresh SP output from the recipient
  address and its own inputs, places it, and reveals the ECDH `share` and BIP374 `proof`. The
  counterparty verifies the share and proof, so it trusts the fee is paid to the agreed operator
  without the operator revealing a key. The signer must be BIP352-aware.
- **Normal address (new, simpler).** The payer places the recipient address's scriptPubKey directly.
  No ECDH share, no DLEQ: the counterparty verifies by recomputing the scriptPubKey from the agreed
  normal address in the offer terms and checking the output matches. A normal-address fee works with
  any signer, not only a BIP352-aware one, so it also removes that requirement for that chain.

Both kinds keep the amount rules (floor, minimum trade, per-side basis points in `fee.rs`).

## Wire format (`FeeTerms`)

The basis points stay global (two values, as today); only the address becomes per chain, each
explicitly named so BTC and xBTC fee destinations can never be confused:

```
struct FeeTerms {
    maker_bps: u16,
    taker_bps: u16,
    btc_address: Option<String>,   // fee the BTC-locking side pays; sp1... or normal
    xbtc_address: Option<String>,  // fee the xBTC-locking side pays; sp1... or normal
}
```

An offer may set a fee address on one chain, both, or neither. Each side reads the address for the
chain it locks. `fee_enabled` was never on in production, so no fee-bearing offers exist in the wild;
the one compatibility rule that matters is that a new client must never parse an old-shaped or
unrecognised `fee` object as "no fee" and lock anyway. An unrecognised fee shape fails the offer
loudly; it never silently drops the fee.

## Anti-mix-up (hard constraint, covers collection too)

In our code both chains resolve to `Network::Bitcoin`, so a BTC and an xBTC address, silent payment or
normal, are byte-identical and the network check cannot tell them apart. Separation is structural:

- `FeeTerms` uses `btc_address` / `xbtc_address`, never one shared field. The engine selects by the
  chain it locks, by construction.
- The collection config is per chain the same way: `btc_` / `xbtc_` scan key, spend key, and payout
  address. A BTC payout address and an xBTC payout address are just as byte-identical, so they are
  named apart too.
- Config and web UI present two clearly labelled inputs ("BTC fee address" / "xBTC fee address") with
  help: BTC from your Sparrow wallet, xBTC from your Shrike wallet, do not swap them. A save-time
  confirmation where the surface allows it.

## Daemon-side collection by chain scanning

The daemon collects silent-payment fees without any external SP index, by scanning the chain through
the node RPC it already holds:

- **Feasibility, confirmed.** Both backends expose input prevouts at `getblock <hash> 3` (Bitcoin Core
  31.2 and Bitcoin Knots BLAKE2b 29.5), so for each transaction the daemon has the input outpoints and
  their scriptPubKeys, which is what the silent-payment shared secret needs. The receiver-side
  scan primitives already exist in `silentpayments.rs` (the module scans a transaction's taproot
  outputs for a recipient).
- **Scan.** From a configured birthday height forward, for each new block the daemon walks each
  non-coinbase transaction that has a taproot output, computes the shared secret from the inputs and
  the operator's scan key, derives the candidate output key, and records a match against the operator's
  SP address. Roughly two EC operations per eligible transaction; on BTC mainnet that is on the order
  of tens of seconds of CPU per day and a few hundred MB of block JSON over the LAN https path, and far
  less on xBTC. This catches fees from every install paying the default address, not only the
  operator's own swaps.
- **Collect.** Spending a matched output needs the SP spend key. The daemon holds a dedicated
  fee-wallet key (scan + spend), separate from any swap or savings seed, so a daemon compromise loses
  at most fees collected since the last sweep, never swap funds. It sweeps matched outputs to a
  configured payout address (which can be cold) on a schedule or above a threshold.

For a normal-address fee there is nothing to scan: the fee lands on the watched address and the
operator's own Fulcrum/Shulcrum shows it. The daemon may report it for convenience but is not needed
to collect it.

## Config surface (package actions, per chain)

Per chain, under the Fee action:

- `fee_address` (BTC / xBTC): the destination, `sp1...` (default) or normal. Kind inferred.
- `maker_bps`, `taker_bps`: global, unchanged.

For silent-payment daemon-side collection, additionally (advanced, only meaningful for an SP address):

- `fee_scan_key` / `fee_spend_key` per chain, or a dedicated fee-wallet descriptor/seed. Secrets:
  stored in the package store, never served to the web layer, never logged. A fresh fee-only wallet is
  recommended.
- `fee_payout_address` per chain: where swept fees go, can be cold.
- `fee_birthday_height` per chain: where the scan starts.
- `fee_sweep_threshold`: sweep when collected fees exceed this.

A normal-address fee needs none of these.

## Security properties and trade-offs

- **Silent payment + daemon scanning (default):** per-swap unlinkable fee outputs, collectable from
  every install, no external index. Cost: the daemon holds a hot fee-wallet key, bounded by using a
  dedicated fee-only wallet and sweeping to cold, and some CPU/bandwidth to scan.
- **Normal address (opt-in):** no key on the daemon and trivial collection, but a fixed fee output
  tags every swap lock that pays it, on chain, for every user, and the taker bears that linkage. This
  is the exact cost 0010 chose silent payments to avoid, so it is opt-in, not the default, and the
  offer UI shows a taker-visible note when an offer's fee pays a reused (normal) address.
- Either way the counterparty verifies the fee before it locks, so no peer can skip or misdirect it.

## Testing

- `fee.rs` amount tests unchanged.
- Normal-address output: the fee output equals the scriptPubKey of the configured normal address; a
  counterparty verifies a correct one and rejects a mismatch.
- Per-chain selection: the BTC address is used when locking BTC and the xBTC address when locking
  xBTC, and the two are never crossed (the anti-mix-up guarantee).
- Silent payment output + DLEQ: existing 0010 tests stand, under the new per-chain selection.
- **Scanner (the case that matters): a regtest test where the daemon collects a fee from a swap it was
  NOT a party to.** Build an SP fee output to the operator address in an unrelated transaction, scan
  the block, assert the daemon matches it and sweeps it to the payout address, and that no swap or
  wallet funds are touched. A test that only covers the operator's own swaps would pass a broken
  design, so it is not sufficient.
- Normal-address end to end on regtest: the fee lands on the watched address, visible via the node
  wallet.
- Negative: an unreachable payout, a mismatched counterparty fee output, an unrecognised fee shape,
  each refused loudly, never a silent skip. Tests use regtest keys only; production fee-wallet keys are
  never placed in tests or echoed.

## Rollout (one reviewable, CI-green, container-built commit per stage)

1. Per-chain `FeeTerms` (global bps, per-chain address), engine selection by the locked chain, and the
   normal-address output plus verification. Depends on nothing else; unblocks collection on existing
   Fulcrum/Shulcrum and works with any signer. Start here.
2. The chain scanner in scan-only mode: detect matches and report count and amount per chain in
   `/status` and the logs. Includes the not-a-party regtest test above. Confirm `getblock 3` behaviour
   on both live nodes before writing the EC path (done: prevouts present on both).
3. Sweep matched outputs to the per-chain payout address with the dedicated fee-only key.
4. Config action fields (per chain) and web UI labels + help, with the anti-mix-up separation.
5. Docs: update 0010's "silent-payment only" statement, and extend the operator guide
   (`guides/fee-silent-payment-address.md`) with the normal-address option and the daemon-side
   collection setup.

## Out of scope

A generic, shareable silent-payments index service for other software. This note scans only for the
operator's own fee address, through the operator's own node, which is all the fee needs.
