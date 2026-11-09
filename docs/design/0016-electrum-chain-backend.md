# 0016 Electrum ChainBackend (E1): chain data without a full node

## Context
`ChainBackend` (node.rs, design 0014) is the chain-data + broadcast surface the engine needs, with no
wallet in it. `ChainNode` (bitcoind RPC) is the first implementation. **E1** adds a second: an
`ElectrumBackend` that reads chain data and broadcasts over an Electrum server (Fulcrum for BTC,
Shulcrum for xBTC) instead of a full node's RPC. This removes the user's full-node requirement for
chain data (the first unblocker for the thin client / hosted service, #46). Funding and signing stay
out of scope here, exactly as the trait does; they move to the user's own wallet in a later stage (E2).

## The trait surface and how each maps to Electrum
Electrum is line-delimited JSON-RPC over TCP (optionally through a SOCKS5 proxy for a Tor onion, like
`rpc.rs`). A contract's output script is addressed by its **scripthash**: `SHA-256(scriptPubKey)`,
byte-reversed, lower hex (the one primitive every `blockchain.scripthash.*` call needs).

| `ChainBackend` method | Electrum call(s) |
|---|---|
| `network()` | stored at construction |
| `height()` | `blockchain.headers.subscribe` -> `.height` |
| `get_tx(txid)` | `blockchain.transaction.get(txid, false)` -> raw hex -> deserialize |
| `watch_contract(contract)` | no-op: Electrum is query-based, nothing to register |
| `lock_view(contract, amount, ours)` | `blockchain.scripthash.listunspent` + `.get_history` on the contract's scripthash (see below) |
| `broadcast(tx)` | `blockchain.transaction.broadcast(hex)`; an already-known tx counts as success |
| `estimate_fee_sat_vb(target)` | `blockchain.estimatefee(target)` -> BTC/kvB -> sat/vB; `-1`/absent -> `None` |

### `lock_view` algorithm (mirrors `ChainNode` semantics via scripthash queries)
1. `sh = scripthash(contract.script_pubkey())`.
2. `listunspent(sh)` -> the live UTXOs at the contract address. Pick the one whose `value` equals
   `amount` (sets `amount_ok = true`); else the first (`amount_ok = false`). That gives `outpoint`
   `(tx_hash, tx_pos)`, `value`, and `height` (0 = unconfirmed). `confirmed_height = (h>0).then(h)`.
   If there is no UTXO *and* no spend (step 3 finds nothing either), return `None`.
3. Spend detection: `get_history(sh)` lists every tx touching the scripthash. For each history tx that
   is not the funding tx, `transaction.get` it and check whether any input's `previous_output` is the
   lock `outpoint`. The first that does is the spend -> `SpendView { preimage: extract_preimage(tx,
   contract), depth: conf-of-the-spend, ours: any output script in `ours` }`. When the lock is already
   spent it will not be in `listunspent`; recover the funding outpoint from `get_history` + the
   funding tx's outputs to the scripthash so the spend can still be detected.
4. `fee: FeeState::NotRequired` (the node never knows a swap's fee terms; the engine sets the
   counterparty lock's fee state after verifying it, design 0010), identical to `ChainNode`.

Confirmations: Electrum returns a block `height` per entry, not a confirmation count, so compute
`confirmations = tip - height + 1` from `height()` (the inverse of what `ChainNode` does with
bitcoind's `confirmations`).

## Transport
Plain TCP, line-framed JSON-RPC, one request/one response line, reusing `crate::socks::socks5_connect`
for an onion (Tor authenticates the endpoint). TLS for a clearnet LAN Electrum (rustls is already a
dep) is a **follow-up**; regtest and Tor both work over plain TCP first.

## Build order (this is E1, split for safe review)
1. **This PR , client core + scripthash.** The `ElectrumClient` (connect direct/SOCKS, `call`) and the
   `scripthash` helper, with a unit test pinning `scripthash` against the Electrum reference vector.
   Self-contained and provable without a live server.
2. **Next PR , `ElectrumBackend: ChainBackend`.** The six methods above, wired into `engine.rs`
   `backend()` selection behind config, then **regtest-verified against our own Fulcrum/Shulcrum**
   (the gate: index a contract, read a header, fund+confirm+spend a lock, read it back through the
   Electrum path, and match what `ChainNode` reports for the same swap).
3. Later: TLS transport; E3 watch-only descriptors; E2 user-held signing.

## Why this is open core, not private
E1 is protocol-level chain access, not the commercial hosting layer. It stays in the AGPL core; the
multi-tenant engine and the proprietary web frontend (the commercial parts, #46) are separate private
work built on top.
