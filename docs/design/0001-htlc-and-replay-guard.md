# 0001 HTLC contract and replay guard

Status: accepted for implementation, 2026-11-05.

## Problem

Two parties swap BTC for xBTC (Bitcoin Blake2b, the BLAKE2b proof-of-work hard fork of Bitcoin)
without trusting each other or anyone else. Each locks coins on its own chain in a contract that pays
the other side against a secret, or returns the coins after a timeout. The two chains share their
history up to the fork, their address format and their script language, which makes the contract
simple and creates one hazard of its own: transaction replay from BTC to xBTC.

## Contract

Secret-hash contract in a P2WSH output (witness v0), the template BasicSwap has used in production
since 2020:

```
OP_IF
    OP_SIZE 32 OP_EQUALVERIFY
    OP_SHA256 <H> OP_EQUALVERIFY
    OP_DUP OP_HASH160 <claim pubkey hash>
OP_ELSE
    <T> OP_CHECKSEQUENCEVERIFY OP_DROP
    OP_DUP OP_HASH160 <refund pubkey hash>
OP_ENDIF
OP_EQUALVERIFY OP_CHECKSIG
```

- Claim witness `<sig> <pubkey> <preimage> 0x01 <script>`; refund witness `<sig> <pubkey> <> <script>`
  with `nSequence = T`. Transactions are version 2 (required for CSV). `T` is a relative lock in
  blocks of the chain the contract sits on.
- Signatures are SIGHASH_ALL over the BIP143 message, low-S. On xBTC this legacy message stays valid
  after the fork; a regtest run with the fork active confirmed claim and refund.
- **`OP_SIZE 32` is required, not cosmetic.** xBTC enforces BIP-110 (RDTS): witness items above 256
  bytes are invalid there, while a 300-byte item is consensus-valid on BTC. The party that chose the
  secret could otherwise claim on BTC with a preimage the other party cannot use on xBTC.
- Public key hashes keep public keys off-chain until spend.
- Why not Taproot: RDTS makes tapscripts that execute `OP_IF` invalid. The P2WSH contract stays inside
  every RDTS limit by construction (34-byte output, witness items of 73, 33 and 32 bytes).

## Verifying the counterparty's lock

Before acting on the other side's lock transaction, the engine rebuilds the expected script from its
own values (H, both public key hashes, T) and checks the transaction output against it: the output at
the agreed index pays exactly the agreed amount to the P2WSH of exactly that script. Each mismatch is
a distinct error, so a log or test can say which field was wrong. Nothing is parsed out of a script
the counterparty supplied; it is only compared with ours.

## Replay guard

xBTC signs with a replay-protected signature hash by default, and such signatures are invalid on BTC.
Legacy signatures, which BTC wallets produce, are valid on xBTC. A BTC transaction therefore replays
on xBTC whenever its inputs also exist unspent on xBTC: coins from before the fork, or coins later
moved only with legacy signatures. A replayed BTC lock creates the same contract on xBTC, which the
counterparty can claim with the same secret.

Rule: before any lock or fee transaction is signed and broadcast, every input outpoint is looked up
on the other chain, and the engine refuses if one exists there unspent. Both directions are checked;
only BTC to xBTC is a live threat today. The lookup is a one-method trait, so the check is a pure
function and testable with a stub. The node implementation uses `gettxout` including the mempool.
Electrum backends follow separately.

## Out of scope here

Swap state machine, wallet, messaging, fees, fee estimation (fee is a parameter).

## Test plan

- Unit: script bytes against a known vector, template verification rejecting each wrong field,
  preimage extraction, guard with a stub lookup.
- Regtest, Bitcoin Core and Knots BLAKE2b with the fork active (activation checked by a 164-byte
  header, not assumed): claim; refund after T; rejected: wrong preimage, 33-byte and 300-byte preimage
  (rejected on BTC as well, which proves the size check rather than RDTS), refund before T, hash type
  `0x21`.
- Replay: both nodes get the same pre-fork blocks (`submitblock`), so they share a coinbase outpoint; a
  legacy-signed spend of it is accepted by both; the guard refuses that outpoint on the other chain.
  The reverse direction (an xBTC replay-protected signature rejected where the fork is not active)
  was shown on a control regtest before this suite and is not repeated here.
- `find_lock_output` is exercised negatively by unit tests only; on chain it runs on the honest path.
- Known gap: this regtest does not enforce RDTS (a 257-byte witness item was accepted), so RDTS limits
  are covered by construction and by mainnet review, not by these tests.

## Build

Container image pinned by digest, `cargo build --locked`, `Cargo.lock` committed. Dependencies are
vendored at the release milestone.
