# Security

## Reporting a vulnerability

Report privately, through
[GitHub's private vulnerability reporting](https://github.com/TwentyOneLife/sovereign-swap/security/advisories/new).
It is enabled on this repository and goes only to the maintainer. Please do not open a public issue
for anything that could cost someone coins.

## What matters here

This code builds and signs the transactions that lock, claim and refund coins in a swap. The parts
where a bug costs money:

- **The contract** (`src/htlc.rs`): the script template, its exact-match check against what a
  counterparty sends, and the 32-byte secret size check that keeps a secret usable on both chains.
- **The replay guard** (`src/replay.rs`): a BTC transaction whose inputs also exist on xBTC is valid
  on both chains. The guard refuses to sign one.
- **The supply chain**: dependencies pinned exactly, the build image by digest, CI actions by commit,
  and the node releases the tests use checked by hash and by their publishers' signatures
  (`scripts/fetch-nodes.sh`, keys in `keys/`).

## Status

Early development. Not for real funds; no release has been made.
