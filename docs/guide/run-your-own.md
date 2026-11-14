# Run your own

Sovereign Swap is meant to be run on your own node. This page covers getting the software, **verifying**
it before you trust it, and connecting it to your chains. It is deliberately generic: fill in your own
hosts and addresses.

## 1. Get and verify the package

The client and relay ship as reproducible, GPG-signed StartOS `.s9pk` packages. **Always verify before
installing.** A release provides three files: the `.s9pk`, a `SHA256SUMS`, and a `SHA256SUMS.asc`
signature.

```sh
# import the published release key (fingerprint is in the repo: keys/twentyonelife-release.asc)
gpg --import keys/twentyonelife-release.asc

# verify the signature over the checksums, then the checksums over the file
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
```

Both must pass: a **good signature from `TwentyOne.Life <dev@twentyone.life>`** and `OK` on the
checksum. If either fails, do not install the package. The full procedure, including verifying in a clean
keyring exactly as a fresh user would, is in
[verifying a release](/verifying-a-release).

> The signing key is a subkey published in the repository; the primary key certifies it and never leaves
> the machine that made it, so a compromised build runner costs a subkey, not the identity.

## 2. Bring up your chains

You need a node for each chain, reachable by the client:

- **BTC**: Bitcoin Core or Knots, with RPC enabled.
- **xBTC**: Bitcoin Knots BLAKE2b, with RPC enabled.

On StartOS each exposes an RPC interface; point the client at each node's RPC endpoint and credentials.
Over a LAN use the node's HTTPS RPC with its StartOS Root CA; over Tor use the node's `.onion`
([design 0011](/design/)). Optionally put an Electrum server (Fulcrum for BTC, Shulcrum for xBTC) in
front for thinner chain reads ([design 0016](/design/)).

### Minimum node requirements

Each chain's node must provide, over RPC:

- **A wallet with descriptor support, enabled.** The client creates and loads a descriptor wallet and
  derives addresses from it (`createwallet`, `importdescriptors`, `getnewaddress`, `getwalletinfo`,
  `getaddressinfo`, `getdescriptorinfo`). A node started with `disablewallet=1` cannot be used. In cold
  or interactive funding the wallet is watch-only and the client parks an unsigned PSBT for you to sign
  elsewhere, so `walletprocesspsbt` must be available.
- **The swap wallet as a watch wallet.** The client imports each swap's lock as a descriptor into the
  node wallet and reads the counterparty's spend from the wallet's own transaction history to learn the
  revealed preimage; so the wallet must be loadable and see those transactions. An Electrum server
  (Fulcrum for BTC, Shulcrum for xBTC) in front gives thinner chain reads but is optional. `txindex=1`
  is **not required** (a node without it settles fine); it only makes the fee-proof prevout lookup
  (`getrawtransaction` on a counterparty's older funding inputs) more robust, so it is a reasonable
  extra on a busy market-making node, not a prerequisite.
- **Fee estimation and broadcast** (`estimatesmartfee`, `sendrawtransaction`).
- **Reachable for the life of a swap.** Do not restart a node while a swap is mid-flight: the client
  reports the chain down until RPC returns, then resumes. Node software version does not otherwise
  matter, only that these RPCs work.

### Assign each chain to the right node (there is no automatic guard)

BTC and xBTC share Bitcoin's network parameters and address format (they descend from the same chain),
so the client **cannot** auto-detect which node is which; it trusts your configuration. Point the BTC
node setting at your Bitcoin Core/Knots node and the xBTC node setting at your Bitcoin Knots BLAKE2b
node. There is **no automatic wrong-chain guard** on the node assignment, so a swapped pair would direct
a leg to the wrong chain. Set each carefully and confirm with the status read before any real value.
(The per-chain fee **address** is a separate per-chain field, so that fees land on the right chain; it
does not police which node you assigned, see [design 0013](/design/).)

### Reaching onion relays and nodes (Tor)

The client dials `.onion` relays and `.onion` node RPC through a SOCKS5 proxy (on StartOS this is the
Tor service's proxy). A LAN clearnet node needs no proxy. At least one relay must be reachable, and you
and a counterparty must share at least one relay to find each other.

### The relay needs no Bitcoin node

The relay is a Nostr-style event relay: it connects to **no** Bitcoin node and holds no funds or keys.
It only needs to be reachable (StartOS provisions its onion automatically). Operators run it to host a
marketplace for others to discover offers over.

## 3. Configure the client

In the client's config actions, set:

- **Nodes** - the BTC and xBTC RPC endpoints, credentials, and (for HTTPS) the Root CA.
- **Relays** - one or more Nostr relay addresses, a Tor `.onion` preferred. You and a counterparty must
  share at least one relay to find each other.
- **Funding mode per chain** - hot, cold, or interactive (see [architecture](/guide/architecture)). Cold
  or interactive keeps spending keys off the hot node. In interactive mode you sign each funding PSBT in
  your own wallet: **Sparrow for the BTC leg, Shrike for the xBTC (Bitcoin Blake2b) leg** (a plain
  Bitcoin wallet such as Sparrow does not sign on xBTC).
- **Fee** - on by default to the project addresses; adjust or set your own ([fees](/guide/fees)).
- **Minimums and the beta cap** - the smallest tradeable leg and a safety cap on the real-value (BTC)
  leg while the software is young.

Settings that change the daemon's wiring restart it cleanly; your swap data is preserved in place across
an update.

## 4. Verify it is healthy

The client exposes a small status read: it should report the engine up, both chain nodes reachable, and
at least one relay connected. Then publish a tiny test offer, or take one, and watch the swap-detail
screen drive it to `Done`. Start on regtest or with dust before any real value.

## Keeping it updated

Updates are the same install step with a newer verified `.s9pk`; the package revision bumps in place and
your configuration and swap history carry over. If you ever need to roll back, install the previous
verified `.s9pk`.

## Related reading

- [Overview](/guide/overview) and [architecture](/guide/architecture) for the shape of the system.
- [Security model](/guide/security-model) for the discipline (verify what you run, keys cold, testnet
  first).
- The repository's own setup guides under `docs/guides/` for step-by-step node and client configuration.
