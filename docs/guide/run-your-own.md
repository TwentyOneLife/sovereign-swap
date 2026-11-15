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

- **BTC (SHA256)**: Bitcoin Core or Knots, with RPC enabled.
- **BTC (Blake2b)**: Bitcoin Knots BLAKE2b, with RPC enabled.

On StartOS each exposes an RPC interface; point the client at each node's RPC endpoint and credentials.
Over a LAN use the node's HTTPS RPC with its StartOS Root CA; over Tor use the node's `.onion`
([design 0011](/design/)). Optionally put an Electrum server, Fulcrum for BTC (SHA256) and Shulcrum for BTC (Blake2b), in
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
  revealed preimage; so the wallet must be loadable and see those transactions. An Electrum server,
  Fulcrum for BTC (SHA256) and Shulcrum for BTC (Blake2b), in front gives thinner chain reads but is optional. `txindex=1`
  is **not required** (a node without it settles fine); it only makes the fee-proof prevout lookup
  (`getrawtransaction` on a counterparty's older funding inputs) more robust, so it is a reasonable
  extra on a busy market-making node, not a prerequisite.
- **Fee estimation and broadcast** (`estimatesmartfee`, `sendrawtransaction`).
- **Reachable for the life of a swap.** Do not restart a node while a swap is mid-flight: the client
  reports the chain down until RPC returns, then resumes. Node software version does not otherwise
  matter, only that these RPCs work.

### Assign each chain to the right node (there is no automatic guard)

BTC (SHA256) and BTC (Blake2b) share Bitcoin's network parameters and address format (they descend from the same chain),
so the client **cannot** auto-detect which node is which; it trusts your configuration. Point the BTC (SHA256)
node setting at your Bitcoin Core/Knots node and the BTC (Blake2b) node setting at your Bitcoin Knots BLAKE2b
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

- **Nodes** - the BTC (SHA256) and BTC (Blake2b) RPC endpoints, credentials, and (for HTTPS) the Root CA.
- **Relays** - one or more Nostr relay addresses, a Tor `.onion` preferred. You and a counterparty must
  share at least one relay to find each other.
- **Funding mode per chain** - hot, cold, or interactive (see [architecture](/guide/architecture), which
  explains the **watch-only wallets** the node uses to see and build without ever being able to spend).
  Cold or interactive keeps spending keys off the hot node. In interactive mode you sign each funding PSBT
  in your own wallet: **Sparrow for the BTC (SHA256) leg, Shrike for the BTC (Blake2b) leg** (a plain
  Bitcoin wallet such as Sparrow does not sign on the Blake2b chain). **Pick the interactive shape to fit your signer:**
  configure your **account descriptor** and the node builds a **fully-funded** PSBT you only sign - the
  right choice for an **air-gapped / QR signer** (e.g. SeedSigner), since it adds no coins in the signer;
  leave the descriptor empty ("output-only") and the node builds an **inputless** PSBT your own wallet
  funds and signs - fine for a software wallet that can fund a template, awkward for an air-gapped signer.
- **Fee** - on by default to the project addresses; adjust or set your own ([fees](/guide/fees)).
- **Minimums and the beta cap** - the smallest tradeable leg and a safety cap on the real-value BTC (SHA256)
  leg while the software is young.

Settings that change the daemon's wiring restart it cleanly; your swap data is preserved in place across
an update.

### Signing a funding PSBT (interactive mode)

In interactive mode the node never signs the lock. When a swap reaches its funding step, the swap-detail
screen shows a parked funding PSBT for you to sign in your own wallet and hand back. The node has already
selected your inputs and added the change and fee output, so you are only adding a signature. Use
**Sparrow for the BTC (SHA256) leg and Shrike for the BTC (Blake2b) leg** (a plain Bitcoin wallet does not
sign on the Blake2b chain).

1. **Load the PSBT.** Copy the base64 from the "Sign your funding" box and open it in your wallet
   (`File > Open Transaction`, paste). Confirm the outputs: the lock amount to the HTLC address, your
   change back to you, and the fee. Leave the sighash at **All**; the HTLC requires a `SIGHASH_ALL`
   signature.
2. **Sign it.** Two ways, your choice:
   - **Air-gapped (recommended for real value):** display the PSBT as a QR, scan it with an offline signer
     (e.g. SeedSigner), sign on the device, scan the signed QR back into your wallet. The spending key
     never touches a networked machine.
   - **Hot:** if the wallet itself holds the keys (loaded from the seed, not a watch-only xpub), sign
     directly, no second device. Faster, but the key is on a networked machine - fine for dust tests, keep
     real value on the air-gapped path.
3. **Export the signed PSBT as base64.** In Sparrow/Shrike: `File > Save PSBT > To Clipboard > As Base64`.
   It must be the **base64** PSBT (it starts `cHNidP8...`), **not** hex and **not** the final raw
   transaction.
4. **Paste it back and submit.** Paste into the "Signed PSBT (paste)" box and click **Submit**. The engine
   finalizes and broadcasts the lock itself and drives the rest of the swap.

**Do not broadcast the funding transaction from your wallet.** The engine must broadcast it so it can pin
the lock's txid and track the swap; if your wallet broadcasts first, the engine never receives the signed
PSBT and the swap stalls. Sign, export, paste, submit - never "Broadcast".

The counterparty's leg works the same way: once your lock confirms, the other chain's node parks its own
funding PSBT for you to sign and submit by the same steps.

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
