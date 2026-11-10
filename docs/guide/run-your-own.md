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

## 3. Configure the client

In the client's config actions, set:

- **Nodes** - the BTC and xBTC RPC endpoints, credentials, and (for HTTPS) the Root CA.
- **Relays** - one or more Nostr relay addresses, a Tor `.onion` preferred. You and a counterparty must
  share at least one relay to find each other.
- **Funding mode per chain** - hot, cold, or interactive (see [architecture](/guide/architecture)). Cold
  or interactive keeps spending keys off the hot node.
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
