# Separating your BTC and xBTC coins yourself

> Looking for the simple, guided way (no command line, no node of your own)? See
> [Protect your BTC (Blake2b) coins](/guides/protect-your-coins). This page is the by-hand method for
> people who run their own BTC (Blake2b) node.


Coins you held at block 961,631 or earlier exist on both chains, BTC and xBTC (Bitcoin Blake2b),
under the same keys. Until you separate them, a transaction you make on BTC can be copied onto xBTC
by anyone and confirmed there too, moving your xBTC without your intent. The swap engine refuses to
lock such coins for exactly this reason.

Separating means spending the xBTC copy once, to yourself, with a signature that only xBTC accepts.
After that the two copies are independent.

**This guide needs a Bitcoin Blake2b (Knots) wallet** - one whose signature the BTC chain rejects (the
default; Shrike is one, [`shrike-startos`](https://github.com/TwentyOneLife/shrike-startos)). If that is
how you sign, separating is free: just follow the steps below, or simply spend the coin with that wallet.

**If you can only sign the old way** - a hardware wallet, Sparrow, Electrum, an old SeedSigner - this
by-hand method does not work for you: those signatures are valid on both chains, so nothing is separated
(see "What can go wrong"). Use the **Split tab in the web UI** instead. It lends a Blake2b-only "marker"
coin (and recovers it) so the move cannot exist on the BTC chain regardless of how you sign; you sign on
your own device, non-custodial, for a 0.5% fee. See
[design 0024](/design/0024-coin-split-replay-protection) for how it works.

**Read the whole guide before you start.** A mistake here can move coins on the wrong chain.

## What you need

- A Bitcoin Knots BLAKE2b node, fully synced, holding the keys in one of its wallets. Its default
  signature is the replay-protected one. **It must not run with `walletoldsigs=1`** (check
  `bitcoin.conf` and the command line): that option signs the old way, valid on both chains.
- Strongly recommended: a Bitcoin node (BTC) of your own, to check the result before broadcasting.
- **Not suitable: hardware wallets, Electrum, Sparrow or any other Bitcoin wallet.** They sign the
  old way. On xBTC such a transaction is valid on both chains and moves both copies, so nothing is
  separated. Importing a hardware wallet's seed into a hot wallet removes the protection you bought
  the hardware wallet for; do not do that to save a fee.

In the commands, `xbtc-cli` is `bitcoin-cli` pointed at the Knots BLAKE2b node, `btc-cli` the one
pointed at the BTC node, and `W` the wallet name.

## 1. Check that you are on xBTC

```sh
xbtc-cli getblockchaininfo            # "blocks" equals "headers"
xbtc-cli getblockheader "$(xbtc-cli getbestblockhash)" false | wc -c
```
The header must be 328 hex characters plus a newline (a 164-byte BLAKE2b header). 160 means you
are talking to a BTC node: stop.

## 2. Find the coins that exist on both chains

```sh
xbtc-cli -rpcwallet=W listunspent 1
btc-cli gettxout <txid> <vout>        # for each coin: any output means it exists on BTC too
```
Without a BTC node, treat every coin confirmed at block 961,631 or earlier as shared, and every coin
you received afterwards from someone using an ordinary Bitcoin wallet as possibly shared.
Separating a coin that was not shared does no harm; it costs a fee.

## 3. A new address in the same wallet

```sh
xbtc-cli -rpcwallet=W getnewaddress
```

## 4. Build the transaction, do not send it yet

```sh
xbtc-cli -rpcwallet=W sendall '["<new address>"]' null unset <fee rate sat/vB> '{"add_to_wallet": false}'
```
This spends every coin of the wallet. The result's `hex` is the signed transaction. To separate
coin by coin instead (better for privacy, since one transaction links all its inputs), add
`"inputs": [{"txid": "...", "vout": n}]` to the options.

## 5. Prove that it is valid on xBTC only

```sh
btc-cli  testmempoolaccept '["<hex>"]'    # must show "allowed": false, with a script or signature error
xbtc-cli testmempoolaccept '["<hex>"]'    # must show "allowed": true
```
**If the BTC node says `"allowed": true`, stop and do not broadcast**: the transaction is not
replay-protected and would move your BTC as well.

## 6. Broadcast it on xBTC, nowhere else

```sh
xbtc-cli sendrawtransaction <hex>
```
Never paste the hex into a BTC node, a BTC block explorer or a BTC wallet.

## 7. Wait, then verify

Wait for confirmations: xBTC has little hashrate, so wait at least 6 blocks, and 36 for amounts
around 1 BTC. Then:

```sh
xbtc-cli gettxout <old txid> <old vout>   # empty: the xBTC copy is spent
btc-cli  gettxout <old txid> <old vout>   # still there: the BTC copy is untouched
```
From now on, transactions on either chain stay on that chain.

## What can go wrong

| Mistake | Consequence |
|---|---|
| Node runs with `walletoldsigs=1` | the transaction is valid on BTC too; step 5 catches it |
| A Bitcoin wallet or hardware wallet signs on xBTC | both copies move; nothing is separated |
| The hex is broadcast on BTC | if step 5 was skipped and it was not replay-protected, your BTC moves |
| Coins sent to an address you do not control on one chain | lost on that chain; both chains use the same address format |
| One `sendall` over all coins | all your coins are linked on chain |
| Acting before enough confirmations | a reorg on xBTC can undo the separation |

The steps in this guide are exercised by the test `regtest_separating_coins_as_the_guide_says` on
a regtest pair of Bitcoin Core and Knots BLAKE2b that share their early blocks.
