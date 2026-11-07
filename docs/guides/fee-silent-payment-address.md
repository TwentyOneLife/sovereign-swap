# Creating a silent payment address for the voluntary fee

The voluntary fee pays to a BIP352 silent payment address (one that starts with `sp1`). This guide
explains what that address is, how to create one in Sparrow (for BTC) and Shrike (for xBTC, Bitcoin
Knots BLAKE2b), and what you need in order to receive and spend what it collects. The same address
type works as a donation address.

## Why a silent payment address, not a normal one

A silent payment address is published once but never appears on chain. Each payment to it lands on a
fresh, unlinkable Taproot output that only you can detect and spend. For the fee this matters: no
single address tags the swaps, there is nothing for a third party to cluster, and you can hand the
same `sp1` string to everyone without address reuse. The cost is that the payer's wallet must be able
to build a silent payment output, and your wallet must be able to scan for incoming ones.

## The one setting people get wrong: Policy Type, not Script Type

In Sparrow and Shrike, silent payments are a **Policy Type**, not one of the Script Type options.

When you create the wallet:

1. **Policy Type:** choose **Single Signature SP (Silent Payments)**. Do **not** leave it on
   "Single Signature HD": none of the Script Type options under Single Signature HD (Legacy, Nested
   Segwit, Native Segwit, Taproot) produce a silent payment address.
2. **Script Type:** once the policy is Single Signature SP, the script type is **Taproot (P2TR)**
   automatically. That is correct; silent payment outputs are Taproot outputs.
3. Add your keystore (hardware wallet, air-gapped, or software) as usual and finish creating the
   wallet.
4. Open the **Receive** tab. The address shown now starts with `sp1`. That is the string you paste
   into the swap app's Fee address setting (or publish as a donation address).

## One address per chain

Create a separate silent payment address on each chain, in the wallet that watches that chain:

- **BTC:** a Single Signature SP wallet in **Sparrow**. Collects the fee paid on BTC swap legs.
- **xBTC (Bitcoin Knots BLAKE2b):** a Single Signature SP wallet in **Shrike**. Collects the fee paid
  on xBTC swap legs.

Each swap pays the fee in the coin each side locks, so fees arrive on both chains. The scan and spend
keys of a silent payment address live in one wallet's seed, so use the BTC address for the BTC side
and the xBTC address for the xBTC side rather than trying to make one address serve both wallets.

## What you need to actually receive (not just publish)

Publishing an `sp1` address is not enough to see the money. To detect and spend incoming silent
payments, the wallet has to scan the chain, and for that it must be connected to an Electrum/Fulcrum
server that supports silent payments indexing (BIP352). A wallet pointed at a server without that
support will show the address but never find the payments.

- **BTC (Sparrow):** connect to an Electrum server that advertises silent payments support.
- **xBTC (Shrike):** connect Shrike to your own Bitcoin Knots BLAKE2b node and a BLAKE2b indexer that
  supports silent payments. The public servers that predate the BLAKE2b activation do not serve this
  chain, so a self-hosted indexer is the expected setup.

If your wallet cannot yet reach a silent-payments-capable server for a chain, the fee outputs on that
chain are still real and recoverable later with the same seed; you just cannot see or spend them until
the wallet can scan.

## Using it as a donation address

The same `sp1` address doubles as a donation address, and silent payments are a good fit for donations
(a fresh output per donor, no reuse). Two things to note:

- Many wallets still cannot send to an `sp1` address, so also offer a normal address for donors whose
  wallet does not support silent payments.
- The xBTC (Bitcoin Knots BLAKE2b) chain shares Bitcoin's address format. Anywhere you publish the
  xBTC address, state clearly that coins sent there are BitcoinB2B, a different asset than Bitcoin.

## Summary

| | Policy Type | Script Type | Wallet | Server requirement to receive |
|---|---|---|---|---|
| BTC fee | Single Signature SP | Taproot (P2TR) | Sparrow | Electrum server with silent payments support |
| xBTC fee | Single Signature SP | Taproot (P2TR) | Shrike | Knots BLAKE2b node + silent-payments-capable indexer |
