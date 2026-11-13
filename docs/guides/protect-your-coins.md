# Protect your BTC (Blake2b) coins

If you held Bitcoin before the fork (block 961,632, on 30 August 2026), you own those same coins twice:
once on **BTC (SHA256)**, the Bitcoin you already know, and once on **BTC (Blake2b)**, a separate chain
that branched off at the fork. Both copies sit at the same address, under the same key.

That has a sharp edge. Until you **separate** the two copies, a transaction you make on one chain can be
copied ("replayed") onto the other by anyone and confirmed there too. So a routine spend of your Bitcoin
could also move your BTC (Blake2b) coin without your intent, or the other way round.

This service separates a coin safely, in one move, so the two copies become independent. After that, what
you do on one chain stays on that chain.

## Do you need it?

You need it if you hold pre-fork coins in an ordinary Bitcoin wallet, a hardware wallet, **Sparrow** or
Electrum. Those sign the "old" way, which both chains accept, so a plain spend is replayable.

(If you already keep a coin in a BTC (Blake2b) wallet such as Shrike and spend it there, that spend is
already safe by itself. Most people hold their pre-fork coins in a Bitcoin wallet, which is what this is
for.)

## What you need

1. **A BTC (Blake2b) wallet to receive the separated coins.** Use **Shrike**: the
   [desktop app](https://github.com/privkeyio/shrike), or [on StartOS](https://github.com/TwentyOneLife/shrike-startos).
   Create a wallet and copy a fresh receive address from it.
2. **Your existing Bitcoin wallet** that holds the pre-fork coin, for example **Sparrow**. It signs the
   move. Your BTC (SHA256) coin is never moved: it stays where it is and simply becomes safe to spend.

## How it works, in plain terms

We lend you a small BTC (Blake2b) "marker" coin and take it straight back as change. Because that marker
exists only on BTC (Blake2b), the whole transaction can exist only there too, no matter how your coin is
signed. That is what makes the move impossible to replay. It is non-custodial: you sign on your own
device, and we only ever sign the marker we are lending to ourselves.

## The steps

1. **Check the coin.** Paste your pre-fork coin (from Sparrow) and press Check. We confirm it is a
   pre-fork coin that still needs protecting.
2. **Build.** We build an unsigned transaction that moves your coin, on BTC (Blake2b), to your Shrike
   address, with the marker included. Fee: 0.5% of the coin, taken in BTC (Blake2b).
3. **Sign.** Open that transaction in Sparrow, sign it, and paste it back. We never see your keys.
4. **Broadcast.** We check it is exactly the transaction we built, co-sign the marker, and broadcast it.
5. **Confirm.** After 12 BTC (Blake2b) confirmations, press Verify. It proves the move can never be
   replayed. Your BTC (SHA256) coin is now safe to spend as normal.

## Safety

- Never move or consolidate the coin on the BTC (SHA256) side first; that move is replayable.
- Wait for at least 12 BTC (Blake2b) confirmations before you trust it; this chain has low hashrate and
  can reorganise shallow blocks.
- Only when Verify says FINAL is it safe to spend the BTC (SHA256) side.

## Prefer to do it yourself?

If you run a BTC (Blake2b) node and want to separate a coin by hand, with no fee, see
[Separating your coins yourself](/guides/separating-coins).
