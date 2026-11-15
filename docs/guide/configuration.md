# Configuration

Settings an operator can change, with safe defaults. On StartOS they live in the client package's
**Safety** config action; on a bare daemon they are keys in its settings. The defaults are
chosen so a fresh install behaves exactly as the rest of this guide describes, so change them only once
you understand the trade-off below.

The values and ranges given here are the daemon's. Where the StartOS package is stricter, that is called
out.

## Funding mode (per chain)

How each leg's on-chain lock is funded and signed. **Descriptor-backed interactive is the standard,
recommended mode**: paste your wallet's **account descriptor** (xpub) for the chain, and the node builds a
**fully-funded** PSBT that a normal wallet (Sparrow for BTC (SHA256), Shrike for BTC (Blake2b)) or an
air-gapped signer just opens and signs. **Hot** keeps the keys on the node and signs automatically, good
for regtest/testing only. **Output-only** interactive (interactive with no descriptor) is **advanced**:
it builds an inputless PSBT that Sparrow and Shrike cannot open, so it needs a wallet that funds a template
(Bitcoin Core, Electrum) or a plain pay-to-outputs send; the daemon logs a warning and the web UI flags it
before you commit a trade.

If you configure a descriptor for a chain whose coins already exist on chain, set a **funding birthday**
(a unix timestamp, 0 = genesis) so the wallet rescans and sees them; without it the wallet only tracks
coins received after you configure it, and shows a 0 balance until then. The web UI shows each chain's
funding balance so you can tell a configured-but-unsynced wallet from a funded one.

## Signing window headroom

`signing_headroom_blocks`, default 6, range 2 to 144.

Extra blocks added to the timelocks of offers **you** create. They widen the time you have to hand-sign a
funding PSBT in [Interactive mode](/guide/run-your-own) before the swap would time out. A larger value is
a longer, more comfortable signing window, at the cost of longer-lived offers. This is maker-side only: it
shapes offers you make, never offers you take.

Change it if you sign funding transactions by hand, for example on an air-gapped signer, and 6 blocks,
roughly an hour on BTC (SHA256), is tighter than you would like. Leave it at 6 otherwise.

## Per-chain security depth add

`btc_depth_add` / `xbtc_depth_add`, default 0, range 0 to 100.

Extra confirmations required on top of the engine's built-in security floor, set per chain. It is always
additive: you can only be **more** conservative than the engine, never less. The value is keyed to the
chain, so it protects whichever side is waiting on that chain's lock.

Raising a chain's value lengthens your own offers' timelocks, and makes you refuse to take an offer whose
timelocks leave no room for the deeper wait. Leave both at 0 unless you want to wait for more
confirmations than the engine's floor, for example to be extra cautious on the lower-hashrate
BTC (Blake2b) chain.

## Per-chain funding fee rate

`btc_funding_fee_rate` / `xbtc_funding_fee_rate`, default 2 sat/vB, range 0 to 1000.

The miner fee rate for your funding (lock) transaction, set per chain. A fixed number is a sat/vB rate;
`0` means let your node estimate the fee instead.

A fixed rate that is too low can leave a lock unconfirmed past its signing window, so on a busy
BTC (SHA256) mempool prefer `0` (estimate). On BTC (Blake2b) a fixed rate is the safer choice: a quiet
chain often has no fee estimate to return, so `0` there could fail funding outright.

**UI versus daemon.** The daemon accepts `0` on either chain. The StartOS package is stricter: its Safety
action floors the BTC (Blake2b) rate at 1, precisely because estimation can come back empty on a quiet
chain. Outside the StartOS package the daemon accepts `0` on BTC (Blake2b) too, but a fixed rate is still
the safer choice there.

## Dismiss

Dismiss is a market action, not a setting. It hides a stale peer offer from your own market view,
locally, when a maker has gone silent and left a "ghost" offer behind. It changes nothing on the wire and
nothing for other peers: it only clears the offer from your view, without your having to wait out the
re-seen timeout.
