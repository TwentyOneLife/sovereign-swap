# Fees

Sovereign Swap has one fee: a small **voluntary fee** that supports the project building the software. It
is part of the offer terms, visible to both sides, and verified by the protocol, never a hidden charge.
There is no platform cut, no spread, and no custody of your funds at any point.

## How the fee works

```
   offer terms include:  maker fee = 20 bps (0.20%)
                         taker fee = 30 bps (0.30%)
                         a fee address per chain

   each side pays its own share as an extra output
   on the lock it funds, to the fee address for that chain
```

- The fee is **a share of the traded amount in basis points** (1 bp = 0.01%). Defaults are 20 bps for
  the maker and 30 bps for the taker; an operator can lower or waive either.
- Each side pays its share **on the chain it locks**, to the fee address the offer names for that chain.
  BTC and xBTC fee addresses are kept strictly separate (the chains share an address format, so one must
  never stand in for the other).
- The counterparty **verifies the fee output on chain** before committing or revealing the secret. A
  missing, wrong-address, or underpaid fee makes the honest side refuse and refund. This is enforced,
  not honour-based ([design 0010](/design/) / [0013](/design/)).

## Small trades owe no fee

A leg below a configured **minimum trade** owes no fee output, and both sides agree on that so a small
trade is not broken by a fee rounding to dust. Above the minimum, the fee applies and is floored to a
safe minimum.

## Privacy of fee collection

A fee address can be a normal address or a **silent-payment (sp1)** address. A silent-payment address
produces a fresh, unlinkable output per swap, so the project's fee receipts are not all tied to one
reused address on chain. The protocol already carries the silent-payment fee output and its proof
([design 0010](/design/), [0022](/design/)). Operators can also configure a **rotating set** of fee
addresses that offers cycle through on a fixed offline schedule ([design 0018](/design/)).

## Take-side protection

Because an offer comes from an untrusted peer, the taker's client refuses an offer whose fee for the
chain the taker would lock is unreasonable (above a hard cap, e.g. 1%) or pays an address the operator has
not configured. This stops a hostile maker from using the "fee" to skim to its own address
([design 0018](/design/)).

## Licensing note

The voluntary fee and the project's fee addresses are a default, not a lock-in. The commercial licence
covers removing or redirecting the fee for your own deployment; see the repository's `COMMERCIAL.md`. The
software is sovereign: it is your node, your keys, and your choice.
