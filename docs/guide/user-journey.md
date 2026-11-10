# User journey

This walks a single trade from both sides, as you experience it in the web GUI. The cryptography behind
each step is in [how it works](/guide/how-it-works); here we stay at the level of what you do and see.

## Making an offer (the maker)

```
  1. Open the web GUI on your node.
  2. New offer:  sell  [amount] [chain]   for   [amount] [other chain]
                 e.g.  sell  0.01 xBTC     for   0.01 BTC
  3. Publish.  ──►  the offer is broadcast over Nostr to your relays.
  4. Wait for a taker to bid; accept is automatic once the bid checks out.
```

Your offer carries the amounts, the per-leg timelocks, and the [fee](/guide/fees) terms. It is public:
anyone on a shared relay can see it and verify you signed it. You can **withdraw** it any time before it
is taken.

## Taking an offer (the taker)

```
  1. Browse the market in the GUI (offers discovered over your relays).
  2. Pick an offer, enter how much of it to take (full or partial if allowed).
  3. Take.  ──►  a bid is sent to the maker; the swap begins.
```

## What happens next (both sides)

```
   maker        funds its lock on chain      ──►  you see "Locking" then the lock confirm
   taker        verifies it, funds its lock  ──►  both locks now on chain
   maker        claims, revealing the secret ──►  "Claiming"
   taker        claims with the secret       ──►  both "Done"
```

The engine does the on-chain steps for you according to your **funding mode**:

- **Hot** - your node signs and funds automatically. Simplest; good for small amounts and testing.
- **Cold** - an external signer signs the funding transaction; your spending keys never touch the hot
  node.
- **Interactive** - the GUI hands you the unsigned funding transaction; you sign it in your own wallet
  and submit it back. You stay in the loop for every coin movement.

Throughout, the swap-detail screen shows each lock's txid, confirmations, and the refund countdown, so
you always know where your coins are.

## If something goes wrong

You never need to intervene to stay safe:

- If the counterparty stalls, the engine **refunds** your lock automatically at its timelock.
- If a fee or a lock is wrong, the engine **refuses to proceed** and refunds.
- You can **withdraw** an unsold offer or **abort** a not-yet-locked swap from the GUI.

The guarantee from the [security model](/guide/security-model) holds at every step: the worst outcome is
that you get your own coin back. See the [lifecycle](/guide/lifecycle) for the states a swap moves
through.

## Before your first real trade

- Confirm you are sending each leg to the **right chain** (BTC vs xBTC share an address format).
- Start small. The project runs a soft launch; treat it as early software.
- If you are running your own node and client, follow [run your own](/guide/run-your-own) first.
