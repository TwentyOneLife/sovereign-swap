# User journey

This walks a single trade from both sides, as you experience it in the web GUI. The cryptography behind
each step is in [how it works](/guide/how-it-works); here we stay at the level of what you do and see.

## Making an offer (the maker)

<img class="diagram" src="/diagrams/user-journey-1.svg" alt="Making an offer (the maker) (diagram)" loading="lazy" />

Your offer carries the amounts, the per-leg timelocks, and the [fee](/guide/fees) terms. It is public:
anyone on a shared relay can see it and verify you signed it. You can **withdraw** it any time before it
is taken.

## Taking an offer (the taker)

<img class="diagram" src="/diagrams/user-journey-2.svg" alt="Taking an offer (the taker) (diagram)" loading="lazy" />

## What happens next (both sides)

<img class="diagram" src="/diagrams/user-journey-3.svg" alt="What happens next (both sides) (diagram)" loading="lazy" />

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

### What can and can't happen to your locked coins

Once your lock is **confirmed on chain** it is immutable: it can only be spent two ways, both of them
yours to fall back on. The counterparty, the relay, and a stranger can do nothing to it.

- **Before it confirms** you can still cancel your *own* lock (it is replaceable), and before you
  broadcast anything you can simply **abort** the swap. Nobody else can alter or redirect a lock you
  signed, in or out of the mempool.
- **If the counterparty never locks their leg**, you do not lose your coins. After your refund timelock
  passes, your lock refunds back to you automatically. The only cost of an aborted swap is the small
  on-chain miner fee and, if the offer set one, the voluntary fee; your principal always comes home.
- **Why the wait for confirmations matters.** A taker commits its coin only after the maker's lock is
  several blocks deep (the security depth, set deeper on the lower-hashrate chain). That is what makes a
  "cancel after the other side commits" move impossible: by the time you lock, the other leg is already
  too deep to reverse. It is also why a swap appears to wait before funding the second leg, and why the
  detail screen shows each lock's confirmations against the depth it still needs.

## Before your first real trade

- Confirm you are sending each leg to the **right chain** (BTC vs xBTC share an address format).
- Start small. The project runs a soft launch; treat it as early software.
- If you are running your own node and client, follow [run your own](/guide/run-your-own) first.
