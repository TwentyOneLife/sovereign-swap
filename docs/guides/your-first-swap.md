# Your first swap: a walkthrough

A plain-language, end-to-end walkthrough of doing one BTC/xBTC swap, with the things a real
operator actually runs into. For the protocol mechanics and diagrams see
[`swap-flow.md`](../swap-flow.md); this guide is the "what do I do, and what will I see" companion.

A swap is peer to peer and non-custodial: your keys stay on your node, and every swap ends either
claimed (both sides get the other coin) or refunded (each side gets its own coin back). No third
party can take your funds or freeze the trade.

## Before you start

- **You need a reachable node for each chain** you touch: a Bitcoin node for BTC and a Bitcoin
  BLAKE2b node for xBTC. An offer that sells only BTC still needs the xBTC node to verify the
  counterparty's lock, and vice versa.
- **Funding mode matters.** In hot mode the deposit address is a wallet whose keys live on the node;
  the funds are recoverable but they are not your cold-storage wallet. In cold mode the node holds a
  watch-only wallet and an external signer you control signs each lock. Know which you are using
  before you deposit.
- **Fund the chain you will lock.** A maker selling xBTC funds xBTC; a taker paying BTC funds BTC,
  plus the per-chain fee and a little for miner fees.

## Making an offer (maker)

1. Open the web interface and go to Market, then create an offer.
2. You set the amount you sell and the amount you want for it. The "rate" is just the ratio of those
   two exact integer amounts; nothing is rounded in settlement.
3. Offers are **all-or-nothing**: the whole amount is taken at once (partial fills are not supported
   yet), so the minimum equals the amount.
4. If the voluntary fee is on, it is added as one extra output on your own lock transaction, in the
   coin you lock. The counterparty verifies it on chain before committing.
5. Publish. Your offer appears on the relay for takers to see. You can take it back at any time with
   **withdraw** (see below); only you, its author, can withdraw it.

## Taking an offer (taker)

1. In Market, pick an offer and take it. You take the whole amount.
2. Your node will fund your lock on the chain you pay, once it is safe to (see below). Make sure that
   wallet holds the amount plus the fee plus a little for miner fees first.

## What happens next (the safe ordering)

You do not both lock at once. The sequence is deliberate so neither side can be cheated:

1. **The maker locks first**, with the longer timelock. Its lock is an HTLC bound to a secret only
   the maker knows.
2. **The taker waits** until the maker's lock has enough confirmations, then locks its own coin with a
   shorter timelock. The taker never commits against an unconfirmed maker lock.
3. **The maker claims the taker's coin.** Doing so reveals the secret on chain, in the claim
   transaction's witness.
4. **The taker reads that secret from the chain** and claims the maker's coin. Both sides are now
   done once each claim reaches its confirmation depth.

In the interface each swap shows "Your leg" and "Counterparty", with the transaction and whether it
is unconfirmed, locked, or spent, plus a reminder that funds are safe. A swap can sit for a while:
confirmations depend on the chains, and the xBTC (BLAKE2b) chain can be slow, so a swap may take
hours. That is normal; the timelocks are sized with margin.

## Fees: what you pay, and who pays it

Three things cost money in a swap. You are never charged for the other side's transactions, and the
relay that carries offers and swap messages is free, it never touches coins.

1. **Miner fees, on both chains.** Every on-chain transaction you broadcast pays that chain's miners,
   in that chain's coin:
   - your **lock** (funding) transaction, on the chain you lock;
   - your **claim** transaction, on the *other* chain, when you take the counterparty's coin;
   - your **refund** transaction, on your own chain, only if the swap fails and your lock times out.

   So a completed swap pays a miner fee on *both* chains: a lock fee on your chain and a claim fee on
   the other. These fees are sized by transaction weight at the chain's going rate, so they rise and
   fall with the mempool (with a small floor so a claim or refund still confirms when a chain is quiet).
   The lock fee comes from your wallet; the claim/refund fee comes out of the coin being moved, so you
   receive the locked amount minus the claim fee.
2. **The voluntary project fee (only if enabled).** When it is on, the side locking a coin adds one
   extra output on its lock transaction, a small percentage of the trade, to the project's address for
   that chain. It is paid *on the lock*, before the swap succeeds, and the counterparty checks it is
   there before locking. If the swap later fails and you refund, this fee is **not** returned, it was
   already spent on the lock.
3. **Nothing for messaging.** The relay charges no fee.

In short: a completed swap costs one lock miner fee + one claim miner fee (on the two different chains)
+ your share of the voluntary fee if it is on. A swap you abandon *before* locking costs nothing. A
swap that fails *after* you locked costs the lock miner fee + the refund miner fee + the voluntary fee
already paid on the lock.

## If something stalls

The engine recovers on its own, you do not have to babysit it:

- **Before anyone has locked:** if the counterparty never shows up, your side simply **abandons** and
  no coin ever moves. An unfunded maker gives up on its own once a lock could no longer confirm in
  time; a taker does the same.
- **After you have locked:** if the swap stalls, your lock is **refunded** to you once its timelock
  passes. A locked swap can only ever reach a refund; it is never force-cancelled.

Operator actions you do have:

- **Withdraw an offer** you no longer want to honour (it leaves your market and other nodes' market).
- **Abort a swap that has not locked yet** (it goes to abandoned). A swap whose lock is already funded
  cannot be aborted, because that would strand the coin; it waits for the timelock refund instead.

There is no "cancel a locked swap early" button by design: once coins are locked, the only safe exits
are the on-chain claim or the timelock refund.

## Things that surprise people

- **Hot wallet, not your cold wallet.** In hot mode the deposit and claim addresses belong to the
  node's wallet. If you expected your hardware wallet, you are in the wrong mode.
- **The status dots.** Green means a dependency is up. The price-reference dot is green only when a
  rate was actually fetched, orange when it is enabled but the source cannot be reached, and red when
  it is off.
- **A failed swap still costs the voluntary fee.** That fee rides your lock transaction, so if a swap
  fails after you locked, your refund returns the coin minus fees, but the voluntary fee is already
  spent on the lock and is not refunded.
- **Settings apply on restart.** Changing a minimum or a fee setting takes effect when the engine
  restarts, which the config action does for you.
- **Slow confirmations are not a stuck swap.** If a lock sits unconfirmed, the chain is just mining
  slowly; the swap is still on track as long as it confirms before the timelock.
