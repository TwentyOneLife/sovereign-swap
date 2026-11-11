# Overview

Sovereign Swap lets two people trade **Bitcoin (BTC)** for **Bitcoin Blake2b (xBTC)** and back, peer to
peer, with no exchange and no custodian in the middle. Each trade is enforced by cryptography on both
chains, so neither side has to trust the other, and no third party can take or freeze the coins.

## The two chains

| | BTC | xBTC |
|---|---|---|
| Chain | Bitcoin | Bitcoin Blake2b (the RDTS hard fork whose proof of work is BLAKE2b) |
| Address format | Bitcoin's | the same as Bitcoin's |
| Node | Bitcoin Core / Knots | Bitcoin Knots BLAKE2b |

::: warning The address format is shared, the coins are not
A BTC address and an xBTC address look identical. They are different assets on different chains. Coin
sent to an address on the wrong chain is lost, and nothing on either chain can catch the mistake. Every
step in this documentation names the chain it is on.
:::

## What "sovereign" and "non-custodial" mean here

- **You hold your keys.** The software builds and watches contracts, but the coins only ever move under
  a signature you control. There is no deposit to an operator and no account.
- **No one can freeze funds.** The design deliberately has no fund-freezing or blacklisting mechanism
  (see [abuse deterrence](/guide/security-model)). The only outcomes are: the swap completes, or each
  side refunds its own coin at a timelock.
- **No KYC.** There is no identity, no sign-up. Peers find each other through relays and are known only
  by throwaway routing keys.

## The pieces, at a glance

```
            ┌─────────────────────────────────────────────┐
            │                 Your node                     │
            │                                               │
   you ───► │  Web GUI ─► Engine ─► BTC node   (Bitcoin)    │ ──► BTC chain
            │              │     └─► xBTC node  (Blake2b)    │ ──► xBTC chain
            │              │                                │
            │              └─► Client (Nostr, Tor-first)    │
            └───────────────────────┬───────────────────────┘
                                     │  sealed, signed messages
                                     ▼
                         ┌───────────────────────┐
                         │   Nostr relay(s)       │   carries offers and
                         │   (untrusted,          │   swap steps; holds no
                         │    Tor .onion)         │   funds and no keys
                         └───────────┬───────────┘
                                     │
                                     ▼
                              a counterparty's
                              node, somewhere
```

**Reading the diagram:** your node runs the **engine** (the state machine that drives a swap), talks to
a **BTC node** and an **xBTC node** (yours, so you trust the chain data), and a **client** that carries
messages over **Nostr** relays through **Tor**. The relay is untrusted plumbing: it forwards sealed
messages between peers but never holds coins or keys and cannot read a directed message. The
counterparty is just another node like yours.

## Where to go next

- [User journey](/guide/user-journey) walks a trade from making an offer to settlement.
- [How it works](/guide/how-it-works) explains the atomic-swap contract that makes it trustless.
- [Architecture](/guide/architecture) describes each component.
- [Security model](/guide/security-model) covers the threat model and what can and cannot go wrong.
