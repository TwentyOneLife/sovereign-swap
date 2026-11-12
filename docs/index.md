---
layout: home

hero:
  name: Sovereign Swap
  text: Trustless BTC and xBTC atomic swaps
  tagline: Non-custodial. No KYC. Post-quantum sealed. Tor-first.
  image:
    src: /logo.svg
    alt: Sovereign Swap
  actions:
    - theme: brand
      text: How it works
      link: /guide/how-it-works
    - theme: alt
      text: Security and cryptography
      link: /guide/security-model
    - theme: alt
      text: Project README
      link: https://github.com/TwentyOneLife/sovereign-swap#readme
    - theme: alt
      text: View on GitHub
      link: https://github.com/TwentyOneLife/sovereign-swap

features:
  - icon: 🔑
    title: You hold your keys
    details: Every swap is a hash time-locked contract (HTLC) on each chain. The software never takes custody. Funds are claimed or refunded by you alone, and no party, not even a relay, can freeze them.
  - icon: ⚛️
    title: Atomic, or nothing
    details: Either both legs of a trade complete, or both refund at their timelocks. An interrupted, abandoned, or undiscovered swap always resolves to claim-or-refund. There is no state in which one side keeps both coins.
  - icon: 🛡️
    title: Post-quantum envelope
    details: Messages are sealed with hybrid X25519 + ML-KEM-1024 and signed with Schnorr + ML-DSA-87. An attacker has to break both the classical and the post-quantum scheme to forge or read a message.
  - icon: 🧅
    title: Carried over Nostr, Tor-first
    details: Offers and swap steps travel over untrusted Nostr relays, dialed through Tor by default, so your trading is not tied to your IP address and no relay learns who you are.
---

## What this is

**Sovereign Swap** trades [Bitcoin (BTC)](https://bitcoin.org/en/) for
[Bitcoin Blake2b (xBTC)](https://bitcoinknots.org/) and back, directly between two
people, with no exchange, no custodian, and no account. The two sides never have to trust each other:
the trade is enforced by cryptography on both chains, so the worst case for an honest party is that they
get their own coin back.

> **xBTC is not BTC.** Bitcoin Blake2b is a separate chain that shares Bitcoin's address format. A coin
> on one chain is a different asset from a coin on the other. Sending to an address on the wrong chain
> loses the coin, and nothing on either chain can detect the mistake. This documentation is explicit
> about which chain every step is on.

## Start here

- **Want the quick pitch and current status?** Read the project
  [README](https://github.com/TwentyOneLife/sovereign-swap#readme).
- **New to it?** Read the [Overview](/guide/overview) and the [User journey](/guide/user-journey).
- **Want to know why it is trustless?** Read [How it works](/guide/how-it-works) and the
  [Security model](/guide/security-model).
- **Evaluating the cryptography?** Read [The post-quantum envelope](/guide/envelope).
- **Running it yourself?** See [Run your own](/guide/run-your-own).
- **Auditing the decisions?** Every design decision is recorded in the
  [Design decisions](/design/) index.
