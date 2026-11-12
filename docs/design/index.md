# Design decisions

Every significant decision in Sovereign Swap is recorded as a numbered design note, with its reasoning
and the alternatives it rejected. They are the primary-source record behind the guides; where a guide
says "see design 00xx", this is where it points. Reading them is how you audit *why* the system is built
the way it is, not just what it does.

The notes below are listed in order. Each links to the full text.

## Core protocol

- [0001 - HTLC contract and replay guard](/design/0001-htlc-and-replay-guard) - the on-chain contract
  that makes a swap atomic, and the guard that stops a lock or secret being replayed.
- [0002 - Swap engine](/design/0002-swap-engine) - the state machine, the per-swap wallet, and how swap
  state is persisted and resumed.
- [0015 - Safe swap lifecycle](/design/0015-safe-swap-lifecycle) - the rules that guarantee a swap can
  always reach claim-or-refund: maker deadline, offer teardown, replay handling.
- [0024 - Coin-split / replay-protection service](/design/0024-coin-split-replay-protection) - separating
  a pre-fork coin so it can never be replayed between the two chains, for any signer.
- [0026 - Offer lifecycle and maker reliability](/design/0026-offer-lifecycle-and-maker-reliability) - withdraw, maker-set expiry, and why penalizing a maker does not fit a non-custodial, no-identity system.

## Transport, client, and cryptography

- [0005 - Nostr transport and the post-quantum envelope](/design/0005-nostr-transport-and-pq-envelope) -
  the hybrid-signed, hybrid-encrypted message format.
- [0006 - Nostr client and relay](/design/0006-nostr-client-and-relay) - how messages are carried,
  routed, and discovered.
- [0009 - Client daemon and GUI](/design/0009-client-and-gui) - the daemon API and the web interface.
- [0011 - Node connection over Tor](/design/0011-node-connection-over-tor) - dialing your nodes and
  relays through Tor by default.
- [0014 - Non-custodial re-architecture](/design/0014-non-custodial-rearchitecture) - the thin-client,
  Electrum-backed, user-held-signing direction.
- [0016 - Electrum ChainBackend](/design/0016-electrum-chain-backend) - reading chain data without a
  full node.

## Funding and signing

- [0008 - Cold funding signer, and the fee question](/design/0008-cold-funding-and-fees) - keeping
  spending keys off the hot node.
- [0012 - Wiring the cold funding signer](/design/0012-cold-signer-wiring) - the daemon and package
  integration of the external signer.
- [0017 - User-held signing via PSBT handoff](/design/0017-user-held-signing-psbt-handoff) - interactive
  funding and the watch-only view.
- [0018 - Interactive funding and the fee output](/design/0018-interactive-funding-and-the-fee-output) -
  keeping the normal fee address as the default.
- [0019 - Adopt a user-broadcast funding lock](/design/0019-adopt-a-user-broadcast-funding-lock) -
  recognising a lock the user broadcast themselves.

## Fees

- [0010 - Fee output and silent payments](/design/0010-fee-output-and-silent-payments) - the voluntary
  fee output and its silent-payment option.
- [0013 - Fee collection and address choice](/design/0013-fee-collection-and-address-choice) - silent
  payment or normal address, with daemon-side scanning.
- [0022 - Silent-payment fee and donation collection](/design/0022-sp1-fee-collection) - adopting sp1
  for the project's own collection.

## Pricing

- [0025 - Market-anchored offer pricing](/design/0025-market-anchored-offer-pricing) - the nonkyc
  BTCB2/BTC rate is the default and the anchor, displayed to the maker, who alone sets a bounded margin;
  automation never invents a rate.

## Security and abuse deterrence

- [0003 - Adversarial testing and hardening](/design/0003-adversarial-testing) - how the code is probed
  the way an attacker would.
- [0007 - Abuse deterrence, and why funds are never frozen](/design/0007-abuse-deterrence-no-fund-freezing) -
  deterring abuse without any fund-freezing or blacklist.
- [0020 - Store-flood admission and proof of work](/design/0020-store-flood-admission-and-proof-of-work) -
  hardening the relay store against flooding.
- [0021 - Relay-side tombstone for retired offers](/design/0021-relay-tombstone) - retiring a withdrawn
  offer on the relay.

## Resilience (future)

- [0004 - Redundancy and failover](/design/0004-redundancy-and-failover) - design only, revisited once
  the engine has run under load for a while.

::: tip
These notes are living records: an accepted decision is superseded by a later note, never quietly
rewritten. The number is the stable reference.
:::
