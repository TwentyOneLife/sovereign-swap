# Architecture

Sovereign Swap is a small set of components that each do one job. Nothing in the system holds custody,
and the only trusted parts are the ones you run yourself.

## Components

<img class="diagram" src="/diagrams/architecture-1.svg" alt="Components (diagram)" loading="lazy" />

**Reading the diagram:**

- **Engine** is the heart: a state machine (in Rust) that drives every swap. It reads both chains,
  lets each swap decide its next action, stores the result, and acts (fund, claim, refund). It is the
  subject of [design 0002](/design/) and the [safe lifecycle](/guide/lifecycle).
- **Daemon / Web GUI**: the engine runs inside a daemon that exposes a small, token-gated HTTP API; the
  web GUI is a thin client over it. You drive swaps from your own browser.
- **BTC node and xBTC node**: your own full nodes for each chain. Because they are yours, you trust the
  chain data; the software never asks a third party what happened on chain.
- **Read backend**: chain reads and broadcasts normally go through the node's RPC, but can optionally go
  through an **Electrum** server (Fulcrum for BTC, Shulcrum for xBTC) for a thinner client
  ([design 0016](/design/)). Funding and signing always stay on the node.
- **Cold signer** (optional): funding transactions can be signed off the hot node by an external signer,
  so the spending keys never live on the internet-facing machine ([design 0012](/design/)).
- **Client**: carries protocol messages over [Nostr](/guide/transport-and-privacy), sealing and routing
  them. It talks only to relays, never directly to a peer.
- **Relay**: an untrusted store-and-forward service. It carries offers and swap steps, holds no funds and
  no keys, and cannot read a directed message. You can run your own, or share a peer's.

## Funding modes

The engine supports three ways to fund the on-chain lock, chosen per chain:

| Mode | Keys live | Who signs the lock |
|---|---|---|
| **Hot** | on the node | the node's wallet, automatically |
| **Cold** | on an external signer | the cold signer, over the design-0012 protocol |
| **Interactive** | with you | you sign the funding PSBT out of band and submit it |

Hot is the simplest (good for testing); cold keeps spending keys off the hot machine; interactive hands
you the unsigned funding transaction to sign in your own wallet and hand back - **Sparrow for the BTC
leg, Shrike for the xBTC (Bitcoin Blake2b) leg** (Sparrow does not sign on xBTC)
([design 0017](/design/), [0019](/design/)).

## How it is packaged

Everything ships as **StartOS** packages so it can run on a sovereign node appliance:

- `sovereign-swap-client` - the daemon, engine, web GUI, and client.
- `sovereign-swap-relay` - the relay, for operators who want to run one.

Each is a reproducible, signed `.s9pk`. See [run your own](/guide/run-your-own) for obtaining and
verifying them.

## Source layout

The engine, client, relay, and the post-quantum envelope all live in one Rust crate
(`TwentyOneLife/sovereign-swap`); the two StartOS packages wrap its binaries. The relay source is part of
the same crate (`src/relay_server.rs`), so the whole protocol is auditable in one place.
