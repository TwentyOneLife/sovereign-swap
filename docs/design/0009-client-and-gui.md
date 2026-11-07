# 0009 Client daemon and GUI (M4)

Status: design. The engine, relay, envelope and cold signer exist (0002, 0005, 0006, 0008) and carry
a full swap end to end (proven in the homelab). What is missing is the layer a person uses: a
long-running **client daemon** that drives the engine and holds config, and a **GUI** that views it.

## Problem

Today the engine is driven only by test code calling `tick()` in a loop; there is no service a person
runs and no screen they look at. A swap, once started, must make progress and resolve (claim or
refund on its timelocks) regardless of whether any window is open - coins are at stake. So the client
cannot be "a GUI that runs the engine"; it must be a **daemon that runs the engine**, with the GUI as
a replaceable view on top.

## Shape: a daemon is the source of truth, the GUI is a view

```
        ┌─────────────────────── the user's own machine ───────────────────────┐
        │                                                                       │
        │   GUI (browser or desktop)        sovereign-swap daemon               │
        │   ┌────────────────┐   local      ┌──────────────────────────────┐    │
        │   │ Market / Swaps │  HTTP+SSE     │ Engine (tick loop, persisted)│    │
        │   │ Settings       │◄────────────►│ Config store                 │    │
        │   │ (stateless)    │  127.0.0.1    │ Local private history        │    │
        │   └────────────────┘   + token     └───────┬───────────┬──────────┘    │
        │                                            │           │               │
        └────────────────────────────────────────────┼───────────┼──────────────┘
                                   Electrum/JSON-RPC  │           │ WebSocket/Tor
                                                      ▼           ▼
                                           BTC + xBTC nodes    Nostr relays
```

- The **daemon** is a background service. It opens the engine (`Engine::open(dir, ...)`, which is
  crash-safe: it persists each swap under `dir/swaps/` and rehydrates on start, see 0002), runs the
  tick loop forever, holds the config, and exposes a local API. It is the only thing that touches
  funds or keys. It must keep running for a swap to complete; closing the GUI does not stop it.
- The **GUI** holds no swap state. It reads the daemon's API and renders it. Close it mid-swap and
  the swap keeps going; reopen it and it rehydrates from `GET /swaps` to the live status. It is a web
  app the daemon serves on `127.0.0.1`, or a thin desktop shell around the same - either way it is
  replaceable and carries no authority.

This directly answers "what if the user closes the browser during a swap": nothing happens to the
swap. The daemon locked, will claim or refund on the timelocks, and persists every step; the GUI is
just not watching for a while.

## Style

Match twentyone.life: near-black background (`#0d1117`), one accent (Bitcoin orange `#F7931A`), a
clean sans, flat cards, generous whitespace, no gradients or marketing chrome, plain copy. Tor and
Nostr live in the footer. Every screen states the sovereign facts plainly: non-custodial, keys never
leave the node, no account. This is the same palette the relay's landing page already uses.

### Responsive, and mobile without a native app

The GUI is a responsive web app (mobile-first layout, breakpoints), so it runs on a phone browser with
no native app. But the daemon is loopback-only, so a phone cannot reach `127.0.0.1` on the node. The
sovereign way to reach it from a phone is the node's own authenticated tunnel: StartOS gives the
packaged client (M4c) a **Tor onion** (the same path the relay took), so the phone's Tor browser opens
the responsive GUI over Tor. The loopback API is never exposed to the LAN; "mobile" is the responsive
page served over the node's onion.

## Screens

### Shell (header + footer on every screen)

```
┌──────────────────────────────────────────────────────────────┐
│  ⟠ sovereign-swap        Market   Swaps   Settings      ● Tor │  ● orange when Tor + relays are up
├──────────────────────────────────────────────────────────────┤
│                        [ screen content ]                      │
├──────────────────────────────────────────────────────────────┤
│  non-custodial · your keys stay on your node    onion · nostr │
└──────────────────────────────────────────────────────────────┘
```

### Market (offer book + create)

```
┌──────────────────────────────────────────────────────────────┐
│  Market                                     [ + Create offer ]│ ← orange
│  Direction ▾ All     Min amount ▾ Any        relays: 3  ● Tor │
│                                                                │
│  SELLING      AMOUNT        FOR            RATE      EXPIRES    │
│  ────────────────────────────────────────────────────────────  │
│  xBTC       0.50000000   0.49850000 BTC   0.9970    38 blk    →│
│  BTC        0.10000000   0.10050000 xBTC  1.0050    40 blk    →│
│                                                                │
│  Offers are public. Identities are not - only a routing key.   │
└──────────────────────────────────────────────────────────────┘
```

### Create / Take offer (sheet)

```
┌───────────────── Create offer ─────────────────┐
│  I am selling   ( ) BTC   (•) xBTC             │
│  Amount         [ 0.50000000       ] xBTC      │
│  Price          [ 0.9970           ] BTC/xBTC  │
│  You receive      0.49850000 BTC   (auto)      │
│  Min fill       [ 0.50000000       ] xBTC      │
│  Timelocks        maker 38 blk · taker 20 blk  │ ← from policy, read-only
│  Funding          watch-only · cold signer ●   │
│  ────────────────────────────────────────────  │
│           [ Cancel ]     [ Publish offer ]      │ ← orange, enabled only when valid
└─────────────────────────────────────────────────┘
```

### Swap detail (live status - the screen that matters)

```
┌──────────────────────────────────────────────────────────────┐
│  Swap #a1b2 · selling 0.5 xBTC for 0.4985 BTC     ● Claiming  │
│   YOUR LEG (xBTC)              COUNTERPARTY LEG (BTC)           │
│   ● locked   3/1 conf         ● locked   2/1 conf              │
│   ● claimed  (secret shown)   ○ waiting their claim            │
│   ──────────●───────────●───────────●──────────○───            │
│   Offer   Locked xBTC  Locked BTC  Claimed BTC  Done           │
│   Refund available in: 35 blocks (if it stalls)                │
│   tx  xBTC lock a9f3…  BTC lock 77c1…  BTC claim 3f6c…         │
│   Funds are safe: this ends claimed or refunded, always.       │
└──────────────────────────────────────────────────────────────┘
```

### Settings (one-time setup, persisted)

```
┌──────────────────────────────────────────────────────────────┐
│  Settings                                                      │
│  BTC node    [ 127.0.0.1:8332     ] cookie ▾   ● reachable    │
│  xBTC node   [ 127.0.0.1:8442     ] cookie ▾   ● reachable    │
│  Relays      [ ws://…onion:7777   ] [ + add ]  ● Tor          │
│  Signer      (•) Cold / watch-only  ( ) Hot (regtest only)    │
│  Policy      BTC conf [1]  xBTC conf [2]  margin [2] blk       │
│                                   [ Save ]                     │ ← orange
└──────────────────────────────────────────────────────────────┘
```

#### Node connection: StartOS config, not the web frontend

On a StartOS node the **node RPC connection is set in the StartOS package config, not the web GUI** -
a config Action like the relay's "Relay limits", but better: a **dependency-wired node selection** (the
way electrs/mempool pick their bitcoind), so StartOS hands the daemon the chosen node's RPC address and
cookie automatically. The person never types a host, port, or credential into a web page, and the
daemon never takes them from the untrusted frontend. It is a **separate config** from the relay's (a
different package: the swap client vs the relay). The web GUI then shows the node fields **read-only**
(address + reachability) and the person edits only the swap-level preferences (relays, policy, signer)
there. Off StartOS (a plain daemon), the free-text fields above apply; the daemon reads whichever source
wrote its `settings.json`.

## Daemon API (local, authenticated)

Binds `127.0.0.1` only. A bearer token is written to the data dir on first run (mode 600) and the GUI
reads it from there; this stops other local processes and browser CSRF from driving the daemon. JSON
over HTTP, plus one Server-Sent-Events stream for live updates so the GUI never polls.

| Method & path | Does | Returns |
|---|---|---|
| `GET /status` | daemon + node + Tor/relay health | `{btc_node, xbtc_node, tor, relays[], active_swaps}` |
| `GET /offers` | offers discovered on the relays (kind 4859 broadcast) | `[{id, sell_chain, amount, counter_amount, rate, maker_lock_blocks, taker_lock_blocks, expires_in}]` |
| `POST /offers` | create and publish an offer | `{offer_id}` (422 with reasons if invalid) |
| `DELETE /offers/{id}` | stop advertising our own offer | `{ok}` |
| `POST /offers/{id}/take` | take an offer (bid) and start a swap | `{swap_id}` (422 if invalid/funds short) |
| `GET /swaps` | our swaps, active and past | `[{id, phase, direction, amounts, created_at, refund_in}]` |
| `GET /swaps/{id}` | one swap in full | `{phases{yours, theirs}, confs, txids, secret_revealed, refund_in}` |
| `GET /settings` | current config | `{btc_node, xbtc_node, relays[], signer, policy}` |
| `PUT /settings` | update config (validated) | `{ok}` or 422 with field errors |
| `GET /events` (SSE) | live stream of phase changes, new offers, node/Tor status | event lines |

There is deliberately no "move funds" or "freeze" endpoint. A swap resolves by the protocol; the API
can start one and watch one, never seize or redirect value (0007).

## Persistence and recovery

- **Swaps:** the engine already persists each swap crash-safely (0002); the daemon adds nothing but
  the tick loop. On restart (reboot, crash, update) it reopens the dir and resumes every unfinished
  swap exactly where it was. A swap never depends on a window being open.
- **Config:** nodes, relays, policy and signer mode are saved in the data dir and reloaded on start.
- **GUI:** stateless. It rehydrates from `GET /swaps` and the `/events` stream on every (re)connect,
  so closing and reopening the browser shows the current truth, not a stale snapshot.

## Validation (consistency checks, three layers)

Defence in depth, because the GUI is untrusted and replaceable:

1. **GUI** - immediate, for UX only: amounts are positive and well-formed, the rate is sane, the
   "you receive" figure recomputes live, Publish/Take stay disabled until the form is valid. A BTC
   amount field accepts **both decimal separators**, `0.5` and `0,5` (European), normalizing to
   satoshis before it calls the API (which is integer-sats only, so no locale reaches the protocol);
   a string with both separators or more than eight decimals is refused, not guessed. The canonical
   normalizer is `daemon::parse_btc_to_sats`, which the GUI mirrors.
2. **Daemon / API** - authoritative: amount above the configured minimum leg and above the offer's
   min fill, funds actually available in the funding wallet, node reachable, rate within a sanity
   band, timelocks taken from policy not the form. A bad request is rejected `422` with per-field
   reasons; the GUI shows them. The minimum leg is the `min_swap_sat` setting (default 10,000 sat,
   validated `>= 3,000` so the leg stays spendable after the claim/refund spend fee); lowering it lets
   a small real-rate leg through. A `POST /offers` body gives the counter side either as `price`
   (band-checked, rounded through an f64) or, mutually exclusive with it, as an exact
   `counter_amount_sat` (no band, taken verbatim) for a lopsided real-rate offer whose price would
   fall outside the sanity band.
3. **Engine** - safety-critical invariants it already enforces and cannot be talked out of:
   confirmations and timelocks never below policy whatever an offer or form says (0002), the replay
   guard (0001), envelope verification (0005). The GUI and even the daemon API cannot lower these.

So a malformed or malicious input is caught early for the user and, if it slips past, refused by the
engine where funds are actually at risk.

## Local history (private, local-only)

The daemon keeps a **local** record of the user's own swaps - direction, amounts, phase, timestamps,
and the on-chain txids - so the Swaps screen can show history and so an accountant or the user can
reconcile. Properties:

- **Local only.** It never leaves the machine; there is no telemetry and no remote log. Stored in the
  data dir, and encryptable at rest with the rest of the config.
- **No counterparty identity.** We store the per-swap routing key, never a long-term identity (there
  is none to store; see 0006). The txids are already public on-chain - recording them locally reveals
  nothing a chain watcher does not already have.
- **Purgeable.** The user can delete a past swap's record, or clear history. Active swaps cannot be
  purged (the daemon needs them to finish safely); finished ones can.

This is the opposite of an exchange's ledger: it is the user's own private notebook, held by them,
shared with no one.

## In-context help (tooltips)

Every nav item, table header and option carries a plain-language tooltip on hover (and focus, for
keyboard and screen readers), in the educational, sovereign tone. A starting map:

- **Market / Swaps / Settings** - "Offers from other people", "Your swaps, live and past", "Your
  nodes, relays and limits".
- **Rate** - "How much BTC you get per xBTC (or the reverse). Above 1.0 favours the seller."
- **Expires** - "Blocks until this offer's timelock; after it, an unfinished swap refunds."
- **Timelocks** - "How long before you can refund if the other side stalls. Shorter for the second
  leg, so you are never the one left waiting."
- **Routing key** - "A throwaway key for this swap only. It is not your identity; the relay sees
  nothing else."
- **Cold / watch-only** - "Your spending keys stay offline. The daemon proposes, your signer
  approves; no key to your balance lives here."
- **Confirmations / margin** - "How many blocks we wait before trusting a lock, and the safety gap
  between the two legs' timelocks."

Tooltips are content, versioned with the GUI, and never block the flow (hover help, not modal walls).

## Build order

- **M4a - the daemon.** Wrap the engine in a long-running service: config store, the tick loop, the
  local HTTP+SSE API above, the local history, and a packaged way to run it (a binary, later a
  StartOS service like the relay). No GUI yet; drive it with `curl` and the existing integration
  harness. This is where the real new backend is.
- **M4b - the GUI.** The screens above against the M4a API, in the twentyone.life style, with the
  tooltips and the three-layer validation. Served by the daemon on `127.0.0.1`.
- **M4c - package and ship.** The daemon (and its GUI) as a StartOS service for the node, the same
  path the relay took, so a node runs its own swap client with its own BTC and xBTC nodes beside it.

## Test plan

- Daemon: the API round-trips (create offer, list, take, status), `PUT /settings` validates and
  persists, and a restart mid-swap resumes the swap from disk (reopen the dir, the swap finishes) -
  reusing the regtest harness and `lab_e2e`.
- Validation: a below-dust amount, an amount over the funding wallet, and a timelock below policy are
  each refused (daemon `422`, and the engine refuses the unsafe ones regardless).
- Recovery: kill the daemon between lock and claim, restart, and assert the swap still reaches claim
  or refund - the "closed the browser / lost power" case.
- History: a finished swap is recorded locally, is purgeable, and records no counterparty identity;
  nothing is written off-machine (asserted by the no-network check already in CI for the lab).
- GUI: component tests for the forms (disabled-until-valid, live "you receive"), and an end-to-end
  click-through of a regtest swap against a local daemon.
