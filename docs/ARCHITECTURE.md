# Architecture and data flow

How a swap's data moves through the pieces, and which technology handles each hop. Two independent
planes: the **message plane** (offers, bids, swap steps, over Nostr relays) and the **settlement
plane** (the actual coins, in HTLCs on the two chains). The message plane is untrusted end to end;
the settlement plane is where value moves.

## Who runs what: the three pieces

sovereign-swap is peer to peer and non-custodial. No one, not even the operator who runs the relay,
ever holds another person's coins or keys. There are three pieces, and it helps to be clear about
who runs each one.

```
   MAKER (any user)                                         TAKER (any user)
  ┌───────────────────────┐       ┌───────────────┐       ┌───────────────────────┐
  │ sovereign-swap-client │       │ sovereign-    │       │ sovereign-swap-client │
  │  (StartOS package)    │       │ swap-relay    │       │  (StartOS package)    │
  │                       │ kind  │ (the operator │ kind  │                       │
  │  web GUI (loopback)   │ 4859  │  runs this)   │ 4859  │  web GUI (loopback)   │
  │  swap engine          │<─────>│               │<─────>│  swap engine          │
  │  their own BTC + xBTC │  E2E  │ hardened      │  E2E  │  their own BTC + xBTC │
  │  nodes                │encrypt│ Nostr relay:  │encrypt│  nodes                │
  │  their keys (cold)    │       │ no funds,     │       │  their keys (cold)    │
  └───────────┬───────────┘       │ no keys,      │       └───────────┬───────────┘
              │                   │ no matching,  │                   │
              │                   │ no wallet;    │                   │
              │                   │ just forwards │                   │
              │                   │ opaque msgs   │                   │
              │                   └───────────────┘                   │
              │     the swap settles DIRECTLY between the two peers:   │
              └────────── HTLC locks on the BTC and xBTC chains ───────┘
```

1. **The relay (`sovereign-swap-relay`)**, run by the operator, usually as one public StartOS
   service reachable over Tor. It is a hardened Nostr relay: a message post office. It stores and
   forwards opaque, end-to-end-encrypted messages (event kind 4859) so a maker and a taker can find
   each other and exchange the steps of a swap. It holds no funds, no keys, has no wallet, sees no
   plaintext, and does no order matching. Users point their clients at it (and may add others; it is
   the flagship meeting point, not a single point of control).

2. **The client (`sovereign-swap-client`)**, run by **each user on their own node**. This is the
   daemon plus the web GUI. It binds to loopback on that user's own machine, talks to that user's own
   BTC and xBTC (Bitcoin Blake2b) nodes, holds that user's own keys (cold by default), and runs the
   swap engine. There is no shared, multi-user website that strangers log into: the maker runs their
   client, the taker runs their client, and each person sees only their own.

3. **The two chains**, where the coins actually move. A swap is a pair of hash-timelocked contracts
   (HTLCs), one on each chain. It is atomic: either both legs complete or both refund. Neither the
   counterparty nor the relay operator can take the coins; the relay could at worst drop a message,
   which just sends the swap down the always-safe refund path.

**The fee, and how the operator earns.** Because the operator is never in the path of anyone's funds,
the fee is not skimmed from passing swaps. Instead, each client (the default build) adds a small,
**voluntary** fee output to **its own** lock transaction, paying the operator's published silent
payment address (BIP352): a fresh, unlinkable on-chain address every swap. The operator collects by
scanning that address on chain, off the swap path entirely. Being open-source and peer to peer, the
fee is enforced by the clients, not by cryptography: two modified clients on their own relay can swap
without paying, and that is accepted. The fee funds the relay and development, alongside a commercial
licence for organisations that want proprietary terms. See design 0010; the fee ships off by default.

The rest of this document is the developer view: how a single message and a single swap move through
the pieces above, and which technology handles each hop.

## Components

```
        ┌───────────────────────── one party's node (the user's own machine) ─────────────────────────┐
        │                                                                                              │
        │   ┌────────────┐    Message     ┌──────────────┐   RoutedMessage   ┌────────────────────┐    │
        │   │ swap engine │◄─────────────►│ RelayTransport │◄────────────────►│ envelope (format 3) │    │
        │   │ (state      │  (Rust enum)  │ routing +      │  identity hint +  │ hybrid PQ encrypt / │    │
        │   │  machine)   │               │ peer learning  │  sealed/ signed   │ sign (libcrux +     │    │
        │   └─────┬───────┘               └───────┬────────┘   envelope bytes  │ secp256k1 + AES-GCM)│    │
        │         │ Action (fund/claim/refund)    │                            └─────────┬──────────┘    │
        │         ▼                               │ Nostr event (kind 4859,              │               │
        │   ┌──────────────┐                      │ id + Schnorr sig, p-tag)             ▼               │
        │   │ ChainNode    │                      ▼                            ┌────────────────────┐    │
        │   │ (watch-only  │               ┌──────────────┐                    │ Nostr client       │    │
        │   │  + funding   │               │ (M3b-3) WS    │                    │ (event encode)     │    │
        │   │  wallets)    │               │ over Tor      │                    └────────────────────┘    │
        │   └──────┬───────┘               └──────┬────────┘                                              │
        └──────────┼─────────────────────────────┼─────────────────────────────────────────────────────┘
                   │ JSON-RPC / Electrum          │ WebSocket over Tor
                   ▼                              ▼
        ┌──────────────────────┐      ┌────────────────────────┐         ┌───────── the counterparty ─────────┐
        │ BTC node (Core) and  │      │ Nostr relay(s)          │◄───────►│ the same stack, mirrored:           │
        │ xBTC node (Knots     │      │ store + forward opaque  │  events │ relay client ─ envelope ─ transport │
        │ BLAKE2b); Electrum   │      │ events; UNTRUSTED       │         │ ─ engine ─ its own BTC/xBTC nodes   │
        │ for BTC optionally   │      │ (several, Tor-first)    │         └─────────────────────────────────────┘
        └──────────┬───────────┘      └────────────────────────┘
                   ▼
        ═══════════════════════ BTC chain ═══ and ═══ xBTC chain ═══════════════════════
                 HTLC locks, claims and refunds (the settlement plane)
```

Trust: the relay sees only throwaway routing keys and ciphertext; a forged or dropped event cannot
break a swap (a forged envelope fails verification, a dead relay is replaced). The coins are safe
because every swap ends either claimed or refunded, whatever the message plane does.

## Message plane: how one message travels (sequence)

```
 maker engine        maker RelayTransport        relay            taker RelayTransport        taker engine
     │                      │                      │                      │                      │
     │ send(Offer) ────────►│                      │                      │                      │
     │                      │ serialize → sign_broadcast (ML-DSA+Schnorr)  │                      │
     │                      │ wrap: identity hint + envelope               │                      │
     │                      │ Event::build (id=SHA256, Schnorr sig), no p-tag                     │
     │                      │ publish ────────────►│  store               │                      │
     │                      │                      │◄──── query(kind) ─────│ receive()            │
     │                      │                      │ ──── Offer event ────►│ verify event sig     │
     │                      │                      │                      │ verify_broadcast(env) │
     │                      │                      │                      │ learn maker = (event  │
     │                      │                      │                      │  pubkey, identity)    │
     │                      │                      │                      │ ──── Offer ──────────►│ seen
     │                      │                      │                      │◄──── bid(offer) ──────│
     │                      │                      │◄─ publish Bid event ──│ seal to maker ident, │
     │                      │                      │   p-tag = maker route │ p-tag maker route    │
     │◄── query(p=me) ──────│ receive()            │                      │                      │
     │ verify event + open(env) against taker ident (from hint, authenticated by the envelope sig)│
     │ learn taker = (event pubkey, identity)      │                      │                      │
     │◄── Bid ──────────────│                      │                      │                      │
     │ send(Accept) ───────►│ seal to taker, p-tag taker route ─ publish ─►│ ─── Accept event ───►│ ...
     │                      │                      │                      │                      │
     ▼ swap proceeds: each side locks on its chain, waits confirmations, claims, reads the secret ▼
```

## Settlement plane: the swap itself (sequence, maker sells xBTC)

```
 maker engine                         xBTC chain              BTC chain                 taker engine
     │ lock xBTC in HTLC(H, claim=taker, refund=maker, T1) ─►│                          │
     │ [replay guard: inputs absent on BTC] + fee output     │                          │
     │                                    (N_x confirmations)│                          │ verify lock,
     │                                                       │◄─ lock BTC HTLC(H, ──────│ wait N_x, then
     │                                                       │   claim=maker, T2<T1)    │ lock on BTC
     │ wait N_b confirmations ──────────────────────────────┼─────────────────────────►│
     │ claim BTC (reveals preimage) ─────────────────────────────────────────────────► │
     │                                                       │  read preimage from BTC  │
     │                                                       │◄─ claim xBTC with it ────│
     │ both legs settled; else after T1/T2 each side refunds │                          │
```

Confirmation depths (N_x, N_b) and timelocks (T1, T2) come from each engine's own `Policy`, never
below it whatever the offer says (design 0002). The preimage is the hash-lock secret; revealing it
to claim one leg is what lets the other leg be claimed.

## Where each technology sits

| Hop | Technology |
|---|---|
| swap decisions, timelocks, funds safety | the Rust swap engine (`engine`, `swap`, `policy`, `htlc`, `replay`) |
| message confidentiality + authenticity | format-3 envelope: X25519+ML-KEM-1024, Schnorr+ML-DSA-87, AES-256-GCM, HKDF-SHA-512 (`envelope`, libcrux) |
| addressing, discovery, delivery | Nostr events kind 4859 + relay routing (`nostr`, `relay`, `routing`) |
| transport | WebSocket over Tor to relays (M3b-3) |
| settlement | Bitcoin + Bitcoin Blake2b HTLCs via node JSON-RPC / Electrum (`node`) |
```
