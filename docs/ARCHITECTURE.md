# Architecture and data flow

How a swap's data moves through the pieces, and which technology handles each hop. Two independent
planes: the **message plane** (offers, bids, swap steps, over Nostr relays) and the **settlement
plane** (the actual coins, in HTLCs on the two chains). The message plane is untrusted end to end;
the settlement plane is where value moves.

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
