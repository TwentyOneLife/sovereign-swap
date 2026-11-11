# The post-quantum envelope

Every message between peers is wrapped in what the code calls the **payload-format-3 envelope**. It gives
two guarantees at once, each **hybrid** (classical + post-quantum): authenticity for all messages, and
confidentiality for directed ones. *Hybrid* means an attacker has to break **both** the classical scheme
**and** the post-quantum scheme to forge or read a message, so the system is no weaker than today's
elliptic-curve crypto and additionally resists a future quantum adversary.

This page states exactly which primitives and libraries are used, so the claims can be checked against
the source (`src/envelope.rs`, `Cargo.toml`).

## The cryptographic stack

| Purpose | Classical | Post-quantum | Library |
|---|---|---|---|
| Signatures | secp256k1 **Schnorr** | **ML-DSA-87** (FIPS 204) | `bitcoin` secp256k1; `libcrux-ml-dsa` |
| Key agreement | **X25519** | **ML-KEM-1024** (FIPS 203) | `x25519-dalek`; `libcrux-ml-kem` |
| Key derivation | **HKDF** | | `hkdf` |
| Authenticated encryption | **AES-256-GCM** | | `aes-gcm` |
| Hashing | **SHA-2** (SHA-256) | | `sha2` |

All of these dependencies are **version-pinned** (`=` in `Cargo.toml`), so a build cannot silently pull a
different implementation.

## A party's public identity

A peer is known by a **public identity** (not a chain address, and not tied to an IP):

```
 Public identity  =  X25519 public key          (classical key agreement)
                  +  ML-KEM-1024 public key      (post-quantum key agreement)
                  +  ML-DSA-87 verification key  (post-quantum signature)
                  +  Schnorr x-only public key   (classical signature)
```

To send a peer a private message you need its X25519 and ML-KEM public keys; to verify a message from it
you need its Schnorr and ML-DSA keys. Both halves are always present, which is what makes every operation
hybrid.

## Two kinds of message

```
 BROADCAST  (an offer, a withdrawal)        DIRECTED  (a bid, accept, swap step, fee proof)
 ───────────────────────────────────        ─────────────────────────────────────────────
 signed, NOT encrypted                       signed, THEN encrypted to one recipient
 (public by nature: anyone may read          (only the named recipient can read it; the
  an offer and verify who signed it)          relay and everyone else see only ciphertext)
```

- **Broadcasts** are offers and their withdrawals. They are meant to be public, so they are signed with
  the hybrid signature but left in the clear. Anyone, including a relay, can read an offer and check its
  signature, which is how a tombstone for a withdrawn offer is even possible (see
  [design 0021](/design/)).
- **Directed messages** are everything addressed to one counterparty. They are signed and then sealed so
  that only the recipient can open them. The relay forwards opaque ciphertext and learns nothing.

## How a directed message is sealed

```
   plaintext Message (JSON)
          │
          ▼
   ┌──────────────────┐   hybrid signature over the payload
   │  sign            │   = Schnorr (secp256k1)  +  ML-DSA-87
   └────────┬─────────┘   (valid only if BOTH verify)
            ▼
   signed payload
            │
            ▼
   ┌──────────────────┐   shared secret from TWO key agreements:
   │  derive key      │     X25519   (classical)
   │  (HKDF)          │   + ML-KEM-1024 (post-quantum)
   └────────┬─────────┘   combined with HKDF into one AES-256 key
            ▼
   ┌──────────────────┐
   │  encrypt         │   AES-256-GCM (authenticated encryption)
   └────────┬─────────┘
            ▼
   sealed envelope  ──►  carried as the Nostr event content (hex)
```

**Reading the diagram:** the message is first **signed** with both signature schemes, then a session key
is derived by combining an **X25519** and an **ML-KEM-1024** shared secret through **HKDF**, and the
signed payload is **encrypted** with **AES-256-GCM** under that key. An attacker who recovers only the
classical secret, or only the post-quantum secret, learns nothing: they need both. Tampering is caught by
GCM's authentication tag and, independently, by the two signatures.

A broadcast skips the encryption box: it is just the hybrid-signed payload in the clear.

## Where the envelope sits in a Nostr event

```
 Nostr event (kind 4859)
   └── content = hex( frame )
         frame = [ sender public-identity hint ] ++ [ envelope ]
                        (a hint only; the envelope's own signatures are
                         verified against it, so a wrong hint just fails)
```

The envelope is the unit this page describes; the surrounding Nostr event, relay, and Tor transport are
covered in [transport and privacy](/guide/transport-and-privacy). The envelope protects the message
regardless of the transport, which is why the relay can be completely untrusted.

## Why hybrid, and why now

Bitcoin Blake2b and this software are built for the long term. A message signed or sealed today could be
recorded by an adversary and attacked years later with a quantum computer ("harvest now, decrypt later").
Using a post-quantum scheme **in addition to** a battle-tested classical one means:

- today, security is at least as strong as standard elliptic-curve Bitcoin cryptography;
- against a future quantum adversary, the post-quantum half still stands.

Neither half is trusted alone. That is the whole point of hybrid.
