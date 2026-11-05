# 0008 Cold funding signer, and the fee question (M2b)

Status: design; the cold funding seam is built, the fee mechanism is a decision below.

## The requirement

No key to the user's balance may live on the engine host. The engine runs online to drive swaps, so
it cannot also be the custodian of the user's coins.

## What is hot and what is cold

A swap has two kinds of signing, and they are not the same risk:

- **Funding a lock** spends from the user's balance. This is the large, standing value, and its keys
  are **cold**: the engine builds the unsigned transaction and an external signer signs it. The
  engine's funding wallet is **watch-only** (private keys disabled).
- **Claiming or refunding a lock** spends a coin already committed to one swap, and must happen on
  time without a human (within the timelock). Its per-swap key is derived from the engine seed and is
  necessarily **online**. The value exposed is only what is in flight in active swaps, transiently,
  and a missed claim falls back to a refund. This is inherent to any automated atomic-swap engine.

So "cold" means the user's balance is never signable by the engine; only ephemeral per-swap HTLC
keys are, and only for coins already in a swap.

## The seam (built)

`FundingSigner` (src/node.rs): the engine builds the funded PSBT, runs the replay guard on its
inputs, then hands the PSBT to a signer and finalises the result through the node. Two implementations:

- `WalletSigner`: the node wallet signs. Hot; regtest and tests only.
- an external signer (a cold device, an air-gapped wallet, a remote HSM): injected with
  `ChainNode::with_signer`. The engine's funding wallet is then watch-only.

Proven by `tests/cold_signer.rs`: the engine's funding wallet has `private_keys_enabled=false`, yet
an external signer funds a valid, broadcastable lock.

Operational note: an air-gapped human signer cannot react within a timelock, so a production cold
funding signer is a connected-but-separate device or service (its own machine, an HSM, a hardware
wallet with an automated approver under a policy), not a person approving each PSBT. The point is key
separation, not latency. Funding happens once per swap at the start, when there is time; claims and
refunds use the online per-swap keys.

## The fee question (decision needed)

The protocol fee (section 7 of the spec) is an output in the funding transaction. Two ways to choose
its address, and cold funding forces the choice:

1. **Silent payments (BIP352)**: a different, unlinkable address every time, no coordinator. But the
   sender needs the funding inputs' private keys to derive the output, and those keys are now at the
   cold signer. So the signer must be BIP352-aware (compute the fee output itself). Best privacy,
   needs a capable signer.
2. **Fresh address from the operator's xpub**: the engine derives a new fee address per swap from a
   watch-only xpub, no input keys needed, works with any cold signer. A different address each time,
   but anyone holding the xpub can link them as the operator's.

Recommendation: ship option 2 (xpub-derived) as the default because it works with any cold signer,
and offer option 1 (silent payments) when the signer supports it. The fee output itself is not yet
implemented (fees are a later milestone); this records the decision so M2b does not hard-code a
choice that blocks cold signing.
