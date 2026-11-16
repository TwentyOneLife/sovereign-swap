# 0024 Coin-split / replay-protection service

Status: shipped in daemon v0.6.22, 2026-11-12. Builds on
[0001](0001-htlc-and-replay-guard.md) (the replay guard) and
[0017](0017-user-held-signing-psbt-handoff.md) (user-held signing). The by-hand version is the guide
[Separating your coins yourself](/guides/separating-coins); this note is the automated service behind
the web UI's **Split** tab.

## Problem

BTC (SHA256) and BTC (Blake2b) share byte-identical history up to mainnet block **961,631** and first differ
at **961,632** (the BIP-110 split; BLAKE2b proof-of-work follows at 961,640). A coin that existed at or
before 961,631 therefore exists on **both** chains under the same key, and a transaction spending it can
be valid on both — it is **replayable**: a spend you make on one chain can be copied onto the other and
move the twin without your intent. To make a coin safe it must be moved once, in a transaction that can
exist on **one chain only**.

## Two ways to separate a coin

1. **Unified signature hash (free, no service).** The fork defines an opt-in signature hash that the
   SHA256 chain rejects at consensus. A spend signed that way is valid on Blake2b only, so it separates
   the coin by itself. A BTC (Blake2b) wallet, e.g. Shrike, signs this way by default, so its
   spends are already non-replayable. This is the by-hand guide, and it is the right path when you sign
   with such a wallet.

2. **Chain-exclusive marker (this service).** A stock or hardware signer (Sparrow, Electrum, a hardware
   wallet, an old SeedSigner) signs the *old* way, which is valid on both chains — so method 1 does not
   help it. Instead, spend the pre-fork coin together with a **Blake2b-Coin** (a coin mined after the
   fork, which exists on Blake2b only). The whole transaction is then invalid on the SHA256 chain because
   that input does not exist there — regardless of how the coin itself is signed. This works for any
   signer and gives a guarantee that does not depend on the signature.

## The lent-marker move

The user brings only their pre-fork coin and a destination address. The service **lends** a Blake2b-Coin
marker from a pool (it is never given away — it comes back as change), co-signs only that marker, and the
move is made on the Blake2b chain. The user's coin is separated; the service takes a 0.5% fee, charged in
XBT on the Blake2b side (the side whose value is unlocked). Non-custodial throughout: the user signs their
own input on their own device, outputs go to the user's address, and the service only ever signs the
marker it is lending to itself.

A separating transaction has three outputs: the user's separated value to their address (minus the fee and
the network fee), the fee to the service, and the marker recovered to the service.

## Endpoints and flow

- `POST /split/classify` — is a coin a replayable pre-fork coin, or already chain-specific?
- `POST /split/build` — reserve a marker, build the **unsigned** PSBT (user's coin + the lent marker,
  each carrying `witness_utxo` and, for non-witness inputs, `non_witness_utxo`, so any signer can sign),
  and return it with a job id.
- `POST /split/submit` — the user signs their input **first**; the service validates and co-signs the
  marker **last**, then broadcasts. No signed marker is ever outstanding. When the coin being split is
  itself held in the service's own hot funding wallet (the user has no key for it), the service signs that
  input too in the same co-sign (#314); the safety invariants below keep that case replay-safe and
  drain-safe.
- `POST /split/verify` — once the move is 12 confirmations deep on Blake2b, confirm its inputs do not all
  exist on the SHA256 chain, i.e. it can never be replayed.

The web UI's **Split** tab walks this end to end and leads with method 1: if you sign with a Blake2b
wallet you are already safe and need no service.

## Safety invariants (enforced in code)

- A separating transaction MUST include at least one chain-exclusive marker, or the builder refuses it:
  without it the move would be replayable.
- The submit step requires the submitted transaction to be byte-for-byte the one we built, and the user's
  inputs to be signed with an ALL-family sighash — never ANYONECANPAY/NONE/SINGLE, which could be lifted
  into a transaction funded on the other chain.
- Inputs the service signs itself, the lent marker always and (since #314) any coin held in its own hot
  funding wallet, decided at build time and persisted with the job, must be left **unsigned** at submit;
  the service adds the only signatures on them. After co-signing, **every** input (the service's included)
  is re-checked for an ALL-family signature before broadcast: the byte-for-byte check does not cover
  per-input sighash fields, which whoever submits the PSBT controls.
- When any input is service-owned, the service also chooses the destination itself, a fresh address in its
  own funding wallet, and ignores any caller-supplied one (#314). Otherwise `/split/build` plus
  `/split/submit` would be a path to move any hot-wallet coin to an arbitrary address (for anyone holding
  the GUI token, or a same-origin script); and the separated value must return to the funding wallet for
  the funding view's safe balance to cover the leg. A job is all user-held or all service-held, never a mix.
- `verify` refuses to run unless the SHA256 node has a fully synced `txindex`: without it an absent input
  cannot be told apart from a merely unindexed one, which could wrongly report a replayable coin as safe.
- A move is "final" only at ≥12 Blake2b confirmations; the low-hashrate chain reorgs, and a shallow
  separation can be undone.

## Marker pool

Markers come from mined Blake2b-Coins, are reserved to one job at a time with a timeout (so an abandoned
job cannot drain the pool), and a move's recovered change is never reused as a future marker — otherwise
every user's split would spend the previous one's change and chain all users into one cluster.

The whole flow is exercised end to end by regtest tests against a Bitcoin Core + Knots BLAKE2b pair that
share their pre-fork blocks, including a daemon-level test that drives build → sign → submit → broadcast
and asserts the move is accepted on Blake2b and rejected on SHA256 for missing inputs.

## Funding-view pre-check (split-first)

Rather than let a swap fund a lock from a replayable coin and hit the runtime guard only when the user
signs, the funding view predicts the guard: `POST /funding/survey {chain}` classifies the funding
wallet's own UTXOs by the SAME predicate the guard uses (an outpoint still unspent on the OTHER chain is
replayable), one `gettxout` per UTXO (no `txindex`, no scan). It returns
`{ replayable, replayable_sat, safe_sat, unverified }`, fails closed (a lookup error is `unverified`,
never counted safe), and the client warns, and offers a split first, only when there are replayable coins
AND the safe balance cannot cover the leg. Output-only funding has no wallet to survey, so the guard is
the only protection there. Deliberately NOT ancestry classification: a pre-fork coin already spent or
split on the other chain is no longer replayable, and only the guard's own predicate agrees with the
backstop. How the marker is signed follows the Blake2b funding mode:

- **Hot (keyed wallet):** the service co-signs the marker, and any coin held in its own hot wallet (#314).
- **Cold / descriptor-backed interactive (watch-only wallet):** the service signs nothing; the user's own
  wallet or air-gapped device signs **every** input, the marker included (#310). The built PSBT is passed
  once through the watch-only wallet with `walletprocesspsbt(sign=false, bip32derivs=true)` so a
  derivation-path signer (SeedSigner, a hardware wallet) can find its keys; the unsigned tx is unchanged,
  so the byte-for-byte gate still holds. The marker's recovered change is a change address of the funding
  wallet (`getrawchangeaddress`, so it works whatever the descriptor type).
- **Output-only interactive (no wallet):** refused, there is no wallet to lend a marker from.

In cold mode the lent marker is one of the operator's own coins, so the anti-reuse taint still applies:
a funding wallet holding a single Blake2b-Coin can split once, then needs another Blake2b-Coin to serve as
the next marker (same as hot).
