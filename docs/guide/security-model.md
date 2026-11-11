# Security model

The guiding principle is simple: **the worst case for an honest party is getting their own coin back.**
No counterparty, relay, or network attacker can do better than stall a swap, and a stalled swap refunds.

## What you trust, and what you do not

<img class="diagram" src="/diagrams/security-model-1.svg" alt="What you trust, and what you do not (diagram)" loading="lazy" />

The software reads chain state only from **your own nodes**, moves coins only under **your own
signatures**, and treats every incoming message as hostile until its signatures and, for a lock, its
on-chain reality are verified.

## Non-custodial by construction

There is **no mechanism to freeze, hold, or seize funds**, deliberately ([design 0007](/design/)). A
swap has exactly these end states:

<img class="diagram" src="/diagrams/security-model-2.svg" alt="Non-custodial by construction (diagram)" loading="lazy" />

Every interruption, abandonment, or attack funnels into one of the refund paths. This is enforced by the
chains' own timelocks, not by this software, so it holds even if the software, the relay, or the
counterparty disappears mid-swap. See the [lifecycle](/guide/lifecycle) for how the engine drives every
swap to one of these states.

## Threats and why they fail

| Threat | Why it fails |
|---|---|
| Counterparty tries to take both coins | To claim they must reveal the secret on chain, which lets you claim too (see [how it works](/guide/how-it-works)). |
| Counterparty abandons after you fund | You refund your own lock at its timelock. |
| Counterparty funds a wrong/missing/underpaid fee | You verify the counterparty's fee output on chain before committing or revealing, and refuse if it is wrong ([design 0010/0013](/design/)). |
| Relay drops or delays messages | Cannot move a coin; the swap stalls and refunds. Use multiple relays for resilience. |
| Relay or observer tries to read a directed message | It is sealed with the hybrid [envelope](/guide/envelope); they see only ciphertext. |
| Someone forges a message | Every message carries hybrid Schnorr + ML-DSA signatures; a forgery fails verification. |
| A lock or secret is replayed into another swap | Per-swap keys and a replay guard bind each artifact to its swap ([design 0001](/design/)). |
| A future quantum computer attacks recorded traffic | The envelope is hybrid post-quantum ([envelope](/guide/envelope)). |

## Abuse deterrence without fund-freezing

A public, permissionless system cannot blacklist, so it must make abuse **not worth it** rather than
forbidden. The relay is rate-limited and its event store is hardened against flooding
([design 0007](/design/), [0020](/design/)), and offers self-heal by re-announcement. Crucially, none of
these controls can ever cost a coin: the backstop is always that an interrupted swap refunds. Proof-of-
work and fidelity bonds are analysed as optional future deterrents in
[design 0020](/design/); the project does **not** rely on them for safety.

## Adversarial testing

The code is tested the way an attacker would probe it ([design 0003](/design/)):

- **Parser fuzzing** of every untrusted input (envelopes, Nostr frames, PSBTs).
- **Malicious-counterparty tests** that tamper with messages, lock amounts, and fee outputs and assert
  the honest party never loses: it abandons or refunds, and never reveals the secret to a cheat.
- **Mutation testing** of new tests, so a test that would pass even against broken code is caught.
- **Live regtest end-to-end** swaps on both chains, including reorgs, restarts, and refund races.

## Operational discipline

- **Testnet / regtest first.** Treat mainnet funds as radioactive; the project's own process verifies
  every change on regtest before it goes near real value.
- **Verify what you run.** Every release `.s9pk` is reproducible and GPG-signed; verify it before
  installing ([run your own](/guide/run-your-own)).
- **Keys stay cold where it matters.** Use cold or interactive funding so spending keys never live on an
  internet-facing machine ([design 0012](/design/)).

## Honest limitations

- This is **availability-weak, not custody-weak**: a determined hostile relay can degrade discovery or
  delay a swap into a refund. That is an annoyance, never a loss.
- The software is young and the posture is a **soft launch**; the engine has not yet run for years under
  adversarial load. Size positions accordingly.
- **xBTC is a different asset from BTC.** The single biggest user risk is sending to an address on the
  wrong chain, which no software can detect. Check the chain every time.
