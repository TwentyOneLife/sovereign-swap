# 0030 Public-relay profile: a non-custodial deployment mode

Status: implemented (first version), 2026-11-13. A single operator setting that distinguishes a
PRIVATE/standalone node from a PUBLIC node that serves other people, and flips on the non-custodial
safety bundle so a public operator cannot accidentally run a service with spendable keys on the infra.

## Why

The custody-sensitive settings (funding mode, user-held claim/refund) are individually configurable,
but an operator standing up a public service has to get every one right, and a single wrong default
(hot funding) puts user and operator funds on the infra. The owner's ask: one "public relay" switch
that, when set, makes the deployment non-custodial by profile.

## What it does

`Settings.public_relay` (default false):

- **false (private / standalone):** today's behaviour, unchanged. Local signing is correct here because
  the engine runs on the operator's own device, so the per-swap keys are already theirs.
- **true (public):** the node serves other people, so no spendable key may live on the host:
  - **`user_held_spends` is forced on** (in `engine_config`: `s.user_held_spends || s.public_relay`):
    the engine never signs claim/refund; it parks them for the user's browser to sign (0027), and the
    browser verifies the contracts commit its own bundle first (0027 funding-time check).
  - **Hot funding is refused at start:** if either `btc_funding` or `xbtc_funding` is `hot`, the daemon
    refuses to start with a clear error. Funding must be **cold** (an external/offline signer, design
    0012) or **interactive** (the user signs the lock PSBT in their own wallet, design 0017), so the
    funding key is never on the host either.

The two together are the whole custody line (0014): with `public_relay` on, the host holds no spend
key, no funding key, and no secret, by construction, and the daemon fails closed if misconfigured.

## Scope and interpretation

- The flag lives on the CLIENT/node `Settings` (where funding and signing config already live), not on
  the relay-discovery binary, which holds no funds; "public relay" names the operator's deployment
  posture. The hosted multi-tenant layer sets it in each per-identity instance's settings.
- First version enforces the two invariants above. Natural extensions (not yet): also require the fee
  to be on, publish the node's relay in a directory for federation (0029), and surface the profile in
  the config UI. Those are additive.

## Tests

`engine_config` forces `user_held_spends` on under `public_relay` (unit, mutation-verified). The
hot-funding refusal is a start-time guard in `Daemon::start`.
