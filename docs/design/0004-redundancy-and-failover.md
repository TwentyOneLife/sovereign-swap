# 0004 Redundancy and failover

Status: design, not implemented. Implementation waits until the engine runs as a deployed service
(after M3/M4); today it is a library.

## The question

Keep the service running if a server fails, in a sovereign way, without a single point of failure
and without depending on a managed cloud load balancer.

## The trap: a swap engine must not be run active/active

A load balancer in front of two live engines **sharing one identity would lose coins**, not just
duplicate work. The engine is a background decider that signs and broadcasts transactions and hands
out per-swap key indices from a counter. Two live instances on one seed and one state directory
would:

- hand the **same key index** to two different swaps, so one secret and one key pair get reused
  across swaps. Reused keys and secrets are catastrophic: a counterparty who sees the secret of one
  swap can take the other.
- fund the same lock twice, double-broadcast, and race each other's claims and refunds.

So the engine is **not** a stateless request handler that a load balancer can fan out. It needs
**exactly one active decider per identity at a time**. The good news: the engine is already built
for this. It is level-triggered and idempotent (it decides from chain state each tick, writes state
before acting, and every action is safe to repeat), so a standby that takes over simply opens the
state directory and ticks. Downtime never loses funds, because a swap interrupted at any point ends
in a refund (tested: `a_taker_offline_past_its_window_still_refunds_on_return`).

## The sovereign design: active/passive with a single-writer lease

```
                 same seed + same swap files (replicated)
        ┌───────────────────────────────┴───────────────────────────────┐
   ┌────▼───── PRIMARY (holds the lease) ─────┐      ┌───── STANDBY (watching) ──────┐
   │  swap engine: ticks, signs, broadcasts   │      │  swap engine: idle, does NOT   │
   │  renews a time-bound lease each tick      │      │  tick while the lease is held  │
   └────┬─────────────────────────────────────┘      └────┬───────────────────────────┘
        │ reads/writes state, renews lease                │ if the lease expires, it
        ▼                                                 ▼ acquires it and becomes primary
   ┌───────────── shared state (one writer at a time) ─────────────┐
   │  swap files + seed, on replicated storage or a small KV with  │
   │  a compare-and-swap lease key (fencing token)                 │
   └────────────────────────────────────────────────────────────── ┘
        │                                   the chains are the shared source of truth:
        ▼                                   both instances see the same locks and spends
   BTC node / xBTC node (each instance has its own or a shared read view)
```

- **Lease (fencing).** One instance holds a time-bound lease and renews it; only the lease-holder
  ticks. If it dies, the lease expires and the standby acquires it. The lease must be a
  compare-and-swap on a single resource (a file on shared storage with an exclusive lock, or one KV
  key), so two instances can never both believe they hold it (split-brain). The key-index counter is
  only ever advanced by the lease-holder.
- **Takeover is cheap** precisely because the engine is idempotent: the new primary opens the files
  and ticks; in-flight broadcasts are simply reissued.
- **The real redundancy is the seed and the chain.** Every key and secret derives from one seed by
  hardened derivation, and almost all swap state is recoverable from the chain. A machine with the
  seed backup and the list of active swap ids can rebuild and continue. This is the sovereign core:
  no coordination service is required beyond replicating the seed and the small swap files.
- **Cold signing (M2b) fits.** With signing done by an external cold signer, both primary and standby
  are watch-only deciders pointing at the same signer; neither holds a spending key, so a compromised
  server cannot spend, and failover does not move keys.

## What a load balancer is actually for here

The stateless, user-facing parts, not the decider:

- the local API / UI a user drives: can be multi-instanced behind a balancer.
- **the relay**: run several, and clients already list many (`xbtc-swap-spec.md` section 6: any relay
  works, our relay is one of many). Relay redundancy is horizontal and needs no coordination, because
  a relay holds no swap state. This is the most sovereign redundancy of all: more independent relays,
  on different machines and networks, Tor and clearnet.

## Options, most sovereign first

1. **Two boxes, active/passive, lease on shared storage**, seed replicated to both. Floating address
   via VRRP/keepalived for the user-facing API only. No cloud, no managed service.
2. **One active box, cold seed backup, manual failover.** Simplest; a human (or a one-shot script)
   starts the standby with the seed after a confirmed failure. Acceptable because downtime cannot
   lose funds, only delay settlement, and refund deadlines are generous.
3. **Several relays, always.** Independent of 1 and 2; do this regardless.

Avoid: active/active behind a load balancer (loses funds, see above), and any managed cloud balancer
or KV as the only lease authority (reintroduces a non-sovereign single point of trust). A cloud KV
may be used as one lease backend among options, never as a required dependency.

## Test plan (when implemented)

- Two engines on one seed and one leased state dir: the standby never acts while the lease is held;
  killing the primary lets the standby take over and complete or refund every in-flight swap.
- Fault injection: kill the primary mid-broadcast, mid-claim, and between state write and action;
  the standby must never reuse a key index and never lose funds.
- Split-brain probe: force both to believe they are primary (lease backend unavailable); the fencing
  must stop the second from acting.
