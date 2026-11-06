# 0011 Connecting the client to the two bitcoind nodes, over Tor by default

Status: Proposed. Opens the node-connection question that [0009](0009-client-and-gui.md) left as
"point the client at your own nodes" and that [0010](0010-fee-output-and-silent-payments.md) narrowed
to plain bitcoind RPC (no Fulcrum, no coordinator). Nothing here is approved yet; it records the
constraint, the options, and the work each option implies, so the owner can choose one.

## The problem

The client is a daemon that drives both legs of a swap. Each leg talks to a full node by JSON-RPC: a
Bitcoin Core node for BTC and a Bitcoin Knots BLAKE2b node for xBTC. On StartOS, a freshly installed
node does **not** publish its RPC on the host network. The RPC interface exists and is bound, but
until the operator attaches an address to it, nothing off the node can reach it; sibling services on
the same server reach it over an internal bridge, not over the LAN.

So "install the client, then fill in two RPC addresses" has no addresses to fill in until the operator
exposes each node's RPC deliberately. This document is about **how** to expose it in a way every user
can reproduce, not just on one particular network.

## The constraint that decides it: both nodes are remote, for everyone

Both node packages carry the StartOS package id `bitcoind` (Core and the Knots BLAKE2b fork are each
`bitcoind`). Two packages with the same id cannot be installed on one StartOS server. Therefore a user
who runs both chains runs them on **two** servers, and the client, wherever it sits, is on the same
server as at most one of them. The other node is always across the network.

This makes remote RPC the base case, not an edge case. A design that only works when the node is
local solves the swap for nobody, because no single server holds both nodes. Any accepted option has
to carry at least one leg to a node on another machine.

## Options

**A. Expose RPC on the LAN (rpcbind to a host address).**
Reject as the primary path. It only works when client and node share a subnet, so it cannot serve the
cross-server leg that every user has. It needs a per-site firewall rule and a static credential set by
hand. Bitcoin Core's own guidance is not to expose RPC on an untrusted network, and not on the public
internet at all; exposure is expected to be done only over a secured channel. The StartOS RPC tuning
dialog does not offer a bind-and-credential control, so this is not even a setting a normal user can
reach without leaving the product. It remains available to a single-subnet operator who accepts the
trade, but it is not the shipped answer.

**B. StartOS dependency wiring (local only).**
When one node sits on the same server as the client, StartOS can wire the client to it internally:
the node package exports its RPC to a declared dependent, credentials and address handled by the
platform, nothing exposed off the box. This is the right path for the **local** leg and we should use
it where it applies. It cannot cover the other leg, because that node is on another server by the
constraint above. So B is a complement, never the whole answer.

**C. RPC over the node's Tor onion (the portable base case).**
Every StartOS service can be given a Tor (v3 onion) address, and every StartOS service already has an
outbound Tor proxy. A node reached at `<onion>:<rpc-port>` is reachable from any other StartOS server
on earth, with no LAN assumption, no port forward, and no per-site firewall rule. Authentication is
carried by the node's own RPC credentials over the onion; the onion gives transport confidentiality
and the credentials gate access, which is exactly the "secured channel plus auth" shape Bitcoin Core
asks for. This is the only option that serves the cross-server leg for an arbitrary user, so it is the
default the client is designed around.

## Recommendation

Design the client for **C as the baseline, B as a local optimisation, A not shipped**:

- Each node leg takes an RPC endpoint and credentials. The endpoint is normally an onion; it may be a
  local/bridge address when the node is co-resident.
- Where a node is on the same StartOS server as the client, prefer the dependency wiring (B) and skip
  Tor for that leg.
- The remaining leg, and the whole thing when the client is on a third server, goes over the node's
  onion (C).

The setup a user follows, per node: open the node's **Interfaces**, enable a Tor address on its RPC
interface, obtain per-application RPC credentials for that node, and paste `<onion>:<rpc-port>` plus
those credentials into the client's node settings. The relay list is unchanged and already Tor-first
([0006](0006-nostr-client-and-relay.md)).

## What the daemon has to do for C

Reaching an onion is not free; the RPC client needs real work, not a config string:

- **SOCKS5 with remote DNS (socks5h).** The daemon resolves and dials the onion through the StartOS
  Tor SOCKS proxy; the name must be resolved proxy-side, never locally. Per-leg proxy setting, because
  a local (B) leg must not be forced through Tor.
- **An optional `tor` dependency / proxy address in the package**, so the daemon knows where the SOCKS
  proxy is on a StartOS install, and can run without it when a leg is local.
- **Tor-sized timeouts and retries.** Onion round-trips are slow and occasionally stall; RPC calls
  need generous timeouts and bounded retries, distinct from a localhost RPC budget.
- **"RPC unreachable" is a wait, not a failure.** The engine already treats a node it cannot reach as
  a reason to hold and retry, never to abandon a leg. This has a safety consequence: the **timelock
  margin must absorb a Tor outage**. If a node's onion is unreachable across a refund boundary the
  swap must still be safe, so the margin ([0001](0001-htlc-and-replay-guard.md),
  [0004](0004-redundancy-and-failover.md)) is sized for Tor's worst case, not localhost's.

None of this is on the swap-crypto path; it is transport. But the timelock-margin point is a safety
item, so C is not a pure packaging choice.

## Open questions for the owner

1. **Per-application RPC credentials on the Knots BLAKE2b node.** The portable path assumes each node
   package can hand an external application its own RPC credentials (not a local cookie file, which
   does not cross machines and rotates on restart). This must be confirmed on the **BLAKE2b/Knots**
   package specifically, since every xBTC user runs it. If that package lacks it, the portable path
   depends on the package adding it, and that becomes an upstream task, not a client task.
2. **Co-resident layout.** Decide whether we recommend putting the client on the same server as one of
   the two nodes (so one leg is local via B) or on a third server (both legs over Tor). The first is
   cheaper per swap; the second keeps the client off both node servers.
3. **Approval.** This is Proposed. On approval it becomes the node-connection section of the client
   package instructions and a daemon work item (the SOCKS5 transport above).
