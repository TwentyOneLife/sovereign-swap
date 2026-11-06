# 0011 Connecting the client to the two bitcoind nodes, over Tor by default

Status: Proposed. Opens the node-connection question that [0009](0009-client-and-gui.md) left as
"point the client at your own nodes" and that [0010](0010-fee-output-and-silent-payments.md) narrowed
to plain bitcoind RPC (no Fulcrum, no coordinator). Nothing here is approved yet; it records the
constraint, the options, and the work each option implies, so the owner can choose one.

## The problem

The client is a daemon that drives both legs of a swap. Each leg talks to a full node by JSON-RPC: a
Bitcoin Core node for BTC and a Bitcoin Knots BLAKE2b node for xBTC. On StartOS the RPC is not a plain
`http://host:8332` endpoint. The platform fronts bitcoind's RPC with a **TLS reverse proxy** and
presents it as **HTTPS on a dedicated port**, with a StartOS Root CA certificate. The node's
**Interfaces** page offers that one RPC endpoint over several addresses at once, each a toggle: a Local
LAN address (IPv4 and mDNS), an optional Public address, and a **Tor onion**. Plain HTTP on the
internal `8332` is reachable only over the platform's internal bridge, never off the box.

So the endpoints exist and are a few clicks away; two things still have to be decided. First, **which**
address a user should point the client at so the choice works for everyone, not just on one network.
Second, that the client's RPC transport can actually speak to a StartOS endpoint: **HTTPS with a
self-signed Root CA**, optionally over Tor. A client that only knows how to make a plain-HTTP call to
`host:8332` connects to neither node. This document settles both.

## The constraint that decides it: both nodes are remote, for everyone

Both node packages carry the StartOS package id `bitcoind` (Core and the Knots BLAKE2b fork are each
`bitcoind`). Two packages with the same id cannot be installed on one StartOS server. Therefore a user
who runs both chains runs them on **two** servers, and the client, wherever it sits, is on the same
server as at most one of them. The other node is always across the network.

This makes remote RPC the base case, not an edge case. A design that only works when the node is
local solves the swap for nobody, because no single server holds both nodes. Any accepted option has
to carry at least one leg to a node on another machine.

## Options

**A. The node's Local LAN address (HTTPS).**
A legitimate same-site path, but not the shipped default. StartOS makes it one toggle (the Local IPv4
or mDNS address on the RPC interface, HTTPS with the Root CA), so it is genuinely easy, and where the
client and the node sit on one trusted subnet it just works with no Tor round-trip. Its limit is
structural, not difficulty: it only reaches a node on the same subnet, so it cannot serve the
cross-server leg that every user has (see the constraint above). It also inherits Bitcoin Core's
standing caution, keep RPC off untrusted and public networks, so the Public address stays off. Offer
it as an option for a co-subnet node; do not build the design on it.

**B. StartOS dependency wiring (local only).**
When one node sits on the same server as the client, StartOS can wire the client to it internally:
the node package exports its RPC to a declared dependent, credentials and address handled by the
platform, nothing exposed off the box. This is the right path for the **local** leg and we should use
it where it applies. It cannot cover the other leg, because that node is on another server by the
constraint above. So B is a complement, never the whole answer.

**C. RPC over the node's Tor onion (the portable base case).**
Every StartOS node already carries a Tor (v3 onion) address on its RPC interface, and every StartOS
service already has an outbound Tor proxy. A node reached at `https://<onion>:<rpc-port>` is reachable
from any other StartOS server on earth, with no LAN assumption, no port forward, and no per-site
firewall rule. Three layers stack cleanly: the onion authenticates the endpoint (the address is its
key) and encrypts the transport, the HTTPS proxy sits inside that, and the node's RPC credentials gate
access. That is exactly the "secured channel plus auth" shape Bitcoin Core asks for, and because the
onion already authenticates the endpoint the self-signed Root CA on the inside is acceptable rather
than a trust gap. This is the only option that serves the cross-server leg for an arbitrary user, so
it is the default the client is designed around.

## Recommendation

Design the client for **C as the baseline, B as a local optimisation, A as a co-subnet option**:

- Each node leg takes an HTTPS RPC endpoint and credentials. The endpoint is normally an onion; it may
  be a Local LAN (A) or bridge (B) address when the node is on the same subnet or the same server.
- Where a node is on the same StartOS server as the client, prefer the dependency wiring (B) and skip
  Tor for that leg.
- The remaining leg, and the whole thing when the client is on a third server, goes over the node's
  onion (C).

The setup a user follows, per node: open the node's **Interfaces**, copy the RPC interface's **Tor**
address (it is already there, as `https://<onion>:<rpc-port>`), obtain per-application RPC credentials
for that node, and paste the HTTPS onion URL plus those credentials into the client's node settings.
For a co-subnet node they may instead copy the Local LAN address (A). The relay list is unchanged and
already Tor-first ([0006](0006-nostr-client-and-relay.md)).

## What the daemon has to do

Reaching a StartOS node is not a config string; the RPC client needs real work:

- **HTTPS, not HTTP, with a self-signed Root CA.** Every StartOS RPC endpoint is TLS, fronted by the
  platform's proxy with a StartOS-issued Root CA certificate. The daemon's RPC client must speak HTTPS
  and accept that CA: import the node's Root CA, or pin the certificate, per node. A plain-HTTP client
  reaches nothing. Over an onion (C) the Tor address already authenticates the endpoint, so the inner
  certificate need only be accepted, not independently verified against a public CA; on the LAN (A) the
  node's Root CA has to be trusted explicitly. This applies to every option, A and B included, not just
  the onion.
- **SOCKS5 with remote DNS (socks5h).** For the onion leg, the daemon resolves and dials the onion
  through the StartOS Tor SOCKS proxy; the name must be resolved proxy-side, never locally. Per-leg
  proxy setting, because a local (A or B) leg must not be forced through Tor.
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
   package instructions and a daemon work item (the HTTPS-plus-Root-CA and SOCKS5 transport above).
