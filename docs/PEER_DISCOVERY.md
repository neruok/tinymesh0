# Peer Discovery in tinymesh0

Two related but distinct mechanisms control how nodes find each other: **gossip-based peer discovery** (how a joining node learns about the cluster and vice versa) and **hostname resolution** (how bare names like `node-a:7946` become actual IP addresses). They are easy to conflate but operate on completely separate code paths.

---

## Part 1 — How a node discovers its peers

### Step 1 — Assemble your identity packet

Before touching the network, a starting node builds a `NodeState` struct (`gossip/state.go`). This is the single payload that gets gossiped to every other node:

```go
NodeState {
    PublicKey: "oBdaXbwzjm01..."   // WireGuard Curve25519 public key
    MeshIP:    "100.75.167.232"    // derived deterministically from that key via SHA-256
    Hostname:  "node-c"
    Endpoint:  "203.0.113.5:51820" // STUN-discovered public IP + WireGuard listen port
    Policies:  [...]               // this node's declared allow/deny rules
}
```

The endpoint comes from STUN (`tm0d.go`, `resolveEndpoint()`). STUN asks a third-party server "what IP and port did my UDP packet arrive from?" — it tells the node its own public-facing address without requiring any manual configuration.

### Step 2 — The joining node knocks on the bootstrap peer's door

```
node-c                                node-a (bootstrap peer)
   │                                        │
   │── TCP SYN → node-a:7946 ──────────────▶│
   │              (gossip port)              │
   │◀─────────────── TCP ACK ───────────────│
   │                                        │
   │  memberlist push/pull exchange         │
   │◀────── here is everyone I know ───────│
   │        (node-b, node-d, node-e, ...)   │
   │                                        │
```

This is `joinWithRetry()` in `manager.go`, which calls `memberlist.Join(bootstrapPeers)`. memberlist does a **push-pull sync** with the bootstrap peer: node-a sends node-c its complete membership table, and node-c sends back its own state. After this single exchange, node-c knows every node already in the cluster.

The retry loop matters here: in Docker and cloud environments the bootstrap node may not be ready yet. The code backs off linearly (`attempt × 1 second`) up to `retry-join` attempts.

### Step 3 — How node-c broadcasts itself to everyone else

node-c does **not** send a message to every other node directly. It passes its `NodeState` to memberlist through one callback:

```go
// manager.go
func (m *Manager) NodeMeta(limit int) []byte {
    data, _ := encodeState(m.self)
    return data  // JSON-encoded NodeState
}
```

memberlist calls `NodeMeta()` whenever it needs to include this node's metadata in any protocol message — probe pings, push-pull syncs, gossip piggybacks. The `NodeState` payload rides along for free on whatever traffic SWIM is already generating. tinymesh0 doesn't implement any broadcast logic itself; it just hands the data to memberlist and memberlist spreads it.

The underlying mechanism is **infection-style gossip**: every message that node-a sends to node-b (probing that node-b is alive) also carries the latest state of recently-changed nodes, including node-c. After a few rounds, every node has seen node-c's `NodeState`. For small meshes (2–6 nodes) this converges in under a second.

### Step 4 — Every existing node receives the event and configures WireGuard

When node-b's memberlist instance receives node-c's `NodeState` for the first time, it fires:

```go
// manager.go
func (m *Manager) NotifyJoin(node *memberlist.Node) {
    ns, _ := decodeState(node.Meta)  // unpack the NodeState
    m.syncPeer(ns)                   // hand it to wgSyncer
}
```

`syncPeer()` calls back into `wgSyncer.SyncPeer()` (`tm0d.go`), which fans out to four subsystems in a single call:

```
wgSyncer.SyncPeer(node-c's key, mesh IP, endpoint, hostname)
   ├─ wireguard.Manager.AddPeer()   ← WireGuard peer configured; kernel starts handshake
   ├─ policy.Engine.AddPeer()       ← iptables rules for node-c's mesh IP installed
   ├─ dns.Server.AddPeer()          ← node-c.mesh → 100.x.x.x added to DNS table
   └─ topology.Server.AddPeer()     ← UI graph updated; SSE event fired to browsers
```

All of that happens synchronously in the `NotifyJoin` callback. By the time gossip has converged, every node has a live WireGuard tunnel configured to every other node.

### Step 5 — WireGuard completes the actual connection

At this point the kernel-level WireGuard tunnel isn't established yet — the peers are configured but no packets have flowed. The first real traffic triggers the **WireGuard handshake**: node-b reaches out to node-c's endpoint, they exchange ephemeral keys using the Noise protocol, and the encrypted tunnel is live. All of that happens in the kernel; tinymesh0 doesn't touch it.

### The full picture: node-c joining a 3-node mesh

```
                        ┌──────────────────────┐
                        │  node-a (bootstrap)  │
                        │  gossip :7946        │
                        └──────┬───────────────┘
                               │ already knows node-b
                               │
   node-c boots up             │
   ─────────────────           │
   1. STUN → learns public IP  │
   2. builds NodeState         │
   3. memberlist.Join ─────────▶ push-pull: node-c gets node-b's state
                               │            node-a gets node-c's state
                               │
                               │ SWIM gossip spreads node-c's NodeState
                               │ to node-b (piggybacked on next probe)
                               │
   node-c                   node-a                   node-b
   NotifyJoin(node-a) ◀──   NotifyJoin(node-c) ──▶  NotifyJoin(node-c)
   └─ AddPeer(node-a)        └─ AddPeer(node-c)       └─ AddPeer(node-c)
      WireGuard configured      WireGuard configured      WireGuard configured
      DNS record added          DNS record added           DNS record added
      iptables rules set        iptables rules set         iptables rules set
      UI updated                UI updated                 UI updated
```

### Where the boundary is between memberlist and tinymesh0

memberlist owns the transport and convergence algorithm entirely. tinymesh0 only interacts with it through three callbacks:

| Callback | tinymesh0's role |
|---|---|
| `NodeMeta()` | Return the JSON `NodeState` to embed in SWIM messages |
| `NotifyJoin()` | Call `syncPeer()` to wire up WireGuard + policy + DNS + topology |
| `NotifyLeave()` | Call `RemovePeer()` to tear everything back down |

Everything in between — probing, suspicion timers, retransmit counts, push-pull scheduling — is memberlist's job. `NotifyUpdate()` is also wired and simply calls `NotifyJoin()`, so if a node's endpoint changes (after a STUN refresh, for example), every peer re-syncs the updated address automatically.

---

## Part 2 — How "node-a:7946" resolves to an IP address

There are two places in the codebase where a bare hostname like `node-a` is resolved. They look similar but use different mechanisms for different purposes.

### The bootstrap-peers string: resolved by Docker's DNS, not tinymesh0

When node-b starts, memberlist reads:

```yaml
gossip:
  bootstrap-peers:
    - "node-a:7946"
```

and calls `memberlist.Join(["node-a:7946"])`. memberlist passes that string directly to Go's standard `net.ResolveTCPAddr()` — an ordinary OS-level DNS lookup, the same thing `curl node-a:7946` would do.

Inside a Docker Compose network, Docker runs an embedded DNS resolver at `127.0.0.11`. Every container gets `/etc/resolv.conf` pointing there, and Docker registers each service name with it automatically. When node-b asks "what is `node-a`?", Docker's resolver answers with the bridge IP it assigned to that container — something like `172.20.0.2`. memberlist then opens a TCP connection to `172.20.0.2:7946` to perform the initial push-pull sync.

tinymesh0's own `.mesh` DNS hasn't started yet at this point. The startup sequence in `tm0d.go` is `WireGuard up → policy → dns → topology → gossip`. Even if it had started, it only serves `<name>.mesh` names — not bare hostnames. Docker DNS handles the bare `node-a` lookup.

### advertise-endpoint: a completely different problem

`advertise-endpoint` is not involved in gossip connectivity at all. It only controls what gets put into `NodeState.Endpoint` — the WireGuard UDP address that gets gossiped to peers so they can reach this node's WireGuard interface.

The reason it exists in the Docker config is a quirk of NAT. If STUN ran inside node-a's container, it would return the host machine's public IP. But node-b is also behind the same host NAT — they'd both advertise the same public IP, and then try to send WireGuard UDP to the host's public IP, which may loop back, get dropped, or fail depending on the router's hairpin NAT support.

So the setup script overrides STUN for both nodes:

```yaml
# node-a's config
advertise-endpoint: "node-a:51820"

# node-b's config
advertise-endpoint: "node-b:51820"
```

When a peer receives `"node-a:51820"` from gossip and calls `net.ResolveUDPAddr("udp", "node-a:51820")` (`manager.go`, `syncPeer()`), Docker DNS again resolves `node-a` to the bridge IP. WireGuard traffic then flows over the bridge network rather than out through the host's public IP.

### The two lookups side by side

```
"node-a:7946"  in bootstrap-peers
  └─ looked up by: Go stdlib (net.ResolveTCPAddr)
     resolved by:  Docker embedded DNS (127.0.0.11)
     used for:     gossip TCP connection (memberlist push-pull, SWIM probes)
     timing:       at startup, before any tinymesh0 subsystem is running

"node-a:51820" in advertise-endpoint / NodeState.Endpoint
  └─ looked up by: Go stdlib (net.ResolveUDPAddr)
     resolved by:  Docker embedded DNS (127.0.0.11)
     used for:     WireGuard UDP tunnel endpoint
     timing:       when a peer receives the gossip NodeState and calls SyncPeer
```

Both happen to use Docker DNS, but for completely independent reasons on completely independent code paths.

### On real machines

On real machines the `advertise-endpoint` field is usually omitted — STUN handles endpoint discovery automatically. The `bootstrap-peers` list contains a real hostname or public IP of a known seed node, resolved by whatever DNS the machine normally uses. Docker DNS is specific to the local development environment.
