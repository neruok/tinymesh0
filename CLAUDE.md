# tinymesh0 — Project Context for Claude

## What this project is

tinymesh0 is a decentralized mesh VPN built in Go by Jake Nocentino (GitHub: JakeNocentino). It connects machines across the internet into a private encrypted network with no central coordinator. Think Tailscale, but built from scratch as a learning project.

**Tagline:** "Peer pressure, but encrypted."

## Current state

| Phase | Status | Description |
|---|---|---|
| 1 — Core tunnel | ✅ Done | WireGuard interface via wgctrl+netlink, STUN client (RFC 5389 from scratch), deterministic mesh IP from pubkey hash |
| 2 — Gossip | ✅ Done | hashicorp/memberlist (SWIM), dynamic WireGuard peer config, STUN endpoint propagated via gossip |
| 3 — Policy engine | 📋 Next | iptables rules on tinymesh0, rules distributed via gossip |
| 4 — Mesh DNS | 📋 Planned | `<hostname>.mesh` resolution from gossip state |
| 5 — Topology UI | 📋 Planned | Live D3.js graph over WebSocket |

Open items and detailed phase specs are in **TODO.md**.

## Module and binary names

- Go module: `github.com/JakeNocentino/tinymesh0`
- Daemon binary: `tinymesh0d` (built from `./cmd/tinymesh0d/`)
- WireGuard interface: `tinymesh0`

## Key architecture decisions

**Mesh IP assignment:** Each node's mesh IP is deterministically derived by SHA-256 hashing the WireGuard public key and mapping 22 bits into `100.64.0.0/10` (CGNAT, RFC 6598). No DHCP, no coordinator needed. Because WireGuard cryptographically binds source IP to public key, the mesh IP is also an unforgeable identity — important for Phase 3 policy enforcement.

**STUN:** Implemented from scratch in `internal/stun/stun.go` against RFC 5389. The discovered `public_ip:listen_port` is stored in `NodeState.Endpoint` and gossiped to all peers. This is the mechanism by which peers learn how to reach each other without manual config.

**`advertise-endpoint` config field:** Overrides STUN when set. Required for Docker dev (both containers share the same public IP from STUN, so packets would never route correctly). In Docker, set to `"<hostname>:51820"` — Docker DNS resolves the hostname to the bridge IP at connection time.

**Gossip:** Wraps `hashicorp/memberlist`. `NodeState` (pubkey, mesh IP, hostname, endpoint) is embedded as memberlist node metadata. `NotifyJoin` → `wgMgr.AddPeer`, `NotifyLeave` → `wgMgr.RemovePeer`. A critical bug to know about: memberlist fires `NotifyJoin` for the local node *during* `memberlist.Create()`, before `m.list` is assigned — so the self-check uses `m.nodeName` (stored separately), not `m.list.LocalNode().Name`.

## Package layout

```
cmd/tinymesh0d/       CLI (cobra): up, down, status, keygen
internal/config/      YAML config loader + defaults
internal/ipam/        Deterministic mesh IP from public key
internal/stun/        STUN client, RFC 5389, no dependencies
internal/wireguard/   Interface lifecycle: wgctrl + netlink, peer add/remove + route management
internal/gossip/      memberlist wrapper: NodeState broadcast, WireGuard sync on events
scripts/              setup-dev.sh — generates keypairs + configs for Docker test
```

## How to build and run

```bash
# Build
go build -o tinymesh0d ./cmd/tinymesh0d/

# Generate a keypair
./tinymesh0d keygen

# Run (requires root for netlink/WireGuard)
sudo ./tinymesh0d up -c tinymesh0.yaml
```

## Docker dev workflow (two-node local test)

```bash
bash scripts/setup-dev.sh        # generates keys + configs in keys/ and configs/
docker compose up --build         # starts node-a (seed) and node-b (joins node-a)

# Verify gossip discovered peers and tunnel is up
docker exec node-b tinymesh0d status
docker exec node-a ping <node-b-mesh-ip>    # mesh IPs shown in startup logs
docker exec node-b ping <node-a-mesh-ip>
```

node-a is the seed (no bootstrap peers). node-b bootstraps from `node-a:7946`.

## Config reference

```yaml
hostname: mynode
listen-port: 51820
key-file: ./tinymesh0.key
advertise-endpoint: ""        # overrides STUN; use "<hostname>:51820" in Docker
stun-servers:
  - stun.l.google.com:19302
gossip:
  bind-port: 7946
  retry-join: 10
  bootstrap-peers:
    - "seed-node:7946"        # empty list if this is the seed node
```

## What's next (Phase 3 — Policy Engine)

- Add `PolicyRule` type and a `Policies []PolicyRule` field to `NodeState` so rules are gossip-distributed
- Implement `internal/policy/` that translates rules into iptables chains on `tinymesh0`
- Rules use mesh IPs as identity (safe because WireGuard makes them unforgeable)
- Apply rules on peer join, remove on peer leave
- See TODO.md for full spec
