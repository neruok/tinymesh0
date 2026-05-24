```
 _   _                                  _        ___
| |_(_)_ __  _   _ _ __ ___   ___  ___| |__    / _ \
| __| | '_ \| | | | '_ ` _ \ / _ \/ __| '_ \  | | | |
| |_| | | | | |_| | | | | | |  __/\__ \ | | | | |_| |
 \__|_|_| |_|\__, |_| |_| |_|\___||___/_| |_|  \___/
             |___/
```

> **Peer pressure, but encrypted.**

[![Go Version](https://img.shields.io/badge/go-1.22-blue)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What is tinymesh0?

tinymesh0 connects machines across the internet into a private encrypted network — like Tailscale or ZeroTier, but built from scratch. Every node is equal: there is no central server, no account required, and no single point of failure.

Each node:
- Gets a **stable private IP** derived deterministically from its cryptographic identity
- **Discovers its own public endpoint** via STUN (no manual IP configuration)
- Establishes **encrypted WireGuard tunnels** directly to every peer
- Enforces **per-node access policy** at the network layer *(Phase 3)*
- Participates in **gossip-based peer discovery** — nodes find each other automatically *(Phase 2)*

---

## How it works

```
  node-a (home)                                    node-b (cloud)
┌────────────────────┐                         ┌────────────────────┐
│  100.75.167.232    │                         │  100.117.163.169   │
│  tinymesh0         │◀── WireGuard / UDP ────▶│  tinymesh0         │
│  203.0.113.5:51820 │     (encrypted)         │  198.51.100.9:51820│
└────────────────────┘                         └────────────────────┘
```

- **Identity** — each node's public key (Curve25519) is its identity. The mesh IP is a SHA-256 hash of that key, mapped into `100.64.0.0/10`.
- **Discovery** — STUN tells each node its own public IP without any central registry.
- **Encryption** — WireGuard (ChaCha20-Poly1305 + Noise protocol) encrypts all traffic between nodes.
- **No coordinator** — gossip (SWIM protocol) propagates peer state across the mesh. *(Phase 2)*

For a detailed technical walkthrough, see [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

---

## Getting started

### Prerequisites

- Linux (kernel 5.6+ for built-in WireGuard support)
- Go 1.22+
- Root / `CAP_NET_ADMIN` (required to create network interfaces)

### Build

```bash
git clone https://github.com/jakenoc/tinymesh0
cd tinymesh0
go build -o tinymesh0d ./cmd/tinymesh0d/
```

### Generate a keypair

```bash
./tinymesh0d keygen
# private-key: <base64>
# public-key:  <base64>
```

Share your **public key** and your **public IP:port** with the nodes you want to connect.

### Configure

Copy the example config and fill in your peers:

```bash
cp tinymesh0.example.yaml tinymesh0.yaml
```

```yaml
hostname: mynode
listen-port: 51820
key-file: ./tinymesh0.key

stun-servers:
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478

peers:
  - public-key: "<peer public key>"
    endpoint: "<peer public IP>:51820"
```

The peer's mesh IP is derived automatically from their public key — you don't configure it manually.

### Run

```bash
sudo ./tinymesh0d up -c tinymesh0.yaml
```

```
public key : oBdaXbwzjm01c60kFOjhxToB1duJHpjZ7J0KFMFBTDg=
mesh IP    : 100.75.167.232
discovering public endpoint via STUN...
public endpoint: 216.243.46.97:51820
tinymesh0 is up
  peer Nh/YpdBJKH/... → 100.117.163.169 via 1.2.3.4:51820
```

### Commands

| Command | Description |
|---|---|
| `tinymesh0d up -c <config>` | Bring up the mesh interface |
| `tinymesh0d down` | Take down the mesh interface |
| `tinymesh0d status` | Show interface and peer status |
| `tinymesh0d keygen` | Generate a new WireGuard keypair |

---

## Local development with Docker

You can simulate a two-node mesh on a single machine using Docker Compose.

**1. Generate keys and configs:**

```bash
bash scripts/setup-dev.sh
```

**2. Start both nodes:**

```bash
docker compose up --build
```

**3. Verify the tunnel:**

```bash
# Check peer status on node-b
docker exec node-b tinymesh0d status

# Ping node-a's mesh IP from node-b
docker exec node-b ping 100.75.167.232
```

You should see sub-millisecond ping times and a confirmed WireGuard handshake.

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| 1 — Core tunnel | ✅ Done | WireGuard interface management, STUN discovery, static peer config |
| 2 — Gossip | 🔨 In progress | SWIM-based peer discovery, no static config needed |
| 3 — Policy engine | 📋 Planned | Per-node allow/deny rules enforced via iptables |
| 4 — Mesh DNS | 📋 Planned | Resolve `<hostname>.mesh` to peer mesh IPs |
| 5 — Topology UI | 📋 Planned | Live network graph via WebSocket + D3.js |

---

## Architecture

```
tinymeshd
├── cmd/tinymesh0d/       CLI entry point (cobra)
├── internal/
│   ├── config/           YAML config loader
│   ├── ipam/             Deterministic mesh IP assignment
│   ├── stun/             STUN client (RFC 5389, from scratch)
│   └── wireguard/        Interface lifecycle via wgctrl + netlink
└── scripts/              Development utilities
```

---

## License

MIT
