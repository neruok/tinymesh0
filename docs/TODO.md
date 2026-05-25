# tinymesh0 — Open Items

## Testing

- [ ] **Real-machine test** — run two nodes on physically separate machines (different networks, behind real NAT) and verify STUN endpoint discovery + WireGuard tunnel establishment end-to-end
  - Confirm STUN returns correct public IPs for each machine
  - Confirm gossip propagates endpoints across the internet (not just a Docker bridge)
  - Confirm `ping` and arbitrary TCP/UDP traffic flows through the tunnel
  - Test with at least one node behind a residential NAT

---

## Phase 3 — Policy Engine

Enforce per-node allow/deny rules at the WireGuard interface using iptables. Because WireGuard cryptographically binds source IP to public key, mesh IPs are unforgeable and safe to use as identity in rules.

- [x] Define a policy rule DSL in config:
  ```yaml
  policy:
    default: allow
    rules:
      - allow: "node-a -> node-b port 5432"
      - deny:  "* -> node-internal port 22"
  ```
- [x] Distribute policies via gossip (add `Policies []PolicyRule` to `NodeState`)
- [x] Implement policy engine (`internal/policy/`) that translates rules into iptables chains on `tinymesh0`
- [x] Apply rules on peer join, remove on peer leave
- [x] Add `tinymesh0d policy list` and `tinymesh0d policy reload` CLI commands
- [x] Policy auto-reloads from config every 5 seconds; manual reload via SIGHUP also supported
- [x] Test: verify denied traffic is actually dropped (not just missing route)

---

## Phase 4 — Mesh DNS

Each node runs a lightweight DNS resolver on the WireGuard interface. Hostname → mesh IP mappings come from gossip state, so `curl http://node-b.mesh` works from any node without `/etc/hosts` changes.

- [x] Implement DNS server (`internal/dns/`) using `github.com/miekg/dns`
- [x] Bind to the node's mesh IP on port 53 (UDP + TCP)
- [x] Resolve `<hostname>.mesh` → peer's mesh IP from gossip membership
- [x] Handle negative responses (NXDOMAIN) for unknown hostnames
- [x] Update `/etc/resolv.conf` on the host (or document manual step) to point `.mesh` queries at the local resolver
- [x] Add `tinymesh0d dns list` to show current hostname → IP table

---

## Phase 5 — Topology UI

A live graph rendered in the browser showing nodes, active tunnels, per-link latency, and bandwidth. Served directly by each daemon.

- [x] Add `/api/topology` HTTP endpoint returning current membership + WireGuard stats as JSON
- [x] Add `/api/stream` SSE endpoint that pushes topology events in real time
- [x] Implement periodic latency probes (ICMP ping across mesh IPs) and feed results into the stream
- [x] Build single-page UI (`ui/`) using D3.js force-directed graph:
  - Nodes labelled with hostname + mesh IP
  - Edges labelled with latency (ms); hover shows bandwidth + handshake age
  - Node colour reflects connection state (orange=self, green=active, dark=idle)
- [x] Serve the UI as embedded static assets from the daemon binary (`//go:embed`)
- [x] Add `tinymesh0d status --web` flag to open the UI in a browser automatically

---

## User Experience & Onboarding

Getting someone from zero to a running mesh in under five minutes is the single biggest lever for adoption. Right now they need Go installed, a manual config file, and root access with no guidance if something goes wrong.

- [ ] **Pre-built binaries** — add a GitHub Actions release workflow using goreleaser to publish `tinymesh0d` binaries for `linux/amd64`, `linux/arm64`, and `darwin/amd64` on every tagged release. Users should be able to `curl` a single binary and run it without installing Go.
- [ ] **Install script** — a `curl | sh` bootstrap that detects OS/arch, downloads the right binary, and places it in `/usr/local/bin`. One command to get started.
- [ ] **`tinymesh0d version`** — print version string, build commit hash, Go version, and target OS/arch. Makes it easy for users to report bugs and for operators to confirm what's deployed.
- [ ] **`tinymesh0d doctor`** — pre-flight check command: verifies WireGuard kernel module is loaded, the listen port is available, at least one STUN server is reachable, CAP_NET_ADMIN is present, and iptables is accessible. Prints a clear pass/fail per check with a suggested fix for each failure. Eliminates the most common first-run failures silently.
- [ ] **`tinymesh0d config check`** — parse and validate a config file without starting the daemon. Exit 0 if valid, print specific errors if not. Useful for CI, for operators editing live configs, and for first-time users who misspell a key.
- [ ] **Structured startup output** — print step-by-step progress during `up` (STUN discovery, interface creation, gossip join, policy install) so users can see where the daemon is and what it's doing. Right now a slow STUN lookup or a gossip timeout produces no feedback.
- [ ] **Systemd unit file** — ship a `tinymesh0d.service` template in `scripts/` so users can `cp` it into `/etc/systemd/system/` and run the daemon as a persistent service. Include `After=network-online.target` and `Restart=on-failure`.

---

## Security & Trust

A new user joining a network needs assurance about who else can join. Right now any node that knows a bootstrap peer's address can join the mesh unconditionally.

- [ ] **Peer allowlist** — add an optional `allowed-keys` list in config: a set of WireGuard public keys that are permitted to join. If set, gossip events from unknown keys are ignored and their WireGuard peers are never configured. This gives operators explicit admission control without a central authority.
- [ ] **Network namespace / pre-shared token** — add an optional `network-id` field (a short string or token) that is included in gossip `NodeState`. Nodes with different `network-id` values ignore each other's gossip. Prevents accidental mesh merging when two independent deployments share a bootstrap server.
- [ ] **TLS on the topology server** — add an option to serve the topology UI and `/metrics` over HTTPS using a self-signed cert with the node's mesh IP as SAN. Print the cert fingerprint on startup so operators can pin it. Prevents sniffing of peer metadata (latency, bytes, endpoints) on untrusted networks.

---

## Topology UI — Continued

- [ ] **Latency sparkline in detail panel** — store the last N latency samples per peer in memory and render a small inline SVG sparkline in the click-to-open detail panel. Lets users see whether latency is stable, trending up, or spiking — much more useful than a single number.
- [ ] **Join/leave event highlights** — when a peer joins, briefly animate its node with a green pulse ring; when it leaves, briefly dim and shake it before it disappears. Makes state changes legible at a glance on a large mesh instead of requiring the user to read the peer count.
- [ ] **Node search / filter** — add a search input in the header that highlights matching nodes and dims the rest. Essential for meshes with more than ~10 nodes where the graph becomes dense.
- [ ] **Bandwidth history graph** — a small time-series chart of aggregate TX/RX bytes per second in the header bar, updated from the SSE stream. Lets users see traffic spikes without switching to Prometheus.

---

## Improvements & Nice-to-Haves

- [ ] **Endpoint refresh** — re-run STUN on an interval and push updated `NodeState` via gossip if the public endpoint changes (handles dynamic IPs, NAT rebinding)
- [ ] **Symmetric NAT fallback** — add a TURN-style relay for nodes behind symmetric NAT where UDP hole punching fails
- [ ] **Persistent membership** — write gossip membership to disk so nodes can reconnect to known peers without a bootstrap peer after a restart
- [ ] **macOS support** — use `golang.zx2c4.com/wireguard` (userspace WireGuard) for macOS where kernel WireGuard may not be available
- [ ] **Key rotation** — support rotating the WireGuard keypair and propagating the new public key via gossip
- [ ] **tinymesh0d -> tm0d** — `tinymesh0d` is a mouthful to type out. shorten the daemon acronym to `tm0d`
- [x] **Metrics endpoint** — expose Prometheus metrics (peer count, handshake age, bytes transferred) at `/metrics`

---

## Replace Third-Party Dependencies with Own Implementations

### Own Gossip Protocol (replace `hashicorp/memberlist`)

Currently using `hashicorp/memberlist` as a black box. Replacing it with a hand-rolled SWIM implementation would be a significant learning exercise and remove the only major third-party dependency in the core path.

- [ ] Implement the SWIM failure detector: direct probes (`ping`), indirect probes (`ping-req` via k random members), and suspicion timeout before marking a node dead
- [ ] Implement infection-style dissemination: piggyback membership events (join, leave, suspect, dead) on top of outgoing probe messages to gossip state without extra traffic
- [ ] Implement push-pull sync: periodically exchange full membership state with a random peer to converge faster after partitions
- [ ] Serialize membership messages with a compact binary format (or reuse the existing JSON `NodeState`)
- [ ] Expose the same `NotifyJoin` / `NotifyLeave` / `NotifyUpdate` event interface so the rest of the codebase is unaffected
- [ ] Tune probe interval, suspicion timeout, and retransmit multiplier and document the tradeoffs
- [ ] Test convergence time with 3+ nodes in Docker

### Add server fallback in high-latency mesh communication

In the case of hight-latency or failures observed over the network, we should add a fallback server to direct nodes to one another.
This would be similar to a DERP server in the Tailscale case.

### Own STUN Server (replace Google/Cloudflare)

Currently relying on `stun.l.google.com` and `stun.cloudflare.com`. Running our own means no external dependency at runtime and full visibility into what the server sees.

- [ ] Implement a minimal RFC 5389 STUN server in Go (`cmd/tinymesh0-stun/`) — Binding Request → Binding Response with `XOR-MAPPED-ADDRESS` only
- [ ] Add UDP and TCP transport support
- [ ] Deploy on a small public VPS (the server needs a public IP reachable from both sides of a NAT)
- [ ] Add the self-hosted address as the first entry in the default `stun-servers` list in `config.Default()`
- [ ] Log each request (source IP, timestamp) for debugging NAT traversal issues
- [ ] Optionally: add a `/health` HTTP endpoint alongside the STUN UDP port for uptime monitoring
