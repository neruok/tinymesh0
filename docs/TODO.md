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

## Improvements & Nice-to-Haves

- [ ] **Endpoint refresh** — re-run STUN on an interval and push updated `NodeState` via gossip if the public endpoint changes (handles dynamic IPs, NAT rebinding)
- [ ] **Symmetric NAT fallback** — add a TURN-style relay for nodes behind symmetric NAT where UDP hole punching fails
- [ ] **Persistent membership** — write gossip membership to disk so nodes can reconnect to known peers without a bootstrap peer after a restart
- [ ] **macOS support** — use `golang.zx2c4.com/wireguard` (userspace WireGuard) for macOS where kernel WireGuard may not be available
- [ ] **Key rotation** — support rotating the WireGuard keypair and propagating the new public key via gossip
- [ ] **Metrics endpoint** — expose Prometheus metrics (peer count, handshake age, bytes transferred) at `/metrics`

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

### Own STUN Server (replace Google/Cloudflare)

Currently relying on `stun.l.google.com` and `stun.cloudflare.com`. Running our own means no external dependency at runtime and full visibility into what the server sees.

- [ ] Implement a minimal RFC 5389 STUN server in Go (`cmd/tinymesh0-stun/`) — Binding Request → Binding Response with `XOR-MAPPED-ADDRESS` only
- [ ] Add UDP and TCP transport support
- [ ] Deploy on a small public VPS (the server needs a public IP reachable from both sides of a NAT)
- [ ] Add the self-hosted address as the first entry in the default `stun-servers` list in `config.Default()`
- [ ] Log each request (source IP, timestamp) for debugging NAT traversal issues
- [ ] Optionally: add a `/health` HTTP endpoint alongside the STUN UDP port for uptime monitoring
