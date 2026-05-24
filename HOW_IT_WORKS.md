# How tinymesh0 Works

This document walks through every layer of tinymesh0 — from keypair generation down to the encrypted bytes on the wire — so you understand not just *what* it does, but *why* each piece exists.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [Node Identity: WireGuard Keypairs](#2-node-identity-wireguard-keypairs)
3. [Mesh IP Assignment: Deterministic Hashing](#3-mesh-ip-assignment-deterministic-hashing)
4. [NAT Traversal: The STUN Protocol](#4-nat-traversal-the-stun-protocol)
5. [The Encrypted Tunnel: How WireGuard Works](#5-the-encrypted-tunnel-how-wireguard-works)
6. [Creating the Interface: Linux Netlink](#6-creating-the-interface-linux-netlink)
7. [End-to-End Packet Walk](#7-end-to-end-packet-walk)
8. [The Docker Test Environment](#8-the-docker-test-environment)

---

## 1. The Big Picture

When two machines join a tinymesh0 network, each one runs a daemon (`tinymesh0d`) that:

1. Generates a cryptographic identity (a WireGuard keypair)
2. Derives a stable private IP address from that identity
3. Discovers its own public IP address (via STUN)
4. Creates an encrypted virtual network interface on the host
5. Configures the kernel to route traffic destined for other mesh nodes through that interface

The result is that two machines — which might be on completely different networks, behind NATs, in different data centres — can communicate as if they were on the same private LAN.

```
  Machine A                                          Machine B
  (home network)                                     (cloud VM)

┌──────────────────────┐                        ┌──────────────────────┐
│  App: ping           │                        │  App: receives ICMP  │
│  100.117.163.169     │                        │                      │
│          │           │                        │          │           │
│   tinymesh0          │                        │   tinymesh0          │
│   100.75.167.232     │                        │   100.117.163.169    │
│   [WireGuard]        │                        │   [WireGuard]        │
│          │           │   encrypted UDP        │          │           │
│       eth0  ─────────┼────────────────────────┼─────  eth0           │
│   203.0.113.5:51820  │   over the internet    │   198.51.100.9:51820 │
└──────────────────────┘                        └──────────────────────┘
      mesh IP: 100.75.167.232                      mesh IP: 100.117.163.169
      public key: oBdaXb...                        public key: Nh/Ypd...
```

The internet only ever sees encrypted UDP packets. The plaintext traffic travels inside the tunnel, invisible to anyone in between.

---

## 2. Node Identity: WireGuard Keypairs

Every tinymesh0 node has a **Curve25519 keypair** — a private key and a public key. This is the same elliptic-curve cryptography used in TLS 1.3 and Signal.

```
Private Key (32 bytes, secret)  ──▶  Public Key (32 bytes, shared freely)
```

- The **private key** never leaves the machine. It is used to perform the cryptographic handshake and to decrypt incoming traffic.
- The **public key** is your identity on the mesh. You share it with peers so they can encrypt traffic meant for you and verify that traffic actually came from you.

When tinymesh0 starts for the first time, it calls `wgtypes.GeneratePrivateKey()`, which generates a random 32-byte private key and clamps it according to Curve25519 requirements. The public key is derived mathematically from the private key and is deterministic — the same private key always produces the same public key.

```go
// internal/wireguard/keys.go
key, err := wgtypes.GeneratePrivateKey()
pubKey := key.PublicKey()
```

The keypair is persisted to disk so the node has the same identity across restarts. If the key file doesn't exist, tinymesh0 creates the parent directory and writes the new key with `0600` permissions (owner-readable only).

### Why this matters for security

WireGuard's security model is built on these keys. Before any data flows, two peers perform a **cryptographic handshake** using the Noise protocol framework (specifically Noise_IKpsk2). During the handshake:

- Each side proves it holds the private key corresponding to its public key
- A unique session key is derived for this specific connection
- That session key is rotated every few minutes (forward secrecy)

If an attacker intercepts your traffic, they cannot decrypt it — even if they later steal your private key — because each session's key is ephemeral.

---

## 3. Mesh IP Assignment: Deterministic Hashing

Every node needs a stable IP address on the mesh. tinymesh0 assigns these without any central DHCP server, using a simple rule: **your mesh IP is derived from your public key**.

```
Public Key (32 bytes)
       │
       ▼
  SHA-256 hash (32 bytes)
       │
       ├─ byte[0] → second octet: 64 + (byte & 0x3F)  →  64–127
       ├─ byte[1] → third octet                        →  0–255
       └─ byte[2] → fourth octet                       →  1–254
       
Result: 100.X.X.X  (within 100.64.0.0/10, the CGNAT range)
```

```go
// internal/ipam/ipam.go
hash := sha256.Sum256(pubKey[:])
ip[0] = 100
ip[1] = 64 + (hash[0] & 0x3F)
ip[2] = hash[1]
ip[3] = hash[2]
```

The address space used is `100.64.0.0/10`, which is reserved by RFC 6598 for carrier-grade NAT. It will never appear on the public internet, so it is safe to use as a private overlay network.

**Key properties of this scheme:**

| Property | Explanation |
|---|---|
| Deterministic | The same public key always maps to the same IP |
| No coordinator needed | Any node can compute any other node's mesh IP from their public key |
| Collision resistant | SHA-256 makes accidental IP collisions astronomically unlikely |
| Unforgeable | You cannot choose your IP — it is fixed by your public key |

This last point is important for the policy engine (Phase 3): because WireGuard cryptographically binds source IP to public key, a packet arriving on `tinymesh0` claiming to be from `100.75.167.232` *provably* came from the node holding the private key for that public key. There is no way to spoof a mesh IP.

---

## 4. NAT Traversal: The STUN Protocol

Most machines sit behind a NAT (Network Address Translation) router — a device that translates between your private IP (e.g. `192.168.1.5`) and your public IP (e.g. `216.243.46.97`). The problem: if node-a wants to send a UDP packet to node-b, it needs to know node-b's *public* IP and port, not its private one.

STUN (Session Traversal Utilities for NAT, RFC 5389) solves the discovery part: it tells you what your public IP and port look like from the outside.

### How the STUN protocol works

tinymesh0 implements STUN from scratch (see `internal/stun/stun.go`). Here's what happens:

**Step 1: Send a Binding Request**

tinymesh0 opens a UDP socket and sends a 20-byte message to a public STUN server (e.g. `stun.l.google.com:19302`):

```
Bytes 0–1:   Message Type   = 0x0001  (Binding Request)
Bytes 2–3:   Message Length = 0x0000  (no attributes)
Bytes 4–7:   Magic Cookie   = 0x2112A442  (fixed constant, RFC 5389)
Bytes 8–19:  Transaction ID = 12 random bytes
```

The magic cookie and transaction ID exist so the response can be matched back to the request, even if multiple requests are in flight.

**Step 2: The STUN server reads your public endpoint**

The STUN server receives your packet. From its perspective, the packet came from your *public* IP and port (after NAT translation). It puts that information in its response.

**Step 3: Parse the Binding Response**

The response contains attributes in TLV (Type-Length-Value) format. tinymesh0 looks for the `XOR-MAPPED-ADDRESS` attribute (type `0x0020`):

```
Bytes 0:    reserved
Byte  1:    Family  = 0x01 (IPv4)
Bytes 2–3:  X-Port  = actual_port XOR (magic_cookie >> 16)
Bytes 4–7:  X-Addr  = actual_ip   XOR magic_cookie
```

The XOR encoding exists to prevent NAT devices from rewriting IP addresses they find inside the packet payload (some broken NATs do this).

Decoding:
```go
port := int(xPort ^ uint16(magicCookie >> 16))
addr := xAddr ^ magicCookie
```

**The result** is your public IP — but not necessarily your public WireGuard port. Most home NATs use *port preservation* for outbound UDP: the external port matches the internal port. tinymesh0 takes advantage of this by advertising `<stun-discovered-ip>:<configured-listen-port>` as its reachable endpoint.

```
Your machine                  NAT router               STUN server
192.168.1.5:51820  ──UDP──▶  216.243.46.97:51820  ──▶  sees source: 216.243.46.97:51820
                                                          responds: XOR-MAPPED-ADDRESS = 216.243.46.97:51820
```

---

## 5. The Encrypted Tunnel: How WireGuard Works

WireGuard is a modern VPN protocol built into the Linux kernel since version 5.6. It is dramatically simpler than IPSec or OpenVPN — the entire protocol fits in ~4,000 lines of code.

### The virtual interface

WireGuard presents itself as a standard Linux network interface (`tinymesh0`). From the operating system's perspective, it looks like any other network card. You assign it an IP, add routes to it, and the kernel sends packets to it just like it would to `eth0`.

The difference is what happens to those packets internally: WireGuard encrypts them and wraps them in UDP before sending them out through the real network interface.

```
Kernel routing table sees:
  100.117.163.169/32  via  tinymesh0

Packet to 100.117.163.169:
  ┌─────────────┐
  │  IP header  │  dst: 100.117.163.169
  │  payload    │
  └─────────────┘
         │
         ▼  enters tinymesh0
  ┌──────────────────────────────┐
  │  WireGuard looks up peer     │
  │  for 100.117.163.169         │
  │  → public key: Nh/Ypd...     │
  │  → endpoint: 172.22.0.3:51820│
  └──────────────────────────────┘
         │
         ▼  encrypt + encapsulate
  ┌──────────────────────────────────────────────┐
  │  UDP header  │  src: 172.22.0.2:51820        │
  │              │  dst: 172.22.0.3:51820        │
  │  WireGuard   │  4-byte receiver index        │
  │  header      │  8-byte nonce                 │
  │  payload     │  encrypted original packet    │
  │              │  16-byte Poly1305 auth tag    │
  └──────────────────────────────────────────────┘
         │
         ▼  exits eth0 → travels over network → arrives at node-b's eth0
```

### The handshake

Before data can flow, the two peers perform a **one-RTT handshake** (one round trip):

```
node-a                                    node-b
  │                                          │
  │── Handshake Initiation ─────────────────▶│
  │   (ephemeral public key,                 │
  │    encrypted static public key,          │
  │    encrypted timestamp)                  │
  │                                          │
  │◀── Handshake Response ───────────────────│
  │    (ephemeral public key,                │
  │     empty encrypted payload)             │
  │                                          │
  │══ encrypted data flows both ways ═══════▶│
```

After the handshake, both sides have derived a shared symmetric key using Diffie-Hellman over Curve25519. All data is then encrypted with **ChaCha20-Poly1305**, an authenticated encryption algorithm. The Poly1305 authentication tag ensures that any tampering is detected and the packet is dropped.

The session key is **rotated every 3 minutes** (or every 2^64 packets), providing forward secrecy: compromising today's key doesn't expose past traffic.

### Peer configuration

tinymesh0 configures WireGuard peers via `wgctrl`, a Go library that talks to the kernel's WireGuard generic netlink interface:

```go
wgtypes.PeerConfig{
    PublicKey:                   peer.PublicKey,
    Endpoint:                    peer.Endpoint,       // where to send UDP packets
    AllowedIPs:                  []net.IPNet{...},    // which IPs to route through this peer
    PersistentKeepaliveInterval: &ka,                 // send keepalive every 25s to maintain NAT mapping
}
```

`AllowedIPs` acts as both a routing rule and a security filter: WireGuard will only send packets to a peer if the destination IP is in their `AllowedIPs` list, and will only accept packets *from* a peer if the source IP is in their `AllowedIPs`. This enforces the identity-to-IP binding described in section 3.

---

## 6. Creating the Interface: Linux Netlink

Linux networking is configured through a kernel subsystem called **netlink** — a socket-based IPC mechanism between userspace and the kernel. When you run `ip link add` or `ip addr add`, the `ip` command is speaking netlink to the kernel under the hood. tinymesh0 does the same directly from Go.

### Step 1: Create the WireGuard interface

```go
// internal/wireguard/manager.go
link := &netlink.GenericLink{
    LinkAttrs: netlink.LinkAttrs{Name: "tinymesh0"},
    LinkType:  "wireguard",
}
netlink.LinkAdd(link)
// equivalent to: ip link add tinymesh0 type wireguard
```

The kernel creates a new network interface backed by the WireGuard driver. At this point it has no IP, no keys, and is administratively down.

### Step 2: Configure WireGuard via generic netlink

WireGuard has its own netlink family (`wireguard`) separate from the standard link netlink. `wgctrl` handles this:

```go
m.client.ConfigureDevice("tinymesh0", wgtypes.Config{
    PrivateKey: &privKey,
    ListenPort: &port,
    Peers:      [...],
})
// equivalent to: wg set tinymesh0 private-key ... listen-port 51820 peer ...
```

### Step 3: Assign the mesh IP

```go
addr := &netlink.Addr{
    IPNet: &net.IPNet{IP: meshIP, Mask: net.CIDRMask(10, 32)},
}
netlink.AddrAdd(link, addr)
// equivalent to: ip addr add 100.75.167.232/10 dev tinymesh0
```

The `/10` prefix mask means the kernel knows the entire `100.64.0.0/10` subnet is reachable through this interface.

### Step 4: Bring the interface up

```go
netlink.LinkSetUp(link)
// equivalent to: ip link set tinymesh0 up
```

### Step 5: Add per-peer routes

```go
netlink.RouteAdd(&netlink.Route{
    LinkIndex: link.Attrs().Index,
    Dst:       &peerAllowedIP,  // e.g. 100.117.163.169/32
})
// equivalent to: ip route add 100.117.163.169/32 dev tinymesh0
```

This tells the kernel: "if you need to reach `100.117.163.169`, send the packet to `tinymesh0`." WireGuard then takes over, looks up which peer owns that IP, and encrypts and forwards the packet.

---

## 7. End-to-End Packet Walk

Let's trace exactly what happens when you run `ping 100.117.163.169` from node-a.

```
node-a                                                    node-b
100.75.167.232                                            100.117.163.169
172.22.0.2 (Docker eth0)                                  172.22.0.3 (Docker eth0)

1. ping generates an ICMP Echo Request:
   ┌────────────────────────────────┐
   │ IP  src=100.75.167.232         │
   │     dst=100.117.163.169        │
   │ ICMP type=8 (echo request)     │
   │     seq=1, data=56 bytes       │
   └────────────────────────────────┘

2. Kernel consults routing table:
   100.117.163.169/32 dev tinymesh0
   → packet is sent to tinymesh0

3. WireGuard intercepts the packet:
   - looks up peer with AllowedIP matching 100.117.163.169
   - finds: pubkey=Nh/Ypd..., endpoint=172.22.0.3:51820
   - checks if a valid session key exists (from recent handshake)
   - if not: initiates handshake first, then proceeds

4. WireGuard encrypts the packet:
   - generates a nonce (8 bytes, monotonically increasing counter)
   - encrypts payload with ChaCha20-Poly1305 using session key
   - appends 16-byte Poly1305 authentication tag

5. WireGuard wraps in UDP:
   ┌──────────────────────────────────────────────┐
   │ IP   src=172.22.0.2  dst=172.22.0.3          │
   │ UDP  src=51820       dst=51820               │
   │ WG   type=data, receiver=<session_id>        │
   │      nonce=<counter>                         │
   │      encrypted ICMP packet + auth tag        │
   └──────────────────────────────────────────────┘

6. Packet travels over Docker bridge network (172.22.0.0/24)
   → arrives at node-b's eth0 (172.22.0.3)

7. node-b's kernel delivers UDP to WireGuard (port 51820)

8. WireGuard on node-b:
   - identifies session from receiver index
   - verifies Poly1305 auth tag (drops packet if invalid)
   - decrypts with ChaCha20-Poly1305
   - verifies source IP (100.75.167.232) is in peer's AllowedIPs
   - injects decrypted packet into tinymesh0

9. Kernel on node-b receives:
   ┌────────────────────────────────┐
   │ IP  src=100.75.167.232         │
   │     dst=100.117.163.169        │
   │ ICMP type=8 (echo request)     │
   └────────────────────────────────┘
   → delivers to local network stack
   → generates ICMP Echo Reply, sends back through tinymesh0
   → same process in reverse
```

The round-trip time you see in ping output is the time for this entire process, twice — including encryption, decryption, and two network hops through the Docker bridge.

---

## 8. The Docker Test Environment

Since both nodes run on the same physical machine for local development, Docker provides isolated network namespaces that simulate two separate machines.

```
Host machine
└── Docker bridge network: tinymesh0_mesh-test (172.22.0.0/24)
    ├── Container: node-a
    │   ├── eth0: 172.22.0.2  (Docker bridge — the "real" network)
    │   └── tinymesh0: 100.75.167.232  (the mesh overlay)
    │
    └── Container: node-b
        ├── eth0: 172.22.0.3  (Docker bridge — the "real" network)
        └── tinymesh0: 100.117.163.169  (the mesh overlay)
```

Each container has its own **network namespace** — a Linux kernel feature that gives it an isolated view of network interfaces, routing tables, and firewall rules. The WireGuard interface created inside node-a's namespace is completely invisible to node-b, and vice versa.

The containers run with `CAP_NET_ADMIN` capability, which grants permission to:
- Create network interfaces (via netlink)
- Configure WireGuard (via generic netlink)
- Add routes and addresses

The WireGuard traffic travels over the Docker bridge (`172.22.0.x`) as ordinary encrypted UDP — the same path it would take over the real internet, just at LAN speed.

STUN still runs, but both containers discover the same public IP (the host's external IP). This is expected and harmless for local testing — in production, each node would be on a different network with a different public IP.
