# Packet Tracing Exercise: End-to-End Through tinymesh0

This exercise walks a single ICMP ping from **Alice** to **Bob** through the full mesh stack — from key generation through gossip discovery, WireGuard handshake, encryption, transit, decryption, and reply.

Concrete values are used throughout. Follow the arrows and verify each transformation yourself.

---

## The Two Nodes

```
┌──────────────────────────────────┐     ┌──────────────────────────────────┐
│ hostname: alice                  │     │ hostname: bob                    │
│ real IP : 203.0.113.10           │     │ real IP : 198.51.100.20          │
│ WG port : 51820                  │     │ WG port : 51820                  │
│ gossip  : :7946                  │     │ gossip  : :7946                  │
└──────────────────────────────────┘     └──────────────────────────────────┘
```

Both have just started. Neither knows the other's mesh IP or endpoint yet. We will derive everything from scratch.

---

## Part 1 — Key Generation and Mesh IP Derivation

### 1a. Curve25519 Key Pairs

WireGuard uses **Curve25519** — a specific elliptic curve designed for Diffie-Hellman. You pick a random 32-byte private scalar, clamp it (explained below), then multiply by the curve's base point G to get your public key. The base point G is a fixed constant defined in the RFC.

**Why clamping?** Three bit manipulations are applied to the private scalar to prevent implementation-specific timing attacks and to avoid small-subgroup cofactor attacks:
- Clear bits 0–2 of byte 0 (forces scalar divisible by 8 — the curve's cofactor)
- Clear bit 7 of byte 31 (keeps scalar in a safe range)
- Set bit 6 of byte 31 (forces scalar ≥ 2^254 — prevents weak keys near 0)

```
Alice's key pair (base64-encoded):
  private: YHvkX3wQm2...  ← 32 random bytes, clamped
  public:  RzXL5a9Pk8...  ← 32 bytes = priv_scalar × G

Bob's key pair:
  private: tN3rW1mZcQ...
  public:  mBk7sP2Xw4...
```

Each node's public key is its permanent identity in the mesh.

---

### 1b. Mesh IP Derivation — trace through `internal/ipam/ipam.go`

tinymesh0 deterministically assigns each node an IP in `100.64.0.0/10` (CGNAT range, RFC 6598) by hashing the public key. This means no DHCP, no coordinator — every node can independently compute any other node's mesh IP from its public key alone.

```go
// ipam/ipam.go:16-29
func DeriveIP(pubKey wgtypes.Key) net.IP {
    hash := sha256.Sum256(pubKey[:])      // 32-byte hash
    ip := make(net.IP, 4)
    ip[0] = 100
    ip[1] = 64 + (hash[0] & 0x3F)        // mask to 6 bits → values 64–127
    ip[2] = hash[1]
    ip[3] = hash[2]
    // avoid .0 and .255
    ...
}
```

**Trace for Alice's public key `RzXL5a9Pk8...` (32 raw bytes):**

```
Step 1: sha256(alice_pubkey_bytes)
        = [0x01, 0xAB, 0x42, 0xE7, ...]
               └─────┴─────┴── first 3 bytes used

Step 2: ip[0] = 100           (fixed)
        ip[1] = 64 + (0x01 & 0x3F)
              = 64 + 1
              = 65
        ip[2] = 0xAB = 171
        ip[3] = 0x42 = 66     (not 0 or 255 → keep)

Alice mesh IP: 100.65.171.66
```

**Trace for Bob's public key `mBk7sP2Xw4...`:**

```
Step 1: sha256(bob_pubkey_bytes)
        = [0x21, 0x0F, 0x99, 0x3C, ...]

Step 2: ip[0] = 100
        ip[1] = 64 + (0x21 & 0x3F)
              = 64 + 33
              = 97
        ip[2] = 0x0F = 15
        ip[3] = 0x99 = 153    (not 0 or 255 → keep)

Bob mesh IP: 100.97.15.153
```

**The /10 address space** gives us 2^22 = 4,194,304 possible addresses before the .0/.255 exclusions. Hash collisions are possible but statistically very unlikely in a small mesh.

---

## Part 2 — Endpoint Discovery via STUN

Alice's real IP is behind a NAT (her router has `203.0.113.10` externally but she's `192.168.1.5` internally). She needs to know her external IP:port to advertise to Bob.

### 2a. STUN Binding Request (RFC 5389) — trace through `internal/stun/stun.go`

STUN exploits the fact that a NAT router forwards the *reflected* address back in the response. Alice sends a UDP packet to a STUN server; the server sees the packet arriving from `203.0.113.10:54321` (NAT-translated) and puts that address in the response.

```
Alice builds a 20-byte Binding Request:

Offset  Bytes  Value         Field
───────────────────────────────────────────────────
 0–1    2      0x0001        Message Type = Binding Request
 2–3    2      0x0000        Message Length (0 — no attributes)
 4–7    4      0x2112A442    Magic Cookie (fixed constant, RFC 5389)
 8–19   12     <random>      Transaction ID (12 random bytes for matching)

Alice generates txID: [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02,
                       0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
```

**Why the Magic Cookie?** It distinguishes RFC 5389 STUN from the older RFC 3489. Servers can tell which protocol version a client speaks by checking bytes 4–7. It also participates in XOR address encoding (see below).

```
Alice → stun.l.google.com:19302 (UDP):
┌────────────────────────────────────────────────────────┐
│ 00 01 00 00  21 12 A4 42  DE AD BE EF  01 02 03 04 │
│ 05 06 07 08                                          │
└────────────────────────────────────────────────────────┘
```

### 2b. STUN Binding Response with XOR-MAPPED-ADDRESS

The STUN server sees the packet arriving from `203.0.113.10:54321` and encodes that address using XOR with the Magic Cookie. XOR encoding prevents application-layer NAT helpers from rewriting the IP inside the payload.

```
Server encodes Alice's reflected endpoint:
  Real IP:   203.0.113.10  = 0xCB00710A
  XOR with:  0x2112A442    (Magic Cookie)
  X-Address: 0xCB00710A ^ 0x2112A442 = 0xEA12D548

  Real port: 54321         = 0xD431
  XOR with:  0x2112          (high 16 bits of Magic Cookie)
  X-Port:    0xD431 ^ 0x2112 = 0xF523

Response packet (abbreviated):
  Type:     0x0101 (Binding Response)
  Length:   12 (one attribute)
  Cookie:   0x2112A442
  TxID:     DE AD BE EF 01 02 03 04 05 06 07 08  ← must match
  Attr:     XOR-MAPPED-ADDRESS
            Family:    0x01 (IPv4)
            X-Port:    0xF523
            X-Address: 0xEA12D548
```

**Alice decodes** (`internal/stun/stun.go:161-168`):
```
port = 0xF523 ^ 0x2112 = 0xD431 = 54321
addr = 0xEA12D548 ^ 0x2112A442 = 0xCB00710A = 203.0.113.10

Alice's public endpoint: 203.0.113.10:51820
  (tinymesh0 uses ListenPort from config, not the STUN-observed port,
   because the WireGuard socket is the actual listener — STUN just
   confirms the external IP)
```

---

## Part 3 — Peer Discovery via Gossip (SWIM Protocol)

With her endpoint known, Alice needs to find Bob. tinymesh0 uses **memberlist**, which implements the **SWIM** (Scalable Weakly-consistent Infection-style Membership) gossip protocol.

### 3a. What Alice Broadcasts

Alice encodes her `NodeState` struct (`internal/gossip/state.go`) as JSON into her memberlist metadata:

```json
{
  "public_key": "RzXL5a9Pk8...",
  "mesh_ip":    "100.65.171.66",
  "hostname":   "alice",
  "endpoint":   "203.0.113.10:51820"
}
```

This metadata is attached to Alice's member entry. memberlist gossips it to all other nodes automatically — Alice doesn't need to send it explicitly. Every node in the cluster eventually receives every other node's metadata.

### 3b. SWIM Dissemination Model

SWIM uses two mechanisms running concurrently:

```
MECHANISM 1: Piggybacking (infection-style)
─────────────────────────────────────────────
Every SWIM ping/ack packet carries a "gossip payload" — recent
membership events (joins, leaves, metadata updates). Even if you
only send a health-check ping to Bob, you're also infecting Bob
with Alice's NodeState.

MECHANISM 2: Full-state push/pull on join
──────────────────────────────────────────
When Bob joins and contacts alice as a bootstrap peer, they
exchange full membership state. After that, only deltas are
gossiped.

Time → convergence:
  t=0:  Bob joins, contacts Alice
  t=1:  Alice has Bob's state. Bob has Alice's state.
  t=2:  Both have each other's WireGuard config.
        NotifyJoin() fires on each node.
```

### 3c. What Happens When NotifyJoin Fires

```go
// gossip/manager.go:104-117
func (m *Manager) NotifyJoin(node *memberlist.Node) {
    ns, err := decodeState(node.Meta)   // parse NodeState JSON from metadata
    // ...
    m.syncPeer(ns)                       // → calls wgSyncer.SyncPeer()
}
```

`syncPeer` resolves the endpoint and calls `wgSyncer.SyncPeer()` in `main.go`:
```go
// main.go:206-212
func (s *wgSyncer) SyncPeer(pubKey wgtypes.Key, meshIP net.IP, endpoint *net.UDPAddr) error {
    return s.mgr.AddPeer(wireguard.PeerConfig{
        PublicKey: pubKey,
        AllowedIP: net.IPNet{IP: meshIP, Mask: net.CIDRMask(32, 32)},
        Endpoint:  endpoint,
    })
}
```

This calls into `wireguard/manager.go:AddPeer()` which:
1. Calls `wgctrl.ConfigureDevice()` — sends the peer config to the WireGuard kernel module via a **netlink** socket (covered in the next section)
2. Calls `addRoute()` — adds a kernel route: `100.97.15.153/32 via tinymesh0`

After `NotifyJoin` completes on Alice's node:
```
Kernel route table on Alice:
  100.65.171.66/32  dev tinymesh0  (Alice's own address)
  100.97.15.153/32  dev tinymesh0  (Bob — newly added)

WireGuard peer table on Alice:
  peer: mBk7sP2Xw4...   (Bob's public key)
    endpoint:   198.51.100.20:51820
    allowed-ips: 100.97.15.153/32
    keepalive:  25s
```

---

## Part 4 — The WireGuard Handshake (Noise Protocol)

No data can flow until Alice and Bob complete a **cryptographic handshake** that establishes a shared session key. WireGuard uses the **Noise_IKpsk2** handshake from the Noise Protocol Framework.

### 4a. First: What is Diffie-Hellman and Why Does WireGuard Need It?

Diffie-Hellman solves: "Alice and Bob want to share a secret, but they can only communicate over a channel Eve is watching. They have never met."

**Simplified DH with small numbers (to trace the math):**
```
Public parameters (known to everyone):
  prime p = 23
  generator g = 5

Alice picks secret a = 6
Bob   picks secret b = 15

Alice computes:  A = g^a mod p = 5^6  mod 23 = 8   → sends A=8  to Bob
Bob   computes:  B = g^b mod p = 5^15 mod 23 = 19  → sends B=19 to Alice

Alice computes shared secret:  s = B^a mod p = 19^6 mod 23 = 2
Bob   computes shared secret:  s = A^b mod p = 8^15 mod 23 = 2  ✓

Eve sees: p=23, g=5, A=8, B=19 — but cannot compute s without
solving the discrete logarithm problem (hard for large p).
```

**Curve25519 DH** (what WireGuard actually uses) does the same thing but on an elliptic curve instead of integers mod p. Instead of `g^a mod p`, you compute `a × G` where G is a point on the curve and `×` is elliptic curve scalar multiplication:

```
Alice: private_a (32 bytes scalar), public_A = a × G
Bob:   private_b (32 bytes scalar), public_B = b × G

Shared secret = a × public_B = a × (b × G) = ab × G
              = b × public_A = b × (a × G) = ab × G  ✓

Security: recovering a from (G, a×G) requires solving the
          Elliptic Curve Discrete Logarithm Problem (ECDLP) —
          computationally infeasible for Curve25519.
```

### 4b. Why Four DH Operations in Noise_IKpsk2?

A single DH exchange proves "Alice knows her private key, Bob knows his private key." But that only gives you authentication and a static shared secret. WireGuard needs more:

| Goal | DH Operation |
|------|-------------|
| Forward secrecy (compromise today's key, can't decrypt past sessions) | Ephemeral × Responder-static |
| Mutual authentication (each node proves identity) | Initiator-static × Responder-static |
| Freshness / replay protection | Ephemeral × Ephemeral |
| Bind the session to known identities | Initiator-static × Responder-static |

**Forward secrecy** means: even if Alice's long-term private key leaks tomorrow, an attacker who recorded this session's encrypted traffic cannot decrypt it — because the session key also depended on an ephemeral key that was deleted after the handshake.

### 4c. The Handshake Packet Exchange

```
Alice (Initiator)                           Bob (Responder)
─────────────────                           ────────────────

ALICE KNOWS: Bob's static public key mBk7sP2Xw4...
             (learned via gossip — no out-of-band exchange needed)

──────────── Handshake Initiation (msg type 1) ────────────

1. Generate ephemeral keypair:
   Einit_priv = random,   Einit_pub = Einit_priv × G

2. Initialize chaining key and hash:
   ck   = hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
   h    = hash(ck || "WireGuard v1 zx2c4 Jason@zx2c4.com")

3. Mix Bob's static public key into hash:
   h = hash(h || Sresp_pub)       ← binds handshake to Bob's identity

4. Mix Einit_pub into ck and h:
   ck = kdf(ck, Einit_pub)
   h  = hash(h || Einit_pub)

5. DH #1 — ephemeral×static:
   ss1 = dh(Einit_priv, Sresp_pub)   ← Einit_priv × Bob's static pub point
   ck, k = kdf(ck, ss1)              ← new chaining key + encryption key

6. Encrypt Alice's static public key:
   enc_Sinit = AEAD_encrypt(k, nonce=0, Sinit_pub, ad=h)
   h = hash(h || enc_Sinit)          ← mix ciphertext into hash

7. DH #2 — static×static:
   ss2 = dh(Sinit_priv, Sresp_pub)   ← Alice's static priv × Bob's static pub
   ck, k = kdf(ck, ss2)

8. Encrypt timestamp (prevents replay):
   enc_ts = AEAD_encrypt(k, nonce=0, TAI64N_timestamp, ad=h)
   h = hash(h || enc_ts)

9. Compute mac1 = MAC(hash("mac1" || Sresp_pub), msg_so_far)
   (mac1 proves message is addressed to Bob without decrypting)

Alice → Bob UDP packet:
┌────────────────────────────────────────────────────────────────────┐
│ type=1 (4B) │ sender_idx (4B) │ Einit_pub (32B) │ enc_Sinit (48B) │
│ enc_ts (28B) │ mac1 (16B) │ mac2 (16B)                            │
│                                        Total: 148 bytes            │
└────────────────────────────────────────────────────────────────────┘

BOB RECEIVES msg1:
  ▶ Verifies mac1 (can he decrypt it? is it addressed to him?)
  ▶ Derives ss1 = dh(Sresp_priv, Einit_pub)   ← same result as Alice's ss1
    [Bob uses his own static private key and Alice's ephemeral public key]
  ▶ Decrypts enc_Sinit → recovers Alice's static public key Sinit_pub
  ▶ Derives ss2 = dh(Sresp_priv, Sinit_pub)   ← same result as Alice's ss2
  ▶ Decrypts enc_ts → verifies timestamp is fresh (within 3 minutes)
  ▶ Looks up Alice in his peer table by Sinit_pub

──────────── Handshake Response (msg type 2) ────────────

Bob continues from the same ck and h state:

1. Generate ephemeral keypair:
   Eresp_priv = random,   Eresp_pub = Eresp_priv × G

2. Mix Eresp_pub into ck and h:
   ck = kdf(ck, Eresp_pub)
   h  = hash(h || Eresp_pub)

3. DH #3 — ephemeral×ephemeral:
   ss3 = dh(Eresp_priv, Einit_pub)   ← Bob's ephemeral × Alice's ephemeral
   ck = kdf(ck, ss3)

4. DH #4 — ephemeral×static:
   ss4 = dh(Eresp_priv, Sinit_pub)   ← Bob's ephemeral × Alice's static
   ck = kdf(ck, ss4)

5. Mix PSK into ck (if configured; zeroed if not):
   ck, k = kdf(ck, psk)

6. Encrypt empty payload (confirms both parties derived same ck):
   enc_empty = AEAD_encrypt(k, nonce=0, "", ad=h)

Bob → Alice UDP packet:
┌────────────────────────────────────────────────────────────────────┐
│ type=2 (4B) │ sender_idx (4B) │ recv_idx (4B) │ Eresp_pub (32B)  │
│ enc_empty (16B) │ mac1 (16B) │ mac2 (16B)                         │
│                                        Total: 92 bytes             │
└────────────────────────────────────────────────────────────────────┘

──────────── Session Keys Derived (both sides independently) ────────

Both Alice and Bob now have the same chaining key ck.
They derive two symmetric keys from it:

  T_send_alice, T_recv_alice = KDF(ck, "")
  T_send_bob,   T_recv_bob   = KDF(ck, "")

  where: T_send_alice = T_recv_bob   (Alice's outbound = Bob's inbound)
         T_recv_alice = T_send_bob   (Alice's inbound  = Bob's outbound)

Each key is 32 bytes. The cipher is ChaCha20-Poly1305 (AEAD).
Keys are rotated every 180 seconds or 2^64 messages (whichever first).
```

**Why ChaCha20-Poly1305?** Unlike AES-GCM, it's fast even without hardware AES acceleration (important on embedded/ARM). It's also immune to timing side-channels that can afflict AES software implementations.

---

## Part 5 — Data Plane: Alice Pings Bob

The handshake is complete. Alice runs:

```bash
ping 100.97.15.153   # Bob's mesh IP
```

### 5a. The Kernel Routing Decision

```
ping creates ICMP Echo Request:
  src: 100.65.171.66  (Alice's tinymesh0 address)
  dst: 100.97.15.153  (Bob's mesh IP)
  payload: "hello Bob"

Kernel consults routing table:
  100.97.15.153/32 → dev tinymesh0   ← matched!

Packet is handed to the tinymesh0 network interface.
tinymesh0 is a virtual WireGuard interface — it has no real driver.
The kernel passes the raw IP packet to the WireGuard kernel module.
```

### 5b. WireGuard Looks Up the Peer and Encrypts

```
WireGuard module receives raw IP packet, dst=100.97.15.153

Peer lookup (by allowed-ips):
  100.97.15.153 matches peer mBk7sP2Xw4... (Bob)
  ✓ Session keys available (handshake already done)
  ✓ Endpoint: 198.51.100.20:51820

Encrypt with T_send_alice (ChaCha20-Poly1305):

  Before encryption (plaintext IP packet):
  ┌────────────────────────────────────────────────────────────┐
  │ IP hdr (20B) │ ICMP hdr (8B) │ payload (variable)         │
  │ src=100.65.171.66  dst=100.97.15.153  proto=ICMP           │
  └────────────────────────────────────────────────────────────┘

  WireGuard transport message:
  ┌────────────────────────────────────────────────────────────┐
  │ type=4 (4B) │ recv_idx (4B) │ counter (8B)                │
  │ encrypted_packet (len=original+16 for AEAD tag)            │
  └────────────────────────────────────────────────────────────┘

  counter (nonce): starts at 0, increments per packet.
  The AEAD tag (16B) provides both confidentiality AND integrity.
  If even one bit of the ciphertext is flipped, decryption fails.
```

### 5c. The Packet Leaves Alice's Machine

```
WireGuard wraps the encrypted transport message in a UDP packet:

  Outer UDP packet (what Eve on the network sees):
  ┌──────────────────────────────────────────────────────────────┐
  │ Ethernet frame                                               │
  │  └─ IP header:  src=203.0.113.10  dst=198.51.100.20         │
  │      └─ UDP:    src_port=51820   dst_port=51820              │
  │          └─ WireGuard transport msg (opaque ciphertext)      │
  └──────────────────────────────────────────────────────────────┘

Eve sees:
  ✗ Cannot tell this is ICMP
  ✗ Cannot see src/dst mesh IPs
  ✗ Cannot decrypt payload
  ✓ Can see real IPs (203.0.113.10 → 198.51.100.20) and UDP ports
  ✓ Can observe packet timing and size (traffic analysis is possible)
```

### 5d. Bob Receives and Decrypts

```
Bob's kernel receives the UDP packet on port 51820.
WireGuard module takes over:

  1. Parse type=4 (transport message)
  2. Look up session by recv_idx
  3. Check counter against replay window
     (WireGuard maintains a 2048-bit window — each bit = one counter value.
      A packet with a counter already seen in the window is dropped.)
  4. Decrypt with T_recv_bob (= T_send_alice)
  5. Verify AEAD tag — if tampered, drop silently
  6. Verify source IP of decrypted packet is in peer's allowed-ips:
       100.65.171.66 ∈ {100.65.171.66/32} for Alice's peer entry  ✓
       (This is the cryptographic routing — spoofed source IPs are
        impossible because only Alice's key can produce valid ciphertext)

  Decrypted IP packet injected into Bob's tinymesh0 interface:
  ┌────────────────────────────────────────────────────────────┐
  │ IP hdr: src=100.65.171.66  dst=100.97.15.153  proto=ICMP   │
  │ ICMP Echo Request, id=1, seq=1, data="hello Bob"           │
  └────────────────────────────────────────────────────────────┘

Bob's kernel sees dst=100.97.15.153, which is Bob's own tinymesh0 IP.
The packet is delivered to the ping receiver (or whatever is listening).
```

### 5e. The Reply Path (Bob → Alice)

```
Bob's kernel generates ICMP Echo Reply:
  src: 100.97.15.153
  dst: 100.65.171.66

Route lookup: 100.65.171.66/32 → dev tinymesh0 → peer RzXL5a9Pk8... (Alice)
Encrypt with T_send_bob, wrap in UDP, send to 203.0.113.10:51820.

Alice receives, decrypts, verifies allowed-ips, delivers to ping.
```

---

## Part 6 — Full End-to-End Diagram

```
  ALICE (203.0.113.10)                    BOB (198.51.100.20)
  ─────────────────────────────────────────────────────────────

  [1] tinymesh0d starts
       LoadOrGenerateKey()
       → private key from file (or generate new)
       → public key = priv × G
       → mesh IP = DeriveIP(pub)
                                          [1] Same on Bob's side

  [2] STUN discovery
       UDP → stun.l.google.com:19302
       ← XOR-MAPPED-ADDRESS = 203.0.113.10:51820
       publicEndpoint = "203.0.113.10:51820"
                                          [2] Bob discovers 198.51.100.20:51820

  [3] Gossip bootstrap
       Alice starts memberlist, waits
                                          [3] Bob starts, joins Alice
                                              → push/pull membership exchange
       NotifyJoin(bob_node)               NotifyJoin(alice_node)
       ↓ syncPeer(bob)                    ↓ syncPeer(alice)
       ↓ AddPeer(bob_pubkey,              ↓ AddPeer(alice_pubkey,
            100.97.15.153/32,                  100.65.171.66/32,
            198.51.100.20:51820)               203.0.113.10:51820)
       ↓ addRoute(100.97.15.153/32)       ↓ addRoute(100.65.171.66/32)

  [4] First packet triggers WireGuard handshake
       ping 100.97.15.153
       ↓ kernel routes to tinymesh0
       ↓ WireGuard: no session yet → initiate handshake
       ─── Handshake Init (148B) ──────────────────────────────────▶
           Einit_pub, enc(Sinit_pub), enc(timestamp)
                                          ← verify mac1
                                          ← decrypt → recover Sinit_pub
                                          ← derive ss1, ss2
                                          ← generate Eresp, derive ss3, ss4
       ◀─── Handshake Response (92B) ─────────────────────────────
            Eresp_pub, enc(empty)
       ↓ verify response
       ↓ derive session keys T_send, T_recv

  [5] ICMP travels encrypted
       ICMP Echo Req (inner):
         src=100.65.171.66 dst=100.97.15.153
       ↓ AEAD encrypt with T_send_alice, counter=0
       ─── UDP 203.0.113.10:51820 → 198.51.100.20:51820 ─────────▶
           [WireGuard transport, opaque ciphertext]
                                          ← decrypt with T_recv_bob
                                          ← verify allowed-ips
                                          ← deliver to kernel: ICMP Echo Req
                                          ← kernel generates ICMP Echo Reply
                                          ← encrypt with T_send_bob, counter=0
       ◀─── UDP 198.51.100.20:51820 → 203.0.113.10:51820 ─────────
            [WireGuard transport, opaque ciphertext]
       ↓ decrypt with T_recv_alice
       ↓ deliver to ping: Echo Reply received ✓

  [6] Every 25 seconds: keepalive
       ─── WireGuard keepalive (empty transport msg) ────────────▶
       (prevents NAT state from expiring; see persistentKeepalive
        in wireguard/manager.go:93)
```

---

## Exercises to Trace Yourself

**1. IP derivation:**  
Run `tinymesh0d keygen` and note the public key. Then manually compute `sha256(raw_pubkey_bytes)` (use `openssl dgst -sha256 -binary`). Extract bytes 0–2, apply the formula in `ipam.go:19-28`. Verify it matches the mesh IP your node shows at startup.

**2. STUN decode:**  
Run `tcpdump -i any -x udp port 19302` while starting a node. Find the response packet. Manually XOR the X-Address and X-Port fields with the Magic Cookie (`0x2112A442` / `0x2112`) to recover your real endpoint.

**3. Gossip convergence:**  
Start both Docker nodes (`make dev`). In one terminal, watch: `docker exec alice watch -n1 'tinymesh0d status'`. In another: `docker exec bob watch -n1 'tinymesh0d status'`. Bring down Bob — watch the WireGuard peer entry disappear from Alice after memberlist's failure detection timeout (default ~4.8s on LAN config).

**4. Handshake capture:**  
`tcpdump -i any -x udp port 51820 -c 10` right after `make dev`. The first 148-byte UDP burst is the handshake init. The 92-byte reply is the response. All subsequent packets are ~60-80 bytes (ICMP+headers+AEAD tag).

**5. Key math (optional):**  
The `wg` command-line tool (if available in the Docker container) shows live session handshake times. Run `wg show tinymesh0` after startup. The `latest handshake` timestamp resets every 180 seconds — that is WireGuard's automatic session key rotation interval.

---

## What tinymesh0 Does NOT Do (Yet)

| Feature | Status | Why it matters |
|---------|--------|----------------|
| Policy/firewall (iptables) | Phase 3 — in progress | Without it, any node can reach any other node on any port |
| IPv6 STUN / mesh IPs | Not yet (`stun.go:178`) | Only IPv4 mesh supported |
| Group-key authenticated gossip | Required | Peers must possess the shared key; UDP gossip and TCP state exchanges use authenticated encryption |
| Individual certificate pinning | Not present | All holders of the group key are trusted; no individual hostname-ownership or revocation guarantee |
| Session key rotation on schedule | WireGuard built-in | Handled automatically every 180s |
| Multi-path / failover | Not present | Single endpoint per peer; STUN rediscovery happens only on restart |
