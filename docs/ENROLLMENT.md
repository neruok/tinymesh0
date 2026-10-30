# Shared-key enrollment

## Trust boundary

Possession of the shared mesh key authorizes a node to join and publish its
WireGuard public key, hostname and endpoint. Every holder is a trusted member.
No coordinator, external identity provider, certificates or central database is
required. Initial key distribution still needs a trusted channel.

The key is a random 32-byte value stored as base64 in the file named by
`gossip.key-file`. This is not a human password, password hash or SNMP USM
credential. memberlist's existing AES-256-GCM supplies both message authentication
and encryption using this one group key. There is no separate custom AuthKey /
PrivKey protocol and no plaintext compatibility mode.

## Startup and operation

The configuration loader checks the key before creating WireGuard keys/interfaces,
performing STUN discovery, starting DNS, or starting the topology UI. The file must
be a regular file inaccessible to group/others; 0600 and 0400 are suitable modes.
Protect the containing directory and ensure only the intended daemon user can
replace the file. Invalid key contents are not included in errors.

The gossip manager independently requires a 32-byte key, even when called without
the YAML loader. It requires encrypted incoming and outgoing traffic for TCP
membership/state exchanges and UDP gossip. Failed bootstrap joins shut down their
gossip listeners. Authenticated membership continues to drive the existing
WireGuard/DNS synchronization path.

Keep the key configured after enrollment: it authenticates later announcements as
well as the initial join. Merely learning a bootstrap hostname does not authorize
membership. Every seed is an ordinary peer.

## Credential loss and rotation

Anyone with the key can enroll, publish claims, or impersonate another member.
This patch does not implement individual hostname ownership, per-node revocation,
an invitation service, or a new replay-protection protocol. Keep service
authentication and firewall boundaries independent of shared membership.

If a key leaks, replace it on all retained nodes and restart the mesh. This patch
does not implement overlapping-key online rotation. Removing a hostname or a
WireGuard peer alone does not revoke a holder of the shared key.

## Compatibility and remaining limits

Unmodified plaintext nodes cannot join the protected mesh, in either direction.
Provision the same key on all intended nodes before switching. This patch adds no
new dependencies and leaves WireGuard packet encryption unchanged.

DNS collision handling, automatic `/etc/resolv.conf` changes, default UI exposure,
NAT traversal, address-allocation collisions and firewall ownership are upstream
behaviors, not fixed by enrollment authentication. Do not deploy this directly on
an existing gateway without reviewing those integration boundaries.

## Verification

```sh
GOTOOLCHAIN=local CGO_ENABLED=0 go test ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go vet ./...
GOTOOLCHAIN=local CGO_ENABLED=0 go build ./cmd/tinymesh0d
```

The enrollment tests create only ephemeral loopback gossip listeners and mock the
WireGuard/DNS sync boundary. They verify successful shared-key enrollment,
wrong-key/plaintext rejection and no unauthenticated peer-sync calls. They do not
run a real WireGuard interface, DNS resolver, firewall, UI, STUN query or deployment.
