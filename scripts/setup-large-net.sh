#!/usr/bin/env bash
# setup-large-net.sh — generate keys, configs, and docker-compose.large.yml
# for a six-node tinymesh0 test network with varied policy configurations.
#
# Output (all relative to repo root):
#   keys-large/              one WireGuard private key per node
#   configs-large/           one tinymesh0 YAML config per node
#   docker-compose.large.yml ready to run with "docker compose -f ... up --build"
set -euo pipefail

cd "$(dirname "$0")/.."

NODES=(node-a node-b node-c node-d node-e node-f)

# ── 1. build ──────────────────────────────────────────────────────────────
echo "==> building tinymesh0d..."
go build -o /tmp/tinymesh0d ./cmd/tinymesh0d/

# ── 2. keypairs ───────────────────────────────────────────────────────────
echo "==> generating keypairs..."
mkdir -p keys-large configs-large

for node in "${NODES[@]}"; do
    RAW=$(/tmp/tinymesh0d keygen)
    PRIV=$(echo "$RAW" | awk '/private-key/ {print $2}')
    printf '%s\n' "$PRIV" > "keys-large/${node}.key"
    chmod 600 "keys-large/${node}.key"
    echo "    ${node}: key written"
done

# ── 3. node configs ───────────────────────────────────────────────────────
echo "==> writing configs..."

# node-a — seed node, no policy (fully open)
cat > configs-large/node-a.yaml <<'EOF'
hostname: node-a
listen-port: 51820
key-file: /etc/tinymesh0/private.key
advertise-endpoint: "node-a:51820"
stun-servers:
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478
gossip:
  bind-port: 7946
  retry-join: 10
  bootstrap-peers: []
EOF

# node-b — default allow; blocks two specific application ports
cat > configs-large/node-b.yaml <<'EOF'
hostname: node-b
listen-port: 51820
key-file: /etc/tinymesh0/private.key
advertise-endpoint: "node-b:51820"
stun-servers:
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478
gossip:
  bind-port: 7946
  retry-join: 10
  bootstrap-peers:
    - "node-a:7946"
policy:
  default: allow
  rules:
    - deny: "* -> * port 9999"
    - deny: "* -> * port 2112"
EOF

# node-c — strict allowlist; only web ports pass, everything else dropped
cat > configs-large/node-c.yaml <<'EOF'
hostname: node-c
listen-port: 51820
key-file: /etc/tinymesh0/private.key
advertise-endpoint: "node-c:51820"
stun-servers:
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478
gossip:
  bind-port: 7946
  retry-join: 10
  bootstrap-peers:
    - "node-a:7946"
policy:
  default: deny
  rules:
    - allow: "* -> * port 80"
    - allow: "* -> * port 443"
    - allow: "* -> * port 8080"
EOF

# node-d — database server model; only node-a and node-b may reach port 5432;
#           the topology UI (8080) is open to all for health-checking
cat > configs-large/node-d.yaml <<'EOF'
hostname: node-d
listen-port: 51820
key-file: /etc/tinymesh0/private.key
advertise-endpoint: "node-d:51820"
stun-servers:
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478
gossip:
  bind-port: 7946
  retry-join: 10
  bootstrap-peers:
    - "node-a:7946"
policy:
  default: deny
  rules:
    - allow: "node-a -> * port 5432"
    - allow: "node-b -> * port 5432"
    - allow: "* -> * port 8080"
EOF

# node-e — default allow; blocks node-f from reaching sensitive service ports
cat > configs-large/node-e.yaml <<'EOF'
hostname: node-e
listen-port: 51820
key-file: /etc/tinymesh0/private.key
advertise-endpoint: "node-e:51820"
stun-servers:
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478
gossip:
  bind-port: 7946
  retry-join: 10
  bootstrap-peers:
    - "node-a:7946"
policy:
  default: allow
  rules:
    - deny: "node-f -> * port 22"
    - deny: "node-f -> * port 3306"
EOF

# node-f — quarantined node; default deny, responds only on port 8080
cat > configs-large/node-f.yaml <<'EOF'
hostname: node-f
listen-port: 51820
key-file: /etc/tinymesh0/private.key
advertise-endpoint: "node-f:51820"
stun-servers:
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478
gossip:
  bind-port: 7946
  retry-join: 10
  bootstrap-peers:
    - "node-a:7946"
policy:
  default: deny
  rules:
    - allow: "* -> * port 8080"
EOF

echo "    node-a  no policy (fully open)"
echo "    node-b  default allow  | deny ports 9999, 2112"
echo "    node-c  default deny   | allow ports 80, 443, 8080"
echo "    node-d  default deny   | allow node-a/node-b:5432, *:8080"
echo "    node-e  default allow  | deny node-f:22, node-f:3306"
echo "    node-f  default deny   | allow *:8080 only"

# ── 4. docker-compose.large.yml ───────────────────────────────────────────
echo "==> generating docker-compose.large.yml..."

cat > docker-compose.large.yml <<'EOF'
services:
  node-a:
    build: .
    container_name: node-a-lg
    hostname: node-a
    cap_add: [NET_ADMIN, SYS_MODULE]
    ports:
      - "8080:8080"
    volumes:
      - ./configs-large/node-a.yaml:/etc/tinymesh0/config.yaml:ro
      - ./keys-large/node-a.key:/etc/tinymesh0/private.key:ro
    command: ["up", "-c", "/etc/tinymesh0/config.yaml"]
    networks: [mesh-large]

  node-b:
    build: .
    container_name: node-b-lg
    hostname: node-b
    cap_add: [NET_ADMIN, SYS_MODULE]
    volumes:
      - ./configs-large/node-b.yaml:/etc/tinymesh0/config.yaml:ro
      - ./keys-large/node-b.key:/etc/tinymesh0/private.key:ro
    command: ["up", "-c", "/etc/tinymesh0/config.yaml"]
    networks: [mesh-large]
    depends_on: [node-a]

  node-c:
    build: .
    container_name: node-c-lg
    hostname: node-c
    cap_add: [NET_ADMIN, SYS_MODULE]
    volumes:
      - ./configs-large/node-c.yaml:/etc/tinymesh0/config.yaml:ro
      - ./keys-large/node-c.key:/etc/tinymesh0/private.key:ro
    command: ["up", "-c", "/etc/tinymesh0/config.yaml"]
    networks: [mesh-large]
    depends_on: [node-a]

  node-d:
    build: .
    container_name: node-d-lg
    hostname: node-d
    cap_add: [NET_ADMIN, SYS_MODULE]
    volumes:
      - ./configs-large/node-d.yaml:/etc/tinymesh0/config.yaml:ro
      - ./keys-large/node-d.key:/etc/tinymesh0/private.key:ro
    command: ["up", "-c", "/etc/tinymesh0/config.yaml"]
    networks: [mesh-large]
    depends_on: [node-a]

  node-e:
    build: .
    container_name: node-e-lg
    hostname: node-e
    cap_add: [NET_ADMIN, SYS_MODULE]
    volumes:
      - ./configs-large/node-e.yaml:/etc/tinymesh0/config.yaml:ro
      - ./keys-large/node-e.key:/etc/tinymesh0/private.key:ro
    command: ["up", "-c", "/etc/tinymesh0/config.yaml"]
    networks: [mesh-large]
    depends_on: [node-a]

  node-f:
    build: .
    container_name: node-f-lg
    hostname: node-f
    cap_add: [NET_ADMIN, SYS_MODULE]
    volumes:
      - ./configs-large/node-f.yaml:/etc/tinymesh0/config.yaml:ro
      - ./keys-large/node-f.key:/etc/tinymesh0/private.key:ro
    command: ["up", "-c", "/etc/tinymesh0/config.yaml"]
    networks: [mesh-large]
    depends_on: [node-a]

networks:
  mesh-large:
    driver: bridge
EOF

echo ""
echo "==> done."
echo ""
echo "    launch: docker compose -f docker-compose.large.yml up --build"
echo "       ui : http://localhost:8080  (node-a)"
