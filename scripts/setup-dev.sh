#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> building tinymesh0d..."
go build -o /tmp/tinymesh0d ./cmd/tinymesh0d/

echo "==> generating keypairs..."
RAW_A=$(/tmp/tinymesh0d keygen)
PRIV_A=$(echo "$RAW_A" | awk '/private-key/ {print $2}')

RAW_B=$(/tmp/tinymesh0d keygen)
PRIV_B=$(echo "$RAW_B" | awk '/private-key/ {print $2}')

mkdir -p keys configs

printf '%s\n' "$PRIV_A" > keys/node-a.key
printf '%s\n' "$PRIV_B" > keys/node-b.key
chmod 600 keys/*.key

echo "==> writing configs..."

# node-a is the seed — no bootstrap peers.
# advertise-endpoint uses the Docker hostname so peers resolve to the bridge IP,
# not the shared public IP that STUN would return for both containers.
cat > configs/node-a.yaml <<EOF
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

# node-b bootstraps from node-a's gossip port.
cat > configs/node-b.yaml <<EOF
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
EOF

echo ""
echo "==> done. run: docker compose up --build"
