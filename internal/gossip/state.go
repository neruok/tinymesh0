package gossip

import (
	"encoding/json"

	"github.com/jakenoc/tinymesh0/internal/config"
)

// NodeState is the metadata each node broadcasts about itself via gossip.
// It carries everything a peer needs to configure a WireGuard tunnel back to us.
type NodeState struct {
	PublicKey string              `json:"public_key"` // base64 WireGuard public key
	MeshIP    string              `json:"mesh_ip"`    // derived IP in 100.64.0.0/10
	Hostname  string              `json:"hostname"`
	Endpoint  string              `json:"endpoint"`           // STUN-discovered public IP:WireGuard-port
	Policies  []config.PolicyRule `json:"policies,omitempty"` // this node's declared policy rules
}

func encodeState(ns NodeState) ([]byte, error) {
	return json.Marshal(ns)
}

func decodeState(data []byte) (NodeState, error) {
	var ns NodeState
	return ns, json.Unmarshal(data, &ns)
}
