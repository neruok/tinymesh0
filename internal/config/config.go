package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type GossipConfig struct {
	BindPort       int      `yaml:"bind-port"`
	BootstrapPeers []string `yaml:"bootstrap-peers"`
	RetryJoin      int      `yaml:"retry-join"`
}

// PolicyRule is a single allow or deny entry in the policy config.
// Exactly one of Allow or Deny should be set.
// Spec format: "<src> -> <dst> [port <N>]"
// src/dst may be a hostname, a mesh IP, or "*" (any).
type PolicyRule struct {
	Allow string `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny  string `yaml:"deny,omitempty"  json:"deny,omitempty"`
}

// PolicyConfig holds the per-node firewall policy applied to the mesh interface.
type PolicyConfig struct {
	// Default is the action taken when no rule matches: "allow" (default) or "deny".
	Default string       `yaml:"default"`
	Rules   []PolicyRule `yaml:"rules"`
}

// DNSConfig controls the mesh DNS server's forwarding behaviour.
type DNSConfig struct {
	// UpstreamServers is an explicit list of host:port resolvers to forward
	// non-.mesh queries to. If empty, servers are read from /etc/resolv.conf
	// at daemon startup; if that also fails, 8.8.8.8:53 is used as a fallback.
	UpstreamServers []string `yaml:"upstream-servers"`
}

// TopologyConfig controls the Phase 5 topology HTTP server.
type TopologyConfig struct {
	// ListenAddr is host:port for the HTTP server. Set to "" to disable.
	ListenAddr string `yaml:"listen-addr"`
}

type Config struct {
	Hostname          string         `yaml:"hostname"`
	ListenPort        int            `yaml:"listen-port"`
	KeyFile           string         `yaml:"key-file"`
	STUNServers       []string       `yaml:"stun-servers"`
	AdvertiseEndpoint string         `yaml:"advertise-endpoint"` // overrides STUN when set
	Gossip            GossipConfig   `yaml:"gossip"`
	Policy            PolicyConfig   `yaml:"policy"`
	DNS               DNSConfig      `yaml:"dns"`
	Topology          TopologyConfig `yaml:"topology"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Default() *Config {
	return &Config{
		ListenPort: 51820,
		STUNServers: []string{
			"stun.l.google.com:19302",
			"stun.cloudflare.com:3478",
		},
		Gossip: GossipConfig{
			BindPort:  7946,
			RetryJoin: 10,
		},
		Topology: TopologyConfig{
			ListenAddr: "0.0.0.0:8080",
		},
	}
}
