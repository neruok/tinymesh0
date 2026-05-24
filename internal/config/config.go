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

type Config struct {
	Hostname          string       `yaml:"hostname"`
	ListenPort        int          `yaml:"listen-port"`
	KeyFile           string       `yaml:"key-file"`
	STUNServers       []string     `yaml:"stun-servers"`
	AdvertiseEndpoint string       `yaml:"advertise-endpoint"` // overrides STUN when set
	Gossip            GossipConfig `yaml:"gossip"`
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
	}
}
