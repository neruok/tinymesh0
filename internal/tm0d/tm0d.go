package tm0d

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jakenoc/tinymesh0/internal/config"
	"github.com/jakenoc/tinymesh0/internal/gossip"
	"github.com/jakenoc/tinymesh0/internal/ipam"
	"github.com/jakenoc/tinymesh0/internal/policy"
	"github.com/jakenoc/tinymesh0/internal/stun"
	"github.com/jakenoc/tinymesh0/internal/wireguard"
)

const (
	PidFile              = "/var/run/tinymesh0d.pid"
	policyReloadInterval = 5 * time.Second
)

// Daemon owns the tinymesh0 subsystem lifecycle. Subsystems are started inside
// run() and do not need to be fields — the struct holds only what is needed
// across method calls.
type Daemon struct {
	cfgFile string
}

func NewDaemon(cfgFile string) *Daemon {
	return &Daemon{cfgFile: cfgFile}
}

// run starts all subsystems in order and blocks until SIGINT or SIGTERM.
func (d *Daemon) Run() error {
	cfg, err := config.Load(d.cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	privKey, err := wireguard.LoadOrGenerateKey(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("loading key: %w", err)
	}
	pubKey := privKey.PublicKey()
	meshIP := ipam.DeriveIP(pubKey)

	fmt.Printf("public key : %s\n", pubKey)
	fmt.Printf("mesh IP    : %s\n", meshIP)

	publicEndpoint := d.resolveEndpoint(cfg)

	wgMgr, err := wireguard.NewManager()
	if err != nil {
		return fmt.Errorf("creating WireGuard manager: %w", err)
	}
	defer wgMgr.Close() //nolint:errcheck // best-effort cleanup in defer

	if err = wgMgr.Up(wireguard.Config{
		PrivateKey: privKey,
		ListenPort: cfg.ListenPort,
		MeshIP:     meshIP,
	}); err != nil {
		return fmt.Errorf("bringing up interface: %w", err)
	}
	fmt.Println("tinymesh0 is up")

	policyEngine, err := d.startPolicyEngine(cfg, meshIP)
	if err != nil {
		return err
	}
	if policyEngine != nil {
		defer policyEngine.Down() //nolint:errcheck // best-effort cleanup in defer
		stopReloader := d.startPolicyReloader(policyEngine)
		defer stopReloader()
	}

	gossipMgr, err := gossip.NewManager(
		gossip.Config{
			NodeName:       cfg.Hostname,
			BindPort:       cfg.Gossip.BindPort,
			BootstrapPeers: cfg.Gossip.BootstrapPeers,
			RetryJoin:      cfg.Gossip.RetryJoin,
		},
		gossip.NodeState{
			PublicKey: pubKey.String(),
			MeshIP:    meshIP.String(),
			Hostname:  cfg.Hostname,
			Endpoint:  publicEndpoint,
			Policies:  cfg.Policy.Rules,
		},
		&wgSyncer{mgr: wgMgr, policy: policyEngine},
	)
	if err != nil {
		return fmt.Errorf("starting gossip: %w", err)
	}
	fmt.Printf("gossip listening on :%d\n", cfg.Gossip.BindPort)
	if len(cfg.Gossip.BootstrapPeers) > 0 {
		fmt.Printf("joined cluster via %v\n", cfg.Gossip.BootstrapPeers)
	} else {
		fmt.Println("no bootstrap peers — waiting for others to join")
	}

	if err = writePID(); err != nil {
		fmt.Printf("warning: could not write PID file: %v\n", err)
	}
	defer os.Remove(PidFile) //nolint:errcheck // best-effort cleanup in defer

	d.waitForShutdown(cfg, policyEngine)

	fmt.Println("\nshutting down...")
	_ = gossipMgr.Shutdown()
	return wgMgr.Down()
}

// resolveEndpoint returns the endpoint to advertise to peers via gossip.
// The config's advertise-endpoint takes priority; STUN discovery is the fallback.
func (d *Daemon) resolveEndpoint(cfg *config.Config) string {
	if cfg.AdvertiseEndpoint != "" {
		fmt.Printf("advertise endpoint: %s (from config)\n", cfg.AdvertiseEndpoint)
		return cfg.AdvertiseEndpoint
	}
	fmt.Println("discovering public endpoint via STUN...")
	result, err := stun.Discover(cfg.STUNServers)
	if err != nil {
		fmt.Printf("STUN failed (%v) — peers will connect without a pre-known endpoint\n", err)
		return ""
	}
	endpoint := fmt.Sprintf("%s:%d", result.IP, cfg.ListenPort)
	fmt.Printf("public endpoint: %s\n", endpoint)
	return endpoint
}

// startPolicyEngine initialises and brings up the iptables policy engine when
// the config contains rules or a default-deny. Returns nil without error when
// no policy is configured, leaving all mesh traffic unrestricted.
func (d *Daemon) startPolicyEngine(cfg *config.Config, meshIP net.IP) (*policy.Engine, error) {
	if len(cfg.Policy.Rules) == 0 && !strings.EqualFold(cfg.Policy.Default, "deny") {
		return nil, nil
	}
	engine, err := policy.New(cfg.Policy, cfg.Hostname, meshIP)
	if err != nil {
		return nil, fmt.Errorf("initializing policy engine: %w", err)
	}
	if err = engine.Up(); err != nil {
		return nil, fmt.Errorf("applying policy: %w", err)
	}
	fmt.Printf("policy engine active (%d rules, default=%s)\n",
		len(cfg.Policy.Rules), policyDefaultLabel(cfg.Policy.Default))
	return engine, nil
}

// startPolicyReloader reloads the policy from disk every policyReloadInterval.
// Returns a stop function that terminates the goroutine.
func (d *Daemon) startPolicyReloader(engine *policy.Engine) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(policyReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				newCfg, err := config.Load(d.cfgFile)
				if err != nil {
					fmt.Printf("policy auto-reload: reading config: %v\n", err)
					continue
				}
				if err = engine.Reload(newCfg.Policy); err != nil {
					fmt.Printf("policy auto-reload failed: %v\n", err)
				}
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

// waitForShutdown blocks until SIGINT or SIGTERM, handling SIGHUP as an
// immediate policy reload in between.
func (d *Daemon) waitForShutdown(cfg *config.Config, engine *policy.Engine) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		s := <-sig
		if s != syscall.SIGHUP {
			break
		}
		if engine == nil {
			fmt.Println("policy reload: no policy engine active")
			continue
		}
		newCfg, err := config.Load(d.cfgFile)
		if err != nil {
			fmt.Printf("policy reload: reading config: %v\n", err)
			continue
		}
		if err = engine.Reload(newCfg.Policy); err != nil {
			fmt.Printf("policy reload failed: %v\n", err)
		} else {
			fmt.Println("policy reloaded")
		}
	}
}

func writePID() error {
	return os.WriteFile(PidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
}

func policyDefaultLabel(s string) string {
	if strings.EqualFold(s, "deny") {
		return "deny"
	}
	return "allow"
}

// wgSyncer adapts wireguard.Manager (and optionally policy.Engine) to the
// gossip.PeerSyncer interface.
type wgSyncer struct {
	mgr    *wireguard.Manager
	policy *policy.Engine // nil when no policy is configured
}

func (s *wgSyncer) SyncPeer(pubKey wgtypes.Key, meshIP net.IP, endpoint *net.UDPAddr, hostname string) error {
	if err := s.mgr.AddPeer(wireguard.PeerConfig{
		PublicKey: pubKey,
		AllowedIP: net.IPNet{IP: meshIP, Mask: net.CIDRMask(32, 32)},
		Endpoint:  endpoint,
	}); err != nil {
		return err
	}
	if s.policy != nil {
		if err := s.policy.AddPeer(hostname, meshIP); err != nil {
			fmt.Printf("policy: failed to add peer %s: %v\n", hostname, err)
		}
	}
	return nil
}

func (s *wgSyncer) RemovePeer(pubKey wgtypes.Key, hostname string) error {
	if s.policy != nil {
		if err := s.policy.RemovePeer(hostname); err != nil {
			fmt.Printf("policy: failed to remove peer %s: %v\n", hostname, err)
		}
	}
	return s.mgr.RemovePeer(pubKey)
}
