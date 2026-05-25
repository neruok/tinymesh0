package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jakenoc/tinymesh0/internal/config"
	"github.com/jakenoc/tinymesh0/internal/gossip"
	"github.com/jakenoc/tinymesh0/internal/ipam"
	"github.com/jakenoc/tinymesh0/internal/policy"
	"github.com/jakenoc/tinymesh0/internal/stun"
	"github.com/jakenoc/tinymesh0/internal/wireguard"
)

const pidFile = "/var/run/tinymesh0d.pid"

func main() {
	root := &cobra.Command{
		Use:   "tinymesh0d",
		Short: "tinymesh0 — a decentralized mesh VPN daemon",
	}

	var cfgFile string

	upCmd := &cobra.Command{
		Use:   "up",
		Short: "Bring up the tinymesh0 interface",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUp(cfgFile)
		},
	}
	upCmd.Flags().StringVarP(&cfgFile, "config", "c", "tinymesh0.yaml", "path to config file")

	downCmd := &cobra.Command{
		Use:   "down",
		Short: "Take down the tinymesh0 interface",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDown()
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show tinymesh0 interface status",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runStatus()
		},
	}

	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a WireGuard keypair",
		RunE: func(_ *cobra.Command, _ []string) error {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return err
			}
			fmt.Printf("private-key: %s\n", key)
			fmt.Printf("public-key:  %s\n", key.PublicKey())
			return nil
		},
	}

	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect or reload the mesh policy",
	}

	policyListCmd := &cobra.Command{
		Use:   "list",
		Short: "Show the active iptables policy chain",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runPolicyList()
		},
	}

	policyReloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Signal the running daemon to reload its policy from config",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runPolicyReload()
		},
	}

	policyCmd.AddCommand(policyListCmd, policyReloadCmd)
	root.AddCommand(upCmd, downCmd, statusCmd, keygenCmd, policyCmd)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runUp(cfgFile string) error {
	cfg, err := config.Load(cfgFile)
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

	// Determine the endpoint to advertise to peers via gossip.
	// advertise-endpoint in config takes priority (useful for LAN/Docker/known DNS).
	// Falls back to STUN discovery for the public internet case.
	var publicEndpoint string
	if cfg.AdvertiseEndpoint != "" {
		publicEndpoint = cfg.AdvertiseEndpoint
		fmt.Printf("advertise endpoint: %s (from config)\n", publicEndpoint)
	} else {
		fmt.Println("discovering public endpoint via STUN...")
		if stunResult, stunErr := stun.Discover(cfg.STUNServers); stunErr != nil {
			fmt.Printf("STUN failed (%v) — peers will connect without a pre-known endpoint\n", stunErr)
		} else {
			publicEndpoint = fmt.Sprintf("%s:%d", stunResult.IP, cfg.ListenPort)
			fmt.Printf("public endpoint: %s\n", publicEndpoint)
		}
	}

	wgMgr, err := wireguard.NewManager()
	if err != nil {
		return fmt.Errorf("creating WireGuard manager: %w", err)
	}
	defer wgMgr.Close() //nolint:errcheck // best-effort cleanup in defer

	wgCfg := wireguard.Config{
		PrivateKey: privKey,
		ListenPort: cfg.ListenPort,
		MeshIP:     meshIP,
	}
	if err = wgMgr.Up(wgCfg); err != nil {
		return fmt.Errorf("bringing up interface: %w", err)
	}
	fmt.Println("tinymesh0 is up")

	// Policy engine — only started when rules are configured or default is deny.
	var policyEngine *policy.Engine
	if len(cfg.Policy.Rules) > 0 || strings.EqualFold(cfg.Policy.Default, "deny") {
		policyEngine, err = policy.New(cfg.Policy, cfg.Hostname, meshIP)
		if err != nil {
			return fmt.Errorf("initializing policy engine: %w", err)
		}
		if err = policyEngine.Up(); err != nil {
			return fmt.Errorf("applying policy: %w", err)
		}
		defer policyEngine.Down() //nolint:errcheck // best-effort cleanup in defer
		fmt.Printf("policy engine active (%d rules, default=%s)\n",
			len(cfg.Policy.Rules), defaultAction(cfg.Policy.Default))

		stopReloader := startPolicyReloader(policyEngine, cfgFile)
		defer stopReloader()
	}

	// NodeState is what every peer in the cluster will learn about us via gossip.
	self := gossip.NodeState{
		PublicKey: pubKey.String(),
		MeshIP:    meshIP.String(),
		Hostname:  cfg.Hostname,
		Endpoint:  publicEndpoint,
		Policies:  cfg.Policy.Rules,
	}

	gossipMgr, err := gossip.NewManager(
		gossip.Config{
			NodeName:       cfg.Hostname,
			BindPort:       cfg.Gossip.BindPort,
			BootstrapPeers: cfg.Gossip.BootstrapPeers,
			RetryJoin:      cfg.Gossip.RetryJoin,
		},
		self,
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
	defer os.Remove(pidFile) //nolint:errcheck // best-effort cleanup in defer

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		s := <-sig
		if s == syscall.SIGHUP {
			newCfg, loadErr := config.Load(cfgFile)
			if loadErr != nil {
				fmt.Printf("policy reload: reading config: %v\n", loadErr)
				continue
			}
			if policyEngine != nil {
				if reloadErr := policyEngine.Reload(newCfg.Policy); reloadErr != nil {
					fmt.Printf("policy reload failed: %v\n", reloadErr)
				} else {
					fmt.Println("policy reloaded")
				}
			} else {
				fmt.Println("policy reload: no policy engine active (no rules in original config)")
			}
			continue
		}
		break
	}

	fmt.Println("\nshutting down...")
	_ = gossipMgr.Shutdown()
	return wgMgr.Down()
}

func runDown() error {
	mgr, err := wireguard.NewManager()
	if err != nil {
		return err
	}
	defer mgr.Close() //nolint:errcheck // best-effort cleanup in defer
	if err = mgr.Down(); err != nil {
		return err
	}
	fmt.Println("tinymesh0 down")
	return nil
}

func runStatus() error {
	mgr, err := wireguard.NewManager()
	if err != nil {
		return err
	}
	defer mgr.Close() //nolint:errcheck // best-effort cleanup in defer

	dev, err := mgr.Status()
	if err != nil {
		return err
	}

	fmt.Printf("interface  : %s\n", dev.Name)
	fmt.Printf("public key : %s\n", dev.PublicKey)
	fmt.Printf("listen port: %d\n", dev.ListenPort)
	fmt.Printf("peers      : %d\n\n", len(dev.Peers))

	for _, p := range dev.Peers {
		fmt.Printf("peer: %s\n", p.PublicKey)
		if p.Endpoint != nil {
			fmt.Printf("  endpoint       : %s\n", p.Endpoint)
		}
		fmt.Printf("  last handshake : %s\n", p.LastHandshakeTime)
		fmt.Printf("  transfer       : ↑ %d B  ↓ %d B\n", p.TransmitBytes, p.ReceiveBytes)
	}
	return nil
}

func runPolicyList() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found — run this command on the Linux node (e.g. docker exec node-b tinymesh0d policy list)")
	}
	out, err := exec.Command("iptables", "-L", "TINYMESH0", "-n", "--line-numbers").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reading policy chain — is tinymesh0d running with a policy configured?\n%s", strings.TrimSpace(string(out)))
	}
	fmt.Print(string(out))
	return nil
}

func runPolicyReload() error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("reading PID file (is tinymesh0d running?): %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid PID in %s: %w", pidFile, err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}
	if err = proc.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signalling daemon: %w", err)
	}
	fmt.Printf("sent SIGHUP to tinymesh0d (pid %d)\n", pid)
	return nil
}

// startPolicyReloader reloads the policy from cfgFile every 5 seconds in the
// background. Call the returned stop function to terminate the goroutine.
func startPolicyReloader(engine *policy.Engine, cfgFile string) (stop func()) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				newCfg, err := config.Load(cfgFile)
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

func writePID() error {
	return os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
}

func defaultAction(s string) string {
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
			// Non-fatal: WireGuard peer is up; log and continue.
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
