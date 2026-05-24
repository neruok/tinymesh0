package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jakenoc/tinymesh0/internal/config"
	"github.com/jakenoc/tinymesh0/internal/gossip"
	"github.com/jakenoc/tinymesh0/internal/ipam"
	"github.com/jakenoc/tinymesh0/internal/stun"
	"github.com/jakenoc/tinymesh0/internal/wireguard"
)

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

	root.AddCommand(upCmd, downCmd, statusCmd, keygenCmd)
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
		stunResult, err := stun.Discover(cfg.STUNServers)
		if err != nil {
			fmt.Printf("STUN failed (%v) — peers will connect without a pre-known endpoint\n", err)
		} else {
			publicEndpoint = fmt.Sprintf("%s:%d", stunResult.IP, cfg.ListenPort)
			fmt.Printf("public endpoint: %s\n", publicEndpoint)
		}
	}

	wgMgr, err := wireguard.NewManager()
	if err != nil {
		return fmt.Errorf("creating WireGuard manager: %w", err)
	}
	defer wgMgr.Close()

	wgCfg := wireguard.Config{
		PrivateKey: privKey,
		ListenPort: cfg.ListenPort,
		MeshIP:     meshIP,
	}
	if err := wgMgr.Up(wgCfg); err != nil {
		return fmt.Errorf("bringing up interface: %w", err)
	}
	fmt.Println("tinymesh0 is up")

	// NodeState is what every peer in the cluster will learn about us via gossip.
	self := gossip.NodeState{
		PublicKey: pubKey.String(),
		MeshIP:    meshIP.String(),
		Hostname:  cfg.Hostname,
		Endpoint:  publicEndpoint,
	}

	gossipMgr, err := gossip.NewManager(
		gossip.Config{
			NodeName:       cfg.Hostname,
			BindPort:       cfg.Gossip.BindPort,
			BootstrapPeers: cfg.Gossip.BootstrapPeers,
			RetryJoin:      cfg.Gossip.RetryJoin,
		},
		self,
		&wgSyncer{mgr: wgMgr},
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\nshutting down...")
	_ = gossipMgr.Shutdown()
	return wgMgr.Down()
}

func runDown() error {
	mgr, err := wireguard.NewManager()
	if err != nil {
		return err
	}
	defer mgr.Close()
	if err := mgr.Down(); err != nil {
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
	defer mgr.Close()

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

// wgSyncer adapts wireguard.Manager to the gossip.PeerSyncer interface.
type wgSyncer struct {
	mgr *wireguard.Manager
}

func (s *wgSyncer) SyncPeer(pubKey wgtypes.Key, meshIP net.IP, endpoint *net.UDPAddr) error {
	return s.mgr.AddPeer(wireguard.PeerConfig{
		PublicKey: pubKey,
		AllowedIP: net.IPNet{IP: meshIP, Mask: net.CIDRMask(32, 32)},
		Endpoint:  endpoint,
	})
}

func (s *wgSyncer) RemovePeer(pubKey wgtypes.Key) error {
	return s.mgr.RemovePeer(pubKey)
}
