package gossip

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/memberlist"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerSyncer is the interface the gossip manager uses to keep WireGuard in sync.
// Implemented in main by a thin adapter over wireguard.Manager.
type PeerSyncer interface {
	SyncPeer(pubKey wgtypes.Key, meshIP net.IP, endpoint *net.UDPAddr, hostname string) error
	RemovePeer(pubKey wgtypes.Key, hostname string) error
}

// Config holds gossip subsystem parameters.
type Config struct {
	NodeName       string
	SecretKey      []byte
	BindAddr       string // Empty keeps memberlist's default bind address.
	BindPort       int
	BootstrapPeers []string
	RetryJoin      int
}

// Manager owns the memberlist lifecycle and triggers WireGuard sync on membership events.
type Manager struct {
	list     *memberlist.Memberlist
	self     NodeState
	nodeName string // stored separately: memberlist fires NotifyJoin during Create(), before m.list is set
	syncer   PeerSyncer
}

func NewManager(cfg Config, self NodeState, syncer PeerSyncer) (*Manager, error) {
	if len(cfg.SecretKey) != 32 {
		return nil, fmt.Errorf("a 32-byte shared gossip key is required")
	}
	m := &Manager{self: self, nodeName: cfg.NodeName, syncer: syncer}

	mlCfg := memberlist.DefaultLANConfig()
	mlCfg.Name = cfg.NodeName
	mlCfg.SecretKey = cfg.SecretKey
	mlCfg.GossipVerifyIncoming = true
	mlCfg.GossipVerifyOutgoing = true
	if cfg.BindAddr != "" {
		mlCfg.BindAddr = cfg.BindAddr
	}
	mlCfg.BindPort = cfg.BindPort
	mlCfg.AdvertisePort = cfg.BindPort
	mlCfg.Delegate = m
	mlCfg.Events = m
	mlCfg.Logger = log.New(io.Discard, "", 0)

	list, err := memberlist.Create(mlCfg)
	if err != nil {
		return nil, fmt.Errorf("creating memberlist: %w", err)
	}
	m.list = list

	if len(cfg.BootstrapPeers) > 0 {
		if err := m.joinWithRetry(cfg.BootstrapPeers, cfg.RetryJoin); err != nil {
			_ = list.Shutdown()
			return nil, err
		}
	}

	return m, nil
}

func (m *Manager) Shutdown() error {
	if err := m.list.Leave(5 * time.Second); err != nil {
		return err
	}
	return m.list.Shutdown()
}

func (m *Manager) joinWithRetry(peers []string, maxRetries int) error {
	for attempt := 1; ; attempt++ {
		_, err := m.list.Join(peers)
		if err == nil {
			return nil
		}
		if attempt > maxRetries {
			return fmt.Errorf("joining gossip cluster after %d attempts: %w", attempt, err)
		}
		delay := time.Duration(attempt) * time.Second
		log.Printf("gossip: join attempt %d failed (%v), retrying in %s", attempt, err, delay)
		time.Sleep(delay)
	}
}

// --- memberlist.Delegate ---

// NodeMeta serialises our NodeState into the memberlist metadata slot.
// memberlist gossips this to all other nodes automatically.
func (m *Manager) NodeMeta(limit int) []byte {
	data, err := encodeState(m.self)
	if err != nil || len(data) > limit {
		return nil
	}
	return data
}

func (m *Manager) NotifyMsg([]byte)                           {}
func (m *Manager) GetBroadcasts(overhead, limit int) [][]byte { return nil }
func (m *Manager) LocalState(join bool) []byte                { return nil }
func (m *Manager) MergeRemoteState(buf []byte, join bool)     {}

// --- memberlist.EventDelegate ---

func (m *Manager) NotifyJoin(node *memberlist.Node) {
	if node.Name == m.nodeName {
		return
	}
	ns, err := decodeState(node.Meta)
	if err != nil || ns.PublicKey == "" {
		return
	}
	if err := m.syncPeer(ns); err != nil {
		log.Printf("gossip: syncing peer %s: %v", ns.Hostname, err)
		return
	}
	log.Printf("gossip: peer joined — %s  mesh=%s  endpoint=%s", ns.Hostname, ns.MeshIP, ns.Endpoint)
}

func (m *Manager) NotifyLeave(node *memberlist.Node) {
	if node.Name == m.nodeName {
		return
	}
	ns, err := decodeState(node.Meta)
	if err != nil || ns.PublicKey == "" {
		return
	}
	pubKey, err := wgtypes.ParseKey(ns.PublicKey)
	if err != nil {
		return
	}
	if err := m.syncer.RemovePeer(pubKey, ns.Hostname); err != nil {
		log.Printf("gossip: removing peer %s: %v", ns.Hostname, err)
		return
	}
	log.Printf("gossip: peer left — %s", ns.Hostname)
}

// NotifyUpdate fires when a node's metadata changes (e.g. endpoint rotates after STUN refresh).
func (m *Manager) NotifyUpdate(node *memberlist.Node) {
	m.NotifyJoin(node)
}

func (m *Manager) syncPeer(ns NodeState) error {
	pubKey, err := wgtypes.ParseKey(ns.PublicKey)
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}
	meshIP := net.ParseIP(ns.MeshIP)
	if meshIP == nil {
		return fmt.Errorf("invalid mesh IP %q", ns.MeshIP)
	}

	var endpoint *net.UDPAddr
	if ns.Endpoint != "" {
		if addr, err := net.ResolveUDPAddr("udp", ns.Endpoint); err == nil {
			endpoint = addr
		}
	}

	return m.syncer.SyncPeer(pubKey, meshIP, endpoint, ns.Hostname)
}
