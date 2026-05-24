package wireguard

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	ifName            = "tinymesh0"
	persistentKeepalive = 25 * time.Second
)

// PeerConfig describes a single WireGuard peer.
type PeerConfig struct {
	PublicKey wgtypes.Key
	Endpoint  *net.UDPAddr // nil if endpoint is not yet known
	AllowedIP net.IPNet    // the peer's /32 mesh IP
}

// Config is the full set of parameters needed to bring up the interface.
type Config struct {
	PrivateKey wgtypes.Key
	ListenPort int
	MeshIP     net.IP
	Peers      []PeerConfig
}

// Manager owns the WireGuard interface lifecycle.
type Manager struct {
	client  *wgctrl.Client
	peerIPs map[wgtypes.Key]net.IPNet // tracks AllowedIP per peer for route cleanup
	mu      sync.Mutex
}

func NewManager() (*Manager, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("opening wgctrl: %w", err)
	}
	return &Manager{client: c, peerIPs: make(map[wgtypes.Key]net.IPNet)}, nil
}

func (m *Manager) Close() error {
	return m.client.Close()
}

// Up creates the WireGuard interface, assigns the mesh IP, configures all
// peers, and brings the link up.
func (m *Manager) Up(cfg Config) error {
	if err := m.ensureInterface(); err != nil {
		return err
	}
	if err := m.configureWireGuard(cfg); err != nil {
		return err
	}
	if err := m.assignMeshIP(cfg.MeshIP); err != nil {
		return err
	}
	if err := m.bringUp(); err != nil {
		return err
	}
	for _, peer := range cfg.Peers {
		if err := m.addRoute(peer.AllowedIP); err != nil {
			return fmt.Errorf("adding route for %s: %w", peer.PublicKey, err)
		}
	}
	return nil
}

// Down removes the WireGuard interface and all associated routes.
func (m *Manager) Down() error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		var nfe netlink.LinkNotFoundError
		if errors.As(err, &nfe) {
			return nil
		}
		return fmt.Errorf("looking up interface: %w", err)
	}
	return netlink.LinkDel(link)
}

// AddPeer adds or updates a single peer on the running interface.
func (m *Manager) AddPeer(peer PeerConfig) error {
	ka := persistentKeepalive
	wgPeer := wgtypes.PeerConfig{
		PublicKey:                   peer.PublicKey,
		Endpoint:                    peer.Endpoint,
		AllowedIPs:                  []net.IPNet{peer.AllowedIP},
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: &ka,
	}
	if err := m.client.ConfigureDevice(ifName, wgtypes.Config{Peers: []wgtypes.PeerConfig{wgPeer}}); err != nil {
		return fmt.Errorf("configuring peer: %w", err)
	}
	m.mu.Lock()
	m.peerIPs[peer.PublicKey] = peer.AllowedIP
	m.mu.Unlock()
	return m.addRoute(peer.AllowedIP)
}

// RemovePeer tears down the WireGuard peer and its associated route.
func (m *Manager) RemovePeer(pubKey wgtypes.Key) error {
	m.mu.Lock()
	allowedIP, ok := m.peerIPs[pubKey]
	delete(m.peerIPs, pubKey)
	m.mu.Unlock()

	wgCfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pubKey, Remove: true}},
	}
	if err := m.client.ConfigureDevice(ifName, wgCfg); err != nil {
		return fmt.Errorf("removing WireGuard peer: %w", err)
	}

	if ok {
		if err := m.removeRoute(allowedIP); err != nil {
			return fmt.Errorf("removing route: %w", err)
		}
	}
	return nil
}

// Status returns the current WireGuard device state.
func (m *Manager) Status() (*wgtypes.Device, error) {
	return m.client.Device(ifName)
}

func (m *Manager) ensureInterface() error {
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: ifName},
		LinkType:  "wireguard",
	}
	err := netlink.LinkAdd(link)
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("creating interface %s: %w", ifName, err)
	}
	return nil
}

func (m *Manager) configureWireGuard(cfg Config) error {
	port := cfg.ListenPort
	wgCfg := wgtypes.Config{
		PrivateKey:   &cfg.PrivateKey,
		ListenPort:   &port,
		ReplacePeers: true,
	}

	ka := persistentKeepalive
	for _, peer := range cfg.Peers {
		wgCfg.Peers = append(wgCfg.Peers, wgtypes.PeerConfig{
			PublicKey:                   peer.PublicKey,
			Endpoint:                    peer.Endpoint,
			AllowedIPs:                  []net.IPNet{peer.AllowedIP},
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &ka,
		})
	}

	if err := m.client.ConfigureDevice(ifName, wgCfg); err != nil {
		return fmt.Errorf("configuring WireGuard device: %w", err)
	}
	return nil
}

func (m *Manager) assignMeshIP(ip net.IP) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("looking up interface: %w", err)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(10, 32),
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("assigning mesh IP: %w", err)
	}
	return nil
}

func (m *Manager) bringUp() error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("looking up interface: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing interface up: %w", err)
	}
	return nil
}

func (m *Manager) addRoute(dst net.IPNet) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("looking up interface: %w", err)
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &dst,
	}
	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

func (m *Manager) removeRoute(dst net.IPNet) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("looking up interface: %w", err)
	}
	return netlink.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &dst,
	})
}
