package topology

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/jakenoc/tinymesh0/internal/wireguard"
)

//go:embed ui
var uiFS embed.FS

const (
	probeInterval = 10 * time.Second
	statsInterval = 3 * time.Second
)

var pingRTTRe = regexp.MustCompile(`time=(\d+(?:\.\d+)?)\s*ms`)

// NodeInfo describes this node's identity, set once at daemon startup.
type NodeInfo struct {
	Hostname  string `json:"hostname"`
	MeshIP    string `json:"mesh_ip"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
}

// PeerInfo is a peer's state as returned by /api/topology.
type PeerInfo struct {
	Hostname      string  `json:"hostname"`
	MeshIP        string  `json:"mesh_ip"`
	Endpoint      string  `json:"endpoint"`
	LastHandshake string  `json:"last_handshake"`
	RxBytes       int64   `json:"rx_bytes"`
	TxBytes       int64   `json:"tx_bytes"`
	LatencyMs     float64 `json:"latency_ms"`
	Connected     bool    `json:"connected"`
}

// TopologyResponse is the shape of /api/topology and the SSE topology event.
type TopologyResponse struct {
	Self  NodeInfo   `json:"self"`
	Peers []PeerInfo `json:"peers"`
}

type peerState struct {
	hostname string
	meshIP   string
	endpoint string
}

// Server is the HTTP server: REST topology endpoint, SSE stream, and
// embedded D3 UI. It also runs background ICMP latency probes.
type Server struct {
	self  NodeInfo
	wgMgr *wireguard.Manager

	mu      sync.RWMutex
	peers   map[string]*peerState // hostname → state
	latency map[string]float64    // hostname → last probe RTT (ms)

	subsMu sync.Mutex
	subs   map[chan []byte]struct{}

	httpSrv *http.Server
}

// New creates a Server for the given local node.
func New(self NodeInfo, wgMgr *wireguard.Manager) *Server {
	return &Server{
		self:    self,
		wgMgr:   wgMgr,
		peers:   make(map[string]*peerState),
		latency: make(map[string]float64),
		subs:    make(map[chan []byte]struct{}),
	}
}

// AddPeer registers a peer from a gossip join event and pushes a topology update.
func (s *Server) AddPeer(hostname, meshIP, endpoint string) {
	s.mu.Lock()
	s.peers[hostname] = &peerState{hostname: hostname, meshIP: meshIP, endpoint: endpoint}
	s.mu.Unlock()
	s.broadcastTopology()
}

// RemovePeer drops a peer on gossip leave and pushes a topology update.
func (s *Server) RemovePeer(hostname string) {
	s.mu.Lock()
	delete(s.peers, hostname)
	delete(s.latency, hostname)
	s.mu.Unlock()
	s.broadcastTopology()
}

// Start binds the HTTP server to addr, begins serving, and starts the latency
// probe loop. Returns a stop function. Fails immediately if the port is in use.
func (s *Server) Start(addr string) (stop func(), err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("topology http bind: %w", err)
	}

	ui, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return nil, fmt.Errorf("topology ui embed: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(ui)))
	mux.HandleFunc("/api/topology", s.handleTopology)
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/metrics", s.handleMetrics)

	s.httpSrv = &http.Server{Handler: mux}
	go func() { _ = s.httpSrv.Serve(ln) }()

	ctx, cancel := context.WithCancel(context.Background())
	go s.probeLoop(ctx)
	go s.statsLoop(ctx)

	return func() {
		cancel()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutCancel()
		_ = s.httpSrv.Shutdown(shutCtx)
	}, nil
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(s.buildTopology())
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Send current state immediately so the UI renders without waiting.
	s.writeSSEEvent(w, s.buildTopology())
	flusher.Flush()

	ch := make(chan []byte, 8)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
	}()

	for {
		select {
		case msg := <-ch:
			_, _ = w.Write(msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) broadcastTopology() {
	topo := s.buildTopology()
	data, _ := json.Marshal(topo)
	msg := fmt.Appendf(nil, "event: topology\ndata: %s\n\n", data)

	s.subsMu.Lock()
	for ch := range s.subs {
		select {
		case ch <- msg:
		default: // drop if subscriber is slow
		}
	}
	s.subsMu.Unlock()
}

func (s *Server) writeSSEEvent(w http.ResponseWriter, topo TopologyResponse) {
	data, _ := json.Marshal(topo)
	_, _ = fmt.Fprintf(w, "event: topology\ndata: %s\n\n", data)
}

// buildTopology merges gossip peer state with live WireGuard stats.
func (s *Server) buildTopology() TopologyResponse {
	// Index WireGuard peer stats by mesh IP (each peer's AllowedIPs is a /32).
	wgIndex := map[string]wgtypes.Peer{}
	if dev, err := s.wgMgr.Status(); err == nil {
		for _, p := range dev.Peers {
			for _, ip := range p.AllowedIPs {
				wgIndex[ip.IP.String()] = p
			}
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := TopologyResponse{Self: s.self}
	for hostname, p := range s.peers {
		pi := PeerInfo{
			Hostname:  p.hostname,
			MeshIP:    p.meshIP,
			Endpoint:  p.endpoint,
			LatencyMs: s.latency[hostname],
		}
		if wgp, ok := wgIndex[p.meshIP]; ok {
			if !wgp.LastHandshakeTime.IsZero() {
				pi.LastHandshake = wgp.LastHandshakeTime.Format(time.RFC3339)
				// WireGuard renegotiates every ~3 min; 5 min covers the window.
				pi.Connected = time.Since(wgp.LastHandshakeTime) < 5*time.Minute
			}
			pi.RxBytes = wgp.ReceiveBytes
			pi.TxBytes = wgp.TransmitBytes
		}
		resp.Peers = append(resp.Peers, pi)
	}

	sort.Slice(resp.Peers, func(i, j int) bool {
		return resp.Peers[i].Hostname < resp.Peers[j].Hostname
	})
	return resp
}

// probeLoop sends a single ICMP ping to every known peer every probeInterval
// and updates the latency map. If ping is not in PATH the loop is a no-op.
func (s *Server) probeLoop(ctx context.Context) {
	if _, err := exec.LookPath("ping"); err != nil {
		log.Printf("topology: ping not found — latency probes disabled")
		return
	}

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.probePeers()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) probePeers() {
	s.mu.RLock()
	targets := make([]*peerState, 0, len(s.peers))
	for _, p := range s.peers {
		targets = append(targets, p)
	}
	s.mu.RUnlock()

	type result struct {
		hostname string
		ms       float64
	}
	results := make(chan result, len(targets))

	for _, p := range targets {
		go func(peer *peerState) {
			ms, err := pingRTT(peer.meshIP)
			if err != nil {
				results <- result{peer.hostname, 0}
				return
			}
			results <- result{peer.hostname, ms}
		}(p)
	}

	s.mu.Lock()
	for range targets {
		r := <-results
		s.latency[r.hostname] = r.ms
	}
	s.mu.Unlock()

	s.broadcastTopology()
}

func pingRTT(ip string) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip).Output()
	if err != nil {
		return 0, err
	}
	m := pingRTTRe.FindSubmatch(out)
	if len(m) < 2 {
		return 0, fmt.Errorf("no RTT in ping output")
	}
	return strconv.ParseFloat(string(m[1]), 64)
}

// statsLoop broadcasts the current topology on a short interval so connected
// UI clients see WireGuard byte counters update without waiting for a peer event.
func (s *Server) statsLoop(ctx context.Context) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.broadcastTopology()
		case <-ctx.Done():
			return
		}
	}
}

// handleMetrics serves Prometheus text-format metrics for the local node and
// all known peers. No external library — hand-rolled exposition format.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	topo := s.buildTopology()

	line := func(f string, args ...any) { _, _ = fmt.Fprintf(w, f+"\n", args...) }

	line("# HELP tinymesh0_info Node identity labels.")
	line("# TYPE tinymesh0_info gauge")
	line("tinymesh0_info{hostname=%q,mesh_ip=%q,public_key=%q} 1",
		topo.Self.Hostname, topo.Self.MeshIP, topo.Self.PublicKey)

	line("")
	line("# HELP tinymesh0_peers_total Number of known gossip peers.")
	line("# TYPE tinymesh0_peers_total gauge")
	line("tinymesh0_peers_total %d", len(topo.Peers))

	if len(topo.Peers) == 0 {
		return
	}

	line("")
	line("# HELP tinymesh0_peer_connected 1 if WireGuard handshake is current (< 5 min).")
	line("# TYPE tinymesh0_peer_connected gauge")
	for _, p := range topo.Peers {
		v := 0
		if p.Connected {
			v = 1
		}
		line("tinymesh0_peer_connected{hostname=%q,mesh_ip=%q} %d", p.Hostname, p.MeshIP, v)
	}

	line("")
	line("# HELP tinymesh0_peer_handshake_age_seconds Seconds since last WireGuard handshake.")
	line("# TYPE tinymesh0_peer_handshake_age_seconds gauge")
	for _, p := range topo.Peers {
		if p.LastHandshake == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, p.LastHandshake)
		if err != nil {
			continue
		}
		line("tinymesh0_peer_handshake_age_seconds{hostname=%q,mesh_ip=%q} %.1f",
			p.Hostname, p.MeshIP, time.Since(t).Seconds())
	}

	line("")
	line("# HELP tinymesh0_peer_received_bytes_total Bytes received from peer since daemon start.")
	line("# TYPE tinymesh0_peer_received_bytes_total counter")
	for _, p := range topo.Peers {
		line("tinymesh0_peer_received_bytes_total{hostname=%q,mesh_ip=%q} %d", p.Hostname, p.MeshIP, p.RxBytes)
	}

	line("")
	line("# HELP tinymesh0_peer_transmitted_bytes_total Bytes transmitted to peer since daemon start.")
	line("# TYPE tinymesh0_peer_transmitted_bytes_total counter")
	for _, p := range topo.Peers {
		line("tinymesh0_peer_transmitted_bytes_total{hostname=%q,mesh_ip=%q} %d", p.Hostname, p.MeshIP, p.TxBytes)
	}

	hasLatency := false
	for _, p := range topo.Peers {
		if p.LatencyMs <= 0 {
			continue
		}
		if !hasLatency {
			line("")
			line("# HELP tinymesh0_peer_latency_milliseconds Latest ICMP round-trip time to peer in milliseconds.")
			line("# TYPE tinymesh0_peer_latency_milliseconds gauge")
			hasLatency = true
		}
		line("tinymesh0_peer_latency_milliseconds{hostname=%q,mesh_ip=%q} %.2f", p.Hostname, p.MeshIP, p.LatencyMs)
	}
}
