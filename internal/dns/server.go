package dns

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	StateFile      = "/var/run/tinymesh0d-dns.json"
	meshZone       = "mesh."
	recordTTL      = 60
	forwardTimeout = 3 * time.Second
	resolvConf     = "/etc/resolv.conf"
)

// PeerEntry is one row in the DNS state file and the output of "dns list".
type PeerEntry struct {
	Hostname string `json:"hostname"`
	MeshIP   string `json:"mesh_ip"`
}

// Server is a lightweight authoritative DNS resolver for the .mesh zone that
// forwards all other queries to upstream resolvers.
//
// Upstreams are resolved at Start() time:
//  1. Explicit list from config (dns.upstream-servers)
//  2. Nameservers read from /etc/resolv.conf
//  3. Fallback: 8.8.8.8:53, 1.1.1.1:53
//
// The intended workflow is: start the daemon (which reads the current
// /etc/resolv.conf), then point /etc/resolv.conf at the mesh DNS. Non-.mesh
// queries will be forwarded to whatever resolver was configured before.
type Server struct {
	mu        sync.RWMutex
	peers     map[string]net.IP // hostname → mesh IP (includes self)
	upstreams []string          // host:port of upstream resolvers
	udp       *mdns.Server
	tcp       *mdns.Server
}

// New creates a Server with the local node pre-populated.
// upstreams is the explicit resolver list from config; pass nil to auto-detect.
func New(selfHostname string, selfIP net.IP, upstreams []string) *Server {
	return &Server{
		peers:     map[string]net.IP{selfHostname: selfIP.To4()},
		upstreams: upstreams,
	}
}

// Upstreams returns the resolved upstream list (populated after Start).
func (s *Server) Upstreams() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.upstreams))
	copy(out, s.upstreams)
	return out
}

// AddPeer registers a peer's hostname → IP mapping and updates the state file.
func (s *Server) AddPeer(hostname string, ip net.IP) {
	s.mu.Lock()
	s.peers[hostname] = ip.To4()
	s.mu.Unlock()
	s.writeState()
}

// RemovePeer drops the hostname mapping and updates the state file.
func (s *Server) RemovePeer(hostname string) {
	s.mu.Lock()
	delete(s.peers, hostname)
	s.mu.Unlock()
	s.writeState()
}

// Start resolves upstreams, binds to listenAddr on UDP and TCP, and begins
// serving. Returns a stop function. Errors only if UDP fails to bind.
func (s *Server) Start(listenAddr string) (stop func(), err error) {
	s.resolveUpstreams()

	mux := mdns.NewServeMux()
	mux.HandleFunc(meshZone, s.handleMesh)
	mux.HandleFunc(".", s.handleForward) // catch-all for non-.mesh queries

	ready := make(chan struct{})
	udpErrCh := make(chan error, 1)

	s.udp = &mdns.Server{
		Addr:              listenAddr,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: func() { close(ready) },
	}
	s.tcp = &mdns.Server{Addr: listenAddr, Net: "tcp", Handler: mux}

	go func() {
		if err := s.udp.ListenAndServe(); err != nil {
			select {
			case udpErrCh <- err:
			default:
			}
		}
	}()
	go func() { _ = s.tcp.ListenAndServe() }()

	select {
	case <-ready:
	case err := <-udpErrCh:
		return nil, fmt.Errorf("dns udp bind: %w", err)
	}

	s.writeState()
	restoreResolvConf := updateResolvConf(listenAddr)

	return func() {
		restoreResolvConf()
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
	}, nil
}

// updateResolvConf replaces /etc/resolv.conf with a single nameserver line
// pointing at the mesh DNS, capturing the original content so it can be
// restored on shutdown. Errors are silently ignored — the server still works,
// queries just need an explicit @server flag.
//
// The upstreams must be resolved before this is called so that non-.mesh
// queries can be forwarded to whatever resolver was previously configured.
func updateResolvConf(listenAddr string) (restore func()) {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return func() {}
	}

	original, err := os.ReadFile(resolvConf)
	if err != nil {
		return func() {}
	}

	if err := os.WriteFile(resolvConf, []byte("nameserver "+host+"\n"), 0644); err != nil {
		return func() {}
	}

	fmt.Printf("mesh dns: set %s nameserver to %s (restoring on shutdown)\n", resolvConf, host)
	return func() {
		_ = os.WriteFile(resolvConf, original, 0644)
	}
}

// resolveUpstreams fills s.upstreams if it is empty:
// first from /etc/resolv.conf, then from hard-coded public fallbacks.
func (s *Server) resolveUpstreams() {
	if len(s.upstreams) > 0 {
		return
	}
	cfg, err := mdns.ClientConfigFromFile(resolvConf)
	if err == nil && len(cfg.Servers) > 0 {
		for _, srv := range cfg.Servers {
			s.upstreams = append(s.upstreams, net.JoinHostPort(srv, cfg.Port))
		}
		return
	}
	s.upstreams = []string{"8.8.8.8:53", "1.1.1.1:53"}
}

// handleMesh answers authoritative A queries for the .mesh zone.
func (s *Server) handleMesh(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]

	// q.Name is always FQDN from miekg/dns, e.g. "node-b.mesh."
	hostname := strings.TrimSuffix(q.Name, "."+meshZone)
	if hostname == q.Name || hostname == "" {
		m.SetRcode(r, mdns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	s.mu.RLock()
	ip, ok := s.peers[hostname]
	s.mu.RUnlock()

	if !ok {
		m.SetRcode(r, mdns.RcodeNameError)
		_ = w.WriteMsg(m)
		return
	}

	// Name exists. Only A records are in the mesh (IPv4 only).
	// Non-A queries get NODATA (NOERROR, empty answer).
	if q.Qtype == mdns.TypeA {
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{
				Name:   q.Name,
				Rrtype: mdns.TypeA,
				Class:  mdns.ClassINET,
				Ttl:    recordTTL,
			},
			A: ip.To4(),
		})
	}
	_ = w.WriteMsg(m)
}

// handleForward proxies any non-.mesh query to the configured upstream
// resolvers, trying each in order. Falls back to SERVFAIL if all fail.
func (s *Server) handleForward(w mdns.ResponseWriter, r *mdns.Msg) {
	s.mu.RLock()
	upstreams := s.upstreams
	s.mu.RUnlock()

	for _, upstream := range upstreams {
		resp, err := exchange(r, upstream)
		if err != nil {
			continue
		}
		_ = w.WriteMsg(resp)
		return
	}

	m := new(mdns.Msg)
	m.SetRcode(r, mdns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

// exchange sends r to upstream over UDP. If the response is truncated it
// retries over TCP. Returns the first successful response or an error.
func exchange(r *mdns.Msg, upstream string) (*mdns.Msg, error) {
	resp, _, err := (&mdns.Client{Net: "udp", Timeout: forwardTimeout}).Exchange(r, upstream)
	if err != nil {
		return nil, err
	}
	if !resp.Truncated {
		return resp, nil
	}
	resp, _, err = (&mdns.Client{Net: "tcp", Timeout: forwardTimeout}).Exchange(r, upstream)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) writeState() {
	s.mu.RLock()
	entries := make([]PeerEntry, 0, len(s.peers))
	for h, ip := range s.peers {
		entries = append(entries, PeerEntry{Hostname: h, MeshIP: ip.String()})
	}
	s.mu.RUnlock()

	sort.Slice(entries, func(i, j int) bool { return entries[i].Hostname < entries[j].Hostname })
	data, _ := json.Marshal(entries)
	_ = os.WriteFile(StateFile, data, 0644)
}
