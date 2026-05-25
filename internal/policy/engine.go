package policy

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/jakenoc/tinymesh0/internal/config"
)

const chain = "TINYMESH0"

// Engine manages the iptables policy chain for the mesh interface.
// It maintains a hostname→IP peer map so that rules referencing hostnames
// can be resolved to concrete addresses as peers join and leave.
type Engine struct {
	stateMu       sync.RWMutex
	iptMu         sync.Mutex // serialises iptables operations
	rules         []Rule
	defaultAction Action
	peers         map[string]net.IP // hostname → mesh IP
}

// New creates an Engine from a PolicyConfig.
// selfHostname and selfIP are this node's own identity so that rules
// referencing the local hostname resolve correctly.
func New(cfg config.PolicyConfig, selfHostname string, selfIP net.IP) (*Engine, error) {
	e := &Engine{
		peers: map[string]net.IP{selfHostname: selfIP.To4()},
	}
	if err := e.loadRules(cfg); err != nil {
		return nil, err
	}
	return e, nil
}

// loadRules parses cfg into the engine's rule slice. Must be called with
// stateMu held for writing, or before the engine is shared across goroutines.
func (e *Engine) loadRules(cfg config.PolicyConfig) error {
	e.rules = nil
	if strings.EqualFold(cfg.Default, "deny") {
		e.defaultAction = ActionDeny
	} else {
		e.defaultAction = ActionAllow
	}
	for _, pr := range cfg.Rules {
		switch {
		case pr.Allow != "":
			r, err := Parse(ActionAllow, pr.Allow)
			if err != nil {
				return err
			}
			e.rules = append(e.rules, r)
		case pr.Deny != "":
			r, err := Parse(ActionDeny, pr.Deny)
			if err != nil {
				return err
			}
			e.rules = append(e.rules, r)
		}
	}
	return nil
}

// Up creates the TINYMESH0 iptables chain, inserts the INPUT jump rule,
// and applies the current rule set.
func (e *Engine) Up() error {
	if err := ensureChain(); err != nil {
		return fmt.Errorf("creating iptables chain: %w", err)
	}
	if err := ensureJump(); err != nil {
		return fmt.Errorf("installing iptables jump: %w", err)
	}
	return e.Apply()
}

// Down removes the INPUT jump rule and deletes the TINYMESH0 chain.
func (e *Engine) Down() error {
	_ = ipt("-D", "INPUT", "-i", "tinymesh0", "-j", chain)
	_ = ipt("-F", chain)
	_ = ipt("-X", chain)
	return nil
}

// AddPeer registers hostname→ip and re-applies rules so that any rule
// referencing this hostname is now resolved and installed.
func (e *Engine) AddPeer(hostname string, ip net.IP) error {
	e.stateMu.Lock()
	e.peers[hostname] = ip.To4()
	e.stateMu.Unlock()
	return e.Apply()
}

// RemovePeer removes the hostname mapping and re-applies rules.
func (e *Engine) RemovePeer(hostname string) error {
	e.stateMu.Lock()
	delete(e.peers, hostname)
	e.stateMu.Unlock()
	return e.Apply()
}

// Reload replaces the rule set from a new PolicyConfig without restarting,
// then re-applies. Called on SIGHUP.
func (e *Engine) Reload(cfg config.PolicyConfig) error {
	e.stateMu.Lock()
	err := e.loadRules(cfg)
	e.stateMu.Unlock()
	if err != nil {
		return err
	}
	return e.Apply()
}

// Apply flushes the TINYMESH0 chain and reinstalls all rules for the current
// peer set. Rules whose src or dst hostname cannot yet be resolved are skipped
// and will be installed the next time AddPeer is called.
func (e *Engine) Apply() error {
	e.stateMu.RLock()
	rules := make([]Rule, len(e.rules))
	copy(rules, e.rules)
	peers := make(map[string]net.IP, len(e.peers))
	for k, v := range e.peers {
		peers[k] = v
	}
	defaultAction := e.defaultAction
	e.stateMu.RUnlock()

	e.iptMu.Lock()
	defer e.iptMu.Unlock()

	if err := ipt("-F", chain); err != nil {
		return fmt.Errorf("flushing chain: %w", err)
	}

	for _, r := range rules {
		iptArgs, ok := buildIPTRules(r, peers)
		if !ok {
			log.Printf("policy: deferring rule (unresolved hostname): %s→%s", r.Src, r.Dst)
			continue
		}
		for _, args := range iptArgs {
			if err := ipt(append([]string{"-A", chain}, args...)...); err != nil {
				return fmt.Errorf("installing rule: %w", err)
			}
		}
	}

	// Append the default-deny sentinel at the end of the chain.
	// If default is allow, we omit this — unmatched traffic returns to INPUT
	// and is accepted by INPUT's default policy.
	if defaultAction == ActionDeny {
		if err := ipt("-A", chain, "-j", "DROP"); err != nil {
			return fmt.Errorf("installing default deny: %w", err)
		}
	}
	return nil
}

// buildIPTRules converts a Rule into one or two iptables argument slices.
// When a port is specified, two slices are returned: one for TCP, one for UDP.
// Returns (nil, false) if a hostname cannot be resolved in peers.
func buildIPTRules(r Rule, peers map[string]net.IP) ([][]string, bool) {
	var base []string

	if r.Src != "*" {
		ip := resolve(r.Src, peers)
		if ip == nil {
			return nil, false
		}
		base = append(base, "-s", ip.String())
	}
	if r.Dst != "*" {
		ip := resolve(r.Dst, peers)
		if ip == nil {
			return nil, false
		}
		base = append(base, "-d", ip.String())
	}

	target := []string{"-j", string(r.Action)}

	if r.Port == 0 {
		return [][]string{concat(base, target)}, true
	}

	port := fmt.Sprintf("%d", r.Port)
	tcp := concat(base, []string{"-p", "tcp", "--dport", port}, target)
	udp := concat(base, []string{"-p", "udp", "--dport", port}, target)
	return [][]string{tcp, udp}, true
}

func resolve(name string, peers map[string]net.IP) net.IP {
	if ip := net.ParseIP(name); ip != nil {
		return ip.To4()
	}
	return peers[name]
}

func concat(slices ...[]string) []string {
	var n int
	for _, s := range slices {
		n += len(s)
	}
	out := make([]string, 0, n)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

func ensureChain() error {
	if err := ipt("-N", chain); err == nil {
		return nil
	}
	// Chain may already exist — confirm by listing it.
	return ipt("-L", chain, "-n")
}

func ensureJump() error {
	// -C exits 0 if the rule already exists, non-zero otherwise.
	if ipt("-C", "INPUT", "-i", "tinymesh0", "-j", chain) == nil {
		return nil
	}
	return ipt("-I", "INPUT", "1", "-i", "tinymesh0", "-j", chain)
}

func ipt(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
