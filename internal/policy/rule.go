package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// Action is the iptables target applied when a rule matches.
type Action string

const (
	ActionAllow Action = "ACCEPT"
	ActionDeny  Action = "DROP"
)

// Rule is a parsed, executable policy rule.
type Rule struct {
	Action Action
	Src    string // hostname, "*", or mesh IP
	Dst    string // hostname, "*", or mesh IP
	Port   int    // 0 = any port; non-zero matches both TCP and UDP
}

// Parse converts an action and a DSL spec string into a Rule.
// Spec format: "<src> -> <dst> [port <N>]"
// src/dst may be a hostname, a mesh IP (e.g. 100.64.1.1), or "*" for any.
func Parse(action Action, spec string) (Rule, error) {
	parts := strings.SplitN(spec, " -> ", 2)
	if len(parts) != 2 {
		return Rule{}, fmt.Errorf("invalid rule %q: expected \"<src> -> <dst> [port N]\"", spec)
	}
	src := strings.TrimSpace(parts[0])
	rest := strings.TrimSpace(parts[1])

	dst := rest
	port := 0
	if idx := strings.Index(rest, " port "); idx != -1 {
		dst = strings.TrimSpace(rest[:idx])
		portStr := strings.TrimSpace(rest[idx+6:])
		var err error
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Rule{}, fmt.Errorf("invalid port in rule %q", spec)
		}
	}

	if src == "" || dst == "" {
		return Rule{}, fmt.Errorf("empty src or dst in rule %q", spec)
	}

	return Rule{Action: action, Src: src, Dst: dst, Port: port}, nil
}
