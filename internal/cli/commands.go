package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/jakenoc/tinymesh0/internal/dns"
	"github.com/jakenoc/tinymesh0/internal/wireguard"
)

func RunDown() error {
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

func RunStatus() error {
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

func RunPolicyList() error {
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

// RunStatusWeb prints the topology UI URL and attempts to open it in the
// default browser. addr should be the host:port the daemon is listening on.
func RunStatusWeb(addr string) error {
	url := "http://" + addr
	fmt.Printf("topology UI: %s\n", url)
	var cmd string
	switch runtime.GOOS {
	case "linux":
		cmd = "xdg-open"
	case "darwin":
		cmd = "open"
	default:
		return nil
	}
	if opener, err := exec.LookPath(cmd); err == nil {
		return exec.Command(opener, url).Start()
	}
	return nil // browser opener not available; URL already printed
}

func RunDNSList() error {
	data, err := os.ReadFile(dns.StateFile)
	if err != nil {
		return fmt.Errorf("reading dns state (is tinymesh0d running?): %w", err)
	}
	var entries []dns.PeerEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parsing dns state: %w", err)
	}
	if len(entries) == 0 {
		fmt.Println("no mesh peers known")
		return nil
	}
	fmt.Printf("%-24s  %s\n", "HOSTNAME", "MESH IP")
	for _, e := range entries {
		fmt.Printf("%-24s  %s\n", e.Hostname+".mesh", e.MeshIP)
	}
	return nil
}

func RunPolicyReload(p string) error {
	data, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("reading PID file (is tinymesh0d running?): %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("invalid PID in %s: %w", p, err)
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
