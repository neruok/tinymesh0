package gossip

import (
	"bytes"
	"io"
	"log"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type recordingSyncer struct {
	calls chan string
}

func (s *recordingSyncer) SyncPeer(_ wgtypes.Key, _ net.IP, _ *net.UDPAddr, hostname string) error {
	select {
	case s.calls <- hostname:
	default:
	}
	return nil
}

func (*recordingSyncer) RemovePeer(_ wgtypes.Key, _ string) error { return nil }

func testState(name string) NodeState {
	var key wgtypes.Key
	key[0] = 1
	return NodeState{Hostname: name, PublicKey: key.String(), MeshIP: "100.64.0.2", Endpoint: "127.0.0.1:51820"}
}

func rawNode(t *testing.T, name string, key []byte) *memberlist.Memberlist {
	t.Helper()
	cfg := memberlist.DefaultLocalConfig()
	cfg.Name = name
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = 0
	cfg.AdvertisePort = 0
	cfg.TCPTimeout = 500 * time.Millisecond
	cfg.SecretKey = key
	cfg.Logger = log.New(io.Discard, "", 0)
	cfg.Delegate = &Manager{self: testState(name)}
	node, err := memberlist.Create(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Shutdown() })
	return node
}

func nodeAddress(node *memberlist.Node) string {
	return net.JoinHostPort(node.Addr.String(), strconv.Itoa(int(node.Port)))
}

func TestNewManagerRequiresSharedKey(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33} {
		if _, err := NewManager(Config{SecretKey: make([]byte, size)}, NodeState{}, nil); err == nil {
			t.Fatalf("accepted key length %d", size)
		}
	}
}

func TestEnrollmentAuthenticatesBeforePeerSync(t *testing.T) {
	shared := bytes.Repeat([]byte{0x42}, 32)
	for _, test := range []struct {
		name     string
		key      []byte
		accepted bool
	}{
		{"matching-key", shared, true},
		{"wrong-key", bytes.Repeat([]byte{0x24}, 32), false},
		{"plaintext-upstream-node", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			syncer := &recordingSyncer{calls: make(chan string, 8)}
			seed, err := NewManager(Config{NodeName: "seed", BindAddr: "127.0.0.1", BindPort: 0, SecretKey: shared}, testState("seed"), syncer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = seed.list.Shutdown() })
			candidate := rawNode(t, "candidate", test.key)
			_, err = candidate.Join([]string{nodeAddress(seed.list.LocalNode())})
			if test.accepted {
				if err != nil {
					t.Fatal(err)
				}
				select {
				case name := <-syncer.calls:
					if name != "candidate" {
						t.Fatalf("unexpected peer %q", name)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("authenticated peer was not passed to the WireGuard/DNS sync boundary")
				}
			} else {
				if err == nil {
					t.Fatal("unauthenticated join succeeded")
				}
				select {
				case <-syncer.calls:
					t.Fatal("unauthenticated peer reached the WireGuard/DNS sync boundary")
				case <-time.After(150 * time.Millisecond):
				}
				if seed.list.NumMembers() != 1 {
					t.Fatal("unauthenticated peer entered membership")
				}
			}
		})
	}
}

func TestEncryptedManagerRejectsPlaintextBootstrap(t *testing.T) {
	plaintext := rawNode(t, "plaintext-seed", nil)
	syncer := &recordingSyncer{calls: make(chan string, 8)}
	_, err := NewManager(Config{
		NodeName: "candidate", BindAddr: "127.0.0.1", BindPort: 0,
		SecretKey:      bytes.Repeat([]byte{0x42}, 32),
		BootstrapPeers: []string{nodeAddress(plaintext.LocalNode())}, RetryJoin: 0,
	}, testState("candidate"), syncer)
	if err == nil {
		t.Fatal("encrypted manager joined plaintext bootstrap")
	}
	select {
	case <-syncer.calls:
		t.Fatal("plaintext bootstrap reached peer sync")
	default:
	}
}
