package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadGossipKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	encoded := base64.StdEncoding.EncodeToString(key)
	for _, test := range []struct {
		name  string
		data  string
		mode  os.FileMode
		valid bool
	}{
		{"valid", encoded + "\n", 0600, true},
		{"read-only", encoded, 0400, true},
		{"empty", "", 0600, false},
		{"malformed", "not-a-base64-key", 0600, false},
		{"short", base64.StdEncoding.EncodeToString(key[:16]), 0600, false},
		{"world-readable", encoded, 0644, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "gossip-key")
			if err := os.WriteFile(keyPath, []byte(test.data), test.mode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "node.yaml")
			body := fmt.Sprintf("hostname: node-a\ngossip:\n  key-file: %q\n", keyPath)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(cfg.Gossip.SecretKey, key) {
					t.Fatal("loaded key differs")
				}
			} else {
				if err == nil {
					t.Fatal("invalid/insecure key accepted")
				}
				if test.data != "" && strings.Contains(err.Error(), strings.TrimSpace(test.data)) {
					t.Fatal("error exposes key contents")
				}
			}
		})
	}
}

func TestLoadMissingGossipKeyFile(t *testing.T) {
	if _, err := loadGossipKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing key file accepted")
	}
	if _, err := loadGossipKey(t.TempDir()); err == nil {
		t.Fatal("directory accepted as key file")
	}
}

func TestLoadRequiresGossipKeyBeforeStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(path, []byte("hostname: node-a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("configuration without a gossip key must be rejected")
	}
}
