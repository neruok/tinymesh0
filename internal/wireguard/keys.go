package wireguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LoadOrGenerateKey loads the private key from path, creating and persisting a
// new one if path does not exist. Pass an empty path to generate an ephemeral key.
func LoadOrGenerateKey(path string) (wgtypes.Key, error) {
	if path == "" {
		return wgtypes.GeneratePrivateKey()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return wgtypes.Key{}, fmt.Errorf("reading key file: %w", err)
		}
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("generating key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return wgtypes.Key{}, fmt.Errorf("creating key directory: %w", err)
		}
		if err := os.WriteFile(path, []byte(key.String()+"\n"), 0600); err != nil {
			return wgtypes.Key{}, fmt.Errorf("persisting key: %w", err)
		}
		return key, nil
	}

	return wgtypes.ParseKey(strings.TrimSpace(string(data)))
}
