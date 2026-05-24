package ipam

import (
	"crypto/sha256"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MeshSubnet is the CGNAT range (RFC 6598) used for all mesh node addresses.
const MeshSubnet = "100.64.0.0/10"

// DeriveIP deterministically maps a WireGuard public key to an IP in the mesh
// subnet by hashing the key and mapping 22 bits into the 100.64.0.0/10 space.
func DeriveIP(pubKey wgtypes.Key) net.IP {
	hash := sha256.Sum256(pubKey[:])
	ip := make(net.IP, 4)
	ip[0] = 100
	ip[1] = 64 + (hash[0] & 0x3F) // 6 free bits → 64–127
	ip[2] = hash[1]
	ip[3] = hash[2]
	// Avoid network/broadcast addresses at each /24 boundary.
	if ip[3] == 0 {
		ip[3] = 1
	}
	if ip[3] == 255 {
		ip[3] = 254
	}
	return ip
}
