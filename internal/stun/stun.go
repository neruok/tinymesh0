package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	magicCookie       uint32 = 0x2112A442
	msgTypeBindReq    uint16 = 0x0001
	msgTypeBindResp   uint16 = 0x0101
	attrXORMappedAddr uint16 = 0x0020
	attrMappedAddr    uint16 = 0x0001

	dialTimeout = 5 * time.Second
	readTimeout = 5 * time.Second
)

// Result holds the public IP and port discovered via STUN.
type Result struct {
	IP   net.IP
	Port int
}

func (r *Result) String() string {
	return fmt.Sprintf("%s:%d", r.IP, r.Port)
}

// Discover queries each STUN server in order and returns the first success.
func Discover(servers []string) (*Result, error) {
	var lastErr error
	for _, srv := range servers {
		r, err := query(srv)
		if err == nil {
			return r, nil
		}
		lastErr = fmt.Errorf("%s: %w", srv, err)
	}
	return nil, fmt.Errorf("all STUN servers failed: %w", lastErr)
}

// query sends a single Binding Request to server and parses the response.
func query(server string) (*Result, error) {
	conn, err := net.DialTimeout("udp", server, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close() //nolint:errcheck // best-effort cleanup in defer

	var txID [12]byte
	if _, err = rand.Read(txID[:]); err != nil {
		return nil, fmt.Errorf("generating transaction ID: %w", err)
	}

	req := buildBindingRequest(txID)

	if err = conn.SetDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, err
	}
	if _, err = conn.Write(req); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return parseResponse(buf[:n], txID)
}

// buildBindingRequest constructs a 20-byte STUN Binding Request.
//
// RFC 5389 §6:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|0 0|     STUN Message Type     |         Message Length        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Magic Cookie                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                     Transaction ID (96 bits)                   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func buildBindingRequest(txID [12]byte) []byte {
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], msgTypeBindReq)
	binary.BigEndian.PutUint16(msg[2:4], 0) // no attributes → length 0
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], txID[:])
	return msg
}

func parseResponse(data []byte, txID [12]byte) (*Result, error) {
	if len(data) < 20 {
		return nil, errors.New("response too short")
	}
	if binary.BigEndian.Uint16(data[0:2]) != msgTypeBindResp {
		return nil, errors.New("not a Binding Response")
	}
	for i, b := range txID {
		if data[8+i] != b {
			return nil, errors.New("transaction ID mismatch")
		}
	}

	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	if 20+msgLen > len(data) {
		return nil, errors.New("message length exceeds buffer")
	}

	return parseAttributes(data[20 : 20+msgLen])
}

func parseAttributes(attrs []byte) (*Result, error) {
	offset := 0
	for offset+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(attrs[offset+2 : offset+4]))
		offset += 4

		if offset+attrLen > len(attrs) {
			return nil, errors.New("attribute length exceeds buffer")
		}

		if attrType == attrXORMappedAddr {
			return decodeXORMappedAddr(attrs[offset : offset+attrLen])
		}

		// Attributes are padded to 4-byte boundaries.
		offset += attrLen
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}
	return nil, errors.New("XOR-MAPPED-ADDRESS attribute not found in response")
}

// decodeXORMappedAddr decodes the XOR-MAPPED-ADDRESS attribute value.
//
// RFC 5389 §15.2:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|x x x x x x x x|    Family     |         X-Port                |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                X-Address (Variable)                            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func decodeXORMappedAddr(data []byte) (*Result, error) {
	if len(data) < 8 {
		return nil, errors.New("XOR-MAPPED-ADDRESS value too short")
	}

	family := data[1]
	xPort := binary.BigEndian.Uint16(data[2:4])
	port := int(xPort ^ uint16(magicCookie>>16))

	switch family {
	case 0x01: // IPv4
		xAddr := binary.BigEndian.Uint32(data[4:8])
		addr := xAddr ^ magicCookie
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, addr)
		return &Result{IP: ip, Port: port}, nil
	case 0x02: // IPv6 — 16-byte XOR with magic cookie + transaction ID
		if len(data) < 20 {
			return nil, errors.New("XOR-MAPPED-ADDRESS IPv6 value too short")
		}
		ip := make(net.IP, 16)
		copy(ip, data[4:20])
		// XOR first 4 bytes with magic cookie, remaining 12 with transaction ID.
		// We don't have the txID here, so return an error for now.
		return nil, errors.New("IPv6 XOR-MAPPED-ADDRESS not yet supported")
	default:
		return nil, fmt.Errorf("unknown address family: 0x%02x", family)
	}
}
