package mesh

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"
)

const discoveryMagic = "gargoyle-discovery-v1"

func DiscoverPeers(ctx context.Context, port int, key string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if port <= 0 {
		port = 19998
	}
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	payload, err := buildDiscoveryPayload(key, "")
	if err != nil {
		return nil, err
	}
	bcast := &net.UDPAddr{IP: net.IPv4bcast, Port: port}
	if _, err := conn.WriteTo(payload, bcast); err != nil {
		return nil, err
	}

	peers := map[string]struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		listen, ok := parseDiscoveryPayload(buf[:n], key)
		if !ok {
			continue
		}
		host := addr.String()
		if listen != "" {
			host = strings.TrimSpace(listen)
		}
		peers[host] = struct{}{}
	}
	out := make([]string, 0, len(peers))
	for p := range peers {
		out = append(out, p)
	}
	return out, nil
}

func Advertise(ctx context.Context, port int, key string, listen string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if port <= 0 {
		port = 19998
	}
	addr := net.UDPAddr{IP: net.IPv4zero, Port: port}
	conn, err := net.ListenUDP("udp4", &addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		_, ok := parseDiscoveryPayload(buf[:n], key)
		if !ok {
			continue
		}
		reply, err := buildDiscoveryPayload(key, listen)
		if err != nil {
			continue
		}
		_, _ = conn.WriteToUDP(reply, remote)
	}
}

func buildDiscoveryPayload(key, listen string) ([]byte, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	nonceHex := hex.EncodeToString(nonce)
	base := discoveryMagic + "|" + nonceHex + "|" + listen
	if key == "" {
		return []byte(base), nil
	}
	sum := hmacSHA256(key, base)
	return []byte(base + "|" + sum), nil
}

func parseDiscoveryPayload(data []byte, key string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(string(data)), "|")
	if len(parts) < 2 {
		return "", false
	}
	if parts[0] != discoveryMagic {
		return "", false
	}
	listen := ""
	if len(parts) >= 3 {
		listen = parts[2]
	}
	if key == "" {
		return listen, true
	}
	if len(parts) < 4 {
		return "", false
	}
	base := strings.Join(parts[:3], "|")
	expected := hmacSHA256(key, base)
	if !hmac.Equal([]byte(expected), []byte(parts[3])) {
		return "", false
	}
	return listen, true
}

func hmacSHA256(key, payload string) string {
	h := hmac.New(sha256.New, []byte(key))
	_, _ = h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

var ErrDiscoveryDisabled = errors.New("mesh discovery disabled")
