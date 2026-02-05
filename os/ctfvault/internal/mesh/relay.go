package mesh

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

type relayServer struct {
	mu      sync.Mutex
	waiting map[string]net.Conn
}

func RunRelay(ctx context.Context, listen string) error {
	if listen == "" {
		listen = ":18080"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	srv := &relayServer{waiting: make(map[string]net.Conn)}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go srv.handle(conn)
	}
}

func (s *relayServer) handle(conn net.Conn) {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	hdr, err := readHeader(conn)
	if err != nil {
		return
	}

	switch hdr.Op {
	case "relay":
		if hdr.Token == "" {
			return
		}
		s.pair(conn, hdr.Token)
		conn = nil
		return
	case "relay_chain":
		s.forward(conn, hdr)
		conn = nil
		return
	default:
		return
	}
}

func (s *relayServer) pair(conn net.Conn, token string) {
	s.mu.Lock()
	other, ok := s.waiting[token]
	if ok {
		delete(s.waiting, token)
	} else {
		s.waiting[token] = conn
	}
	s.mu.Unlock()

	if !ok {
		return
	}

	go pipeConn(conn, other)
	go pipeConn(other, conn)
}

func (s *relayServer) forward(conn net.Conn, hdr Header) {
	if hdr.Target == "" {
		return
	}
	next := ""
	rest := ""
	if hdr.Route != "" {
		parts := splitRoute(hdr.Route)
		if len(parts) > 0 {
			next = parts[0]
			rest = strings.Join(parts[1:], ",")
		}
	}

	target := hdr.Target
	if next != "" {
		target = next
	}

	out, err := net.Dial("tcp", target)
	if err != nil {
		return
	}

	if next != "" {
		outHdr := Header{
			Version: 1,
			Op:      "relay_chain",
			Route:   rest,
			Target:  hdr.Target,
			Token:   hdr.Token,
		}
		if err := writeHeader(out, outHdr); err != nil {
			_ = out.Close()
			return
		}
	}

	go pipeConn(conn, out)
	go pipeConn(out, conn)
}

func splitRoute(route string) []string {
	parts := strings.FieldsFunc(route, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func pipeConn(dst net.Conn, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}

var ErrRelayToken = errors.New("relay token is required")
