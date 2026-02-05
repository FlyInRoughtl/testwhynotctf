package mail

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type SinkServer struct {
	Listen  string
	DataDir string

	mu       sync.Mutex
	listener net.Listener
	running  bool
}

func (s *SinkServer) Start() (func() error, error) {
	if s.Listen == "" {
		s.Listen = "127.0.0.1:1025"
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listener = ln
	s.running = true
	s.mu.Unlock()

	go s.acceptLoop()
	return func() error { return s.Stop() }, nil
}

func (s *SinkServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.listener == nil {
		return nil
	}
	s.running = false
	return s.listener.Close()
}

func (s *SinkServer) Status() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.Listen
}

func (s *SinkServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *SinkServer) handleConn(conn net.Conn) {
	defer conn.Close()
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	_, _ = w.WriteString("220 Gargoyle SMTP sink\r\n")
	_ = w.Flush()

	var from string
	var rcpt []string
	const maxSMTPBytes = 10 << 20

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "HELO") || strings.HasPrefix(cmd, "EHLO"):
			_, _ = w.WriteString("250-Hello\r\n250 SIZE 10485760\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			from = strings.TrimSpace(line[10:])
			_, _ = w.WriteString("250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			addr := strings.TrimSpace(line[8:])
			rcpt = append(rcpt, cleanAddr(addr))
			_, _ = w.WriteString("250 OK\r\n")
		case cmd == "DATA":
			_, _ = w.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n")
			_ = w.Flush()
			data, tooLarge := readData(r, maxSMTPBytes)
			if tooLarge {
				_, _ = w.WriteString("552 Message size exceeds fixed maximum message size\r\n")
			} else {
				_ = s.storeMessage(from, rcpt, data)
				_, _ = w.WriteString("250 OK\r\n")
			}
			rcpt = nil
		case cmd == "RSET":
			from = ""
			rcpt = nil
			_, _ = w.WriteString("250 OK\r\n")
		case cmd == "NOOP":
			_, _ = w.WriteString("250 OK\r\n")
		case cmd == "QUIT":
			_, _ = w.WriteString("221 Bye\r\n")
			_ = w.Flush()
			return
		default:
			_, _ = w.WriteString("250 OK\r\n")
		}
		_ = w.Flush()
	}
}

func readData(r *bufio.Reader, limit int64) (string, bool) {
	var b strings.Builder
	var size int64
	tooLarge := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(line) == "." {
			break
		}
		if !tooLarge {
			size += int64(len(line))
			if size > limit {
				tooLarge = true
			} else {
				b.WriteString(line)
			}
		}
	}
	return b.String(), tooLarge
}

func cleanAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	return addr
}

func (s *SinkServer) storeMessage(from string, rcpt []string, data string) error {
	if s.DataDir == "" {
		s.DataDir = "."
	}
	ts := time.Now().UTC().Format("20060102-150405.000000000")
	for _, addr := range rcpt {
		if addr == "" {
			addr = "unknown"
		}
		dir := filepath.Join(s.DataDir, "mail", "inbox", addr)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		path := filepath.Join(dir, fmt.Sprintf("%s.eml", ts))
		content := fmt.Sprintf("From: %s\r\nTo: %s\r\n\r\n%s", from, addr, data)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return err
		}
	}
	return nil
}
