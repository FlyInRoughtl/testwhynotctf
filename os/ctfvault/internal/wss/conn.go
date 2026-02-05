package wss

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	opText   = 1
	opBinary = 2
	opClose  = 8
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type Conn struct {
	conn     net.Conn
	br       *bufio.Reader
	isClient bool
	rbuf     []byte
	closed   bool
}

func Dial(rawURL string) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Host
	if host == "" {
		return nil, errors.New("missing host")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	var conn net.Conn
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	switch scheme {
	case "wss":
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
		conn = tlsConn
	case "ws":
		c, err := dialer.Dial("tcp", host)
		if err != nil {
			return nil, err
		}
		conn = c
	default:
		return nil, errors.New("unsupported scheme")
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		conn.Close()
		return nil, err
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host, keyB64)
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(status, "101") {
		conn.Close()
		return nil, errors.New("websocket upgrade failed: " + strings.TrimSpace(status))
	}
	headers := http.Header{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	accept := headers.Get("Sec-WebSocket-Accept")
	expected := computeAccept(keyB64)
	if accept != expected {
		conn.Close()
		return nil, errors.New("websocket accept mismatch")
	}
	return &Conn{conn: conn, br: br, isClient: true}, nil
}

func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("missing upgrade header")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing websocket key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijacking not supported")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := computeAccept(key)
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	if _, err := bufrw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &Conn{conn: conn, br: bufio.NewReader(conn), isClient: false}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	op, payload, err := readFrame(c.br, c.isClient)
	if err != nil {
		return 0, err
	}
	if op == opClose {
		_ = c.Close()
		return 0, io.EOF
	}
	if len(payload) == 0 {
		return 0, nil
	}
	n := copy(p, payload)
	if n < len(payload) {
		c.rbuf = append(c.rbuf, payload[n:]...)
	}
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 16*1024 {
			chunk = p[:16*1024]
		}
		if err := writeFrame(c.conn, opBinary, chunk, c.isClient); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *Conn) ReadMessage() ([]byte, error) {
	if c.closed {
		return nil, io.EOF
	}
	op, payload, err := readFrame(c.br, c.isClient)
	if err != nil {
		return nil, err
	}
	if op == opClose {
		_ = c.Close()
		return nil, io.EOF
	}
	return payload, nil
}

func (c *Conn) WriteMessageText(payload []byte) error {
	if c.closed {
		return io.EOF
	}
	return writeFrame(c.conn, opText, payload, c.isClient)
}

func (c *Conn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	_ = writeFrame(c.conn, opClose, []byte{}, c.isClient)
	return c.conn.Close()
}

func computeAccept(key string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func readFrame(r *bufio.Reader, isClient bool) (byte, []byte, error) {
	b1, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	fin := (b1 & 0x80) != 0
	opcode := b1 & 0x0f
	if !fin {
		return 0, nil, errors.New("fragmented frames not supported")
	}
	mask := (b2 & 0x80) != 0
	length := int(b2 & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int(ext[7]) | int(ext[6])<<8 | int(ext[5])<<16 | int(ext[4])<<24
	}
	var maskKey [4]byte
	if mask {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if mask {
		for i := 0; i < len(payload); i++ {
			payload[i] ^= maskKey[i%4]
		}
	}
	if isClient && mask {
		return 0, nil, errors.New("server frames must not be masked")
	}
	if !isClient && !mask {
		return 0, nil, errors.New("client frames must be masked")
	}
	return opcode, payload, nil
}

func writeFrame(w io.Writer, opcode byte, payload []byte, isClient bool) error {
	fin := byte(0x80)
	b1 := fin | (opcode & 0x0f)
	var b2 byte
	mask := isClient
	length := len(payload)
	if mask {
		b2 = 0x80
	}
	header := []byte{b1, b2}
	switch {
	case length < 126:
		header[1] |= byte(length)
	case length < 65536:
		header[1] |= 126
		header = append(header, byte(length>>8), byte(length))
	default:
		header[1] |= 127
		header = append(header, 0, 0, 0, 0, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if mask {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return err
		}
		if _, err := w.Write(maskKey[:]); err != nil {
			return err
		}
		masked := make([]byte, len(payload))
		for i := 0; i < len(payload); i++ {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		_, err := w.Write(masked)
		return err
	}
	_, err := w.Write(payload)
	return err
}
