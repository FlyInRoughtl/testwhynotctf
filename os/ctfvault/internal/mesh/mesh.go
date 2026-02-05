package mesh

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gargoyle/internal/security"
)

var ErrNotImplemented = errors.New("not implemented")

type SendOptions struct {
	Security      bool
	MetadataLevel string
	Route         string
	Target        string
	PSK           string
	PSKFile       string
	Relay         string
	Token         string
	Depth         int
	RelayChain    string
	Transport     string
	PaddingBytes  int
}

type ReceiveOptions struct {
	Listen    string
	OutDir    string
	PSK       string
	PSKFile   string
	Relay     string
	Token     string
	Transport string
}

func Up(ctx context.Context) error {
	_ = ctx
	return ErrNotImplemented
}

func Status(ctx context.Context) (string, error) {
	_ = ctx
	return "mesh: direct mode (relay/onion disabled in this build)", nil
}

func Send(ctx context.Context, src, dst string, opts SendOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Target == "" && opts.Relay == "" && opts.RelayChain == "" {
		return errors.New("target or relay is required")
	}
	if opts.MetadataLevel == "" {
		opts.MetadataLevel = "standard"
	}
	if opts.Depth <= 0 {
		opts.Depth = 1
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.PaddingBytes < 0 {
		opts.PaddingBytes = 0
	}
	if opts.PaddingBytes > 1<<20 {
		opts.PaddingBytes = 1 << 20
	}
	if opts.Transport == "tls" && (opts.Relay != "" || opts.RelayChain != "") {
		return errors.New("tls transport is not supported with relay/relay-chain")
	}

	psk, err := loadPSK(opts.PSK, opts.PSKFile)
	if err != nil && opts.Security {
		return err
	}

	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	conn, err := connectTarget(ctx, opts)
	if err != nil {
		return err
	}
	defer conn.Close()

	hdr := Header{
		Version:       1,
		Op:            "send",
		Encrypted:     opts.Security,
		MetadataLevel: opts.MetadataLevel,
	}
	if opts.PaddingBytes > 0 {
		hdr.Padding = opts.PaddingBytes
	}

	if opts.MetadataLevel == "off" {
		if dst == "" {
			dst = filepath.Base(src)
		}
		hdr.Name = dst
		hdr.Size = info.Size()
	}

	if opts.Security {
		streamHeader, salt, nonceBase, err := security.NewStreamHeader(security.DefaultChunkSize, opts.Depth)
		if err != nil {
			return err
		}
		hdr.Security = &SecurityStreamHeader{
			Salt:      streamHeader.Salt,
			NonceBase: streamHeader.NonceBase,
			ChunkSize: streamHeader.ChunkSize,
			Algo:      streamHeader.Algo,
			Depth:     streamHeader.Depth,
			Offset:    streamHeader.Offset,
		}
		if err := writeHeader(conn, hdr); err != nil {
			return err
		}
		if err := writePadding(conn, hdr.Padding); err != nil {
			return err
		}
		return security.EncryptStream(file, conn, psk, nonceBase, salt, streamHeader.ChunkSize, streamHeader.Depth)
	}

	if opts.RelayChain != "" && opts.Relay != "" {
		return errors.New("relay and relay-chain are mutually exclusive")
	}
	if opts.RelayChain != "" && opts.Route != "onion" {
		return errors.New("relay-chain requires route=onion")
	}

	if err := writeHeader(conn, hdr); err != nil {
		return err
	}
	if err := writePadding(conn, hdr.Padding); err != nil {
		return err
	}
	_, err = io.Copy(conn, file)
	return err
}

func Receive(ctx context.Context, opts ReceiveOptions) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Listen == "" {
		opts.Listen = ":19999"
	}
	if opts.OutDir == "" {
		opts.OutDir = "."
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.Transport == "tls" && opts.Relay != "" {
		return "", errors.New("tls transport is not supported with relay")
	}
	if err := os.MkdirAll(opts.OutDir, 0700); err != nil {
		return "", err
	}

	psk, err := loadPSKOptional(opts.PSK, opts.PSKFile)
	if err != nil {
		return "", err
	}

	var conn net.Conn
	if opts.Relay != "" {
		rconn, err := dialTransportContext(ctx, opts.Relay, opts.Transport)
		if err != nil {
			return "", err
		}
		if err := relayHandshake(rconn, opts.Token, "recv"); err != nil {
			rconn.Close()
			return "", err
		}
		conn = rconn
		defer conn.Close()
	} else {
		ln, err := listenTransport(opts.Listen, opts.Transport)
		if err != nil {
			return "", err
		}
		defer ln.Close()
		conn, err = ln.Accept()
		if err != nil {
			return "", err
		}
		defer conn.Close()
	}

	return receiveFromConn(conn, opts, psk)
}

func writePadding(w io.Writer, size int) error {
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

func connectTarget(ctx context.Context, opts SendOptions) (net.Conn, error) {
	if opts.RelayChain != "" && opts.Route == "onion" {
		chain, err := parseChain(opts.RelayChain)
		if err != nil {
			return nil, err
		}
		conn, err := dialTransportContext(ctx, chain[0], opts.Transport)
		if err != nil {
			return nil, err
		}
		hdr := Header{
			Version: 1,
			Op:      "onion_chain",
			Route:   strings.Join(chain[1:], ","),
			Target:  opts.Target,
			Token:   opts.Token,
			TTL:     len(chain) + 1,
		}
		if err := writeHeader(conn, hdr); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	if opts.Relay != "" {
		conn, err := dialTransportContext(ctx, opts.Relay, opts.Transport)
		if err != nil {
			return nil, err
		}
		if err := relayHandshake(conn, opts.Token, "send"); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return dialTransportContext(ctx, opts.Target, opts.Transport)
}

func relayHandshake(conn net.Conn, token string, role string) error {
	if token == "" {
		return errors.New("relay token is required")
	}
	hdr := Header{
		Version: 1,
		Op:      "relay",
		Token:   token,
		Name:    role,
	}
	return writeHeader(conn, hdr)
}

func parseChain(input string) ([]string, error) {
	parts := strings.FieldsFunc(input, func(r rune) bool {
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
	if len(out) == 0 {
		return nil, errors.New("relay chain is empty")
	}
	return out, nil
}

func loadPSK(raw, filePath string) ([]byte, error) {
	data, err := loadPSKOptional(raw, filePath)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("psk is required (use --psk or --psk-file)")
	}
	return data, nil
}

func loadPSKOptional(raw, filePath string) ([]byte, error) {
	if raw != "" {
		return []byte(strings.TrimSpace(raw)), nil
	}
	if filePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(data))), nil
}
