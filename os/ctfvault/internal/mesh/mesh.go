package mesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ctfvault/internal/security"
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
}

type ReceiveOptions struct {
	Listen  string
	OutDir  string
	PSK     string
	PSKFile string
	Relay   string
	Token   string
}

func Up(ctx context.Context) error {
	_ = ctx
	return ErrNotImplemented
}

func Status(ctx context.Context) (string, error) {
	_ = ctx
	return "mesh: direct mode (relay/onion disabled in V1)", nil
}

func Send(ctx context.Context, src, dst string, opts SendOptions) error {
	_ = ctx
	if opts.Target == "" && opts.Relay == "" && opts.RelayChain == "" {
		return errors.New("target or relay is required")
	}
	if opts.MetadataLevel == "" {
		opts.MetadataLevel = "standard"
	}
	if opts.Depth <= 0 {
		opts.Depth = 1
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

	conn, err := connectTarget(opts)
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
		}
		if err := writeHeader(conn, hdr); err != nil {
			return err
		}
		return security.EncryptStream(file, conn, psk, nonceBase, salt, streamHeader.ChunkSize, streamHeader.Depth)
	}

	if opts.RelayChain != "" && opts.Relay != "" {
		return errors.New("relay and relay-chain are mutually exclusive")
	}

	if err := writeHeader(conn, hdr); err != nil {
		return err
	}
	_, err = io.Copy(conn, file)
	return err
}

func Receive(ctx context.Context, opts ReceiveOptions) (string, error) {
	_ = ctx
	if opts.Listen == "" {
		opts.Listen = ":19999"
	}
	if opts.OutDir == "" {
		opts.OutDir = "."
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
		rconn, err := net.Dial("tcp", opts.Relay)
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
		ln, err := net.Listen("tcp", opts.Listen)
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

	hdr, err := readHeader(conn)
	if err != nil {
		return "", err
	}

	name := hdr.Name
	if name == "" {
		name = fmt.Sprintf("received_%d.bin", time.Now().Unix())
	}
	outPath := filepath.Join(opts.OutDir, filepath.Base(name))
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if hdr.Encrypted {
		if len(psk) == 0 {
			return "", errors.New("psk is required to decrypt payload")
		}
		if hdr.Security == nil {
			return "", errors.New("missing security header")
		}
		salt, nonceBase, _, depth, err := security.ParseStreamHeader(security.StreamHeader{
			Salt:      hdr.Security.Salt,
			NonceBase: hdr.Security.NonceBase,
			ChunkSize: hdr.Security.ChunkSize,
			Algo:      hdr.Security.Algo,
			Depth:     hdr.Security.Depth,
		})
		if err != nil {
			return "", err
		}
		if err := security.DecryptStream(conn, out, psk, nonceBase, salt, depth); err != nil {
			return "", err
		}
		return outPath, nil
	}

	if _, err := io.Copy(out, conn); err != nil {
		return "", err
	}
	return outPath, nil
}

func connectTarget(opts SendOptions) (net.Conn, error) {
	if opts.RelayChain != "" {
		chain, err := parseChain(opts.RelayChain)
		if err != nil {
			return nil, err
		}
		conn, err := net.Dial("tcp", chain[0])
		if err != nil {
			return nil, err
		}
		hdr := Header{
			Version: 1,
			Op:      "relay_chain",
			Route:   strings.Join(chain[1:], ","),
			Target:  opts.Target,
			Token:   opts.Token,
		}
		if err := writeHeader(conn, hdr); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	if opts.Relay != "" {
		conn, err := net.Dial("tcp", opts.Relay)
		if err != nil {
			return nil, err
		}
		if err := relayHandshake(conn, opts.Token, "send"); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return net.Dial("tcp", opts.Target)
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
