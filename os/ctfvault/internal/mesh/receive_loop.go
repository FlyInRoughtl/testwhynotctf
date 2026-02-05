package mesh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"gargoyle/internal/security"
)

func Listen(opts ReceiveOptions, handler func(path string) error) (func() error, error) {
	if opts.Listen == "" {
		opts.Listen = ":19999"
	}
	if opts.OutDir == "" {
		opts.OutDir = "."
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.Relay != "" {
		return nil, errors.New("listen does not support relay mode")
	}
	if opts.Transport == "tls" && opts.Relay != "" {
		return nil, errors.New("tls transport is not supported with relay")
	}
	if err := os.MkdirAll(opts.OutDir, 0700); err != nil {
		return nil, err
	}

	psk, err := loadPSKOptional(opts.PSK, opts.PSKFile)
	if err != nil {
		return nil, err
	}

	ln, err := listenTransport(opts.Listen, opts.Transport)
	if err != nil {
		return nil, err
	}

	stop := func() error { return ln.Close() }
	sem := make(chan struct{}, 64)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case sem <- struct{}{}:
				go func(c net.Conn) {
					defer func() { <-sem }()
					defer c.Close()
					path, err := receiveFromConn(c, opts, psk)
					if err != nil {
						return
					}
					if handler != nil {
						_ = handler(path)
					}
				}(conn)
			default:
				_ = conn.Close()
			}
		}
	}()

	return stop, nil
}

func receiveFromConn(conn net.Conn, opts ReceiveOptions, psk []byte) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	hdr, err := readHeader(conn)
	if err != nil {
		return "", err
	}
	if hdr.Padding < 0 {
		return "", errors.New("invalid padding")
	}
	if hdr.Padding > 1<<20 {
		return "", errors.New("padding too large")
	}
	if hdr.Padding > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(hdr.Padding)); err != nil {
			return "", err
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if hdr.Op != "" && hdr.Op != "send" {
		return "", errors.New("unsupported op")
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
		salt, nonceBase, _, depth, offset, err := security.ParseStreamHeader(security.StreamHeader{
			Salt:      hdr.Security.Salt,
			NonceBase: hdr.Security.NonceBase,
			ChunkSize: hdr.Security.ChunkSize,
			Algo:      hdr.Security.Algo,
			Depth:     hdr.Security.Depth,
			Offset:    hdr.Security.Offset,
		})
		if err != nil {
			return "", err
		}
		if err := security.DecryptStream(conn, out, psk, nonceBase, salt, depth, offset); err != nil {
			return "", err
		}
		return outPath, nil
	}

	if _, err := io.Copy(out, conn); err != nil {
		return "", err
	}
	return outPath, nil
}
