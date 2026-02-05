package mesh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"gargoyle/internal/security"
)

const maxMessageSize = 64 * 1024

type MessageOptions struct {
	Target       string
	PSK          string
	PSKFile      string
	Transport    string
	PaddingBytes int
	Security     bool
	Depth        int
	Op           string
}

func SendMessage(ctx context.Context, message string, opts MessageOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Target == "" {
		return errors.New("target is required")
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.Depth <= 0 {
		opts.Depth = 1
	}
	if opts.Op == "" {
		opts.Op = "chat"
	}
	if opts.PaddingBytes < 0 {
		opts.PaddingBytes = 0
	}
	if len(message) > maxMessageSize {
		return errors.New("message too large")
	}

	psk, err := loadPSKOptional(opts.PSK, opts.PSKFile)
	if err != nil {
		return err
	}
	if opts.Security && len(psk) == 0 {
		return errors.New("psk is required for encrypted message")
	}

	conn, err := dialTransportContext(ctx, opts.Target, opts.Transport)
	if err != nil {
		return err
	}
	defer conn.Close()

	hdr := Header{
		Version:   1,
		Op:        opts.Op,
		Encrypted: opts.Security,
		Size:      int64(len(message)),
		Padding:   opts.PaddingBytes,
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
		return security.EncryptStream(bytes.NewReader([]byte(message)), conn, psk, nonceBase, salt, streamHeader.ChunkSize, streamHeader.Depth)
	}

	if err := writeHeader(conn, hdr); err != nil {
		return err
	}
	if err := writePadding(conn, hdr.Padding); err != nil {
		return err
	}
	_, err = conn.Write([]byte(message))
	return err
}

func ListenMessages(opts ReceiveOptions, handler func(op, message string) error) (func() error, error) {
	if opts.Listen == "" {
		opts.Listen = ":19999"
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.Transport == "tls" && opts.Relay != "" {
		return nil, errors.New("tls transport is not supported with relay")
	}
	if opts.Relay != "" {
		return nil, errors.New("listen does not support relay mode")
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
					op, msg, err := receiveMessageFromConn(c, psk)
					if err != nil {
						return
					}
					if handler != nil {
						_ = handler(op, msg)
					}
				}(conn)
			default:
				_ = conn.Close()
			}
		}
	}()
	return stop, nil
}

func receiveMessageFromConn(conn net.Conn, psk []byte) (string, string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	hdr, err := readHeader(conn)
	if err != nil {
		return "", "", err
	}
	if hdr.Padding < 0 || hdr.Padding > 1<<20 {
		return "", "", errors.New("invalid padding")
	}
	if hdr.Padding > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(hdr.Padding)); err != nil {
			return "", "", err
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	if hdr.Encrypted {
		if len(psk) == 0 {
			return "", "", errors.New("psk is required to decrypt message")
		}
		if hdr.Security == nil {
			return "", "", errors.New("missing security header")
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
			return "", "", err
		}
		var buf bytes.Buffer
		if err := security.DecryptStream(conn, &buf, psk, nonceBase, salt, depth, offset); err != nil {
			return "", "", err
		}
		if buf.Len() > maxMessageSize {
			return "", "", errors.New("message too large")
		}
		return hdr.Op, buf.String(), nil
	}

	if hdr.Size <= 0 {
		return "", "", errors.New("missing message size")
	}
	if hdr.Size > maxMessageSize {
		return "", "", errors.New("message too large")
	}
	data := make([]byte, hdr.Size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return "", "", err
	}
	return hdr.Op, string(data), nil
}
