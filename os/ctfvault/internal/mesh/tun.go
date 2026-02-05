//go:build linux
// +build linux

package mesh

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"
	"unsafe"

	"gargoyle/internal/security"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/unix"
)

func TunServe(ctx context.Context, opts TunOptions) error {
	if runtime.GOOS != "linux" {
		return errors.New("tun mode is supported on Linux only")
	}
	if opts.Listen == "" {
		opts.Listen = ":20100"
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.Device == "" {
		opts.Device = "gargoyle0"
	}
	psk, err := loadPSKOptional(opts.PSK, opts.PSKFile)
	if err != nil {
		return err
	}

	if err := setupTunDevice(opts.Device, opts.CIDR, opts.PeerCIDR); err != nil {
		return err
	}
	tunFile, err := openTun(opts.Device)
	if err != nil {
		return err
	}
	defer tunFile.Close()

	ln, err := listenTransport(opts.Listen, opts.Transport)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if err := handleTunConn(conn, tunFile, psk, false); err != nil {
			return err
		}
	}
}

func TunConnect(ctx context.Context, opts TunOptions) error {
	if runtime.GOOS != "linux" {
		return errors.New("tun mode is supported on Linux only")
	}
	if opts.Target == "" {
		return errors.New("target is required")
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.Device == "" {
		opts.Device = "gargoyle0"
	}
	psk, err := loadPSKOptional(opts.PSK, opts.PSKFile)
	if err != nil {
		return err
	}
	if err := setupTunDevice(opts.Device, opts.CIDR, opts.PeerCIDR); err != nil {
		return err
	}
	tunFile, err := openTun(opts.Device)
	if err != nil {
		return err
	}
	defer tunFile.Close()

	conn, err := dialTransportContext(ctx, opts.Target, opts.Transport)
	if err != nil {
		return err
	}
	defer conn.Close()

	return handleTunConn(conn, tunFile, psk, true)
}

func handleTunConn(conn net.Conn, tunFile *os.File, psk []byte, isClient bool) error {
	defer conn.Close()
	var sendCipher, recvCipher *tunCipher
	if len(psk) > 0 {
		header, salt, nonceBase, err := tunHandshake(conn, isClient)
		if err != nil {
			return err
		}
		sendOffset := 0
		if !isClient {
			sendOffset = 1
		}
		recvOffset := 1 - sendOffset
		sendCipher, err = newTunCipher(psk, salt, nonceBase, sendOffset, header.Depth)
		if err != nil {
			return err
		}
		recvCipher, err = newTunCipher(psk, salt, nonceBase, recvOffset, header.Depth)
		if err != nil {
			return err
		}
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- tunToConn(tunFile, conn, sendCipher)
	}()
	go func() {
		errCh <- connToTun(conn, tunFile, recvCipher)
	}()
	err := <-errCh
	return err
}

func tunHandshake(conn net.Conn, isClient bool) (security.StreamHeader, []byte, []byte, error) {
	if isClient {
		h, salt, nonceBase, err := security.NewStreamHeader(4096, 1)
		if err != nil {
			return security.StreamHeader{}, nil, nil, err
		}
		hdr := Header{
			Version:   1,
			Op:        "tun",
			Encrypted: true,
			Security: &SecurityStreamHeader{
				Salt:      h.Salt,
				NonceBase: h.NonceBase,
				ChunkSize: h.ChunkSize,
				Algo:      h.Algo,
				Depth:     h.Depth,
				Offset:    h.Offset,
			},
		}
		if err := writeHeader(conn, hdr); err != nil {
			return security.StreamHeader{}, nil, nil, err
		}
		return h, salt, nonceBase, nil
	}
	hdr, err := readHeader(conn)
	if err != nil {
		return security.StreamHeader{}, nil, nil, err
	}
	if hdr.Op != "tun" {
		return security.StreamHeader{}, nil, nil, errors.New("invalid tun header")
	}
	if hdr.Security == nil {
		return security.StreamHeader{}, nil, nil, errors.New("missing tun security header")
	}
	h := security.StreamHeader{
		Salt:      hdr.Security.Salt,
		NonceBase: hdr.Security.NonceBase,
		ChunkSize: hdr.Security.ChunkSize,
		Algo:      hdr.Security.Algo,
		Depth:     hdr.Security.Depth,
		Offset:    hdr.Security.Offset,
	}
	salt, nonceBase, _, _, _, err := security.ParseStreamHeader(h)
	if err != nil {
		return security.StreamHeader{}, nil, nil, err
	}
	return h, salt, nonceBase, nil
}

func newTunCipher(psk []byte, salt []byte, nonceBase []byte, offset int, depth int) (*tunCipher, error) {
	if depth <= 0 {
		depth = 1
	}
	_ = depth
	key, err := security.DeriveKey(psk, salt, 0, offset)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &tunCipher{aead: aead, nonceBase: nonceBase}, nil
}

type tunCipher struct {
	aead      cipher.AEAD
	nonceBase []byte
	counter   uint64
}

func (c *tunCipher) seal(plain []byte) ([]byte, error) {
	if c == nil {
		return plain, nil
	}
	nonce := nextNonce(c.nonceBase, atomic.AddUint64(&c.counter, 1)-1)
	return c.aead.Seal(nil, nonce, plain, nil), nil
}

func (c *tunCipher) open(ciphertext []byte) ([]byte, error) {
	if c == nil {
		return ciphertext, nil
	}
	nonce := nextNonce(c.nonceBase, atomic.AddUint64(&c.counter, 1)-1)
	return c.aead.Open(nil, nonce, ciphertext, nil)
}

func nextNonce(b []byte, u uint64) any {
	panic("unimplemented")
}

func tunToConn(tunFile *os.File, conn net.Conn, cipher *tunCipher) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := tunFile.Read(buf)
		if err != nil {
			return err
		}
		payload := buf[:n]
		if cipher != nil {
			payload, err = cipher.seal(payload)
			if err != nil {
				return err
			}
		}
		if err := writeFrame(conn, payload); err != nil {
			return err
		}
	}
}

func connToTun(conn net.Conn, tunFile *os.File, cipher *tunCipher) error {
	for {
		payload, err := readFrame(conn)
		if err != nil {
			return err
		}
		if cipher != nil {
			payload, err = cipher.open(payload)
			if err != nil {
				return err
			}
		}
		if _, err := tunFile.Write(payload); err != nil {
			return err
		}
	}
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > int(^uint32(0)) {
		return errors.New("frame too large")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 {
		return nil, errors.New("empty frame")
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func setupTunDevice(dev string, cidr string, peerCIDR string) error {
	if dev == "" {
		return errors.New("tun device is empty")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return errors.New("ip command not found")
	}
	_ = exec.Command("ip", "tuntap", "add", "dev", dev, "mode", "tun").Run()
	if cidr != "" {
		_ = exec.Command("ip", "addr", "add", cidr, "dev", dev).Run()
	}
	_ = exec.Command("ip", "link", "set", dev, "up").Run()
	if peerCIDR != "" {
		_ = exec.Command("ip", "route", "replace", peerCIDR, "dev", dev).Run()
	}
	return nil
}

func openTun(dev string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var ifr struct {
		Name  [unix.IFNAMSIZ]byte
		Flags uint16
		_     [22]byte
	}
	copy(ifr.Name[:], dev)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		_ = f.Close()
		return nil, errno
	}
	return f, nil
}
