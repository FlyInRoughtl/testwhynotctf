package mesh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gargoyle/internal/security"
)

type HydraSendOptions struct {
	Targets      []string
	Transport    string
	PSK          string
	PSKFile      string
	Security     bool
	Depth        int
	ChunkSize    int
	PaddingBytes int
	NoisePackets int
	Mode         string // direct|vortex|obsidian
	Mimic        bool
	MimicPeer    string
	RelayChain   string
	Route        string
	Token        string
}

type HydraReceiveOptions struct {
	Listen    string
	OutDir    string
	PSK       string
	PSKFile   string
	Transport string
	Timeout   time.Duration
}

func HydraSend(ctx context.Context, src string, dst string, opts HydraSendOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Mimic && opts.MimicPeer != "" {
		opts.Targets = []string{opts.MimicPeer}
	}
	if len(opts.Targets) == 0 {
		return errors.New("hydra: targets required")
	}
	if opts.Transport == "" {
		opts.Transport = "tcp"
	}
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = 256 * 1024
	}
	if opts.Depth <= 0 {
		opts.Depth = 1
	}
	if opts.PaddingBytes < 0 {
		opts.PaddingBytes = 0
	}
	if opts.PaddingBytes > 1<<20 {
		opts.PaddingBytes = 1 << 20
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

	if dst == "" {
		dst = filepath.Base(src)
	}
	fileID := randID()
	total := int(math.Ceil(float64(info.Size()) / float64(opts.ChunkSize)))
	if total <= 0 {
		total = 1
	}

	buf := make([]byte, opts.ChunkSize)
	index := 0
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			target := opts.Targets[index%len(opts.Targets)]
			if err := sendHydraChunk(ctx, target, buf[:n], dst, fileID, index, total, psk, opts); err != nil {
				return err
			}
			index++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	for i := 0; i < opts.NoisePackets; i++ {
		target := opts.Targets[i%len(opts.Targets)]
		if err := sendHydraNoise(ctx, target, opts, psk); err != nil {
			return err
		}
	}
	return nil
}

func HydraReceive(ctx context.Context, opts HydraReceiveOptions) (string, error) {
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
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if err := os.MkdirAll(opts.OutDir, 0700); err != nil {
		return "", err
	}

	psk, err := loadPSKOptional(opts.PSK, opts.PSKFile)
	if err != nil {
		return "", err
	}

	ln, err := listenTransport(opts.Listen, opts.Transport)
	if err != nil {
		return "", err
	}
	defer ln.Close()

	var (
		mu       sync.Mutex
		assem    = map[string]*hydraAssembly{}
		donePath string
		doneCh   = make(chan struct{})
	)

	handleConn := func(conn net.Conn) {
		defer conn.Close()
		if err := handleHydraConn(conn, opts.OutDir, psk, &mu, assem, &donePath); err != nil {
			return
		}
		mu.Lock()
		if donePath != "" {
			select {
			case <-doneCh:
			default:
				close(doneCh)
			}
		}
		mu.Unlock()
	}

	deadline := time.Now().Add(opts.Timeout)
	for {
		if time.Now().After(deadline) {
			break
		}
		if tl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
			_ = tl.SetDeadline(time.Now().Add(1 * time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-doneCh:
					goto done
				default:
				}
				continue
			}
			return "", err
		}
		go handleConn(conn)
	}

done:
	mu.Lock()
	defer mu.Unlock()
	if donePath == "" {
		return "", errors.New("hydra: timeout waiting for chunks")
	}
	return donePath, nil
}

type hydraAssembly struct {
	name     string
	total    int
	received map[int]string
}

func handleHydraConn(conn net.Conn, outDir string, psk []byte, mu *sync.Mutex, assem map[string]*hydraAssembly, donePath *string) error {
	hdr, err := readHeader(conn)
	if err != nil {
		return err
	}
	if hdr.Padding > 0 {
		if err := readPadding(conn, hdr.Padding); err != nil {
			return err
		}
	}
	if hdr.Op == "hydra_noise" {
		_, _ = io.Copy(io.Discard, conn)
		return nil
	}
	if hdr.Op != "hydra_chunk" {
		return errors.New("hydra: unexpected op")
	}
	if hdr.FileID == "" || hdr.ChunkTotal <= 0 {
		return errors.New("hydra: missing file id or total")
	}

	tempDir := filepath.Join(outDir, ".hydra")
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return err
	}
	chunkPath := filepath.Join(tempDir, fmt.Sprintf("%s.%06d", hdr.FileID, hdr.ChunkIndex))
	out, err := os.Create(chunkPath)
	if err != nil {
		return err
	}
	if hdr.Encrypted {
		if hdr.Security == nil {
			out.Close()
			return errors.New("hydra: missing security header")
		}
		streamHeader := security.StreamHeader{
			Salt:      hdr.Security.Salt,
			NonceBase: hdr.Security.NonceBase,
			ChunkSize: hdr.Security.ChunkSize,
			Algo:      hdr.Security.Algo,
			Depth:     hdr.Security.Depth,
			Offset:    hdr.Security.Offset,
		}
		salt, nonceBase, _, depth, offset, err := security.ParseStreamHeader(streamHeader)
		if err != nil {
			out.Close()
			return err
		}
		if err := security.DecryptStream(conn, out, psk, nonceBase, salt, depth, offset); err != nil {
			out.Close()
			return err
		}
	} else {
		if _, err := io.Copy(out, conn); err != nil {
			out.Close()
			return err
		}
	}
	if err := out.Close(); err != nil {
		return err
	}

	mu.Lock()
	assembly := assem[hdr.FileID]
	if assembly == nil {
		assembly = &hydraAssembly{
			name:     sanitizeFilename(hdr.OrigName),
			total:    hdr.ChunkTotal,
			received: map[int]string{},
		}
		if assembly.name == "" {
			assembly.name = hdr.FileID
		}
		assem[hdr.FileID] = assembly
	}
	assembly.received[hdr.ChunkIndex] = chunkPath

	if len(assembly.received) >= assembly.total {
		outPath := filepath.Join(outDir, assembly.name)
		if err := assembleHydraFile(outPath, assembly); err != nil {
			mu.Unlock()
			return err
		}
		*donePath = outPath
	}
	mu.Unlock()
	return nil
}

func assembleHydraFile(outPath string, assembly *hydraAssembly) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	for i := 0; i < assembly.total; i++ {
		chunkPath, ok := assembly.received[i]
		if !ok {
			return errors.New("hydra: missing chunk")
		}
		f, err := os.Open(chunkPath)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return nil
}

func sendHydraChunk(ctx context.Context, target string, data []byte, name string, fileID string, index int, total int, psk []byte, opts HydraSendOptions) error {
	conn, err := hydraDial(ctx, target, opts)
	if err != nil {
		return err
	}
	defer conn.Close()

	hdr := Header{
		Version:       1,
		Op:            "hydra_chunk",
		Encrypted:     opts.Security,
		MetadataLevel: "off",
		Name:          name,
		OrigName:      name,
		FileID:        fileID,
		ChunkIndex:    index,
		ChunkTotal:    total,
		ChunkSize:     len(data),
		Size:          int64(len(data)),
		Padding:       opts.PaddingBytes,
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
		return security.EncryptStream(bytes.NewReader(data), conn, psk, nonceBase, salt, streamHeader.ChunkSize, streamHeader.Depth)
	}

	if err := writeHeader(conn, hdr); err != nil {
		return err
	}
	if err := writePadding(conn, hdr.Padding); err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

func sendHydraNoise(ctx context.Context, target string, opts HydraSendOptions, psk []byte) error {
	size := opts.ChunkSize
	if size <= 0 {
		size = 64 * 1024
	}
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	conn, err := hydraDial(ctx, target, opts)
	if err != nil {
		return err
	}
	defer conn.Close()

	hdr := Header{
		Version:   1,
		Op:        "hydra_noise",
		Encrypted: opts.Security,
		Padding:   opts.PaddingBytes,
		ChunkSize: len(buf),
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
		return security.EncryptStream(bytes.NewReader(buf), conn, psk, nonceBase, salt, streamHeader.ChunkSize, streamHeader.Depth)
	}

	if err := writeHeader(conn, hdr); err != nil {
		return err
	}
	if err := writePadding(conn, hdr.Padding); err != nil {
		return err
	}
	_, err = conn.Write(buf)
	return err
}

func hydraDial(ctx context.Context, target string, opts HydraSendOptions) (net.Conn, error) {
	mode := strings.ToLower(opts.Mode)
	if mode == "" {
		mode = "direct"
	}
	if mode == "obsidian" {
		return dialViaSocks5(ctx, "127.0.0.1:9050", target)
	}
	if mode == "vortex" && opts.RelayChain != "" && opts.Route == "onion" {
		sendOpts := SendOptions{
			Target:     target,
			RelayChain: opts.RelayChain,
			Route:      opts.Route,
			Token:      opts.Token,
			Transport:  opts.Transport,
		}
		return connectTarget(ctx, sendOpts)
	}
	return dialTransportContext(ctx, target, opts.Transport)
}

func dialViaSocks5(ctx context.Context, proxyAddr string, target string) (net.Conn, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, errors.New("socks5: auth failed")
	}

	var req []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x05, 0x01, 0x00, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x05, 0x01, 0x00, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, err
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return nil, errors.New("socks5: connect failed")
	}
	atyp := hdr[3]
	switch atyp {
	case 0x01:
		_, _ = io.CopyN(io.Discard, conn, 4)
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		_, _ = io.CopyN(io.Discard, conn, int64(lenBuf[0]))
	case 0x04:
		_, _ = io.CopyN(io.Discard, conn, 16)
	}
	_, _ = io.CopyN(io.Discard, conn, 2)
	return conn, nil
}

func parsePort(s string) (int, error) {
	var port int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("invalid port")
		}
		port = port*10 + int(ch-'0')
	}
	if port <= 0 || port > 65535 {
		return 0, errors.New("invalid port")
	}
	return port, nil
}

func randID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var out strings.Builder
	for _, v := range b {
		out.WriteByte(alphabet[int(v)%len(alphabet)])
	}
	return out.String()
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "..", "")
	name = strings.Trim(name, "\\/")
	if name == "" {
		return ""
	}
	return name
}
