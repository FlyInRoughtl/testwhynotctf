package security

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	DefaultChunkSize = 64 * 1024
)

type StreamHeader struct {
	Salt      string `json:"salt"`
	NonceBase string `json:"nonce_base"`
	ChunkSize int    `json:"chunk_size"`
	Algo      string `json:"algo"`
	Depth     int    `json:"depth"`
}

func DeriveKey(psk []byte, salt []byte, layer int) ([]byte, error) {
	if len(psk) == 0 {
		return nil, errors.New("psk is empty")
	}
	info := []byte("ctfvault-stream")
	if layer > 0 {
		info = []byte("ctfvault-stream-layer-" + itoa(layer))
	}
	h := hkdf.New(sha256.New, psk, salt, info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

func NewStreamHeader(chunkSize int, depth int) (StreamHeader, []byte, []byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if depth <= 0 {
		depth = 1
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return StreamHeader{}, nil, nil, err
	}
	nonceBase := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonceBase); err != nil {
		return StreamHeader{}, nil, nil, err
	}
	header := StreamHeader{
		Salt:      base64.RawStdEncoding.EncodeToString(salt),
		NonceBase: base64.RawStdEncoding.EncodeToString(nonceBase),
		ChunkSize: chunkSize,
		Algo:      "CHACHA20-POLY1305",
		Depth:     depth,
	}
	return header, salt, nonceBase, nil
}

func ParseStreamHeader(header StreamHeader) ([]byte, []byte, int, int, error) {
	salt, err := base64.RawStdEncoding.DecodeString(header.Salt)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	nonceBase, err := base64.RawStdEncoding.DecodeString(header.NonceBase)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	chunkSize := header.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	depth := header.Depth
	if depth <= 0 {
		depth = 1
	}
	return salt, nonceBase, chunkSize, depth, nil
}

func EncryptStream(r io.Reader, w io.Writer, psk []byte, nonceBase []byte, salt []byte, chunkSize int, depth int) error {
	aeads, err := buildAEADs(psk, salt, depth)
	if err != nil {
		return err
	}

	buf := make([]byte, chunkSize)
	counter := uint64(0)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			nonce := nextNonce(nonceBase, counter)
			counter++
			ciphertext := buf[:n]
			for _, aead := range aeads {
				ciphertext = aead.Seal(nil, nonce, ciphertext, nil)
			}
			if err := writeChunk(w, ciphertext); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return writeChunk(w, nil)
		}
		if readErr != nil {
			return readErr
		}
	}
}

func DecryptStream(r io.Reader, w io.Writer, psk []byte, nonceBase []byte, salt []byte, depth int) error {
	aeads, err := buildAEADs(psk, salt, depth)
	if err != nil {
		return err
	}

	counter := uint64(0)
	for {
		ciphertext, err := readChunk(r)
		if err != nil {
			return err
		}
		if len(ciphertext) == 0 {
			return nil
		}
		nonce := nextNonce(nonceBase, counter)
		counter++
		plaintext := ciphertext
		for i := len(aeads) - 1; i >= 0; i-- {
			plaintext, err = aeads[i].Open(nil, nonce, plaintext, nil)
			if err != nil {
				return err
			}
		}
		if _, err := w.Write(plaintext); err != nil {
			return err
		}
	}
}

func nextNonce(base []byte, counter uint64) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(counter >> (8 * i))
	}
	return nonce
}

func buildAEADs(psk []byte, salt []byte, depth int) ([]cipher.AEAD, error) {
	if depth <= 0 {
		depth = 1
	}
	aeads := make([]cipher.AEAD, 0, depth)
	for i := 0; i < depth; i++ {
		key, err := DeriveKey(psk, salt, i)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		aeads = append(aeads, aead)
	}
	return aeads, nil
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
