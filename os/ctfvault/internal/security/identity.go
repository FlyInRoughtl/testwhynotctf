package security

import (
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

const identityAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func GenerateIdentityKey(bits, group int) (string, string, error) {
	if bits <= 0 {
		return "", "", errors.New("bits must be positive")
	}
	if group <= 0 {
		return "", "", errors.New("group must be positive")
	}
	byteLen := (bits + 7) / 8
	rawBytes := make([]byte, byteLen)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", "", err
	}
	raw := base62Encode(rawBytes)
	expected := base62Length(bits)
	if len(raw) < expected {
		raw = strings.Repeat("0", expected-len(raw)) + raw
	}

	formatted := formatGrouped(raw, group)
	return raw, formatted, nil
}

func EnsureIdentityKey(path string, bits, group int) (string, error) {
	if path == "" {
		return "", errors.New("identity key path is empty")
	}
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}

	_, formatted, err := GenerateIdentityKey(bits, group)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(formatted+"\n"), 0600); err != nil {
		return "", err
	}
	return formatted, nil
}

func formatGrouped(raw string, group int) string {
	if group <= 0 {
		return raw
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		b.WriteByte(raw[i])
		if (i+1)%group == 0 && i != len(raw)-1 {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func base62Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	n := new(big.Int).SetBytes(data)
	if n.Sign() == 0 {
		return "0"
	}
	base := big.NewInt(int64(len(identityAlphabet)))
	zero := big.NewInt(0)
	var out []byte
	for n.Cmp(zero) > 0 {
		mod := new(big.Int)
		n.DivMod(n, base, mod)
		out = append(out, identityAlphabet[mod.Int64()])
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base62Length(bits int) int {
	if bits <= 0 {
		return 0
	}
	return int(math.Ceil(float64(bits) / math.Log2(62)))
}
