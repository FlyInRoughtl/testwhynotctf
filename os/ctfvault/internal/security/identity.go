package security

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const identityAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=[]{}:;,.<>?/"

func GenerateIdentityKey(length, group int) (string, string, error) {
	if length <= 0 {
		return "", "", errors.New("length must be positive")
	}
	if group <= 0 {
		return "", "", errors.New("group must be positive")
	}
	raw := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := randomIndex(len(identityAlphabet))
		if err != nil {
			return "", "", err
		}
		raw[i] = identityAlphabet[idx]
	}

	formatted := formatGrouped(string(raw), group)
	return string(raw), formatted, nil
}

func EnsureIdentityKey(path string, length, group int) (string, error) {
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

	_, formatted, err := GenerateIdentityKey(length, group)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(formatted+"\n"), 0600); err != nil {
		return "", err
	}
	return formatted, nil
}

func randomIndex(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("max must be positive")
	}
	b := make([]byte, 1)
	for {
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		if int(b[0]) < 256-(256%max) {
			return int(b[0]) % max, nil
		}
	}
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
