package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateIdentityKey(t *testing.T) {
	raw, formatted, err := GenerateIdentityKey(256, 5)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}
	if len(raw) < 40 || len(raw) > 60 {
		t.Fatalf("raw length out of range: %d", len(raw))
	}
	if !strings.Contains(formatted, "-") {
		t.Fatalf("expected grouped format with dashes: %s", formatted)
	}
}

func TestEnsureIdentityKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "identity.key")
	first, err := EnsureIdentityKey(path, 256, 5)
	if err != nil {
		t.Fatalf("ensure error: %v", err)
	}
	second, err := EnsureIdentityKey(path, 256, 5)
	if err != nil {
		t.Fatalf("ensure error: %v", err)
	}
	if strings.TrimSpace(first) != strings.TrimSpace(second) {
		t.Fatal("expected same identity on second read")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}
}
