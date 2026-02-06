package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateIdentityKey(t *testing.T) {
	raw, formatted, err := GenerateIdentityKey(32, 4)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("raw length mismatch: %d", len(raw))
	}
	if !strings.Contains(formatted, "-") {
		t.Fatalf("expected grouped format with dashes: %s", formatted)
	}
}

func TestEnsureIdentityKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "identity.key")
	first, err := EnsureIdentityKey(path, 32, 4)
	if err != nil {
		t.Fatalf("ensure error: %v", err)
	}
	second, err := EnsureIdentityKey(path, 32, 4)
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

func TestRandomIndexMax(t *testing.T) {
	if _, err := randomIndex(0); err == nil {
		t.Fatal("expected error for max<=0")
	}
}
