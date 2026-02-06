package tools

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPackPath(t *testing.T) {
	home := t.TempDir()
	path := DefaultPackPath(home, "web")
	if filepath.Ext(path) != ".yaml" {
		t.Fatalf("expected .yaml extension, got %s", path)
	}
}

func TestResolvePackPathRelative(t *testing.T) {
	home := t.TempDir()
	path := DefaultPackPath(home, "web")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("pack: web\ntools: []\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ResolvePackPath(home, "web")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != path {
		t.Fatalf("expected %s, got %s", path, got)
	}
}

func TestEnsurePackCreates(t *testing.T) {
	home := t.TempDir()
	path := DefaultPackPath(home, "custom")
	if err := EnsurePack(path, "custom"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected pack file to exist: %v", err)
	}
}

func TestBuiltinPack(t *testing.T) {
	content, ok := BuiltinPack("ctf")
	if !ok || content == "" {
		t.Fatal("expected builtin ctf pack content")
	}
}
