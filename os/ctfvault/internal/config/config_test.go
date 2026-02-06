package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := validate(cfg); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestValidateRejectsBadNetworkMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network.Mode = "nope"
	if err := validate(cfg); err == nil {
		t.Fatal("expected validation error for network.mode")
	}
}

func TestLoadOptionalMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	cfg, err := LoadOptional(path)
	if err != nil {
		t.Fatalf("load optional error: %v", err)
	}
	if cfg.System.Mode != "standard" {
		t.Fatalf("unexpected default mode: %s", cfg.System.Mode)
	}
}
