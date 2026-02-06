package tools

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchPack(t *testing.T) {
	const payload = "pack: demo\ntools: []\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/demo.yaml" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)

	destDir := t.TempDir()
	destPath := filepath.Join(destDir, "demo.yaml")
	if err := FetchPack(srv.URL, "demo", destPath); err != nil {
		t.Fatalf("FetchPack failed: %v", err)
	}
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read pack: %v", err)
	}
	if strings.TrimSpace(string(data)) != strings.TrimSpace(payload) {
		t.Fatalf("unexpected pack content: %q", string(data))
	}
}

func TestFetchPackInvalidName(t *testing.T) {
	destPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := FetchPack("http://example.invalid", "../bad", destPath); err == nil {
		t.Fatalf("expected error for invalid pack name")
	}
}
