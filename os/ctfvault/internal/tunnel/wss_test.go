package tunnel

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildURL(t *testing.T) {
	u := buildURL("https://example.com", "/control", "svc", "tok", "id123")
	if !strings.Contains(u, "service=svc") || !strings.Contains(u, "token=tok") || !strings.Contains(u, "id=id123") {
		t.Fatalf("unexpected url: %s", u)
	}
}

func TestCheckToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/control?service=svc&token=tok", nil)
	if !checkToken(req, "tok", "svc") {
		t.Fatal("expected token to match")
	}
	if checkToken(req, "bad", "svc") {
		t.Fatal("expected token mismatch")
	}
}

func TestRandID(t *testing.T) {
	id, err := randID()
	if err != nil {
		t.Fatalf("randID error: %v", err)
	}
	if len(id) != 16 {
		t.Fatalf("expected hex length 16, got %d", len(id))
	}
}
