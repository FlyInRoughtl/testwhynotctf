package mesh

import "testing"

func TestParseChain(t *testing.T) {
	got, err := parseChain("a, b; c")
	if err != nil {
		t.Fatalf("parseChain error: %v", err)
	}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("unexpected chain: %#v", got)
	}
}

func TestParseChainEmpty(t *testing.T) {
	if _, err := parseChain(" ,  "); err == nil {
		t.Fatal("expected error for empty chain")
	}
}
