package dsl

import "testing"

func TestSplitArgsQuotes(t *testing.T) {
	args := splitArgs(`print "hello world" 'x y'`)
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d: %#v", len(args), args)
	}
	if args[1] != "hello world" || args[2] != "x y" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestSplitArgsEscapes(t *testing.T) {
	args := splitArgs(`cmd "a\"b" c\ d`)
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d: %#v", len(args), args)
	}
	if args[1] != `a"b` || args[2] != "c d" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestRequireArgs(t *testing.T) {
	if err := RequireArgs([]string{"a"}, 2); err == nil {
		t.Fatal("expected error for missing args")
	}
	if err := RequireArgs([]string{"a", "b"}, 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
