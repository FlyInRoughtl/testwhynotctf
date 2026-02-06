package syncer

import (
	"context"
	"testing"
)

func TestStartErrors(t *testing.T) {
	if _, err := Start(context.Background(), Options{Dir: "", Target: "127.0.0.1:1"}, nil); err == nil {
		t.Fatal("expected error for empty dir")
	}
	if _, err := Start(context.Background(), Options{Dir: "/tmp", Target: ""}, nil); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestStartStop(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := Start(ctx, Options{Dir: dir, Target: "127.0.0.1:1"}, nil)
	if err != nil {
		cancel()
		t.Fatalf("start error: %v", err)
	}
	cancel()
	if err := stop(); err != nil {
		t.Fatalf("stop error: %v", err)
	}
}
