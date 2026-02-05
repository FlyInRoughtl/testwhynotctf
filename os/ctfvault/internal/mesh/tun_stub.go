//go:build !linux
// +build !linux

package mesh

import (
	"context"
	"errors"
)

func TunServe(ctx context.Context, opts TunOptions) error {
	_ = ctx
	_ = opts
	return errors.New("tun mode is supported on Linux only")
}

func TunConnect(ctx context.Context, opts TunOptions) error {
	_ = ctx
	_ = opts
	return errors.New("tun mode is supported on Linux only")
}
