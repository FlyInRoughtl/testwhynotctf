package meshgateway

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type Options struct {
	Listen   string
	Upstream string
}

func Start(ctx context.Context, opts Options) (func() error, error) {
	if opts.Listen == "" {
		opts.Listen = ":1080"
	}
	if opts.Upstream == "" {
		return nil, errors.New("upstream is required")
	}
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, err
	}
	sem := make(chan struct{}, 128)
	go func() {
		for {
			if ctx != nil {
				select {
				case <-ctx.Done():
					_ = ln.Close()
					return
				default:
				}
			}
			if tl, ok := ln.(*net.TCPListener); ok {
				_ = tl.SetDeadline(time.Now().Add(1 * time.Second))
			}
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			select {
			case sem <- struct{}{}:
				go func(c net.Conn) {
					defer func() { <-sem }()
					defer c.Close()
					up, err := net.Dial("tcp", opts.Upstream)
					if err != nil {
						return
					}
					defer up.Close()
					pipe(c, up)
				}(conn)
			default:
				_ = conn.Close()
			}
		}
	}()

	stop := func() error { return ln.Close() }
	return stop, nil
}

func pipe(a net.Conn, b net.Conn) {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(b, a)
		errCh <- err
	}()
	<-errCh
}
