package syncer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"gargoyle/internal/mesh"
)

type Options struct {
	Dir           string
	Target        string
	PSK           string
	PSKFile       string
	Transport     string
	PaddingBytes  int
	Depth         int
	MetadataLevel string
}

type Logger func(msg string)

func Start(ctx context.Context, opts Options, logf Logger) (func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Dir == "" {
		return nil, errors.New("sync dir is empty")
	}
	if opts.Target == "" {
		return nil, errors.New("sync target is empty")
	}
	if opts.Transport == "" {
		opts.Transport = "tls"
	}
	if opts.Depth <= 0 {
		opts.Depth = 1
	}
	if opts.MetadataLevel == "" {
		opts.MetadataLevel = "standard"
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := watcher.Add(opts.Dir); err != nil {
		_ = watcher.Close()
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-watcher.Events:
				if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
					continue
				}
				info, err := os.Stat(ev.Name)
				if err != nil || info.IsDir() {
					continue
				}
				time.Sleep(150 * time.Millisecond)
				dst := filepath.Base(ev.Name)
				sendOpts := mesh.SendOptions{
					Security:      true,
					MetadataLevel: opts.MetadataLevel,
					Route:         "direct",
					Target:        opts.Target,
					PSK:           opts.PSK,
					PSKFile:       opts.PSKFile,
					Depth:         opts.Depth,
					Transport:     opts.Transport,
					PaddingBytes:  opts.PaddingBytes,
				}
				if err := mesh.Send(context.Background(), ev.Name, dst, sendOpts); err != nil {
					if logf != nil {
						logf("sync send error: " + err.Error())
					}
				} else if logf != nil {
					logf("sync sent: " + dst)
				}
			case err := <-watcher.Errors:
				if err != nil && logf != nil {
					logf("sync watcher error: " + err.Error())
				}
			}
		}
	}()

	stop := func() error {
		_ = watcher.Close()
		<-done
		return nil
	}
	return stop, nil
}
