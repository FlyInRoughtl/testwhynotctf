package dsl

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gargoyle/internal/config"
	"gargoyle/internal/mesh"
	"gargoyle/internal/paths"
	"gargoyle/internal/security"
	"gargoyle/internal/system"
)

type Dependencies struct {
	MeshConfig MeshConfig
	Services   ServiceControl
	Network    config.NetworkConfig
	Storage    StorageConfig
	Emulate    config.EmulateConfig
	Tunnel     config.TunnelConfig
	Mail       config.MailConfig
	HomeDir    string
}

type MeshConfig struct {
	RelayURL      string
	OnionDepth    int
	MetadataLevel string
	Transport     string
	PaddingBytes  int
}

type ServiceControl interface {
	StartRelay(listen string) error
	StopRelay() error
	StartDoH(listen, url string) error
	StopDoH() error
	StartEmulate(app string, args []string, cfg config.EmulateConfig, home string) error
	StopEmulate() error
	StartTunnel(cfg config.TunnelConfig, service string, port int, home string) error
	StopTunnel() error
	StartMailSink(listen, dataDir string) error
	StopMailSink() error
	StartMailLocal() error
	StopMailLocal() error
	StartMailMesh(listen, psk, pskFile, transport, dataDir string) error
	StopMailMesh() error
	StartHub(listen, dataDir string) error
	StopHub() error
	StartProxy(engine, configPath string) error
	StopProxy() error
}

type StorageConfig struct {
	USBReadOnly bool
}

func RegisterBuiltins(e *Engine, deps Dependencies) {
	e.Register("print", func(ctx *Context, args []string) error {
		ctx.Out(strings.Join(args, " "))
		return nil
	})
	e.Register("set", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		ctx.Vars[args[0]] = strings.Join(args[1:], " ")
		return nil
	})
	e.Register("sleep", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 1); err != nil {
			return err
		}
		ms, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		return nil
	})
	e.Register("file.read", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 1); err != nil {
			return err
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		ctx.Out(string(data))
		return nil
	})
	e.Register("file.write", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		path := args[0]
		if err := guardWritablePath(path, deps.Storage.USBReadOnly); err != nil {
			return err
		}
		content := strings.Join(args[1:], " ")
		return os.WriteFile(path, []byte(content), 0600)
	})
	e.Register("file.append", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		if err := guardWritablePath(args[0], deps.Storage.USBReadOnly); err != nil {
			return err
		}
		f, err := os.OpenFile(args[0], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(strings.Join(args[1:], " ") + "\n")
		return err
	})
	e.Register("file.copy", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		src, dst := args[0], args[1]
		if err := guardWritablePath(dst, deps.Storage.USBReadOnly); err != nil {
			return err
		}
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	e.Register("file.move", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		if err := guardWritablePath(args[0], deps.Storage.USBReadOnly); err != nil {
			return err
		}
		if err := guardWritablePath(args[1], deps.Storage.USBReadOnly); err != nil {
			return err
		}
		return os.Rename(args[0], args[1])
	})
	e.Register("file.delete", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 1); err != nil {
			return err
		}
		if err := guardWritablePath(args[0], deps.Storage.USBReadOnly); err != nil {
			return err
		}
		return os.RemoveAll(args[0])
	})
	e.Register("net.apply", func(ctx *Context, _ []string) error {
		result := system.ApplyNetwork(deps.Network, deps.HomeDir)
		for _, info := range result.Infos {
			ctx.Out(info)
		}
		for _, warn := range result.Warnings {
			ctx.Err(warn)
		}
		return nil
	})
	e.Register("mesh.send", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 4); err != nil {
			return err
		}
		src := args[0]
		dst := args[1]
		target := args[2]
		psk := args[3]
		depth := deps.MeshConfig.OnionDepth
		if len(args) > 4 {
			if v, err := strconv.Atoi(args[4]); err == nil {
				depth = v
			}
		}
		opts := mesh.SendOptions{
			Security:      true,
			MetadataLevel: deps.MeshConfig.MetadataLevel,
			Route:         "direct",
			Target:        target,
			PSK:           psk,
			Depth:         depth,
			Transport:     deps.MeshConfig.Transport,
			PaddingBytes:  deps.MeshConfig.PaddingBytes,
		}
		return mesh.Send(context.Background(), src, dst, opts)
	})
	e.Register("mesh.recv", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		listen := args[0]
		outDir := args[1]
		if err := guardWritablePath(outDir, deps.Storage.USBReadOnly); err != nil {
			return err
		}
		psk := ""
		if len(args) > 2 {
			psk = args[2]
		}
		_, err := mesh.Receive(context.Background(), mesh.ReceiveOptions{
			Listen:    listen,
			OutDir:    outDir,
			PSK:       psk,
			Transport: deps.MeshConfig.Transport,
		})
		return err
	})
	e.Register("relay.start", func(ctx *Context, args []string) error {
		listen := ":18080"
		if len(args) > 0 {
			listen = args[0]
		}
		return deps.Services.StartRelay(listen)
	})
	e.Register("relay.stop", func(ctx *Context, _ []string) error {
		return deps.Services.StopRelay()
	})
	e.Register("doh.start", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 1); err != nil {
			return err
		}
		listen := "127.0.0.1:5353"
		url := args[0]
		if len(args) > 1 {
			listen = args[1]
		}
		return deps.Services.StartDoH(listen, url)
	})
	e.Register("doh.stop", func(ctx *Context, _ []string) error {
		return deps.Services.StopDoH()
	})
	e.Register("exec", func(ctx *Context, args []string) error {
		if len(args) == 0 {
			return errors.New("exec requires a command")
		}
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			ctx.Out(string(out))
		}
		return err
	})
	e.Register("shell", func(ctx *Context, args []string) error {
		if len(args) == 0 {
			return errors.New("shell requires a command line")
		}
		line := strings.Join(args, " ")
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", line)
		} else {
			cmd = exec.Command("sh", "-lc", line)
		}
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			ctx.Out(string(out))
		}
		return err
	})
	e.Register("crypto.encrypt", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 3); err != nil {
			return err
		}
		src := args[0]
		dst := args[1]
		if err := guardWritablePath(dst, deps.Storage.USBReadOnly); err != nil {
			return err
		}
		psk := []byte(args[2])
		depth := 1
		chunkSize := security.DefaultChunkSize
		if len(args) > 3 {
			if v, err := strconv.Atoi(args[3]); err == nil && v > 0 {
				depth = v
			}
		}
		if len(args) > 4 {
			if v, err := strconv.Atoi(args[4]); err == nil && v > 0 {
				chunkSize = v
			}
		}
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()

		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()

		header, salt, nonceBase, err := security.NewStreamHeader(chunkSize, depth)
		if err != nil {
			return err
		}
		if err := writeJSONHeader(out, header); err != nil {
			return err
		}
		return security.EncryptStream(in, out, psk, nonceBase, salt, chunkSize, depth)
	})
	e.Register("crypto.decrypt", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 3); err != nil {
			return err
		}
		src := args[0]
		dst := args[1]
		if err := guardWritablePath(dst, deps.Storage.USBReadOnly); err != nil {
			return err
		}
		psk := []byte(args[2])

		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()

		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()

		var header security.StreamHeader
		if err := readJSONHeader(in, &header); err != nil {
			return err
		}
		salt, nonceBase, _, depth, offset, err := security.ParseStreamHeader(header)
		if err != nil {
			return err
		}
		return security.DecryptStream(in, out, psk, nonceBase, salt, depth, offset)
	})
	e.Register("emulate.run", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 1); err != nil {
			return err
		}
		app := args[0]
		appArgs := []string{}
		if len(args) > 1 {
			appArgs = args[1:]
		}
		return deps.Services.StartEmulate(app, appArgs, deps.Emulate, deps.HomeDir)
	})
	e.Register("emulate.stop", func(ctx *Context, _ []string) error {
		return deps.Services.StopEmulate()
	})
	e.Register("tunnel.expose", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		service := args[0]
		port, err := strconv.Atoi(args[1])
		if err != nil || port <= 0 {
			return errors.New("port must be number")
		}
		if len(args) > 2 && args[2] != "" {
			cfg := deps.Tunnel
			cfg.Token = args[2]
			return deps.Services.StartTunnel(cfg, service, port, deps.HomeDir)
		}
		return deps.Services.StartTunnel(deps.Tunnel, service, port, deps.HomeDir)
	})
	e.Register("tunnel.stop", func(ctx *Context, _ []string) error {
		return deps.Services.StopTunnel()
	})
	e.Register("mail.start", func(ctx *Context, _ []string) error {
		if deps.Mail.Sink {
			if err := deps.Services.StartMailSink(deps.Mail.SinkListen, filepath.Join(deps.HomeDir, "data")); err != nil {
				return err
			}
		}
		if deps.Mail.LocalServer {
			if err := deps.Services.StartMailLocal(); err != nil {
				return err
			}
		}
		if deps.Mail.MeshEnabled {
			if err := deps.Services.StartMailMesh(deps.Mail.MeshListen, deps.Mail.MeshPSK, deps.Mail.MeshPSKFile, deps.MeshConfig.Transport, filepath.Join(deps.HomeDir, "data")); err != nil {
				return err
			}
		}
		return nil
	})
	e.Register("mesh.chat", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 3); err != nil {
			return err
		}
		target := args[0]
		psk := args[1]
		msg := strings.Join(args[2:], " ")
		opts := mesh.MessageOptions{
			Target:       target,
			PSK:          psk,
			Transport:    deps.MeshConfig.Transport,
			PaddingBytes: deps.MeshConfig.PaddingBytes,
			Security:     true,
			Depth:        deps.MeshConfig.OnionDepth,
			Op:           "chat",
		}
		return mesh.SendMessage(context.Background(), msg, opts)
	})
	e.Register("mesh.clipboard.send", func(ctx *Context, args []string) error {
		if err := RequireArgs(args, 2); err != nil {
			return err
		}
		target := args[0]
		psk := args[1]
		text, err := system.ReadClipboard()
		if err != nil {
			return err
		}
		opts := mesh.MessageOptions{
			Target:       target,
			PSK:          psk,
			Transport:    deps.MeshConfig.Transport,
			PaddingBytes: deps.MeshConfig.PaddingBytes,
			Security:     true,
			Depth:        deps.MeshConfig.OnionDepth,
			Op:           "clipboard",
		}
		return mesh.SendMessage(context.Background(), text, opts)
	})
	e.Register("mail.stop", func(ctx *Context, _ []string) error {
		_ = deps.Services.StopMailSink()
		_ = deps.Services.StopMailLocal()
		_ = deps.Services.StopMailMesh()
		return nil
	})
	e.Register("proxy.start", func(ctx *Context, args []string) error {
		engine := deps.Network.ProxyEngine
		configPath := deps.Network.ProxyConfig
		if len(args) > 0 && args[0] != "" {
			engine = args[0]
		}
		if len(args) > 1 && args[1] != "" {
			configPath = args[1]
		}
		return deps.Services.StartProxy(engine, configPath)
	})
	e.Register("proxy.stop", func(ctx *Context, _ []string) error {
		return deps.Services.StopProxy()
	})
	e.Register("hub.start", func(ctx *Context, args []string) error {
		listen := "127.0.0.1:8080"
		if len(args) > 0 {
			listen = args[0]
		}
		return deps.Services.StartHub(listen, filepath.Join(deps.HomeDir, "data"))
	})
	e.Register("hub.stop", func(ctx *Context, _ []string) error {
		return deps.Services.StopHub()
	})
}

func writeJSONHeader(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > int(^uint32(0)) {
		return errors.New("header too large")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readJSONHeader(r io.Reader, v interface{}) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func guardWritablePath(path string, usbReadOnly bool) error {
	if !usbReadOnly {
		return nil
	}
	home := os.Getenv(paths.EnvHome)
	if home != "" && isUnder(path, home) {
		return nil
	}
	onUSB, err := system.IsPathOnRemovable(path)
	if err != nil {
		return nil
	}
	if onUSB {
		return errors.New("usb read-only mode: write blocked")
	}
	return nil
}

func isUnder(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	if absPath == absRoot {
		return true
	}
	if !strings.HasSuffix(absRoot, string(os.PathSeparator)) {
		absRoot += string(os.PathSeparator)
	}
	return strings.HasPrefix(absPath, absRoot)
}
