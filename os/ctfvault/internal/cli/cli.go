package cli

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gargoyle/internal/config"
	"gargoyle/internal/doh"
	"gargoyle/internal/dsl"
	"gargoyle/internal/logging"
	"gargoyle/internal/mesh"
	"gargoyle/internal/paths"
	"gargoyle/internal/security"
	"gargoyle/internal/services"
	"gargoyle/internal/system"
	"gargoyle/internal/tunnel"
	"gargoyle/internal/tools"
	"gargoyle/internal/ui"
	"gargoyle/internal/version"
)

func Run(app string, args []string) int {
	logger := logging.New()

	fs := flag.NewFlagSet(app, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	configPath := fs.String("config", "", "path to config file")
	homePath := fs.String("home", "", "gargoyle home directory (USB or local folder)")
	runTUI := fs.Bool("tui", false, "launch TUI shell")
	applyNetwork := fs.Bool("apply-network", false, "apply network profile (Linux only)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		usage(app)
		return 2
	}

	if *homePath != "" {
		_ = os.Setenv(paths.EnvHome, *homePath)
	}

	resolvedConfigPath := resolveConfigPath(*configPath)

	cfg, err := config.LoadOptional(resolvedConfigPath)
	if err != nil {
		logger.Printf("config error: %v", err)
		return 1
	}
	_ = cfg
	svc := services.New()

	cmd := remaining[0]
	switch cmd {
	case "start":
		homeDir, identityPath, err := system.EnsureHome(cfg)
		if err != nil {
			logger.Printf("start: %v", err)
			return 1
		}
		if *applyNetwork {
			result := system.ApplyNetwork(cfg.Network, homeDir)
			for _, info := range result.Infos {
				logger.Printf("start: %s", info)
			}
			for _, warn := range result.Warnings {
				logger.Printf("start: %s", warn)
			}
		}
		if *runTUI {
			if err := ui.Run(cfg, homeDir, identityPath, svc); err != nil {
				logger.Printf("tui error: %v", err)
				return 1
			}
			return 0
		}
		logger.Printf("start: ok (home=%s)", homeDir)
		return 0
	case "stop":
		logger.Println("stop: ok (no background services running)")
		return 0
	case "status":
		logger.Println(statusSummary(resolvedConfigPath, cfg))
		return 0
	case "init":
		return runInit(logger, resolvedConfigPath, remaining[1:])
	case "mesh":
		return runMesh(logger, cfg, remaining[1:])
	case "relay":
		return runRelay(logger, remaining[1:])
	case "doh":
		return runDoH(logger, cfg, remaining[1:])
	case "emulate":
		return runEmulate(logger, cfg, svc, remaining[1:])
	case "tunnel":
		return runTunnel(logger, cfg, svc, remaining[1:])
	case "mail":
		return runMail(logger, cfg, svc, remaining[1:])
	case "hub":
		return runHub(logger, cfg, svc, remaining[1:])
	case "proxy":
		return runProxy(logger, cfg, svc, remaining[1:])
	case "tools":
		return runTools(logger, cfg, remaining[1:])
	case "doctor":
		return runDoctor(logger, cfg)
	case "update":
		return runUpdate(logger, cfg, remaining[1:])
	case "telegram":
		return runTelegram(logger, cfg, svc, resolvedConfigPath, remaining[1:])
	case "gateway":
		return runGateway(logger, cfg, remaining[1:])
	case "script":
		return runScript(logger, cfg, svc, remaining[1:])
	case "wipe":
		return runWipe(logger, cfg, remaining[1:])
	case "profile":
		return runProfile(logger, resolvedConfigPath, cfg, remaining[1:])
	case "version":
		fmt.Println(version.Version)
		return 0
	case "help":
		usage(app)
		return 0
	case "help-gargoyle":
		fmt.Print(helpGargoyle)
		return 0
	default:
		logger.Printf("unknown command: %s", cmd)
		usage(app)
		return 2
	}
}

func runMesh(logger *log.Logger, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("mesh: expected subcommand (up|send|recv|status|discover|advertise|chat|clipboard|tun)")
		return 2
	}
	switch args[0] {
	case "up":
		if err := mesh.Up(context.Background()); err != nil {
			logger.Printf("mesh up: %v", err)
			return 1
		}
		logger.Println("mesh up: ok")
		return 0
	case "status":
		s, err := mesh.Status(context.Background())
		if err != nil {
			logger.Printf("mesh status: %v", err)
			return 1
		}
		fmt.Println(s)
		return 0
	case "send":
		return runMeshSend(logger, cfg, args[1:])
	case "recv":
		return runMeshRecv(logger, cfg, args[1:])
	case "discover":
		return runMeshDiscover(logger, cfg, args[1:])
	case "advertise":
		return runMeshAdvertise(logger, cfg, args[1:])
	case "chat":
		return runMeshChat(logger, cfg, args[1:])
	case "clipboard":
		return runMeshClipboard(logger, cfg, args[1:])
	case "tun":
		return runMeshTun(logger, cfg, args[1:])
	default:
		fmt.Println("mesh: expected subcommand (up|send|recv|status|discover|advertise|chat|clipboard|tun)")
		return 2
	}
}

func runInit(logger *log.Logger, configPath string, args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	force := fs.Bool("force", false, "overwrite existing config")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	homeDir, err := paths.HomeDir()
	if err != nil {
		logger.Printf("init: %v", err)
		return 1
	}

	if err := paths.EnsureDir(homeDir); err != nil {
		logger.Printf("init: %v", err)
		return 1
	}

	for _, dir := range []string{
		filepath.Join(homeDir, "data"),
		filepath.Join(homeDir, "downloads"),
		filepath.Join(homeDir, "logs"),
		filepath.Join(homeDir, "keys"),
		filepath.Join(homeDir, "shared"),
	} {
		if err := paths.EnsureDir(dir); err != nil {
			logger.Printf("init: %v", err)
			return 1
		}
	}

	if _, err := os.Stat(configPath); err == nil && !*force {
		logger.Printf("init: config already exists (%s). Use --force to overwrite", configPath)
		return 1
	}
	if err := config.Save(configPath, config.DefaultConfig()); err != nil {
		logger.Printf("init: %v", err)
		return 1
	}

	cfg, err := config.LoadOptional(configPath)
	if err != nil {
		logger.Printf("init: %v", err)
		return 1
	}

	identityPath := paths.ResolveInHome(homeDir, cfg.Security.IdentityKeyPath)
	if _, err := security.EnsureIdentityKey(identityPath, cfg.Security.IdentityLength, cfg.Security.IdentityGroup); err != nil {
		logger.Printf("init: %v", err)
		return 1
	}

	logger.Printf("init: created %s", configPath)
	return 0
}

func runMeshSend(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("mesh send", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	security := fs.Bool("security", false, "enable encrypted stream (MVP)")
	metadata := fs.String("metadata", "standard", "off|standard|max")
	route := fs.String("route", "auto", "auto|direct|relay|onion")
	target := fs.String("to", "", "target host:port")
	psk := fs.String("psk", "", "pre-shared key (string)")
	pskFile := fs.String("psk-file", "", "path to file with pre-shared key")
	relay := fs.String("relay", "", "relay host:port")
	token := fs.String("token", "", "relay token")
	depth := fs.Int("depth", cfg.Mesh.OnionDepth, "encryption layers (1..10)")
	relayChain := fs.String("relay-chain", "", "comma-separated relay chain (host1,host2,...)")
	onion := fs.Bool("onion", false, "enable onion chain mode (requires --relay-chain)")
	transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
	pad := fs.Int("pad", cfg.Mesh.PaddingBytes, "padding bytes after header")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Println("mesh send: usage: mesh send <src> <dst> --to host:port [--security] [--psk/--psk-file] [--pad N]")
		return 2
	}
	if *target == "" && *relay == "" {
		fmt.Println("mesh send: --to or --relay is required")
		return 2
	}
	if *relayChain != "" && *target == "" {
		fmt.Println("mesh send: --relay-chain requires --to")
		return 2
	}
	if *onion && *relayChain == "" {
		fmt.Println("mesh send: --onion requires --relay-chain")
		return 2
	}
	if *onion {
		*route = "onion"
	}

	opts := mesh.SendOptions{
		Security:      *security,
		MetadataLevel: *metadata,
		Route:         *route,
		Target:        *target,
		PSK:           *psk,
		PSKFile:       *pskFile,
		Relay:         *relay,
		Token:         *token,
		Depth:         *depth,
		RelayChain:    *relayChain,
		Transport:     *transport,
		PaddingBytes:  *pad,
	}

	if err := mesh.Send(context.Background(), rest[0], rest[1], opts); err != nil {
		logger.Printf("mesh send: %v", err)
		return 1
	}

	logger.Println("mesh send: ok")
	return 0
}

func runMeshRecv(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("mesh recv", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	listen := fs.String("listen", ":19999", "listen address")
	outDir := fs.String("out", ".", "output directory")
	psk := fs.String("psk", "", "pre-shared key (string)")
	pskFile := fs.String("psk-file", "", "path to file with pre-shared key")
	relay := fs.String("relay", "", "relay host:port")
	token := fs.String("token", "", "relay token")
	transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if cfg.Storage.USBReadOnly {
		path, err := filepath.Abs(*outDir)
		if err == nil {
			if onUSB, err := system.IsPathOnRemovable(path); err == nil && onUSB {
				logger.Printf("mesh recv: usb read-only mode blocks writes to %s", path)
				return 1
			}
		}
	}

	outPath, err := mesh.Receive(context.Background(), mesh.ReceiveOptions{
		Listen:    *listen,
		OutDir:    *outDir,
		PSK:       *psk,
		PSKFile:   *pskFile,
		Relay:     *relay,
		Token:     *token,
		Transport: *transport,
	})
	if err != nil {
		logger.Printf("mesh recv: %v", err)
		return 1
	}

	logger.Printf("mesh recv: saved to %s", outPath)
	return 0
}

func runMeshDiscover(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("mesh discover", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	port := fs.Int("port", cfg.Mesh.DiscoveryPort, "discovery UDP port")
	key := fs.String("key", cfg.Mesh.DiscoveryKey, "discovery key (optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	peers, err := mesh.DiscoverPeers(context.Background(), *port, *key)
	if err != nil {
		logger.Printf("mesh discover: %v", err)
		return 1
	}
	if len(peers) == 0 {
		logger.Println("mesh discover: no peers found")
		return 0
	}
	for _, p := range peers {
		fmt.Println(p)
	}
	return 0
}

func runMeshAdvertise(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("mesh advertise", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	port := fs.Int("port", cfg.Mesh.DiscoveryPort, "discovery UDP port")
	key := fs.String("key", cfg.Mesh.DiscoveryKey, "discovery key (optional)")
	listen := fs.String("listen", ":19999", "advertise mesh listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger.Printf("mesh advertise: udp %d (listen=%s)", *port, *listen)
	if err := mesh.Advertise(context.Background(), *port, *key, *listen); err != nil {
		logger.Printf("mesh advertise: %v", err)
		return 1
	}
	return 0
}

func runMeshChat(logger *log.Logger, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("mesh chat: expected subcommand (send|listen)")
		return 2
	}
	switch args[0] {
	case "send":
		fs := flag.NewFlagSet("mesh chat send", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		target := fs.String("to", "", "target host:port")
		psk := fs.String("psk", "", "pre-shared key")
		pskFile := fs.String("psk-file", "", "path to pre-shared key")
		transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
		pad := fs.Int("pad", cfg.Mesh.PaddingBytes, "padding bytes after header")
		secure := fs.Bool("security", true, "enable encryption")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		msg := strings.Join(fs.Args(), " ")
		if *target == "" || msg == "" {
			fmt.Println("mesh chat send: usage: mesh chat send --to host:port [--psk] <message>")
			return 2
		}
		opts := mesh.MessageOptions{
			Target:       *target,
			PSK:          *psk,
			PSKFile:      *pskFile,
			Transport:    *transport,
			PaddingBytes: *pad,
			Security:     *secure,
			Depth:        cfg.Mesh.OnionDepth,
			Op:           "chat",
		}
		if err := mesh.SendMessage(context.Background(), msg, opts); err != nil {
			logger.Printf("mesh chat send: %v", err)
			return 1
		}
		logger.Println("mesh chat: sent")
		return 0
	case "listen":
		fs := flag.NewFlagSet("mesh chat listen", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		listen := fs.String("listen", ":19997", "listen address")
		psk := fs.String("psk", "", "pre-shared key")
		pskFile := fs.String("psk-file", "", "path to pre-shared key")
		transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		logger.Printf("mesh chat: listening on %s", *listen)
		stop, err := mesh.ListenMessages(mesh.ReceiveOptions{
			Listen:    *listen,
			PSK:       *psk,
			PSKFile:   *pskFile,
			Transport: *transport,
		}, func(op, message string) error {
			if op != "chat" {
				return nil
			}
			fmt.Println(message)
			return nil
		})
		if err != nil {
			logger.Printf("mesh chat listen: %v", err)
			return 1
		}
		_ = stop
		select {}
		return 0
	default:
		fmt.Println("mesh chat: expected subcommand (send|listen)")
		return 2
	}
}

func runMeshClipboard(logger *log.Logger, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("mesh clipboard: expected subcommand (send|listen)")
		return 2
	}
	switch args[0] {
	case "send":
		fs := flag.NewFlagSet("mesh clipboard send", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		target := fs.String("to", "", "target host:port")
		psk := fs.String("psk", "", "pre-shared key")
		pskFile := fs.String("psk-file", "", "path to pre-shared key")
		transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
		pad := fs.Int("pad", cfg.Mesh.PaddingBytes, "padding bytes after header")
		secure := fs.Bool("security", true, "enable encryption")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *target == "" {
			fmt.Println("mesh clipboard send: --to host:port is required")
			return 2
		}
		text, err := system.ReadClipboard()
		if err != nil {
			logger.Printf("clipboard read: %v", err)
			return 1
		}
		opts := mesh.MessageOptions{
			Target:       *target,
			PSK:          *psk,
			PSKFile:      *pskFile,
			Transport:    *transport,
			PaddingBytes: *pad,
			Security:     *secure,
			Depth:        cfg.Mesh.OnionDepth,
			Op:           "clipboard",
		}
		if err := mesh.SendMessage(context.Background(), text, opts); err != nil {
			logger.Printf("mesh clipboard send: %v", err)
			return 1
		}
		logger.Println("mesh clipboard: sent")
		return 0
	case "listen":
		fs := flag.NewFlagSet("mesh clipboard listen", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		listen := fs.String("listen", ":19996", "listen address")
		psk := fs.String("psk", "", "pre-shared key")
		pskFile := fs.String("psk-file", "", "path to pre-shared key")
		transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		logger.Printf("mesh clipboard: listening on %s", *listen)
		stop, err := mesh.ListenMessages(mesh.ReceiveOptions{
			Listen:    *listen,
			PSK:       *psk,
			PSKFile:   *pskFile,
			Transport: *transport,
		}, func(op, message string) error {
			if op != "clipboard" {
				return nil
			}
			return system.WriteClipboard(message)
		})
		if err != nil {
			logger.Printf("mesh clipboard listen: %v", err)
			return 1
		}
		_ = stop
		select {}
		return 0
	default:
		fmt.Println("mesh clipboard: expected subcommand (send|listen)")
		return 2
	}
}

func runMeshTun(logger *log.Logger, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("mesh tun: expected subcommand (serve|connect)")
		return 2
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("mesh tun serve", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		listen := fs.String("listen", ":20100", "listen address")
		dev := fs.String("dev", cfg.Mesh.TunDevice, "tun device name")
		cidr := fs.String("cidr", cfg.Mesh.TunCIDR, "tun CIDR for local")
		peer := fs.String("peer-cidr", cfg.Mesh.TunPeerCIDR, "peer CIDR route")
		psk := fs.String("psk", "", "pre-shared key")
		pskFile := fs.String("psk-file", "", "path to pre-shared key")
		transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		err := mesh.TunServe(context.Background(), mesh.TunOptions{
			Listen:    *listen,
			Device:    *dev,
			CIDR:      *cidr,
			PeerCIDR:  *peer,
			PSK:       *psk,
			PSKFile:   *pskFile,
			Transport: *transport,
		})
		if err != nil {
			logger.Printf("mesh tun serve: %v", err)
			return 1
		}
		return 0
	case "connect":
		fs := flag.NewFlagSet("mesh tun connect", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		target := fs.String("to", "", "target host:port")
		dev := fs.String("dev", cfg.Mesh.TunDevice, "tun device name")
		cidr := fs.String("cidr", cfg.Mesh.TunCIDR, "tun CIDR for local")
		peer := fs.String("peer-cidr", cfg.Mesh.TunPeerCIDR, "peer CIDR route")
		psk := fs.String("psk", "", "pre-shared key")
		pskFile := fs.String("psk-file", "", "path to pre-shared key")
		transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *target == "" {
			fmt.Println("mesh tun connect: --to host:port is required")
			return 2
		}
		err := mesh.TunConnect(context.Background(), mesh.TunOptions{
			Target:    *target,
			Device:    *dev,
			CIDR:      *cidr,
			PeerCIDR:  *peer,
			PSK:       *psk,
			PSKFile:   *pskFile,
			Transport: *transport,
		})
		if err != nil {
			logger.Printf("mesh tun connect: %v", err)
			return 1
		}
		return 0
	default:
		fmt.Println("mesh tun: expected subcommand (serve|connect)")
		return 2
	}
}

func runRelay(logger *log.Logger, args []string) int {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	listen := fs.String("listen", ":18080", "listen address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger.Printf("relay: listening on %s", *listen)
	if err := mesh.RunRelay(context.Background(), *listen); err != nil {
		logger.Printf("relay: %v", err)
		return 1
	}
	return 0
}

func runDoH(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("doh", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	listen := fs.String("listen", cfg.Network.DoHListen, "listen address for DoH proxy")
	url := fs.String("url", cfg.Network.DoHURL, "DoH URL (https://.../dns-query)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *url == "" {
		logger.Println("doh: --url is required (set network.doh_url or pass --url)")
		return 2
	}

	runner := doh.Runner{Listen: *listen, URL: *url}
	logger.Printf("doh: %s", doh.ExplainListen(*listen))
	if err := runner.Run(); err != nil {
		logger.Printf("doh: %v", err)
		logger.Printf("doh: %s", doh.Hint())
		return 1
	}
	return 0
}

func runEmulate(logger *log.Logger, cfg config.Config, svc *services.Manager, args []string) int {
	if len(args) == 0 {
		fmt.Println("emulate: expected subcommand (run|stop|status)")
		return 2
	}
	switch args[0] {
	case "run":
		if len(args) < 2 {
			fmt.Println("emulate run: usage: emulate run <app> [args...]")
			return 2
		}
		home, _, err := system.EnsureHome(cfg)
		if err != nil {
			logger.Printf("emulate: %v", err)
			return 1
		}
		app := args[1]
		appArgs := []string{}
		if len(args) > 2 {
			appArgs = args[2:]
		}
		if err := svc.StartEmulate(app, appArgs, cfg.Emulate, home); err != nil {
			logger.Printf("emulate: %v", err)
			return 1
		}
		logger.Printf("emulate: started %s", app)
		waitWhile(func() bool { return svc.Status().Emulate.Running })
		return 0
	case "stop":
		if err := svc.StopEmulate(); err != nil {
			logger.Printf("emulate: %v", err)
			return 1
		}
		logger.Println("emulate: stopped")
		return 0
	case "status":
		st := svc.Status().Emulate
		fmt.Printf("emulate: running=%v app=%s pid=%d\n", st.Running, st.App, st.PID)
		return 0
	default:
		fmt.Println("emulate: expected subcommand (run|stop|status)")
		return 2
	}
}

func runTunnel(logger *log.Logger, cfg config.Config, svc *services.Manager, args []string) int {
	if len(args) == 0 {
		fmt.Println("tunnel: expected subcommand (expose|stop|status|wss-serve|wss-connect)")
		return 2
	}
	switch args[0] {
	case "expose":
		if len(args) < 3 {
			fmt.Println("tunnel expose: usage: tunnel expose <service> <port> [token]")
			return 2
		}
		localIP := cfg.Tunnel.LocalIP
		rest := make([]string, 0, len(args))
		skipNext := false
		for i := 1; i < len(args); i++ {
			if skipNext {
				skipNext = false
				continue
			}
			arg := args[i]
			if arg == "--local-ip" {
				if i+1 >= len(args) {
					fmt.Println("tunnel expose: --local-ip требует значение")
					return 2
				}
				localIP = args[i+1]
				skipNext = true
				continue
			}
			if strings.HasPrefix(arg, "--local-ip=") {
				localIP = strings.TrimPrefix(arg, "--local-ip=")
				continue
			}
			rest = append(rest, arg)
		}
		if len(rest) < 2 {
			fmt.Println("tunnel expose: usage: tunnel expose <service> <port> [token]")
			return 2
		}
		service := rest[0]
		port, err := strconv.Atoi(rest[1])
		if err != nil || port <= 0 {
			fmt.Println("tunnel expose: port must be number")
			return 2
		}
		token := ""
		if len(rest) > 2 {
			token = rest[2]
		}
		if token != "" {
			cfg.Tunnel.Token = token
		}
		if localIP != "" {
			cfg.Tunnel.LocalIP = localIP
		}
		home, _, err := system.EnsureHome(cfg)
		if err != nil {
			logger.Printf("tunnel: %v", err)
			return 1
		}
		if err := svc.StartTunnel(cfg.Tunnel, service, port, home); err != nil {
			logger.Printf("tunnel: %v", err)
			return 1
		}
		logger.Printf("tunnel: %s -> %s (%d)", service, cfg.Tunnel.Server, port)
		waitWhile(func() bool { return svc.Status().TunnelRunning })
		return 0
	case "stop":
		if err := svc.StopTunnel(); err != nil {
			logger.Printf("tunnel: %v", err)
			return 1
		}
		logger.Println("tunnel: stopped")
		return 0
	case "status":
		st := svc.Status()
		fmt.Printf("tunnel: running=%v type=%s server=%s service=%s port=%d pid=%d\n",
			st.TunnelRunning, st.TunnelType, st.TunnelServer, st.TunnelService, st.TunnelPort, st.TunnelPID)
		return 0
	case "wss-serve":
		fs := flag.NewFlagSet("tunnel wss-serve", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		listen := fs.String("listen", ":8443", "wss listen address")
		public := fs.String("public", ":8080", "public tcp listen for clients")
		service := fs.String("service", "service", "service name")
		token := fs.String("token", "", "shared token")
		cert := fs.String("cert", "", "tls cert path (optional)")
		key := fs.String("key", "", "tls key path (optional)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *token == "" {
			logger.Println("tunnel wss-serve: --token is required")
			return 2
		}
		ctx := context.Background()
		err := tunnel.RunWSSServer(ctx, tunnel.WSServer{
			Listen:  *listen,
			Public:  *public,
			Service: *service,
			Token:   *token,
			Cert:    *cert,
			Key:     *key,
		})
		if err != nil {
			logger.Printf("tunnel wss-serve: %v", err)
			return 1
		}
		return 0
	case "wss-connect":
		fs := flag.NewFlagSet("tunnel wss-connect", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		server := fs.String("server", "", "wss://host:port")
		service := fs.String("service", "service", "service name")
		token := fs.String("token", "", "shared token")
		local := fs.String("local", "127.0.0.1:8080", "local target host:port")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *server == "" || *token == "" {
			logger.Println("tunnel wss-connect: --server and --token are required")
			return 2
		}
		ctx := context.Background()
		err := tunnel.RunWSSClient(ctx, tunnel.WSSClient{
			Server:  *server,
			Service: *service,
			Token:   *token,
			Local:   *local,
		})
		if err != nil {
			logger.Printf("tunnel wss-connect: %v", err)
			return 1
		}
		return 0
	default:
		fmt.Println("tunnel: expected subcommand (expose|stop|status|wss-serve|wss-connect)")
		return 2
	}
}

func runMail(logger *log.Logger, cfg config.Config, svc *services.Manager, args []string) int {
	if len(args) == 0 {
		fmt.Println("mail: expected subcommand (start|stop|status|send)")
		return 2
	}
	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("mail start", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		mode := fs.String("mode", cfg.Mail.Mode, "local|tunnel")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		home, _, err := system.EnsureHome(cfg)
		if err != nil {
			logger.Printf("mail: %v", err)
			return 1
		}
		dataDir := filepath.Join(home, "data")
		if cfg.Mail.Sink {
			if err := svc.StartMailSink(cfg.Mail.SinkListen, dataDir); err != nil {
				logger.Printf("mail sink: %v", err)
			}
		}
		if cfg.Mail.LocalServer {
			if err := svc.StartMailLocal(); err != nil {
				logger.Printf("mail local: %v", err)
			}
		}
		if cfg.Mail.MeshEnabled {
			if err := svc.StartMailMesh(cfg.Mail.MeshListen, cfg.Mail.MeshPSK, cfg.Mail.MeshPSKFile, cfg.Mesh.Transport, dataDir); err != nil {
				logger.Printf("mail mesh: %v", err)
			}
		}
		if *mode == "tunnel" && cfg.Tunnel.Server != "" {
			port := parseListenPort(cfg.Mail.SinkListen)
			if port > 0 {
				_ = svc.StartTunnel(cfg.Tunnel, "mail", port, home)
			}
		}
		logger.Println("mail: running")
		waitWhile(func() bool {
			st := svc.Status()
			return st.MailSinkRunning || st.MailLocalRunning || st.MailMeshRunning || st.TunnelRunning
		})
		return 0
	case "stop":
		_ = svc.StopMailSink()
		_ = svc.StopMailLocal()
		_ = svc.StopMailMesh()
		logger.Println("mail: stopped")
		return 0
	case "status":
		st := svc.Status()
		fmt.Printf("mail: sink=%v listen=%s local=%v mesh=%v mesh_listen=%s\n",
			st.MailSinkRunning, st.MailSinkListen, st.MailLocalRunning, st.MailMeshRunning, st.MailMeshListen)
		return 0
	case "send":
		return runMailSend(logger, cfg, args[1:])
	default:
		fmt.Println("mail: expected subcommand (start|stop|status|send)")
		return 2
	}
}

func runMailSend(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("mail send", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	to := fs.String("to", "", "recipient address")
	from := fs.String("from", "gargoyle@local", "sender address")
	subject := fs.String("subject", "Gargoyle mail", "subject")
	body := fs.String("body", "", "body text")
	file := fs.String("file", "", "path to body file")
	target := fs.String("mesh", "", "mesh target host:port")
	psk := fs.String("psk", cfg.Mail.MeshPSK, "pre-shared key")
	pskFile := fs.String("psk-file", cfg.Mail.MeshPSKFile, "path to psk file")
	transport := fs.String("transport", cfg.Mesh.Transport, "tcp|tls")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *to == "" || *target == "" {
		fmt.Println("mail send: --to and --mesh are required")
		return 2
	}
	content := *body
	if *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			logger.Printf("mail send: %v", err)
			return 1
		}
		content = string(data)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", *from, *to, *subject, content)
	tmp, err := os.CreateTemp("", "gargoyle-mail-*.eml")
	if err != nil {
		logger.Printf("mail send: %v", err)
		return 1
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(msg); err != nil {
		_ = tmp.Close()
		logger.Printf("mail send: %v", err)
		return 1
	}
	_ = tmp.Close()

	opts := mesh.SendOptions{
		Security:      true,
		MetadataLevel: cfg.Mesh.MetadataLevel,
		Route:         "direct",
		Target:        *target,
		PSK:           *psk,
		PSKFile:       *pskFile,
		Depth:         cfg.Mesh.OnionDepth,
		Transport:     *transport,
		PaddingBytes:  cfg.Mesh.PaddingBytes,
	}
	if err := mesh.Send(context.Background(), tmp.Name(), *to+".eml", opts); err != nil {
		logger.Printf("mail send: %v", err)
		return 1
	}
	logger.Println("mail send: ok")
	return 0
}

func runProxy(logger *log.Logger, cfg config.Config, svc *services.Manager, args []string) int {
	if len(args) == 0 {
		fmt.Println("proxy: expected subcommand (start|stop|status)")
		return 2
	}
	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("proxy start", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		engine := fs.String("engine", cfg.Network.ProxyEngine, "sing-box|xray|hiddify")
		configPath := fs.String("config", cfg.Network.ProxyConfig, "path to proxy config")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := svc.StartProxy(*engine, *configPath); err != nil {
			logger.Printf("proxy: %v", err)
			return 1
		}
		logger.Printf("proxy: started (%s)", *engine)
		waitWhile(func() bool { return svc.Status().ProxyRunning })
		return 0
	case "stop":
		if err := svc.StopProxy(); err != nil {
			logger.Printf("proxy: %v", err)
			return 1
		}
		logger.Println("proxy: stopped")
		return 0
	case "status":
		st := svc.Status()
		fmt.Printf("proxy: running=%v engine=%s pid=%d\n", st.ProxyRunning, st.ProxyEngine, st.ProxyPID)
		return 0
	default:
		fmt.Println("proxy: expected subcommand (start|stop|status)")
		return 2
	}
}

func runTools(logger *log.Logger, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("tools: expected subcommand (list|install|edit)")
		return 2
	}
	home, _, err := system.EnsureHome(cfg)
	if err != nil {
		logger.Printf("tools: %v", err)
		return 1
	}
	path := paths.ResolveInHome(home, cfg.Tools.File)
	if err := tools.EnsureDefault(path); err != nil {
		logger.Printf("tools: %v", err)
		return 1
	}
	switch args[0] {
	case "list":
		pack, err := tools.Load(path)
		if err != nil {
			logger.Printf("tools: %v", err)
			return 1
		}
		fmt.Printf("pack: %s\n", pack.Pack)
		for _, tool := range pack.Tools {
			if tool.Name == "" {
				continue
			}
			fmt.Println("-", tool.Name)
		}
		return 0
	case "install":
		pack, err := tools.Load(path)
		if err != nil {
			logger.Printf("tools: %v", err)
			return 1
		}
		logs, _ := tools.InstallAll(pack)
		for _, line := range logs {
			logger.Println(line)
		}
		return 0
	case "edit":
		editor := os.Getenv("EDITOR")
		if editor == "" {
			if runtime.GOOS == "windows" {
				editor = "notepad"
			} else {
				editor = "nano"
			}
		}
		cmd := exec.Command(editor, path)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			logger.Printf("tools: %v", err)
			return 1
		}
		return 0
	default:
		fmt.Println("tools: expected subcommand (list|install|edit)")
		return 2
	}
}

func runDoctor(logger *log.Logger, cfg config.Config) int {
	results := system.RunDoctor(cfg)
	fmt.Print(system.FormatDoctor(results))
	return 0
}

func runUpdate(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	url := fs.String("url", cfg.Update.URL, "update URL")
	sum := fs.String("sha256", "", "expected sha256 (optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path, err := system.UpdateBinary(system.UpdateOptions{URL: *url, SHA256: *sum})
	if err != nil {
		logger.Printf("update: %v", err)
		return 1
	}
	if runtime.GOOS == "windows" {
		logger.Printf("update: downloaded to %s (rename on next start)", path)
		return 0
	}
	logger.Printf("update: installed at %s", path)
	return 0
}

func runTelegram(logger *log.Logger, cfg config.Config, svc *services.Manager, cfgPath string, args []string) int {
	if len(args) == 0 {
		fmt.Println("telegram: expected subcommand (start|stop|status)")
		return 2
	}
	switch args[0] {
	case "start":
		home, identityPath, err := system.EnsureHome(cfg)
		if err != nil {
			logger.Printf("telegram: %v", err)
			return 1
		}
		if err := svc.StartTelegram(cfg.Telegram, cfgPath, home, identityPath); err != nil {
			logger.Printf("telegram: %v", err)
			return 1
		}
		logger.Println("telegram: started")
		waitWhile(func() bool { return svc.Status().TelegramRunning })
		return 0
	case "stop":
		if err := svc.StopTelegram(); err != nil {
			logger.Printf("telegram: %v", err)
			return 1
		}
		logger.Println("telegram: stopped")
		return 0
	case "status":
		st := svc.Status()
		fmt.Printf("telegram: running=%v err=%s\n", st.TelegramRunning, st.TelegramError)
		return 0
	default:
		fmt.Println("telegram: expected subcommand (start|stop|status)")
		return 2
	}
}

func runGateway(logger *log.Logger, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("gateway: expected subcommand (start|stop)")
		return 2
	}
	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("gateway start", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		wan := fs.String("wan", "", "wan interface (e.g. wlan0)")
		gwNS := fs.String("gw-ns", "gargoyle-gw", "gateway namespace")
		wsNS := fs.String("ws-ns", "gargoyle-ws", "workstation namespace")
		trans := fs.Int("trans-port", cfg.Network.TorTransPort, "Tor TransPort")
		dns := fs.Int("dns-port", cfg.Network.TorDNSPort, "Tor DNSPort")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *wan == "" {
			logger.Println("gateway start: --wan is required")
			return 2
		}
		if cfg.Network.TorAlwaysOn || cfg.Network.TorStrict {
			home, _, _ := system.EnsureHome(cfg)
			_ = system.ApplyNetwork(cfg.Network, home)
		}
		err := system.StartGateway(system.GatewayOptions{
			WanInterface: *wan,
			GwNS:         *gwNS,
			WsNS:         *wsNS,
			TransPort:    *trans,
			DNSPort:      *dns,
		})
		if err != nil {
			logger.Printf("gateway start: %v", err)
			return 1
		}
		logger.Printf("gateway: started (%s/%s)", *gwNS, *wsNS)
		return 0
	case "stop":
		fs := flag.NewFlagSet("gateway stop", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		gwNS := fs.String("gw-ns", "gargoyle-gw", "gateway namespace")
		wsNS := fs.String("ws-ns", "gargoyle-ws", "workstation namespace")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		err := system.StopGateway(system.GatewayOptions{
			GwNS: *gwNS,
			WsNS: *wsNS,
		})
		if err != nil {
			logger.Printf("gateway stop: %v", err)
			return 1
		}
		logger.Println("gateway: stopped")
		return 0
	default:
		fmt.Println("gateway: expected subcommand (start|stop)")
		return 2
	}
}

func runHub(logger *log.Logger, cfg config.Config, svc *services.Manager, args []string) int {
	if len(args) == 0 {
		fmt.Println("hub: expected subcommand (start|stop|status)")
		return 2
	}
	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("hub start", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		listen := fs.String("listen", "127.0.0.1:8080", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		home, _, err := system.EnsureHome(cfg)
		if err != nil {
			logger.Printf("hub: %v", err)
			return 1
		}
		dataDir := filepath.Join(home, "data")
		if err := svc.StartHub(*listen, dataDir); err != nil {
			logger.Printf("hub: %v", err)
			return 1
		}
		logger.Printf("hub: listening on %s", *listen)
		waitWhile(func() bool { return svc.Status().HubRunning })
		return 0
	case "stop":
		if err := svc.StopHub(); err != nil {
			logger.Printf("hub: %v", err)
			return 1
		}
		logger.Println("hub: stopped")
		return 0
	case "status":
		st := svc.Status()
		fmt.Printf("hub: running=%v listen=%s\n", st.HubRunning, st.HubListen)
		return 0
	default:
		fmt.Println("hub: expected subcommand (start|stop|status)")
		return 2
	}
}

func runScript(logger *log.Logger, cfg config.Config, svc *services.Manager, args []string) int {
	if len(args) == 0 {
		fmt.Println("script: expected subcommand (run)")
		return 2
	}
	switch args[0] {
	case "run":
		if len(args) < 2 {
			fmt.Println("script run: usage: script run <file.gsl>")
			return 2
		}
		engine := dsl.NewEngine()
		deps := dsl.Dependencies{
			MeshConfig: dsl.MeshConfig{
				RelayURL:      cfg.Mesh.RelayURL,
				OnionDepth:    cfg.Mesh.OnionDepth,
				MetadataLevel: cfg.Mesh.MetadataLevel,
				Transport:     cfg.Mesh.Transport,
				PaddingBytes:  cfg.Mesh.PaddingBytes,
			},
			Services: svc,
			Network: cfg.Network,
			Storage: dsl.StorageConfig{
				USBReadOnly: cfg.Storage.USBReadOnly,
			},
			Emulate: cfg.Emulate,
			Tunnel:  cfg.Tunnel,
			Mail:    cfg.Mail,
			HomeDir: homeDirOrDefault(cfg),
		}
		dsl.RegisterBuiltins(engine, deps)
		ctx := &dsl.Context{
			Vars: map[string]string{},
			Out:  func(s string) { logger.Println(s) },
			Err:  func(s string) { logger.Printf("script: %s", s) },
		}
		if err := engine.RunFile(ctx, args[1]); err != nil {
			logger.Printf("script run: %v", err)
			return 1
		}
		return 0
	default:
		fmt.Println("script: expected subcommand (run)")
		return 2
	}
}

func runWipe(logger *log.Logger, cfg config.Config, args []string) int {
	fs := flag.NewFlagSet("wipe", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	emergency := fs.Bool("emergency", false, "emergency wipe (keep identity key)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	homeDir, identityPath, err := system.EnsureHome(cfg)
	if err != nil {
		logger.Printf("wipe: %v", err)
		return 1
	}

	mode := system.WipeNormal
	if *emergency {
		mode = system.WipeEmergency
	}
	if err := system.Wipe(homeDir, identityPath, mode); err != nil {
		logger.Printf("wipe: %v", err)
		return 1
	}

	logger.Printf("wipe: ok (mode=%v)", mode)
	return 0
}

func runProfile(logger *log.Logger, configPath string, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("profile: expected subcommand (ctf-safe)")
		return 2
	}
	switch args[0] {
	case "ctf-safe":
		updated := applyCTFSafe(cfg)
		if err := config.Save(configPath, updated); err != nil {
			logger.Printf("profile: %v", err)
			return 1
		}
		logger.Printf("profile: ctf-safe applied (%s)", configPath)
		return 0
	default:
		fmt.Println("profile: expected subcommand (ctf-safe)")
		return 2
	}
}

func usage(app string) {
	fmt.Printf("%s <command> [options]\n", app)
	fmt.Println("Global flags:")
	fmt.Println("  --config <path>    path to config file (default: <home>/gargoyle.yaml)")
	fmt.Println("  --home <path>      gargoyle home directory (USB or local folder)")
	fmt.Println("  --tui              launch TUI on start")
	fmt.Println("  --apply-network    apply network profile (Linux only)")
	fmt.Println("Commands:")
	fmt.Println("  start [--tui]")
	fmt.Println("  stop")
	fmt.Println("  status")
	fmt.Println("  init [--force]")
	fmt.Println("  mesh up|send|recv|status")
	fmt.Println("  mesh discover|advertise|chat|clipboard|tun")
	fmt.Println("  relay --listen :18080")
	fmt.Println("  doh --listen 127.0.0.1:5353 --url https://.../dns-query")
	fmt.Println("  emulate run|stop|status")
	fmt.Println("  tunnel expose|stop|status")
	fmt.Println("  tunnel wss-serve|wss-connect")
	fmt.Println("  mail start|stop|status|send")
	fmt.Println("  hub start|stop|status")
	fmt.Println("  proxy start|stop|status")
	fmt.Println("  tools list|install|edit")
	fmt.Println("  doctor")
	fmt.Println("  update --url https://... --sha256 <sum>")
	fmt.Println("  telegram start|stop|status")
	fmt.Println("  gateway start|stop")
	fmt.Println("  script run <file.gsl>")
	fmt.Println("  profile ctf-safe")
	fmt.Println("  wipe [--emergency]")
	fmt.Println("  version")
	fmt.Println("  help")
	fmt.Println("  help-gargoyle")
}

func waitWhile(cond func() bool) {
	for cond() {
		time.Sleep(500 * time.Millisecond)
	}
}

func parseListenPort(listen string) int {
	parts := strings.Split(listen, ":")
	if len(parts) != 2 {
		return 0
	}
	port, _ := strconv.Atoi(parts[1])
	return port
}

func homeDirOrDefault(cfg config.Config) string {
	home, _, err := system.EnsureHome(cfg)
	if err != nil {
		return ""
	}
	return home
}

func applyCTFSafe(cfg config.Config) config.Config {
	cfg.Network.TorAlwaysOn = true
	cfg.Network.TorStrict = false
	cfg.Network.MACSpoof = true
	cfg.Network.PortsOpen = false
	cfg.Storage.USBEnabled = false
	cfg.Storage.USBReadOnly = true
	cfg.Network.Mode = "direct"
	return cfg
}

func resolveConfigPath(path string) string {
	if path != "" {
		return path
	}
	homeDir, err := paths.HomeDir()
	if err != nil {
		return "gargoyle.yaml"
	}
	_ = paths.EnsureDir(homeDir)
	return filepath.Join(homeDir, "gargoyle.yaml")
}

//go:embed help_gargoyle.txt
var helpGargoyle string

func statusSummary(configPath string, cfg config.Config) string {
	homeDir, err := paths.HomeDir()
	if err != nil {
		return fmt.Sprintf("status: ok (config: %s)", configPath)
	}
	identityPath := paths.ResolveInHome(homeDir, cfg.Security.IdentityKeyPath)
	identityState := "missing"
	if _, err := os.Stat(identityPath); err == nil {
		identityState = "present"
	}
	return fmt.Sprintf("status: ok (home: %s, config: %s, identity: %s)", homeDir, configPath, identityState)
}
