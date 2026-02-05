package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"ctfvault/internal/config"
	"ctfvault/internal/doh"
	"ctfvault/internal/logging"
	"ctfvault/internal/mesh"
	"ctfvault/internal/paths"
	"ctfvault/internal/security"
	"ctfvault/internal/system"
	"ctfvault/internal/ui"
	"ctfvault/internal/version"
)

func Run(app string, args []string) int {
	logger := logging.New()

	fs := flag.NewFlagSet(app, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	configPath := fs.String("config", "", "path to config file")
	homePath := fs.String("home", "", "ctfvault home directory (USB or local folder)")
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

	cmd := remaining[0]
	switch cmd {
	case "start":
		homeDir, identityPath, err := system.EnsureHome(cfg)
		if err != nil {
			logger.Printf("start: %v", err)
			return 1
		}
		if *applyNetwork {
			result := system.ApplyNetwork(cfg.Network.DNSProfile, cfg.Network.DNSCustom, cfg.Network.MACSpoof, cfg.Network.PortsOpen)
			for _, warn := range result.Warnings {
				logger.Printf("start: %s", warn)
			}
		}
		if *runTUI {
			if err := ui.Run(cfg, homeDir, identityPath); err != nil {
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
	case "wipe":
		return runWipe(logger, cfg, remaining[1:])
	case "version":
		fmt.Println(version.Version)
		return 0
	case "help":
		usage(app)
		return 0
	default:
		logger.Printf("unknown command: %s", cmd)
		usage(app)
		return 2
	}
}

func runMesh(logger *log.Logger, cfg config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Println("mesh: expected subcommand (up|send|recv|status)")
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
		return runMeshRecv(logger, args[1:])
	default:
		fmt.Println("mesh: expected subcommand (up|send|recv|status)")
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

	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Println("mesh send: usage: mesh send <src> <dst> --to host:port [--security] [--psk/--psk-file]")
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
	}

	if err := mesh.Send(context.Background(), rest[0], rest[1], opts); err != nil {
		logger.Printf("mesh send: %v", err)
		return 1
	}

	logger.Println("mesh send: ok")
	return 0
}

func runMeshRecv(logger *log.Logger, args []string) int {
	fs := flag.NewFlagSet("mesh recv", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	listen := fs.String("listen", ":19999", "listen address")
	outDir := fs.String("out", ".", "output directory")
	psk := fs.String("psk", "", "pre-shared key (string)")
	pskFile := fs.String("psk-file", "", "path to file with pre-shared key")
	relay := fs.String("relay", "", "relay host:port")
	token := fs.String("token", "", "relay token")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	outPath, err := mesh.Receive(context.Background(), mesh.ReceiveOptions{
		Listen:  *listen,
		OutDir:  *outDir,
		PSK:     *psk,
		PSKFile: *pskFile,
		Relay:   *relay,
		Token:   *token,
	})
	if err != nil {
		logger.Printf("mesh recv: %v", err)
		return 1
	}

	logger.Printf("mesh recv: saved to %s", outPath)
	return 0
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

func usage(app string) {
	fmt.Printf("%s <command> [options]\n", app)
	fmt.Println("Global flags:")
	fmt.Println("  --config <path>    path to config file (default: <home>/ctfvault.yaml)")
	fmt.Println("  --home <path>      ctfvault home directory (USB or local folder)")
	fmt.Println("  --tui              launch TUI on start")
	fmt.Println("  --apply-network    apply network profile (Linux only)")
	fmt.Println("Commands:")
	fmt.Println("  start [--tui]")
	fmt.Println("  stop")
	fmt.Println("  status")
	fmt.Println("  init [--force]")
	fmt.Println("  mesh up|send|recv|status")
	fmt.Println("  relay --listen :18080")
	fmt.Println("  doh --listen 127.0.0.1:5353 --url https://.../dns-query")
	fmt.Println("  wipe [--emergency]")
	fmt.Println("  version")
	fmt.Println("  help")
}

func resolveConfigPath(path string) string {
	if path != "" {
		return path
	}
	homeDir, err := paths.HomeDir()
	if err != nil {
		return "ctfvault.yaml"
	}
	_ = paths.EnsureDir(homeDir)
	return filepath.Join(homeDir, "ctfvault.yaml")
}

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
