package system

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gargoyle/internal/config"
	"gargoyle/internal/paths"
)

type NetResult struct {
	Infos    []string
	Warnings []string
}

func PreLockFullAnon(cfg config.NetworkConfig) NetResult {
	result := NetResult{}
	if runtime.GOOS != "linux" {
		result.Warnings = append(result.Warnings, "prelock: supported on Linux only (skip)")
		return result
	}

	if err := setNetworking(false); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("prelock: disable network: %v", err))
	}
	if err := applyTorFirewall(cfg); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("prelock: tor firewall: %v", err))
	} else {
		result.Infos = append(result.Infos, "prelock: tor firewall applied")
	}
	if err := setNetworking(true); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("prelock: enable network: %v", err))
	}

	return result
}

func ApplyNetwork(cfg config.NetworkConfig, home string) NetResult {
	result := NetResult{}
	if runtime.GOOS != "linux" {
		result.Warnings = append(result.Warnings, "network apply: supported on Linux only (skip)")
		return result
	}

	if err := applyDNS(cfg.DNSProfile, cfg.DNSCustom); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("dns apply: %v", err))
	}

	if cfg.TorAlwaysOn || cfg.TorStrict {
		if err := ensureTorRunning(cfg, home); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("tor: %v", err))
		}
	}
	if cfg.TorStrict {
		if err := applyTorFirewall(cfg); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("tor firewall: %v", err))
		}
	}

	switch cfg.Mode {
	case "", "direct":
	case "vpn":
		if err := applyVPN(cfg.VPNType, cfg.VPNProfile); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("vpn: %v", err))
		}
	case "gateway":
		if err := applyGateway(cfg.GatewayIP); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("gateway: %v", err))
		}
	case "proxy":
		if err := applyProxy(cfg.ProxyEngine, cfg.ProxyConfig); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("proxy: %v", err))
		}
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("unknown network mode: %s", cfg.Mode))
	}

	if cfg.MACSpoof {
		if err := applyMacRandom(); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("mac spoof: %v", err))
		}
	}

	if !cfg.PortsOpen {
		if err := applyFirewall(); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("firewall: %v", err))
		}
	}

	info, warns := leakCheck(cfg.Mode, cfg.TorAlwaysOn || cfg.TorStrict)
	result.Infos = append(result.Infos, info...)
	result.Warnings = append(result.Warnings, warns...)

	return result
}

func setNetworking(enabled bool) error {
	state := "off"
	if enabled {
		state = "on"
	}

	if nmcli, err := exec.LookPath("nmcli"); err == nil {
		cmd := exec.Command(nmcli, "networking", state)
		return cmd.Run()
	}

	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return errors.New("nmcli/ip not found")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if enabled {
			_ = exec.Command(ipPath, "link", "set", iface.Name, "up").Run()
		} else {
			_ = exec.Command(ipPath, "link", "set", iface.Name, "down").Run()
		}
	}
	return nil
}

func applyDNS(profile, custom string) error {
	switch profile {
	case "system":
		return nil
	case "xbox":
		if custom == "" {
			custom = "https://xbox-dns.ru/dns-query"
		}
		return writeResolvConf("127.0.0.1")
	case "custom":
		if custom == "" {
			return errors.New("custom dns profile requires dns_custom")
		}
		if strings.HasPrefix(custom, "https://") {
			return writeResolvConf("127.0.0.1")
		}
		return writeResolvConf(custom)
	default:
		return fmt.Errorf("unknown dns profile: %s", profile)
	}
}

func writeResolvConf(servers string) error {
	resolv := "/etc/resolv.conf"
	entries := splitServers(servers)
	if len(entries) == 0 {
		return errors.New("no dns servers provided")
	}

	var b strings.Builder
	for _, s := range entries {
		b.WriteString("nameserver ")
		b.WriteString(s)
		b.WriteString("\n")
	}

	info, err := os.Stat(resolv)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0200 == 0 {
		return errors.New("/etc/resolv.conf not writable")
	}
	return os.WriteFile(resolv, []byte(b.String()), 0644)
}

func splitServers(input string) []string {
	raw := strings.FieldsFunc(input, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func applyMacRandom() error {
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return errors.New("ip command not found")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := randomMAC()
		if mac == "" {
			continue
		}
		_ = exec.Command(ipPath, "link", "set", iface.Name, "down").Run()
		_ = exec.Command(ipPath, "link", "set", iface.Name, "address", mac).Run()
		_ = exec.Command(ipPath, "link", "set", iface.Name, "up").Run()
	}

	return nil
}

func applyFirewall() error {
	ufwPath, err := exec.LookPath("ufw")
	if err != nil {
		return errors.New("ufw not found")
	}
	_ = exec.Command(ufwPath, "default", "deny", "incoming").Run()
	_ = exec.Command(ufwPath, "default", "allow", "outgoing").Run()
	_ = exec.Command(ufwPath, "--force", "enable").Run()
	return nil
}

func randomMAC() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	b[0] = (b[0] | 2) & 0xfe
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func ensureTorRunning(cfg config.NetworkConfig, home string) error {
	if _, err := exec.LookPath("tor"); err != nil {
		return errors.New("tor not installed")
	}
	if home == "" {
		if v := os.Getenv(paths.EnvHome); v != "" {
			home = v
		}
	}
	if home == "" {
		dir, err := paths.HomeDir()
		if err == nil {
			home = dir
		}
	}

	torrc, err := writeTorConfig(cfg, home)
	if err != nil {
		return err
	}

	if isPortOpen("127.0.0.1", 9050, 200*time.Millisecond) {
		return nil
	}
	cmd := exec.Command("tor", "-f", torrc, "--RunAsDaemon", "1")
	if err := cmd.Start(); err != nil {
		return err
	}
	return nil
}

func applyVPN(vpnType, vpnProfile string) error {
	if vpnType == "" {
		return errors.New("vpn_type is empty")
	}
	if vpnProfile == "" {
		return errors.New("vpn_profile is empty")
	}
	switch vpnType {
	case "openvpn":
		if _, err := exec.LookPath("openvpn"); err != nil {
			return errors.New("openvpn not installed")
		}
		cmd := exec.Command("openvpn", "--config", vpnProfile, "--daemon")
		return cmd.Run()
	case "wireguard":
		if _, err := exec.LookPath("wg-quick"); err != nil {
			return errors.New("wg-quick not installed")
		}
		cmd := exec.Command("wg-quick", "up", vpnProfile)
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported vpn type: %s", vpnType)
	}
}

func applyGateway(gatewayIP string) error {
	if gatewayIP == "" {
		return errors.New("gateway_ip is empty")
	}
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return errors.New("ip command not found")
	}
	cmd := exec.Command(ipPath, "route", "replace", "default", "via", gatewayIP)
	return cmd.Run()
}

func applyProxy(engine, configPath string) error {
	if engine == "" {
		return errors.New("proxy_engine is empty")
	}
	if configPath == "" {
		return errors.New("proxy_config is empty")
	}
	switch engine {
	case "sing-box":
		if _, err := exec.LookPath("sing-box"); err != nil {
			return errors.New("sing-box not installed")
		}
		cmd := exec.Command("sing-box", "run", "-c", configPath)
		return cmd.Start()
	case "xray":
		if _, err := exec.LookPath("xray"); err != nil {
			return errors.New("xray not installed")
		}
		cmd := exec.Command("xray", "run", "-config", configPath)
		return cmd.Start()
	case "hiddify":
		hiddify, err := exec.LookPath("hiddify")
		if err != nil {
			hiddify, err = exec.LookPath("hiddify-cli")
			if err != nil {
				return errors.New("hiddify not installed")
			}
		}
		cmd := exec.Command(hiddify, "run", "-c", configPath)
		return cmd.Start()
	default:
		return fmt.Errorf("unsupported proxy engine: %s", engine)
	}
}

func applyTorFirewall(cfg config.NetworkConfig) error {
	iptables, err := exec.LookPath("iptables")
	if err != nil {
		return errors.New("iptables not found")
	}
	transPort := cfg.TorTransPort
	if transPort == 0 {
		transPort = 9040
	}
	dnsPort := cfg.TorDNSPort
	if dnsPort == 0 {
		dnsPort = 9053
	}

	torUID := findTorUID()
	chain := "GARGOYLE_TOR"
	natChain := "GARGOYLE_TOR_NAT"
	_ = exec.Command(iptables, "-N", chain).Run()
	_ = exec.Command(iptables, "-F", chain).Run()
	_ = exec.Command(iptables, "-D", "OUTPUT", "-j", chain).Run()
	if err := exec.Command(iptables, "-I", "OUTPUT", "1", "-j", chain).Run(); err != nil {
		return err
	}
	_ = exec.Command(iptables, "-t", "nat", "-N", natChain).Run()
	_ = exec.Command(iptables, "-t", "nat", "-F", natChain).Run()
	_ = exec.Command(iptables, "-t", "nat", "-D", "OUTPUT", "-j", natChain).Run()
	if err := exec.Command(iptables, "-t", "nat", "-I", "OUTPUT", "1", "-j", natChain).Run(); err != nil {
		return err
	}

	commands := [][]string{
		{chain, "-o", "lo", "-j", "ACCEPT"},
		{chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	if torUID >= 0 {
		commands = append(commands, []string{chain, "-m", "owner", "--uid-owner", fmt.Sprintf("%d", torUID), "-j", "ACCEPT"})
	}
	commands = append(commands, []string{chain, "-j", "REJECT"})

	for _, args := range commands {
		full := append([]string{"-A"}, args...)
		if err := exec.Command(iptables, full...).Run(); err != nil {
			return err
		}
	}

	natRules := [][]string{
		{natChain, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dnsPort)},
		{natChain, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", transPort)},
	}
	for _, args := range natRules {
		full := append([]string{"-t", "nat", "-A"}, args...)
		if err := exec.Command(iptables, full...).Run(); err != nil {
			return err
		}
	}
	return nil
}

func EnsureTorKillswitch(cfg config.NetworkConfig) error {
	if runtime.GOOS != "linux" {
		return errors.New("killswitch supported on Linux only")
	}
	if !cfg.TorStrict {
		return errors.New("tor_strict is disabled")
	}
	return applyTorFirewall(cfg)
}

func TorKillswitchActive() (bool, error) {
	if runtime.GOOS != "linux" {
		return false, errors.New("killswitch supported on Linux only")
	}
	iptables, err := exec.LookPath("iptables")
	if err != nil {
		return false, errors.New("iptables not found")
	}
	out, err := exec.Command(iptables, "-S", "OUTPUT").Output()
	if err != nil {
		return false, err
	}
	if !strings.Contains(string(out), "GARGOYLE_TOR") {
		return false, nil
	}
	outNat, err := exec.Command(iptables, "-t", "nat", "-S", "OUTPUT").Output()
	if err != nil {
		return false, err
	}
	if !strings.Contains(string(outNat), "GARGOYLE_TOR_NAT") {
		return false, nil
	}
	return true, nil
}

func writeTorConfig(cfg config.NetworkConfig, home string) (string, error) {
	if cfg.TorrcPath != "" {
		return cfg.TorrcPath, nil
	}
	if home == "" {
		return "", errors.New("home directory is empty")
	}
	dir := filepath.Join(home, "tor")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", err
	}
	transPort := cfg.TorTransPort
	if transPort == 0 {
		transPort = 9040
	}
	dnsPort := cfg.TorDNSPort
	if dnsPort == 0 {
		dnsPort = 9053
	}
	var b strings.Builder
	b.WriteString("RunAsDaemon 1\n")
	b.WriteString("SocksPort 9050\n")
	b.WriteString(fmt.Sprintf("TransPort %d\n", transPort))
	b.WriteString(fmt.Sprintf("DNSPort %d\n", dnsPort))
	b.WriteString("DataDirectory " + dataDir + "\n")
	if cfg.TorUseBridges || len(cfg.TorBridgeLines) > 0 {
		b.WriteString("UseBridges 1\n")
		if cfg.TorTransport != "" {
			b.WriteString("ClientTransportPlugin " + cfg.TorTransport + "\n")
		}
		for _, bridge := range cfg.TorBridgeLines {
			bridge = strings.TrimSpace(bridge)
			if bridge == "" {
				continue
			}
			b.WriteString("Bridge " + bridge + "\n")
		}
	}
	torrc := filepath.Join(dir, "torrc")
	if err := os.WriteFile(torrc, []byte(b.String()), 0600); err != nil {
		return "", err
	}
	return torrc, nil
}

func isPortOpen(host string, port int, timeout time.Duration) bool {
	if port <= 0 {
		return false
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func findTorUID() int {
	for _, name := range []string{"debian-tor", "tor"} {
		if uid := lookupUID(name); uid >= 0 {
			return uid
		}
	}
	return -1
}

func lookupUID(user string) int {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return -1
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, user+":") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		uid, err := parseInt(parts[2])
		if err != nil {
			continue
		}
		return uid
	}
	return -1
}

func parseInt(v string) (int, error) {
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	return n, err
}
