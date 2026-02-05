package system

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type NetResult struct {
	Infos    []string
	Warnings []string
}

func ApplyNetwork(profile, custom string, macSpoof bool, portsOpen bool, mode string, vpnType string, vpnProfile string, gatewayIP string, proxyEngine string, proxyConfig string, torAlwaysOn bool, torStrict bool) NetResult {
	result := NetResult{}
	if runtime.GOOS != "linux" {
		result.Warnings = append(result.Warnings, "network apply: supported on Linux only (skip)")
		return result
	}

	if err := applyDNS(profile, custom); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("dns apply: %v", err))
	}

	if torAlwaysOn || torStrict {
		if err := ensureTorRunning(); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("tor: %v", err))
		}
	}
	if torStrict {
		if err := applyTorFirewall(); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("tor firewall: %v", err))
		}
	}

	switch mode {
	case "", "direct":
	case "vpn":
		if err := applyVPN(vpnType, vpnProfile); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("vpn: %v", err))
		}
	case "gateway":
		if err := applyGateway(gatewayIP); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("gateway: %v", err))
		}
	case "proxy":
		if err := applyProxy(proxyEngine, proxyConfig); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("proxy: %v", err))
		}
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("unknown network mode: %s", mode))
	}

	if macSpoof {
		if err := applyMacRandom(); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("mac spoof: %v", err))
		}
	}

	if !portsOpen {
		if err := applyFirewall(); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("firewall: %v", err))
		}
	}

	if mode == "vpn" || mode == "proxy" || torAlwaysOn || torStrict {
		info, warns := leakCheck(mode, torAlwaysOn || torStrict)
		result.Infos = append(result.Infos, info...)
		result.Warnings = append(result.Warnings, warns...)
	}

	return result
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

func ensureTorRunning() error {
	if _, err := exec.LookPath("tor"); err != nil {
		return errors.New("tor not installed")
	}
	if systemctl, err := exec.LookPath("systemctl"); err == nil {
		_ = exec.Command(systemctl, "enable", "tor").Run()
		if err := exec.Command(systemctl, "start", "tor").Run(); err == nil {
			return nil
		}
	}
	if service, err := exec.LookPath("service"); err == nil {
		if err := exec.Command(service, "tor", "start").Run(); err == nil {
			return nil
		}
	}
	cmd := exec.Command("tor", "--RunAsDaemon", "1")
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
	default:
		return fmt.Errorf("unsupported proxy engine: %s", engine)
	}
}

func applyTorFirewall() error {
	iptables, err := exec.LookPath("iptables")
	if err != nil {
		return errors.New("iptables not found")
	}
	commands := [][]string{
		{"-F", "OUTPUT"},
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "tcp", "--dport", "9050", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "tcp", "--dport", "9051", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-p", "udp", "-d", "127.0.0.1", "--dport", "53", "-j", "ACCEPT"},
		{"-A", "OUTPUT", "-j", "REJECT"},
	}
	for _, args := range commands {
		if err := exec.Command(iptables, args...).Run(); err != nil {
			return err
		}
	}
	return nil
}
