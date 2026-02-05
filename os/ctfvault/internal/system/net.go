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
	Warnings []string
}

func ApplyNetwork(profile, custom string, macSpoof bool, portsOpen bool) NetResult {
	result := NetResult{}
	if runtime.GOOS != "linux" {
		result.Warnings = append(result.Warnings, "network apply: supported on Linux only (skip)")
		return result
	}

	if err := applyDNS(profile, custom); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("dns apply: %v", err))
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
