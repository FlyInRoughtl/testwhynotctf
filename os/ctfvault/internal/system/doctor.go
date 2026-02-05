package system

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"gargoyle/internal/config"
)

type CheckResult struct {
	Name   string
	Status string
	Detail string
}

func RunDoctor(cfg config.Config) []CheckResult {
	results := []CheckResult{}

	add := func(name, status, detail string) {
		results = append(results, CheckResult{Name: name, Status: status, Detail: detail})
	}

	add("config", "ok", "loaded")
	if cfg.Security.IdentityKeyPath == "" {
		add("identity", "warn", "identity_key_path is empty")
	} else {
		add("identity", "ok", cfg.Security.IdentityKeyPath)
	}

	if runtime.GOOS == "linux" {
		checkBin(add, "tor")
		checkBin(add, "iptables")
		checkBin(add, "ufw")
		checkBin(add, "openvpn")
		checkBin(add, "wg-quick")
		checkBin(add, "bwrap")
		checkBin(add, "cloudflared")
		checkBin(add, "nmcli")
		if cfg.Mesh.TunEnabled {
			if _, err := os.Stat("/dev/net/tun"); err != nil {
				add("tun", "err", "/dev/net/tun not available")
			} else {
				add("tun", "ok", "/dev/net/tun")
			}
			checkBin(add, "ip")
		}
	} else if runtime.GOOS == "windows" {
		checkBin(add, "tor.exe")
		checkBin(add, "veracrypt")
	}

	if cfg.Network.Mode == "vpn" && cfg.Network.VPNType != "" {
		add("vpn", "ok", cfg.Network.VPNType)
	}
	if cfg.Network.TorAlwaysOn || cfg.Network.TorStrict {
		add("tor_mode", "ok", "enabled")
	}
	if cfg.Tunnel.Type == "frp" {
		checkBin(add, "frpc")
		checkBin(add, "frpc.exe")
	}

	if cfg.Telegram.Enabled {
		if cfg.Telegram.BotToken == "" {
			add("telegram", "err", "bot_token is empty")
		} else {
			add("telegram", "ok", "enabled")
		}
	}

	return results
}

func checkBin(add func(string, string, string), name string) {
	if _, err := exec.LookPath(name); err != nil {
		add(name, "warn", "not found")
		return
	}
	add(name, "ok", "found")
}

func FormatDoctor(results []CheckResult) string {
	var out string
	for _, r := range results {
		out += fmt.Sprintf("[%s] %s", r.Status, r.Name)
		if r.Detail != "" {
			out += fmt.Sprintf(" -> %s", r.Detail)
		}
		out += "\n"
	}
	return out
}
