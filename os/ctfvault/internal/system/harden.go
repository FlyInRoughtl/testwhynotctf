package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type HardenStatus struct {
	PrelockEnabled bool
	VolatileLogs   bool
}

const (
	prelockScriptPath = "/usr/local/lib/gargoyle/prelock.sh"
	prelockUnitPath   = "/etc/systemd/system/gargoyle-prelock.service"
	journaldConfPath  = "/etc/systemd/journald.conf.d/gargoyle-volatile.conf"
)

func HardenEnable() NetResult {
	result := NetResult{}
	if runtime.GOOS != "linux" {
		result.Warnings = append(result.Warnings, "harden: supported on Linux only")
		return result
	}

	if err := os.MkdirAll(filepath.Dir(prelockScriptPath), 0755); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: create script dir: %v", err))
		return result
	}

	script := `#!/bin/sh
set -eu
if command -v nmcli >/dev/null 2>&1; then
  nmcli networking off || true
fi
iptables -N GARGOYLE_TOR 2>/dev/null || true
iptables -F GARGOYLE_TOR || true
iptables -D OUTPUT -j GARGOYLE_TOR 2>/dev/null || true
iptables -I OUTPUT 1 -j GARGOYLE_TOR || true
iptables -t nat -N GARGOYLE_TOR_NAT 2>/dev/null || true
iptables -t nat -F GARGOYLE_TOR_NAT || true
iptables -t nat -D OUTPUT -j GARGOYLE_TOR_NAT 2>/dev/null || true
iptables -t nat -I OUTPUT 1 -j GARGOYLE_TOR_NAT || true
iptables -A GARGOYLE_TOR -o lo -j ACCEPT
iptables -A GARGOYLE_TOR -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A GARGOYLE_TOR -j REJECT
exit 0
`

	if err := os.WriteFile(prelockScriptPath, []byte(script), 0755); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: write prelock script: %v", err))
		return result
	}

	unit := `[Unit]
Description=Gargoyle pre-lock network (FullAnon)
DefaultDependencies=no
Before=network-pre.target NetworkManager.service systemd-networkd.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/gargoyle/prelock.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile(prelockUnitPath, []byte(unit), 0644); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: write unit: %v", err))
		return result
	}

	if err := os.MkdirAll(filepath.Dir(journaldConfPath), 0755); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: create journald dir: %v", err))
	} else {
		vol := "[Journal]\nStorage=volatile\nRuntimeMaxUse=64M\nRuntimeMaxFileSize=8M\n"
		if err := os.WriteFile(journaldConfPath, []byte(vol), 0644); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("harden: write journald conf: %v", err))
		}
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: systemctl daemon-reload: %v", err))
	}
	if err := run("systemctl", "enable", "--now", "gargoyle-prelock.service"); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: enable prelock: %v", err))
	} else {
		result.Infos = append(result.Infos, "harden: prelock enabled")
	}
	if err := run("systemctl", "restart", "systemd-journald"); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: restart journald: %v", err))
	} else {
		result.Infos = append(result.Infos, "harden: journald set to volatile")
	}

	return result
}

func HardenDisable() NetResult {
	result := NetResult{}
	if runtime.GOOS != "linux" {
		result.Warnings = append(result.Warnings, "harden: supported on Linux only")
		return result
	}

	_ = run("systemctl", "disable", "--now", "gargoyle-prelock.service")
	_ = run("systemctl", "daemon-reload")

	_ = os.Remove(prelockUnitPath)
	_ = os.Remove(prelockScriptPath)
	_ = os.Remove(journaldConfPath)

	if err := run("systemctl", "restart", "systemd-journald"); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("harden: restart journald: %v", err))
	}
	result.Infos = append(result.Infos, "harden: disabled")
	return result
}

func GetHardenStatus() (HardenStatus, error) {
	if runtime.GOOS != "linux" {
		return HardenStatus{}, errors.New("harden status supported on Linux only")
	}
	status := HardenStatus{
		PrelockEnabled: fileExists(prelockUnitPath),
		VolatileLogs:   fileExists(journaldConfPath),
	}
	return status, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
