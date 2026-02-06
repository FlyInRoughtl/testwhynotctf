package system

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

const hotspotConnName = "gargoyle-hotspot"

type HotspotConfig struct {
	SSID     string
	Password string
	Ifname   string
	Shared   bool
}

func StartHotspot(cfg HotspotConfig) error {
	if runtime.GOOS != "linux" {
		return errors.New("hotspot supported on Linux only")
	}
	if cfg.SSID == "" {
		return errors.New("ssid is required")
	}
	if cfg.Ifname == "" {
		return errors.New("ifname is required")
	}
	nmcli, err := exec.LookPath("nmcli")
	if err != nil {
		return errors.New("nmcli not found")
	}
	args := []string{"device", "wifi", "hotspot", "ifname", cfg.Ifname, "con-name", hotspotConnName, "ssid", cfg.SSID}
	if cfg.Password != "" {
		args = append(args, "password", cfg.Password)
	}
	if err := exec.Command(nmcli, args...).Run(); err != nil {
		return err
	}
	if cfg.Shared {
		_ = exec.Command(nmcli, "connection", "modify", hotspotConnName, "ipv4.method", "shared").Run()
		_ = exec.Command(nmcli, "connection", "modify", hotspotConnName, "ipv6.method", "ignore").Run()
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	}
	return nil
}

func StopHotspot() error {
	if runtime.GOOS != "linux" {
		return errors.New("hotspot supported on Linux only")
	}
	nmcli, err := exec.LookPath("nmcli")
	if err != nil {
		return errors.New("nmcli not found")
	}
	_ = exec.Command(nmcli, "connection", "down", hotspotConnName).Run()
	_ = exec.Command(nmcli, "connection", "delete", hotspotConnName).Run()
	return nil
}

func HotspotStatus() (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("hotspot supported on Linux only")
	}
	nmcli, err := exec.LookPath("nmcli")
	if err != nil {
		return "", errors.New("nmcli not found")
	}
	out, err := exec.Command(nmcli, "-t", "-f", "NAME,DEVICE,ACTIVE", "connection", "show", "--active").Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, hotspotConnName+":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				return fmt.Sprintf("active (%s)", parts[1]), nil
			}
			return "active", nil
		}
	}
	return "inactive", nil
}
