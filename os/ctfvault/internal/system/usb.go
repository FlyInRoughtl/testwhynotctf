package system

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type USBEvent struct {
	Removed bool
	Device  string
	Mount   string
	Err     error
}

func StartUSBWatcher(home string, interval time.Duration) (<-chan USBEvent, func()) {
	out := make(chan USBEvent, 1)
	if runtime.GOOS != "linux" {
		close(out)
		return out, func() {}
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}

	mount, err := findMountForPath(home)
	if err != nil {
		out <- USBEvent{Err: err}
		close(out)
		return out, func() {}
	}

	base := baseBlockDevice(mount.Device)
	if base == "" || !isRemovable(base) {
		close(out)
		return out, func() {}
	}

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				close(out)
				return
			case <-ticker.C:
				if !isMounted(mount) || !deviceExists(mount.Device) {
					out <- USBEvent{Removed: true, Device: mount.Device, Mount: mount.Mount}
					close(out)
					return
				}
			}
		}
	}()
	return out, func() { close(stop) }
}

type mountInfo struct {
	Device string
	Mount  string
}

func findMountForPath(path string) (mountInfo, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return mountInfo{}, err
	}
	defer f.Close()

	path = filepath.Clean(path)
	var best mountInfo
	bestLen := -1
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		device, mount := fields[0], fields[1]
		if !strings.HasPrefix(path, mount) {
			continue
		}
		if len(mount) > bestLen {
			best = mountInfo{Device: device, Mount: mount}
			bestLen = len(mount)
		}
	}
	if err := scanner.Err(); err != nil {
		return mountInfo{}, err
	}
	if bestLen == -1 {
		return mountInfo{}, errors.New("mount point not found for home")
	}
	return best, nil
}

func isMounted(m mountInfo) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[0] == m.Device && fields[1] == m.Mount {
			return true
		}
	}
	return false
}

func deviceExists(dev string) bool {
	if dev == "" {
		return false
	}
	_, err := os.Stat(dev)
	return err == nil
}

func baseBlockDevice(dev string) string {
	base := filepath.Base(dev)
	if strings.HasPrefix(base, "nvme") && strings.Contains(base, "p") {
		if idx := strings.LastIndex(base, "p"); idx > 0 {
			return base[:idx]
		}
	}
	if strings.HasPrefix(base, "mmcblk") && strings.Contains(base, "p") {
		if idx := strings.LastIndex(base, "p"); idx > 0 {
			return base[:idx]
		}
	}
	i := len(base) - 1
	for i >= 0 && base[i] >= '0' && base[i] <= '9' {
		i--
	}
	if i < 0 {
		return ""
	}
	return base[:i+1]
}

func isRemovable(block string) bool {
	data, err := os.ReadFile(filepath.Join("/sys/block", block, "removable"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

func ListUSBDevices() ([]string, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("usb list supported on linux only")
	}
	if _, err := exec.LookPath("lsblk"); err != nil {
		return nil, errors.New("lsblk not found")
	}
	cmd := exec.Command("lsblk", "-d", "-o", "NAME,MODEL,SIZE,TRAN")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) <= 1 {
		return []string{}, nil
	}
	var devices []string
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		tran := fields[len(fields)-1]
		if tran != "usb" {
			continue
		}
		name := fields[0]
		size := fields[len(fields)-2]
		model := strings.Join(fields[1:len(fields)-2], " ")
		devices = append(devices, strings.TrimSpace(name+" "+model+" "+size))
	}
	return devices, nil
}

func IsPathOnRemovable(path string) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, errors.New("usb check supported on linux only")
	}
	mount, err := findMountForPath(path)
	if err != nil {
		return false, err
	}
	base := baseBlockDevice(mount.Device)
	if base == "" {
		return false, nil
	}
	return isRemovable(base), nil
}
