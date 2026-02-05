package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

type Status struct {
	Running bool
	Type    string
	Server  string
	Service string
	Port    int
	PID     int
	Error   string
}

func StartFRP(server string, service string, port int, token string, localIP string, home string) (*exec.Cmd, func() error, error) {
	if server == "" {
		return nil, nil, errors.New("tunnel server is empty")
	}
	if service == "" {
		service = "service"
	}
	if port <= 0 {
		return nil, nil, errors.New("port must be > 0")
	}
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if strings.ContainsAny(localIP, "\r\n") {
		return nil, nil, errors.New("local_ip contains invalid characters")
	}
	if _, err := net.ResolveIPAddr("ip", localIP); err != nil && strings.Contains(localIP, ":") {
		return nil, nil, errors.New("local_ip is invalid")
	}
	if err := validateServiceName(service); err != nil {
		return nil, nil, err
	}
	frpcPath, err := findFRPC(home)
	if err != nil {
		return nil, nil, err
	}
	cfgPath, cleanup, err := writeFRPConfig(server, service, port, token, localIP, home)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(frpcPath, "-c", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, nil, err
	}
	stop := func() error {
		if cmd.Process == nil {
			cleanup()
			return nil
		}
		_ = cmd.Process.Kill()
		cleanup()
		return nil
	}
	return cmd, stop, nil
}

func writeFRPConfig(server string, service string, port int, token string, localIP string, home string) (string, func(), error) {
	addr, srvPort, err := splitHostPort(server)
	if err != nil {
		return "", func() {}, err
	}
	dir := home
	if dir == "" {
		dir = "."
	}
	cfgDir := filepath.Join(dir, "tunnel")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return "", func() {}, err
	}
	tmpFile, err := os.CreateTemp(cfgDir, "gargoyle-frp-*.ini")
	if err != nil {
		return "", func() {}, err
	}
	cfgPath := tmpFile.Name()
	var b strings.Builder
	b.WriteString("[common]\n")
	b.WriteString("server_addr = " + addr + "\n")
	b.WriteString(fmt.Sprintf("server_port = %d\n", srvPort))
	if token != "" {
		b.WriteString("token = " + token + "\n")
	}
	b.WriteString("\n[" + service + "]\n")
	b.WriteString("type = tcp\n")
	b.WriteString("local_ip = " + localIP + "\n")
	b.WriteString(fmt.Sprintf("local_port = %d\n", port))
	b.WriteString(fmt.Sprintf("remote_port = %d\n", port))
	if _, err := tmpFile.WriteString(b.String()); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(cfgPath)
		return "", func() {}, err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(cfgPath)
		return "", func() {}, err
	}
	cleanup := func() {
		_ = os.Remove(cfgPath)
	}
	return cfgPath, cleanup, nil
}

func validateServiceName(service string) error {
	if service == "" {
		return errors.New("service name is empty")
	}
	if len(service) > 64 {
		return errors.New("service name is too long")
	}
	for _, r := range service {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			continue
		}
		return errors.New("invalid service name")
	}
	return nil
}

func findFRPC(home string) (string, error) {
	if home != "" {
		candidate := filepath.Join(home, "bin", frpcName())
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	localCandidate := filepath.Join(".", "bin", frpcName())
	if _, err := os.Stat(localCandidate); err == nil {
		return localCandidate, nil
	}
	if path, err := exec.LookPath("frpc"); err == nil {
		return path, nil
	}
	return "", errors.New("frpc not found")
}

func frpcName() string {
	if runtime.GOOS == "windows" {
		return "frpc.exe"
	}
	return "frpc"
}

func splitHostPort(input string) (string, int, error) {
	parts := strings.Split(input, ":")
	if len(parts) != 2 {
		return "", 0, errors.New("tunnel server must be host:port")
	}
	if parts[0] == "" {
		return "", 0, errors.New("tunnel server host is empty")
	}
	var port int
	_, err := fmt.Sscanf(parts[1], "%d", &port)
	if err != nil || port <= 0 {
		return "", 0, errors.New("invalid tunnel port")
	}
	return parts[0], port, nil
}
