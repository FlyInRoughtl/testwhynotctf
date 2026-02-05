package tunnel

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func StartFRP(server string, service string, port int, token string, home string) (*exec.Cmd, func() error, error) {
	if server == "" {
		return nil, nil, errors.New("tunnel server is empty")
	}
	if service == "" {
		service = "service"
	}
	if port <= 0 {
		return nil, nil, errors.New("port must be > 0")
	}
	if _, err := exec.LookPath("frpc"); err != nil {
		return nil, nil, errors.New("frpc not found")
	}
	cfgPath, err := writeFRPConfig(server, service, port, token, home)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command("frpc", "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	stop := func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return cmd, stop, nil
}

func writeFRPConfig(server string, service string, port int, token string, home string) (string, error) {
	addr, srvPort, err := splitHostPort(server)
	if err != nil {
		return "", err
	}
	dir := home
	if dir == "" {
		dir = "."
	}
	cfgDir := filepath.Join(dir, "tunnel")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return "", err
	}
	cfgPath := filepath.Join(cfgDir, "frpc.ini")
	var b strings.Builder
	b.WriteString("[common]\n")
	b.WriteString("server_addr = " + addr + "\n")
	b.WriteString(fmt.Sprintf("server_port = %d\n", srvPort))
	if token != "" {
		b.WriteString("token = " + token + "\n")
	}
	b.WriteString("\n[" + service + "]\n")
	b.WriteString("type = tcp\n")
	b.WriteString("local_ip = 127.0.0.1\n")
	b.WriteString(fmt.Sprintf("local_port = %d\n", port))
	b.WriteString(fmt.Sprintf("remote_port = %d\n", port))
	return cfgPath, os.WriteFile(cfgPath, []byte(b.String()), 0600)
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
