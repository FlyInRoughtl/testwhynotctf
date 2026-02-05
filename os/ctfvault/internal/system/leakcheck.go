package system

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func leakCheck(mode string, tor bool) ([]string, []string) {
	var infos []string
	var warns []string

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	if tor {
		ip, err := torIPCheck(ctx)
		if err != nil {
			warns = append(warns, "leakcheck: tor ip check failed: "+err.Error())
		} else if ip != "" {
			infos = append(infos, "leakcheck: tor ip="+ip)
		}
	} else if mode == "vpn" || mode == "proxy" {
		ip, err := httpGetText(ctx, "https://api.ipify.org")
		if err != nil {
			warns = append(warns, "leakcheck: ipify failed: "+err.Error())
		} else if ip != "" {
			infos = append(infos, "leakcheck: ip="+ip)
		}
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, "example.com")
	if err != nil {
		warns = append(warns, "leakcheck: dns resolve failed: "+err.Error())
	} else if len(ips) > 0 {
		infos = append(infos, "leakcheck: dns ok")
	}

	return infos, warns
}

func torIPCheck(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("curl"); err != nil {
		return "", errors.New("curl not found")
	}
	cmd := exec.CommandContext(ctx, "curl", "--socks5-hostname", "127.0.0.1:9050", "-s", "https://check.torproject.org/api/ip")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return extractIP(string(out)), nil
}

func httpGetText(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return extractIP(string(data)), nil
}

var ipRe = regexp.MustCompile(`([0-9]{1,3}\.){3}[0-9]{1,3}`)

func extractIP(text string) string {
	match := ipRe.FindString(text)
	return strings.TrimSpace(match)
}
