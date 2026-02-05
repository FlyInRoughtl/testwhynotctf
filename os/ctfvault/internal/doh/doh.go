package doh

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
)

type Runner struct {
	Listen string
	URL    string
}

func (r Runner) Run() error {
	if r.URL == "" {
		return errors.New("doh url is required")
	}
	listen := r.Listen
	if listen == "" {
		listen = "127.0.0.1:5353"
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}

	cloudflared, err := exec.LookPath("cloudflared")
	if err != nil {
		return errors.New("cloudflared not found (install to run DoH proxy)")
	}

	cmd := exec.Command(cloudflared, "proxy-dns", "--address", host, "--port", port, "--upstream", r.URL)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func Hint() string {
	return "Install cloudflared to enable DoH proxy (cloudflared proxy-dns)"
}

func ExplainListen(listen string) string {
	return fmt.Sprintf("DoH proxy listens on %s and upstreams to DoH URL", listen)
}
