package system

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

type GatewayOptions struct {
	WanInterface string
	GwNS         string
	WsNS         string
	GwIP         string
	WsIP         string
	CIDR         string
	TransPort    int
	DNSPort      int
}

func StartGateway(opts GatewayOptions) error {
	if runtime.GOOS != "linux" {
		return errors.New("gateway mode is supported on Linux only")
	}
	if opts.WanInterface == "" {
		return errors.New("wan_interface is required")
	}
	if opts.GwNS == "" {
		opts.GwNS = "gargoyle-gw"
	}
	if opts.WsNS == "" {
		opts.WsNS = "gargoyle-ws"
	}
	if opts.CIDR == "" {
		opts.CIDR = "10.200.0.0/24"
	}
	if opts.GwIP == "" {
		opts.GwIP = "10.200.0.1/24"
	}
	if opts.WsIP == "" {
		opts.WsIP = "10.200.0.2/24"
	}
	if opts.TransPort == 0 {
		opts.TransPort = 9040
	}
	if opts.DNSPort == 0 {
		opts.DNSPort = 9053
	}

	_ = run("ip", "netns", "add", opts.GwNS)
	_ = run("ip", "netns", "add", opts.WsNS)
	_ = run("ip", "link", "add", "gw0", "type", "veth", "peer", "name", "ws0")
	_ = run("ip", "link", "set", "gw0", "netns", opts.GwNS)
	_ = run("ip", "link", "set", "ws0", "netns", opts.WsNS)

	_ = run("ip", "netns", "exec", opts.GwNS, "ip", "addr", "add", opts.GwIP, "dev", "gw0")
	_ = run("ip", "netns", "exec", opts.GwNS, "ip", "link", "set", "gw0", "up")
	_ = run("ip", "netns", "exec", opts.GwNS, "ip", "link", "set", "lo", "up")

	_ = run("ip", "netns", "exec", opts.WsNS, "ip", "addr", "add", opts.WsIP, "dev", "ws0")
	_ = run("ip", "netns", "exec", opts.WsNS, "ip", "link", "set", "ws0", "up")
	_ = run("ip", "netns", "exec", opts.WsNS, "ip", "link", "set", "lo", "up")
	_ = run("ip", "netns", "exec", opts.WsNS, "ip", "route", "add", "default", "via", "10.200.0.1")

	_ = run("sysctl", "-w", "net.ipv4.ip_forward=1")
	_ = run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.200.0.0/24", "-o", opts.WanInterface, "-j", "MASQUERADE")

	_ = run("iptables", "-t", "nat", "-A", "PREROUTING", "-i", opts.WanInterface, "-j", "ACCEPT")
	_ = run("iptables", "-t", "nat", "-A", "PREROUTING", "-i", "gw0", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", opts.DNSPort))
	_ = run("iptables", "-t", "nat", "-A", "PREROUTING", "-i", "gw0", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", opts.TransPort))

	return nil
}

func StopGateway(opts GatewayOptions) error {
	if runtime.GOOS != "linux" {
		return errors.New("gateway mode is supported on Linux only")
	}
	if opts.GwNS == "" {
		opts.GwNS = "gargoyle-gw"
	}
	if opts.WsNS == "" {
		opts.WsNS = "gargoyle-ws"
	}
	_ = run("ip", "netns", "del", opts.GwNS)
	_ = run("ip", "netns", "del", opts.WsNS)
	return nil
}

func run(args ...string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := exec.Command(args[0], args[1:]...)
	return cmd.Run()
}
