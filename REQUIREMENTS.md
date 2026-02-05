# Requirements

Minimal:
- Go 1.24+ (for building the CLI/TUI)
- Network access to download Go modules (first build only)

Linux installer dependencies (for full USB layout):
- whiptail (TUI wizard)
- sgdisk (partitioning)
- cryptsetup (LUKS2)
- mkfs.ext4 (e2fsprogs)
- mkfs.exfat (exfatprogs)
- ufw (optional firewall profile)
- iptables (Tor fail-closed profile)
- lsblk (USB device scan)

Optional network tooling:
- cloudflared (DoH proxy backend)
- tor (always-on profile)
- openvpn (VPN mode)
- wireguard-tools (wg-quick)
- curl (Tor leak check via SOCKS)
- frpc (FRP client for tunnel)
- postfix + dovecot (local mail server)
- sing-box or xray or hiddify-cli (proxy mode)
- avahi-utils (optional mDNS discovery if you switch from UDP broadcast)
- wl-clipboard or xclip (clipboard share, Linux)
- iproute2 (tun/tap setup)

Optional (later stages):
- QEMU/KVM for VM mode
- live-build, squashfs-tools, xorriso (Live-USB build)

EmulateEL (Linux GUI apps):
- X11/Wayland desktop
- firefox / torbrowser-launcher / xdg-open (optional)
- bubblewrap (privacy mode sandbox, best-effort)
- cage / gamescope / weston (optional anti-capture display server)

Windows extras:
- VeraCrypt (optional encrypted container)

Quick start:
- Windows: run installers/windows/bootstrap.cmd
- Linux:   run installers/linux/bootstrap.sh

