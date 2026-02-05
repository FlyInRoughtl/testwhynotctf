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
- sing-box or xray (proxy mode)

Optional (later stages):
- QEMU/KVM for VM mode
- USB imaging tools for Live-USB creation

EmulateEL (Linux GUI apps):
- X11/Wayland desktop
- firefox / torbrowser-launcher / xdg-open (optional)

Quick start:
- Windows: run installers/windows/bootstrap.cmd
- Linux:   run installers/linux/bootstrap.sh

