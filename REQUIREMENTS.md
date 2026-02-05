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

Optional network tooling:
- cloudflared (DoH proxy backend)

Optional (later stages):
- QEMU/KVM for VM mode
- USB imaging tools for Live-USB creation

Quick start:
- Windows: run installers/windows/bootstrap.cmd
- Linux:   run installers/linux/bootstrap.sh
