# Gargoyle Live-OS (Linux)

This folder contains the Live-OS build pipeline (Debian Bookworm).
Goal: build an ISO (squashfs rootfs) with toram support.

## Requirements (Debian/Ubuntu)
- live-build
- debootstrap
- squashfs-tools
- xorriso
- grub-efi-amd64-bin
- shim-signed

## Build
```
cd os/liveusb
./build.sh
```

## Notes
- ISO is built into os/liveusb/build/.
- toram copies the rootfs to RAM, USB can be removed.
