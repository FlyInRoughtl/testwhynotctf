# Linux Installer

- `bootstrap.sh`: build the MVP binaries
- `wizard.sh`: TUI installer (USB and folder)
- Wizard outputs `start.sh` and `build.sh` into the install root

Dependencies: whiptail, sgdisk, cryptsetup, mkfs.ext4, mkfs.exfat, go (optional for build)
