# Gargoyle Live-USB (Linux)

Этот каталог содержит **best-effort** сборочный пайплайн Live-USB.
Цель: собрать ISO образ с squashfs rootfs + опцией `toram`.

## Требования (Debian/Ubuntu)
- live-build (`apt install live-build`)
- squashfs-tools
- xorriso
- grub-efi-amd64-bin

## Быстрый старт
```bash
cd os/liveusb
./build.sh
```

## Toram
Параметр ядра `toram` копирует squashfs в RAM и позволяет выдернуть USB.

## Примечание
Это **скелет** для сборки. Вы можете заменить базовую систему на Kali,
или использовать свой список пакетов и overlay.
