# Gargoyle

Gargoyle OS — переносимая изолированная среда для CTF/лабораторных задач.  
Фокус: удобство, модульные инструменты, best‑effort приватность.  
Live‑OS/ISO: v5 “Ghost Protocol” (Debian + i3/Xorg).

Документация:
- SPEC.md — краткое ТЗ и рамки
- REQUIREMENTS.md — зависимости
- CHANGELOG.md — изменения
- CHEATSHEET.md — быстрые команды

## Быстрый старт
  - Windows: `installers/windows/bootstrap.cmd`
  - Linux: `bash installers/linux/bootstrap.sh`
  - Live‑OS: `os/liveusb/build.sh`
- Wizard (USB/Folder):
  - Windows: `installers/windows/wizard.cmd`
  - Windows quick (USB, defaults): `installers/windows/quick.cmd`
  - Linux: `bash installers/linux/wizard.sh`
  - Нажмите `A` на шаге базовых настроек для Advanced профиля
  - Dry‑run + лог: `installer.log`
  - Windows: создаются `start.cmd` и `build.cmd` в папке установки
  - Linux: создаются `start.sh` и `build.sh` в папке установки
- Dependencies (best‑effort):
  - Windows: `powershell -ExecutionPolicy Bypass -File installers/windows/deps.ps1`
  - Linux: `bash installers/linux/deps.sh`
- Harden (Linux, optional): `gargoyle harden enable`

## Что умеет (кратко)
- TUI‑рабочий стол с подсказками и hotkeys
- Mesh/Relay обмен файлами (TCP/TLS, optional padding)
- EmulateEL (Linux GUI‑мост) для запуска GUI‑приложений
- Resource Hub (webhook / drop / vault)
- Hotspot/NAT, Mesh‑gateway, Loot‑sync (Linux best‑effort)
- Tools packs (CTF/OSINT/Anonymity)
- FullAnon профиль (Tor strict + kill‑switch на Linux)

## CLI essentials
```
# запуск

gargoyle start --tui

gargoyle status

# mesh обмен

gargoyle mesh recv --listen :19999 --out ./downloads --psk secret --transport tls

gargoyle mesh send ./file.txt file.txt --to 127.0.0.1:19999 --security --psk secret --transport tls

# HYDRA (multi-path file transfer)
gargoyle mesh hydra-send ./file.txt --targets 10.0.0.2:19999,10.0.0.3:19999 --security --psk secret --mode direct
gargoyle mesh hydra-recv --listen :19999 --out ./downloads --psk secret

# help

gargoyle help

gargoyle help-gargoyle

gargoyle doctor --deep

# update (sha256 + optional signature)
gargoyle update --url https://.../gargoyle --sha256 <sum> --sig <sig_b64> --pub <pub_b64> [--ram]

# mask (boss key)
gargoyle mask --mode update
```

## Tools packs
Встроенные: `ctf`, `ctf_emulate`, `ctf-ultimate`, `anonymity`, `osint`, `empty`.
```
# установить встроенный pack

gargoyle install pack-osint

# загрузить pack из репозитория

gargoyle install pack-osint --repo https://raw.githubusercontent.com/<org>/<repo>/main/os/ctfvault/internal/tools/packs
```

## Конфиг и домашняя папка
- По умолчанию: `~/.gargoyle` (Linux) / `%USERPROFILE%\.gargoyle` (Windows)
- Переопределить: `GARGOYLE_HOME=/path` или `--home <path>`
- Конфиг: `gargoyle.yaml`

## Важные примечания
- Linux поддерживается лучше (LUKS, iptables kill‑switch, USB watcher).
- FullAnon на Linux включает pre‑lock: сеть выключается, затем ставится kill‑switch, и только потом сеть включается.
- Даже с FullAnon есть «окно» до запуска Gargoyle (boot‑leak) на хост‑ОС. В Live‑OS это закрывается pre‑lock.
- Linux USB layout: recovery codes (если включены) сохраняются в shared‑разделе на флешке.
- Windows: best‑effort, без LUKS и без системного forced‑Tor.
- Windows‑ограничения: нет iptables‑kill‑switch, нет nmcli/hotspot/NAT, нет USB‑watcher, нет bubblewrap‑изоляции.
- DNS не меняет внешний IP (это не VPN).

## Windows vs Linux
- **Linux**: полный функционал (Tor kill‑switch, nmcli, hotspot/NAT, USB watcher, bubblewrap).
- **Windows**: урезанный режим (без iptables/nmcli/bubblewrap). 
- **Tools packs**: `apt:` работает только на Linux/WSL. На Windows используйте `winget:` или `choco:`.
