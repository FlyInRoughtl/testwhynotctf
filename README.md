# Gargoyle

Gargoyle — переносимая изолированная среда для CTF/лабораторных задач (CLI/TUI на хост‑ОС).  
Фокус: удобство, модульные инструменты, best‑effort приватность.  
Полной анонимности не обещаем; Live‑OS/ISO отложены (roadmap v5+).

Документация:
- SPEC.md — краткое ТЗ и рамки
- REQUIREMENTS.md — зависимости
- CHANGELOG.md — изменения
- CHEATSHEET.md — быстрые команды

## Быстрый старт
- Windows: `installers/windows/bootstrap.cmd`
- Linux: `bash installers/linux/bootstrap.sh`
- Wizard (USB/Folder):
  - Windows: `installers/windows/wizard.cmd`
  - Linux: `bash installers/linux/wizard.sh`
  - Нажмите `A` на шаге базовых настроек для Advanced профиля
  - Dry‑run + лог: `installer.log`
- Dependencies (best‑effort):
  - Windows: `powershell -ExecutionPolicy Bypass -File installers/windows/deps.ps1`
  - Linux: `bash installers/linux/deps.sh`

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

# help

gargoyle help

gargoyle help-gargoyle

# update (sha256 + optional signature)
gargoyle update --url https://.../gargoyle --sha256 <sum> --sig <sig_b64> --pub <pub_b64>
```

## Tools packs
Встроенные: `ctf`, `ctf_emulate`, `anonymity`, `osint`, `empty`.
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
- Windows: best‑effort, без LUKS и без системного forced‑Tor.
- DNS не меняет внешний IP (это не VPN).
