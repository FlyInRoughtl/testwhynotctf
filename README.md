# Gargoyle

Gargoyle: изолированная среда для CTF/лабораторных задач (Live-USB + VM).
Полное ТЗ: [SPEC.md](SPEC.md).
Требования: [REQUIREMENTS.md](REQUIREMENTS.md).
Changelog: [CHANGELOG.md](CHANGELOG.md).
CLI/бинарник: `gargoyle`.

Коротко по целям:
- TUI-первым (терминальный «рабочий стол»), удобные подсказки команд.
- Mesh/relay сеть и защищенный файловый обмен (в т.ч. onion-режим).
- Модульная установка CTF-инструментов.
- Приватность внутри изолированной среды, без внешних API/аккаунтов.

Структура проекта (план):
- os/
- installers/
- SPEC.md

Быстрый старт (MVP CLI/TUI):
- Windows: `installers/windows/bootstrap.cmd`
- Linux: `bash installers/linux/bootstrap.sh`

Инсталлер (TUI wizard):
- Windows: `installers/windows/wizard.cmd`
- Linux: `bash installers/linux/wizard.sh`
  - Windows (опционально): VeraCrypt контейнер для шифрования данных (если установлен)

Что уже реализовано (MVP):
- CLI с базовыми командами и TUI-прототипом
- Конфиг `gargoyle.yaml` и валидация
- Прямой зашифрованный обмен файлами (TCP/TLS) + опциональный padding
- TUI виджеты с анимацией, меню, экраном статуса и горячими клавишами (relay/DoH)
- Relay-сервер для передачи через публичные сети (V1.1)
- Gargoyle Script (DSL) + пример скрипта
- Экстренный wipe в TUI (клавиша `x`, двойное подтверждение)
- USB remove watcher (Linux, best-effort): при отключении носителя блокирует UI и требует emergency wipe
- RAM-only session (Linux, best-effort)
- EmulateEL (Linux GUI): запуск приложений через CLI/TUI, privacy mode через bubblewrap (best-effort)
- Resource Hub (webhook/file drop/vault/inbox)
- Tunnel (FRP, self-hosted)
- Mail: SMTP-sink + local mail (Postfix/Dovecot) + mesh-mail
- Proxy service (sing-box/xray/hiddify)
- Mesh discovery (UDP broadcast, best-effort)
- Mesh chat/clipboard (CLI)
- Mesh tun/tap overlay (Linux, best-effort)
- Telegram C2 (allowlist, best-effort)
- Boss-key (F10) в TUI
- Tools pack (tools.yaml) + CLI installer
- Doctor/Update команды
- Live-USB build skeleton (os/liveusb)

Планируется далее:
- Relay/Onion маршруты, полноценный mesh
- Сервисные компоненты OS-уровня и installer wizard

Пример (MVP file transfer):
```
# receiver
gargoyle mesh recv --listen :19999 --out ./downloads --psk secret --transport tls

# sender
gargoyle mesh send ./file.txt file.txt --to 127.0.0.1:19999 --security --psk secret --depth 3 --transport tls --pad 256
```

Пример (relay через публичную сеть):
```
# relay server
gargoyle relay --listen :18080

# receiver (connect via relay)
gargoyle mesh recv --relay 1.2.3.4:18080 --token ROOM1 --psk secret

# sender (connect via relay)
gargoyle mesh send ./file.txt file.txt --relay 1.2.3.4:18080 --token ROOM1 --security --psk secret
```

Пример (relay chain, multi-hop):
```
# relay chain: r1 -> r2 -> target
gargoyle mesh send ./file.txt file.txt --to 10.0.0.5:19999 --relay-chain 1.2.3.4:18080,5.6.7.8:18080 --security --psk secret --depth 5 --onion
```

Сеть (применение профиля):
- `gargoyle start --apply-network` (Linux, best-effort)

DoH proxy (V1.1):
- Установить `cloudflared`
- Запуск: `gargoyle doh --listen 127.0.0.1:5353 --url https://xbox-dns.ru/dns-query`

EmulateEL:
- CLI: `gargoyle emulate run firefox`
- TUI: вкладка Emulate, горячие клавиши `f/t/o/s`
- Privacy mode — best-effort, без 100% гарантии
- Anti-capture (best-effort): `emulate.display_server: cage|gamescope|weston`

Tunnel (FRP):
- `gargoyle tunnel expose web 8080 --local-ip 127.0.0.1`
- Требуется `frpc` и заполненный `tunnel.server` в конфиге (host:port)
- Relay остаётся fallback для file-transfer (mesh relay)

Tunnel (WSS, встроенный):
- Server: `gargoyle tunnel wss-serve --listen :8443 --public :8080 --service web --token SECRET`
- Client: `gargoyle tunnel wss-connect --server wss://host:8443 --service web --token SECRET --local 127.0.0.1:8080`

Mesh discovery:
- `gargoyle mesh discover`
- `gargoyle mesh advertise --listen :19999`

Mesh chat:
- `gargoyle mesh chat send --to 1.2.3.4:19997 "hello"`
- `gargoyle mesh chat listen --listen :19997`

Mesh clipboard:
- `gargoyle mesh clipboard send --to 1.2.3.4:19996`
- `gargoyle mesh clipboard listen --listen :19996`

Mesh tun (overlay VPN):
- `gargoyle mesh tun serve --listen :20100 --dev gargoyle0 --cidr 10.42.0.1/24`
- `gargoyle mesh tun connect --to 1.2.3.4:20100 --dev gargoyle0 --cidr 10.42.0.2/24`

Tools pack:
- `gargoyle tools list`
- `gargoyle tools install`
- `gargoyle tools edit`

Doctor/Update:
- `gargoyle doctor`
- `gargoyle update --url https://... --sha256 <sum>`

Telegram C2:
- `gargoyle telegram start`
- `/stats`, `/cli <cmd>`, `/wipe` (если включено в конфиг)

Gateway (Whonix-like, best-effort):
- `gargoyle gateway start --wan wlan0`
- `gargoyle gateway stop`

Mail:
- `gargoyle mail start --mode local`
- SMTP-sink слушает `mail.sink_listen`, письма в `data/mail/inbox/<addr>`
- Local mail: Postfix+Dovecot (Linux)
- Mesh mail: `gargoyle mail send --to user@host --mesh host:port`
- Публичный доступ: включить `mail.mode: tunnel` и настроить `tunnel.server`

Resource Hub:
- `gargoyle hub start --listen 127.0.0.1:8080`
- Webhook: `/webhook/<token>`
- File drop: `/drop/<token>`
- Vault: `POST /vault`
- Inbox: `/inbox/<address>`

Gargoyle Script (DSL):
- Запуск: `gargoyle script run ./scripts/sample.gsl`

Команды Gargoyle Script (DSL, v2.1b):
- `print <text...>` — вывести строку
- `set <var> <value...>` — установить переменную (пока без интерполяции)
- `sleep <ms>` — пауза в миллисекундах
- `file.read <path>` — вывести содержимое файла
- `file.write <path> <text...>` — перезаписать файл
- `file.append <path> <text...>` — дописать строку в файл
- `file.copy <src> <dst>` — копировать файл
- `file.move <src> <dst>` — переместить файл
- `file.delete <path>` — удалить файл/папку
- `net.apply` — применить сетевой профиль из `gargoyle.yaml`
- `mesh.send <src> <dst> <target> <psk> [depth]` — отправить файл
- `mesh.recv <listen> <out> [psk]` — принять файл
- `relay.start [listen]` — запустить relay (по умолчанию `:18080`)
- `relay.stop` — остановить relay
- `doh.start <url> [listen]` — запустить DoH (по умолчанию `127.0.0.1:5353`)
- `doh.stop` — остановить DoH
- `exec <cmd> [args...]` — выполнить команду ОС и вывести результат
- `shell <cmdline...>` — выполнить командную строку через системный shell
- `crypto.encrypt <src> <dst> <psk> [depth] [chunk]` — зашифровать файл (ChaCha20-Poly1305)
- `crypto.decrypt <src> <dst> <psk>` — расшифровать файл
- `emulate.run <app> [args...]` — запустить GUI приложение
- `emulate.stop` — остановить GUI приложение
- `tunnel.expose <service> <port> [token]` — пробросить сервис
- `tunnel.stop` — остановить туннель
- `mail.start` — запустить почтовый sink/local
- `mail.stop` — остановить почту
- `proxy.start [engine] [config]` — запустить proxy engine
- `proxy.stop` — остановить proxy engine
- `hub.start [listen]` — старт Resource Hub
- `hub.stop` — остановить Resource Hub

Сетевые профили (advanced):
- `network.mode`: `direct` | `vpn` | `gateway` | `proxy`
- `network.vpn_type`: `openvpn` | `wireguard`
- `network.vpn_profile`: путь к профилю VPN
- `network.gateway_ip`: IP шлюза/raspberry
- `network.proxy_engine`: `sing-box` | `xray` | `hiddify`
- `network.proxy_config`: путь к конфигу proxy engine
- `network.tor_always_on`: запуск Tor при старте (best-effort)
- `network.tor_strict`: строгий Tor (iptables, только Tor-трафик)
- `storage.usb_enabled`: доступ к USB внутри Gargoyle (по умолчанию off)
- `storage.usb_read_only`: USB только чтение
- `storage.ram_only`: RAM-only сессия (всё в tmpfs, без записи на диск)
- `emulate.privacy_mode`: best-effort приватность EmulateEL
- `tunnel.type`: `frp` | `relay`
- `tunnel.server`: `host:port` FRP сервера
- `tunnel.local_ip`: локальный IP для проброса (по умолчанию 127.0.0.1)
- `mail.mode`: `local` | `tunnel`
- `mesh.padding_bytes`: байты padding после заголовка (уменьшает fingerprinting)

Профили:
- `gargoyle profile ctf-safe` — применить мягкий CTF-safe профиль
- `gargoyle help-gargoyle` — методичка по Gargoyle и всем модулям

Хранилище (USB или папка):
- По умолчанию используется `~/.gargoyle`
- Можно указать свою директорию (например, флешка):
  - Windows: `set GARGOYLE_HOME=E:\\gargoyle`
  - Linux: `export GARGOYLE_HOME=/media/usb/gargoyle`
- Инициализация структуры:
  - `gargoyle init`
  - `gargoyle init --force` (перезаписать конфиг)

Важно про DNS:
- DNS не меняет внешний IP и геолокацию, это не VPN.
- DNS влияет только на разрешение доменных имен.

Примечание по платформам:
- Linux поддерживается лучше (USB-ивенты, LUKS, iptables).
- Windows работает, но без LUKS и без жёсткой блокировки устройств.
- Для шифрования на Windows используется BitLocker/BitLocker To Go (NTFS/exFAT).

Tor always-on:
- В профиле `tor_always_on` Gargoyle пытается запустить Tor сервис (best-effort).
- Есть fail-closed режим через iptables (Linux): весь исходящий трафик блокируется, кроме Tor.
- Это может блокировать обычные приложения, если они не используют Tor.

Leak-check:
- После применения Tor/VPN Gargoyle делает best-effort проверку IP/DNS.

Proxy mode (sing-box/xray):
- Используется как прокси‑движок (не классический VPN).
- Указать `network.proxy_engine` и `network.proxy_config`.

Live-USB build:
- `os/liveusb/build.sh` (скелет сборки ISO, включает toram)


