# testwhynotctf

Gargoyle: изолированная среда для CTF/лабораторных задач (Live-USB + VM).
Полное ТЗ: [SPEC.md](SPEC.md).
Требования: [REQUIREMENTS.md](REQUIREMENTS.md).

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

Что уже реализовано (MVP):
- CLI с базовыми командами и TUI-прототипом
- Конфиг `ctfvault.yaml` и валидация
- Прямой зашифрованный обмен файлами по TCP (`mesh send` / `mesh recv`)
- TUI виджеты с анимацией, меню и базовыми экранами
- Relay-сервер для передачи через публичные сети (V1.1)

Планируется далее:
- Relay/Onion маршруты, полноценный mesh
- Сервисные компоненты OS-уровня и installer wizard

Пример (MVP file transfer):
```
# receiver
ctfvault mesh recv --listen :19999 --out ./downloads --psk secret

# sender
ctfvault mesh send ./file.txt file.txt --to 127.0.0.1:19999 --security --psk secret --depth 3
```

Пример (relay через публичную сеть):
```
# relay server
ctfvault relay --listen :18080

# receiver (connect via relay)
ctfvault mesh recv --relay 1.2.3.4:18080 --token ROOM1 --psk secret

# sender (connect via relay)
ctfvault mesh send ./file.txt file.txt --relay 1.2.3.4:18080 --token ROOM1 --security --psk secret
```

Пример (relay chain, multi-hop):
```
# relay chain: r1 -> r2 -> target
ctfvault mesh send ./file.txt file.txt --to 10.0.0.5:19999 --relay-chain 1.2.3.4:18080,5.6.7.8:18080 --security --psk secret --depth 5
```

Сеть (применение профиля):
- `ctfvault start --apply-network` (Linux, best-effort)

DoH proxy (V1.1):
- Установить `cloudflared`
- Запуск: `ctfvault doh --listen 127.0.0.1:5353 --url https://xbox-dns.ru/dns-query`

Хранилище (USB или папка):
- По умолчанию используется `~/.ctfvault`
- Можно указать свою директорию (например, флешка):
  - Windows: `set CTFVAULT_HOME=E:\\ctfvault`
  - Linux: `export CTFVAULT_HOME=/media/usb/ctfvault`
- Инициализация структуры:
  - `ctfvault init`
  - `ctfvault init --force` (перезаписать конфиг)

Важно про DNS:
- DNS не меняет внешний IP и геолокацию, это не VPN.
- DNS влияет только на разрешение доменных имен.
