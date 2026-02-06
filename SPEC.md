# Gargoyle — SPEC (кратко)
Версия: 3.1.3r_0.1.2
Статус: Release
Дата: 2026-02-06

## 1. Цель
Переносимая среда для CTF/лабораторных задач с TUI‑интерфейсом и модульными инструментами.  
Основной режим — запуск на хост‑ОС (USB/папка). Live‑OS/ISO отложены (roadmap v5+).

## 2. Не‑цели
- Гарантированная анонимность уровня Tails.
- Очистка логов хост‑ОС.
- Самописная криптография (используем стандартные примитивы).

## 3. Ключевые функции
- TUI‑панель и меню, быстрые подсказки команд.
- Mesh/Relay обмен файлами (TCP/TLS, padding, onion‑depth).
- EmulateEL (Linux GUI‑мост) для запуска GUI‑приложений.
- Resource Hub (webhook/drop/vault), Mail, Proxy, Tunnel.
- Hotspot/NAT, Mesh‑gateway, Loot‑sync (Linux best‑effort).
- Tools packs (CTF/OSINT/Anonymity).
- FullAnon профиль (Tor strict + kill‑switch на Linux).

## 4. Режимы
- Host‑mode: основной, CLI/TUI на Windows/Linux.
- Live‑OS/ISO: roadmap v5+.

## 5. Безопасность/приватность (best‑effort)
- Tor strict = iptables kill‑switch (Linux).
- MAC spoofing, закрытые порты по умолчанию.
- RAM‑only режим без записи на диск (Linux best‑effort).
- Логи по умолчанию в RAM.

## 6. Хранилище (USB layout — рекомендация)
- EFI/BOOT (FAT32 ~512MB)
- SYSTEM (ext4 RO / squashfs)
- PERSISTENT (LUKS2 + ext4)
- SHARED (exFAT)

## 7. Roadmap
- v4.x: улучшение mesh overlay/discovery.
- v5.x: Live‑OS/ISO pipeline.
