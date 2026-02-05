# Gargoyle — Техническое задание (SPEC)
Версия: 1.0
Статус: Draft
Дата: 2026-02-05
Языки: RU (основной), EN (краткие резюме)

---

## 0. Коротко о проекте
Gargoyle — переносимая изолированная среда для CTF/лабораторных задач. Основной режим — Live-USB Linux с удобным TUI (терминальная «почти ОС»). Дополнительно поддерживается запуск в VM. Система не требует аккаунтов и внешних API, работает офлайн после установки пакетов и делает акцент на приватности внутри изолированной среды.

EN: Portable isolated CTF environment, primary Live-USB mode with TUI-first UX, optional VM mode, offline-capable after setup, privacy-focused inside the sandbox.

---

## 1. Цели и рамки
### 1.1 Цели
- Быстрый запуск изолированной среды с USB или в VM.
- TUI-ориентированный «рабочий стол» с меню, виджетами и подсказками команд.
- Модульная установка CTF-инструментов по категориям.
- Mesh-сеть и защищенный файловый обмен (опционально onion-маршрут).
- Максимум приватности внутри изолированной среды без внешних аккаунтов.
- Никаких AI-сервисов и внешних API-зависимостей.

### 1.2 Не-цели
- Гарантия «полной анонимности» в интернете.
- Удаление или модификация логов хост-ОС.
- Использование самописных криптоалгоритмов вместо проверенных примитивов.

### 1.3 Модель угроз (кратко)
- Защита данных сессии и сетевого трафика от сторонних наблюдателей.
- Снижение следов на хосте за счет Live-режима и строгой изоляции.
- Публичные Wi‑Fi, NAT, client isolation — поддержка через relay-fallback.

EN: Goals are isolation, fast UX, modular tooling, secure mesh/file transfer, privacy inside the sandbox. Out of scope: guaranteed anonymity, host log wiping, custom crypto primitives.

---

## 2. Термины (коротко)
- Live-USB: загрузка ОС с флешки без установки на диск.
- Persistent: зашифрованный раздел для сохранения состояния.
- Mesh: оверлейная сеть поверх любой физической сети.
- Relay: самохостед узел для проброса трафика.
- Onion-маршрут: многоуровневое шифрование с цепочкой промежуточных узлов.

---

## 3. Режимы и издания
### 3.1 Режимы запуска
- Live-USB (основной): загрузка собственного Linux, изоляция, минимум следов.
- VM-режим: запуск образа через QEMU/KVM без перезагрузки.

### 3.2 Издания
- Public: минимальный, безопасный набор инструментов и функций.
- Private: расширенный набор (доп. инструменты, сетевые функции, расширенные режимы).

EN: Primary Live-USB, optional VM. Editions: Public (minimal) and Private (extended).

---

## 4. Архитектура (обзор)
### 4.1 База ОС
- Debian/Ubuntu LTS.
- Поддержка UEFI/BIOS.

### 4.2 Основные компоненты
- Boot/Installer: мастер создания USB/VM.
- Core services: сетевой стек, storage manager, wipe manager.
- TUI shell: оболочка с меню и виджетами.
- Tool manager: модульная установка инструментов.
- Mesh/Relay: overlay-сеть, onion-маршруты, LAN-чат.
- EmulateEL: отдельное GUI-приложение (обертка над Xpra/Waypipe/VNC).

EN: Debian/Ubuntu base; core services + TUI shell + tooling + mesh/relay + GUI bridge.

---

## 5. UI/UX (TUI-первым)
### 5.1 Основной экран
- «Терминал-десктоп» (TUI) с панелями статуса.
- Аналог меню «Пуск»: категории Tools/Network/Storage/Mesh/System.
- Ярлыки и иконки из open-source паков (например, Kali), с соблюдением лицензий.
- Нет «сухих» надписей Terminal/Files; только человеко-понятные названия.
- Встроенный файловый менеджер с быстрым выбором/копированием.
- Drag-and-drop поддерживается в GUI-мосте и VM-режиме.
- Цветовые темы и акценты для статусов (errors/warn/ok).
- Частота обновления виджетов: 5–10 FPS (адаптивно).

### 5.2 Подсказки команд
- Автодополнение и подсказки синтаксиса.
- Быстрые шаблоны команд (например, mesh send --security).

### 5.3 Графика в TUI
- ASCII/box-drawing для окон, карточек, логов.
- Смена тем (светлая/темная) в один клик.

### 5.4 GUI-мост (EmulateEL)
- Отдельное приложение, запускается из TUI.
- Низкий FPS/качество по умолчанию (экономия ресурсов).
- Канал между средой и GUI-окном шифруется.

EN: Terminal-like desktop with menu/start, icons, command hints, themes; GUI bridge in separate app.

---

## 6. Инсталлеры и мастер настройки
### 6.1 Установщики
- Windows + Linux.

### 6.2 Мастер
- Выбор USB/диска.
- Форматирование под задачу.
- Размер system/persistent/shared.
- Настройка общих папок.
- Выбор RAM/CPU/диска (для VM) и лимитов (для Live через cgroups).
- Режим «Установка в папку» (disk install без форматирования): выбор пустой папки, строгая изоляция внутри выбранного пути.
  - Граница доступа: система не выходит за пределы выбранной папки, кроме явно разрешенных shared-папок.
- Advanced экран: Wi‑Fi/BT/порты/сеть, выбор DNS профиля.

EN: Installers for Windows/Linux; guided wizard for USB/VM setup.

---

## 7. Хранилище, сессии и wipe
### 7.1 Разметка USB
- EFI/Boot.
- System (read-only).
- Persistent (LUKS2).
- Shared (опционально).
  - Shared режимы: public (без шифрования) и private (с шифрованием).
- exFAT shared: cluster size 512 KB по умолчанию.

### 7.2 Сессии
- Временная сессия (без сохранения) — по умолчанию.
- Сохранение сессии в encrypted-раздел.
- Опциональный контейнер-файл для хранения на диске хоста.
- Поддержка USB hotplug: уведомление, безопасное монтирование/размонтирование.

### 7.3 Recovery-коды
- Генерируются 10 кодов; сохраняются в txt-файл.
- Для восстановления нужен файл с кодами.
- 3 неверных попытки — стирание контейнера.

### 7.4 USB-удаление
- При извлечении USB: немедленный wipe активной сессии.
- Ключи в RAM уничтожаются.
- Best-effort очистка временных данных внутри среды; вмешательство в логи хоста не выполняется.

EN: Encrypted persistent partition + optional container file, recovery codes, auto-wipe on USB removal.

---

## 8. Безопасность и приватность
### 8.1 Общие принципы
- Нет внешних аккаунтов, API и телеметрии.
- Логи по умолчанию в RAM.
- Экспорт логов только вручную.

### 8.2 Смешанный подход
- Базовый режим (default): защита и очистка только внутри среды.
- Расширенный режим (опция): дополнительные меры с явным предупреждением.
- Команда «Экстренный сброс»: удаляет все пользовательские данные, но сохраняет ключ идентичности устройства.

### 8.3 Приватность сети
- Опциональные профили прокси и DNS.
- MAC-рандомизация.
- Firewall-профили.
- Tor/Firefox — по выбору пользователя.
- DNS профили: system / xbox / custom (DoH).

EN: No accounts/telemetry; RAM logs; default privacy inside the sandbox; advanced mode optional.

---

## 9. Криптография (гибридная модель)
### 9.1 Примитивы (строго стандартные)
- X25519, ChaCha20-Poly1305, HKDF, Argon2, LUKS2.

### 9.2 «Своя криптография» как протокол
- Используются стандартные примитивы, но собственная схема:
  - Handshake и ротации ключей.
  - Многоуровневое шифрование с независимыми ключами.
  - Recovery-коды и policy-проверки.

### 9.3 Многораундное шифрование
- Параметр depth (1..10).
- Каждый слой использует уникальный ключ (запрещено повторное шифрование одним ключом).
- Default: depth=3. Пользователь может выставить 10.

EN: Standard primitives only; custom protocol layer with key rotation and multi-layer encryption.

### 9.4 Identity-ключ устройства
- 256 символов (A‑Z a‑z 0‑9 спецсимволы).
- Отображение: группы по 15 символов с дефисом.
- Хранение: keys/identity.key (в persistent).

---

## 10. Сетевой стек
### 10.1 Базовые функции
- Управление Wi‑Fi и Bluetooth (скан/подключение/список устройств).
- Профили прокси и DNS (преднастроенные + пользовательские).
- MAC-рандомизация и firewall-профили.
- Опциональная установка/запуск Tor + Firefox.

### 10.2 Mesh-сеть
- Overlay-сеть с P2P и self-hosted relay.
- Ключи машин + ACL.
- Авто-fallback для сложных сетей (публичный Wi‑Fi, client isolation).

### 10.3 Connectivity Matrix (fallback)
Приоритет по умолчанию: P2P → Relay → TCP:443.
- Прямой LAN без изоляции: P2P.
- LAN с client isolation: relay.
- Публичный Wi‑Fi: relay с TCP:443 fallback.
- Заблокирован UDP: relay через TCP:443.

### 10.4 Tunnel (аналог ngrok)
- Режим «server»: публикация локального сервиса через relay.
- Каждая машина имеет identity-ключ; доступ к каналу через обмен ключами.
- Дополнительный файл с 10 кодами для подтверждения доступа (одноразовые/многоразовые политики настраиваются).
- Все данные проходят E2E-шифрование, глубина шифрования = onion_depth.
- Relay-сервер: отдельный процесс `ctfvault relay` (V1.1).
 - Relay-chain: последовательный forward через цепочку relay (V1.1, multi-hop).

EN: Mesh overlay with P2P and relay fallback; connectivity matrix and prioritized fallback order.

---

## 11. Передача файлов (mesh + onion)
### 11.1 Команда
ctfvault mesh send <src> <dst> --security --metadata standard

### 11.2 Поведение --security
- В V1.1: многослойное шифрование (depth 1..10) поверх прямого канала, relay или relay-chain.
- Полная E2E-шифрация данных.

### 11.3 Режим передачи
- Streaming + resume (чанки с checkpoint).
- При обрыве маршрут перестраивается, прогресс сохраняется.

### 11.4 Защита метаданных
- metadata=off | standard | max
- standard: скрытие имен/путей, округление размеров, базовый padding.
- max: усиленный padding/задержки/микширование.

EN: Onion routing for secure file transfer; streaming with resume; metadata protection levels.

---

## 12. LAN-мессенджер
- Собственный минимальный протокол (LAN-only).
- mDNS-обнаружение + TLS/Noise.
- История сообщений по умолчанию в RAM.

EN: LAN-only chat with mDNS discovery and encrypted transport.

---

## 13. EmulateEL (GUI-мост)
- Отдельное приложение, запускается из TUI.
- Обертка над Xpra/Waypipe/VNC.
- Низкий FPS/качество по умолчанию.
- Используется, например, для Tor Browser.

EN: Separate GUI bridge app, low-FPS, encrypted channel.

---

## 14. Модульные инструменты
### 14.1 Категории
- Crypto, Web, Pwn, Forensics, Reversing, Wireless, Misc.

### 14.2 Установка
- Мастер на первом старте предлагает выбор категорий.
- Поддержка offline-кэша пакетов.
- Пример опций: aircrack-ng, сетевые утилиты, reverse/proxy наборы.
- Интернет нужен только для загрузки пакетов; дальнейшая работа возможна офлайн.

EN: Modular tool categories with first-run selection and offline cache.

---

## 15. CLI и конфиг
### 15.1 CLI команды (минимум)
- ctfvault start
- ctfvault stop
- ctfvault status
- ctfvault mesh up
- ctfvault mesh send --security
- ctfvault wipe --emergency

### 15.2 Конфиг
Файл ctfvault.yaml:
- system: ram_limit, cpu_limit, locale, edition
- storage: persistent, shared, recovery_codes
- network: proxy, dns_profile, dns_custom, tor, mac_spoof, wifi_enabled, bluetooth_enabled, ports_open
- security: identity_key_path, identity_length, identity_group
- mesh: relay_url, onion_depth, metadata_level
- ui: theme, language

EN: Core CLI commands and a single YAML config.

---

## 16. Структура репозитория
Требование: 2 папки и 1 README.
- os/ — сборка и конфиги ОС.
- installers/ — установщики USB/VM.
- README.md — краткое описание и ссылка на SPEC.

EN: Two folders (os/, installers/) plus README.

---

## 17. Нефункциональные требования
- Быстрый старт (target <= 60 секунд).
- Работа на 4 GB RAM (минимум), 8 GB (рекомендовано).
- Минимум фоновых сервисов.
- Офлайн-режим без деградации базового функционала.

EN: Fast boot, low resource usage, minimal background services, offline-first.

---

## 18. Тесты и приемка
- Boot-тест Live-USB на разных ПК.
- VM-режим: корректные лимиты RAM/CPU/диск.
- Шифрование/расшифровка persistent-раздела.
- Recovery-коды и 3-кратная ошибка → wipe.
- Mesh-чат и обмен файлами через relay + P2P.
- Onion-файлообмен: A→B→C→G (relays не видят содержимое).
- Потеря узла на маршруте → успешное возобновление.
- USB hotplug: нотификация и безопасное монтирование.

EN: Boot/VM, encryption, recovery codes, mesh/onion transfer, resume, USB hotplug.

---

## 19. Риски и допущения
- Полная анонимность не гарантируется.
- Публичные Wi‑Fi и NAT требуют relay.
- «Своя криптография» реализуется только как протокол, не как алгоритм.

EN: No full anonymity; public Wi‑Fi requires relay; custom crypto only as protocol layer.

---

## 20. Дорожная карта
- V1: Live-USB + TUI + базовые инструменты + mesh/relay.
- V1.1: onion-файлообмен, расширенные профили приватности.
- V2: web-панель (browser mode) и расширенный GUI.

EN: V1 Live-USB+TUI+mesh; V1.1 onion transfer; V2 web UI.

