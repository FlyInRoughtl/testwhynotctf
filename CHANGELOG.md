# Changelog

All notable changes to Gargoyle will be documented in this file.

## [Unreleased]

## [3.1.3r] - 2026-02-06
### Added
- FullAnon profile (Tor always-on + kill-switch via iptables).
- Hotspot/NAT helper (NetworkManager shared mode, Linux).
- Mesh gateway (local TCP forwarder to upstream tunnel).
- Loot sync (fsnotify watcher -> mesh send).
- TUI screens for hotspot/gateway/sync/broadcast.
- TUI help overlay (`?`) and updated hints.
- Wizard option for FullAnon mode (system.mode).
- Wizard language selection (ru/en) and advanced privacy/mesh toggles on Windows.
- Relay allowlist support (token list).
- Tools pack editing and external pack files.
### Tests
- Added basic unit tests for config/tools/mesh/syncer packages.
### Fixed
- WSS random ID now checks crypto entropy errors.
- Update downloader has HTTP timeouts.
- Tools `cmd:` parsing honors quotes (shlex).
- TUN nonce derivation fixed.
### Changed
- Windows update uses helper wrapper (no manual rename).
- Documentation updated; Live-OS deferred to v5+.

## [2.1b] - 2026-02-05
### Added
- Mesh TLS transport with optional header padding to reduce fingerprinting.
- Mesh-mail (local + mesh by default) and `mail send` over mesh.
- Proxy service commands (sing-box/xray/hiddify).
- EmulateEL privacy mode uses bubblewrap on Linux when available.
- EmulateEL display-server wrappers (cage/gamescope/weston) for best-effort anti-capture.
- Mesh discovery (UDP broadcast), chat, clipboard, and tun/tap overlay (Linux).
- Telegram C2 (allowlist/pairing, best-effort).
- Tools pack (`tools.yaml`) + CLI manager.
- `doctor` and `update` commands.
- Boss-key (F10) in TUI.
- Live-USB build skeleton (os/liveusb).
- Tor transproxy config (torrc + iptables strict).
- WSS tunnel (built-in server/client).
- Gateway mode (Whonix-like via namespaces, best-effort).
- Optional VeraCrypt container support in Windows wizard (best-effort).
- Hub hardening: size limits, safer file handling, server timeouts.
- Tunnel hardening: service name validation, temp config cleanup, local_ip option.
- Relay safety: connection limiter + TTL to avoid chain loops.
### Fixed
- SMTP sink enforces message size limit to avoid memory abuse.

### Changed
- UI header now uses the version constant.
- Mesh defaults: TLS transport + padding bytes.
- DSL argument parser handles escapes/quotes more safely.

### Known Limitations
- Hiddify CLI integration is best-effort and requires external install.
- VeraCrypt container creation/mount is best-effort and depends on local setup.

## [1.3.0] - 2026-02-05
### Added
- TUI shell with dashboard, menu navigation, status screens, and hotkeys.
- Installer wizards for Linux/Windows with USB or folder setup.
- USB layout options (EFI/SYSTEM/PERSIST/SHARED) and optional free space.
- Gargoyle Script (DSL) engine and sample scripts.
- Mesh/relay file transfer with encrypted streams and onion depth.
- EmulateEL (Linux GUI launcher) with CLI/TUI control.
- Resource Hub (webhook, file drop, vault, inbox).
- Tunnel support via FRP (self-hosted).
- Mail stack: SMTP sink + local mail server.
- Privacy pack: CTF-safe profile, leak-check, Tor strict (Linux), RAM-only session.
- USB watcher (Linux) + emergency wipe flow.
- `help-gargoyle` full manual embedded in the binary.

### Changed
- CLI/binary name is `gargoyle`.
- Default home is `~/.gargoyle` and config file is `gargoyle.yaml`.
- Windows USB formatting defaults to exFAT with 256KB clusters.

### Fixed
- Multiple UI and config consistency issues during V1.3 stabilization.

### Known Limitations
- Windows USB layout is shared-only (full layout requires Linux).
- Anonymity is best-effort; no absolute guarantees.
