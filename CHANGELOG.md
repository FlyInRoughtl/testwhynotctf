# Changelog

All notable changes to Gargoyle will be documented in this file.

## [Unreleased]

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
