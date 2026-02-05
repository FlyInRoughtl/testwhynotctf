# os/

This folder will contain the OS build definitions, base image scripts, and runtime services for Gargoyle.

Planned areas:
- base/ (rootfs, packages)
- services/ (network, storage, wipe)
- ui/ (TUI shell)
- mesh/ (relay, onion routing)
- liveusb/ (live-build pipeline)

See SPEC.md for details.

Current MVP code lives in `os/ctfvault` (Go CLI/TUI prototype).

