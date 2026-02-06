#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${LOG_FILE:-installer.log}"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[installer] log: $LOG_FILE"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

use_whiptail=false
if command -v whiptail >/dev/null 2>&1; then
  use_whiptail=true
fi

prompt_menu() {
  local title="$1"; shift
  local opts=("$@")
  if $use_whiptail; then
    local menu=()
    local i=1
    for opt in "${opts[@]}"; do
      menu+=("$i" "$opt")
      i=$((i+1))
    done
    local choice
    choice=$(whiptail --title "$title" --menu "$title" 20 70 10 "${menu[@]}" 3>&1 1>&2 2>&3)
    echo "${opts[$((choice-1))]}"
  else
    echo "$title"
    local i=1
    for opt in "${opts[@]}"; do
      echo "[$i] $opt"
      i=$((i+1))
    done
    read -rp "Select: " choice
    echo "${opts[$((choice-1))]}"
  fi
}

prompt_yesno() {
  local q="$1"; local default="$2"
  if $use_whiptail; then
    if whiptail --yesno "$q" 10 60; then echo "yes"; else echo "no"; fi
  else
    local hint="[y/N]"
    [ "$default" = "yes" ] && hint="[Y/n]"
    read -rp "$q $hint " ans
    ans=${ans:-$default}
    case "$ans" in y|Y|yes|YES) echo "yes";; *) echo "no";; esac
  fi
}

prompt_input() {
  local q="$1"; local def="$2"
  if $use_whiptail; then
    local out
    out=$(whiptail --inputbox "$q" 10 60 "$def" 3>&1 1>&2 2>&3)
    echo "$out"
  else
    read -rp "$q [$def]: " out
    echo "${out:-$def}"
  fi
}

prompt_advanced() {
  if $use_whiptail; then
    local choice
    choice=$(whiptail --title "Advanced settings" --menu "Open advanced settings?" 12 60 2 \
      "continue" "Proceed with defaults" \
      "advanced" "Open advanced settings" 3>&1 1>&2 2>&3)
    [ "$choice" = "advanced" ] && echo "yes" || echo "no"
  else
    read -rp "Press A for Advanced or Enter to continue: " ans
    ans=$(echo "$ans" | tr '[:lower:]' '[:upper:]')
    [ "$ans" = "A" ] && echo "yes" || echo "no"
  fi
}

yaml_list_flow() {
  local raw="$1"
  if [ -z "$raw" ]; then
    printf "[]"
    return
  fi
  local out="["
  IFS=',;' read -ra items <<< "$raw"
  local first=1
  for item in "${items[@]}"; do
    item=$(echo "$item" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$item" ] && continue
    if [ $first -eq 0 ]; then
      out+=","
    fi
    out+="\"$item\""
    first=0
  done
  out+="]"
  printf "%s" "$out"
}

print_plan() {
  local target="$1"
  local location="$2"
  local layout="$3"
  local sys="$4"
  local persist="$5"
  local free="$6"
  local cluster="$7"
  echo ""
  echo "===== INSTALL PLAN ====="
  echo "Target: $target"
  echo "Location: $location"
  [ -n "$layout" ] && echo "USB layout: $layout"
  [ -n "$sys" ] && echo "SYSTEM size: $sys MB"
  [ -n "$persist" ] && echo "PERSIST size: $persist MB"
  [ -n "$free" ] && echo "Free space: $free MB"
  [ -n "$cluster" ] && echo "exFAT cluster: ${cluster} KB"
  [ -n "$usb_label" ] && echo "USB label: $usb_label"
  echo "Edition: $edition"
  echo "Mode: $op_mode"
  echo "DNS: $dns_profile"
  echo "Tor strict: $tor_strict"
  echo "USB enabled: $usb_enabled, USB read-only: $usb_read_only"
  echo "RAM-only: $ram_only"
  echo "Recovery codes: $gen_recovery"
  echo "Copy source: $copy_source, Auto build: $auto_build"
  echo "Tools pack: $tools_file (auto_install=$tools_auto)"
  echo "========================"
  echo ""
}

write_config() {
  local path="$1" edition="$2" op_mode="$3" locale="$4" ram_limit="$5" cpu_limit="$6" dns_profile="$7" dns_custom="$8" wifi="$9" bt="${10}" ports="${11}" usb_enabled="${12}" usb_read_only="${13}" ram_only="${14}" auto_wipe_remove="${15}" auto_wipe_exit="${16}" net_mode="${17}" vpn_type="${18}" vpn_profile="${19}" gateway_ip="${20}" proxy_engine="${21}" proxy_config="${22}" tor_install="${23}" tor_strict="${24}" tor_trans_port="${25}" tor_dns_port="${26}" tor_use_bridges="${27}" tor_transport="${28}" tor_bridge_lines="${29}" torrc_path="${30}" mac_spoof="${31}" mesh_onion="${32}" mesh_discovery="${33}" mesh_discovery_port="${34}" mesh_discovery_key="${35}" mesh_auto_join="${36}" mesh_chat="${37}" mesh_chat_listen="${38}" mesh_chat_psk="${39}" mesh_chat_psk_file="${40}" mesh_clipboard="${41}" mesh_clipboard_warn="${42}" mesh_tun_enabled="${43}" mesh_tun_device="${44}" mesh_tun_cidr="${45}" mesh_tun_peer_cidr="${46}" mesh_padding="${47}" mesh_transport="${48}" mesh_metadata="${49}" mesh_onion_depth="${50}" mesh_relay_allowlist="${51}" hotspot_ssid="${52}" hotspot_password="${53}" hotspot_ifname="${54}" hotspot_shared="${55}" emulate_privacy="${56}" emulate_temp="${57}" emulate_downloads="${58}" emulate_display="${59}" tunnel_type="${60}" tunnel_server="${61}" tunnel_token="${62}" tunnel_local_ip="${63}" mail_mode="${64}" mail_sink="${65}" mail_local="${66}" mail_sink_listen="${67}" mail_sink_ui="${68}" mail_mesh_enabled="${69}" mail_mesh_listen="${70}" mail_mesh_psk="${71}" mail_mesh_psk_file="${72}" ui_theme="${73}" ui_boss_key="${74}" ui_boss_mode="${75}" tools_file="${76}" tools_auto="${77}" tools_repo="${78}" update_url="${79}" update_channel="${80}" update_public_key="${81}" update_auto="${82}" sync_enabled="${83}" sync_target="${84}" sync_dir="${85}" sync_psk="${86}" sync_psk_file="${87}" sync_transport="${88}" sync_padding="${89}" sync_depth="${90}" telegram_enabled="${91}" telegram_bot_token="${92}" telegram_allowed_user="${93}" telegram_pairing_ttl="${94}" telegram_allow_cli="${95}" telegram_allow_wipe="${96}" telegram_allow_stats="${97}" doh_url="${98}" doh_listen="${99}"
  cat > "$path" <<EOF
# Gargoyle config
system:
  ram_limit_mb: $ram_limit
  cpu_limit: $cpu_limit
  locale: "$locale"
  edition: "$edition"
  mode: "$op_mode"

storage:
  persistent: true
  shared: true
  recovery_codes: "recovery_codes.txt"
  usb_enabled: $usb_enabled
  usb_read_only: $usb_read_only
  ram_only: $ram_only
  auto_wipe_on_usb_remove: $auto_wipe_remove
  auto_wipe_on_exit: $auto_wipe_exit

network:
  proxy: ""
  mode: "$net_mode"
  vpn_type: "$vpn_type"
  vpn_profile: "$vpn_profile"
  gateway_ip: "$gateway_ip"
  proxy_engine: "$proxy_engine"
  proxy_config: "$proxy_config"
  dns_profile: "$dns_profile"
  dns_custom: "$dns_custom"
  doh_url: "$doh_url"
  doh_listen: "$doh_listen"
  tor: $tor_install
  tor_always_on: $tor_install
  tor_strict: $tor_strict
  tor_trans_port: $tor_trans_port
  tor_dns_port: $tor_dns_port
  tor_use_bridges: $tor_use_bridges
  tor_transport: "$tor_transport"
  tor_bridge_lines: $tor_bridge_lines
  torrc_path: "$torrc_path"
  mac_spoof: $mac_spoof
  wifi_enabled: $wifi
  bluetooth_enabled: $bt
  ports_open: $ports

security:
  identity_key_path: "keys/identity.key"
  identity_bits: 256
  identity_group: 5

mesh:
  relay_url: ""
  onion_depth: $mesh_onion_depth
  metadata_level: "$mesh_metadata"
  transport: "$mesh_transport"
  padding_bytes: $mesh_padding
  discovery_enabled: $mesh_discovery
  discovery_port: $mesh_discovery_port
  discovery_key: "$mesh_discovery_key"
  auto_join: $mesh_auto_join
  chat_enabled: $mesh_chat
  chat_listen: "$mesh_chat_listen"
  chat_psk: "$mesh_chat_psk"
  chat_psk_file: "$mesh_chat_psk_file"
  clipboard_share: $mesh_clipboard
  clipboard_warn: $mesh_clipboard_warn
  tun_enabled: $mesh_tun_enabled
  tun_device: "$mesh_tun_device"
  tun_cidr: "$mesh_tun_cidr"
  tun_peer_cidr: "$mesh_tun_peer_cidr"
  onion_only: $mesh_onion
  relay_allowlist: $mesh_relay_allowlist
  hotspot:
    ssid: "$hotspot_ssid"
    password: "$hotspot_password"
    ifname: "$hotspot_ifname"
    shared: $hotspot_shared

ui:
  theme: "$ui_theme"
  language: "$locale"
  boss_key: $ui_boss_key
  boss_mode: "$ui_boss_mode"

emulate:
  privacy_mode: $emulate_privacy
  temp_dir: "$emulate_temp"
  downloads_dir: "$emulate_downloads"
  display_server: "$emulate_display"

tunnel:
  type: "$tunnel_type"
  server: "$tunnel_server"
  token: "$tunnel_token"
  local_ip: "$tunnel_local_ip"

mail:
  mode: "$mail_mode"
  sink: $mail_sink
  local_server: $mail_local
  sink_listen: "$mail_sink_listen"
  sink_ui: "$mail_sink_ui"
  mesh_enabled: $mail_mesh_enabled
  mesh_listen: "$mail_mesh_listen"
  mesh_psk: "$mail_mesh_psk"
  mesh_psk_file: "$mail_mesh_psk_file"

tools:
  file: "$tools_file"
  auto_install: $tools_auto
  repository: "$tools_repo"

update:
  url: "$update_url"
  channel: "$update_channel"
  public_key: "$update_public_key"
  auto: $update_auto

sync:
  enabled: $sync_enabled
  target: "$sync_target"
  dir: "$sync_dir"
  psk: "$sync_psk"
  psk_file: "$sync_psk_file"
  transport: "$sync_transport"
  padding_bytes: $sync_padding
  depth: $sync_depth

telegram:
  enabled: $telegram_enabled
  bot_token: "$telegram_bot_token"
  allowed_user_id: $telegram_allowed_user
  pairing_ttl: $telegram_pairing_ttl
  allow_cli: $telegram_allow_cli
  allow_wipe: $telegram_allow_wipe
  allow_stats: $telegram_allow_stats
EOF
}

gen_identity_key() {
  local path="$1"
  local raw
  raw=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=[]{}:;,.<>?/' </dev/urandom | head -c 256)
  local formatted=""
  local i=0
  while [ $i -lt ${#raw} ]; do
    formatted+="${raw:$i:15}"
    i=$((i+15))
    if [ $i -lt ${#raw} ]; then
      formatted+="-"
    fi
  done
  mkdir -p "$(dirname "$path")"
  printf "%s\n" "$formatted" > "$path"
  chmod 600 "$path" || true
}

gen_recovery_codes() {
  local path="$1"
  local count="${2:-10}"
  local length="${3:-30}"
  local group="${4:-5}"
  local alphabet='A-Za-z0-9'
  mkdir -p "$(dirname "$path")"
  : > "$path"
  local i=0
  while [ $i -lt "$count" ]; do
    local raw
    raw=$(tr -dc "$alphabet" </dev/urandom | head -c "$length")
    if [ "${#raw}" -lt "$length" ]; then
      continue
    fi
    local formatted=""
    local j=0
    while [ $j -lt ${#raw} ]; do
      formatted+="${raw:$j:$group}"
      j=$((j+group))
      if [ $j -lt ${#raw} ]; then
        formatted+="-"
      fi
    done
    echo "$formatted" >> "$path"
    i=$((i+1))
  done
  chmod 600 "$path"
}

write_sample_script() {
  local path="$1"
  cat > "$path" <<'EOF'
# Gargoyle Script sample
print "Gargoyle Script: hello"
print "Starting relay on :18080"
relay.start :18080
sleep 500
print "Relay running"
# Example mesh send: mesh.send <src> <dst> <target> <psk> [depth]
# mesh.send ./file.txt file.txt 127.0.0.1:19999 secret 3
EOF
}

copy_source() {
  local dest_root="$1"
  local src="$repo_root/os/ctfvault"
  if [ ! -f "$src/go.mod" ]; then
    echo "WARN: source not found at $src"
    return
  fi
  mkdir -p "$dest_root/src"
  if [ -d "$dest_root/src/ctfvault" ]; then
    rm -rf "$dest_root/src/ctfvault"
  fi
  cp -a "$src" "$dest_root/src/ctfvault"
}

build_binaries() {
  local dest_root="$1"
  if ! command -v go >/dev/null 2>&1; then
    echo "WARN: Go not found; skipping build."
    return
  fi
  local src="$dest_root/src/ctfvault"
  if [ ! -f "$src/go.mod" ]; then
    src="$repo_root/os/ctfvault"
  fi
  if [ ! -f "$src/go.mod" ]; then
    echo "WARN: go.mod not found; cannot build."
    return
  fi
  (cd "$src" && go build -o "$dest_root/gargoyle" ./cmd/gargoyle && go build -o "$dest_root/gargoylectl" ./cmd/gargoylectl)
}

copy_binaries() {
  local dest_root="$1"
  local candidates=(
    "$repo_root/gargoyle"
    "$repo_root/gargoylectl"
    "$repo_root/os/ctfvault/gargoyle"
    "$repo_root/os/ctfvault/gargoylectl"
  )
  for bin in "${candidates[@]}"; do
    if [ -f "$bin" ]; then
      cp -f "$bin" "$dest_root/" || true
    fi
  done
}

write_start_sh() {
  local dest_root="$1"
  cat > "$dest_root/start.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export GARGOYLE_HOME="$ROOT"
if [ -x "$ROOT/gargoyle" ]; then
  exec "$ROOT/gargoyle" --home "$ROOT" start --tui
fi
echo "gargoyle binary not found in $ROOT"
echo "Build it with ./build.sh (requires Go)."
EOF
  chmod +x "$dest_root/start.sh" || true
}

write_build_sh() {
  local dest_root="$1"
  cat > "$dest_root/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src/ctfvault"
if [ ! -f "$SRC/go.mod" ]; then
  echo "Source not found at $SRC"
  echo "Copy source to $ROOT/src/ctfvault or re-run wizard with copy source."
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "Go not found. Install Go and retry."
  exit 1
fi
(cd "$SRC" && go build -o "$ROOT/gargoyle" ./cmd/gargoyle && go build -o "$ROOT/gargoylectl" ./cmd/gargoylectl)
echo "Build complete."
EOF
  chmod +x "$dest_root/build.sh" || true
}

pick_usb() {
  local list
  list=$(lsblk -d -o NAME,MODEL,SIZE,TRAN | awk '$4=="usb" {print "/dev/"$1" "$2" "$3}')
  if [ -z "$list" ]; then
    echo ""
    return
  fi
  if $use_whiptail; then
    local menu=()
    local idx=1
    while read -r line; do
      menu+=("$idx" "$line")
      idx=$((idx+1))
    done <<< "$list"
    local choice
    choice=$(whiptail --title "USB disks" --menu "Select USB disk" 20 70 10 "${menu[@]}" 3>&1 1>&2 2>&3)
    local pick
    pick=$(echo "$list" | sed -n "${choice}p")
    echo "$pick" | awk '{print $1}'
  else
    echo "USB disks:"
    echo "$list"
    read -rp "Enter device path (e.g., /dev/sdb): " dev
    echo "$dev"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }
}

apply_usb_layout() {
  local dev="$1" system_size="$2" persist_size="$3" free_mb="$4" cluster_kb="$5" gen_recovery="$6"
  require_cmd sgdisk
  require_cmd mkfs.ext4
  require_cmd mkfs.exfat
  require_cmd cryptsetup

  echo "WARNING: This will erase $dev"
  read -rp "Type FORMAT to continue: " confirm
  [ "$confirm" = "FORMAT" ] || { echo "Cancelled"; exit 1; }

  local shared_end="0"
  if [[ "$free_mb" =~ ^[0-9]+$ ]] && [ "$free_mb" -gt 0 ]; then
    shared_end="-$free_mb"M
  fi
  if ! [[ "$cluster_kb" =~ ^[0-9]+$ ]]; then
    cluster_kb=512
  fi
  if [ "$cluster_kb" -lt 4 ]; then
    cluster_kb=512
  fi
  local cluster_sectors=$((cluster_kb * 2))

  sudo sgdisk --zap-all "$dev"
  sudo sgdisk -n 1:0:+512M -t 1:ef00 -c 1:GARGOYLE_EFI "$dev"
  sudo sgdisk -n 2:0:+${system_size}M -t 2:8300 -c 2:GARGOYLE_SYS "$dev"
  sudo sgdisk -n 3:0:+${persist_size}M -t 3:8300 -c 3:GARGOYLE_PERSIST "$dev"
  sudo sgdisk -n 4:0:${shared_end} -t 4:0700 -c 4:GARGOYLE_SHARED "$dev"

  sudo mkfs.vfat -F32 "${dev}1"
  sudo mkfs.ext4 -L GARGOYLE_SYS "${dev}2"

  local luks_pass=""
  local luks_pass2=""
  while true; do
    read -rsp "Enter LUKS passphrase: " luks_pass
    echo ""
    read -rsp "Confirm LUKS passphrase: " luks_pass2
    echo ""
    if [ "$luks_pass" = "$luks_pass2" ] && [ -n "$luks_pass" ]; then
      break
    fi
    echo "Passphrases do not match. Try again."
  done

  printf '%s' "$luks_pass" | sudo cryptsetup luksFormat --type luks2 --batch-mode --key-file - "${dev}3"
  printf '%s' "$luks_pass" | sudo cryptsetup open "${dev}3" gargoyle_persist --key-file -
  sudo mkfs.ext4 -L GARGOYLE_PERSIST /dev/mapper/gargoyle_persist

  # exFAT cluster size: cluster_kb (default 512KB)
  local label="${usb_label:-GARGOYLE_SHARED}"
  sudo mkfs.exfat -s "$cluster_sectors" -n "$label" "${dev}4" || sudo mkfs.exfat -n "$label" "${dev}4"

  sudo mkdir -p /mnt/gargoyle_persist
  sudo mount /dev/mapper/gargoyle_persist /mnt/gargoyle_persist
  sudo mkdir -p /mnt/gargoyle_persist/{data,downloads,logs,keys,shared}

  if [ "$gen_recovery" = "yes" ]; then
    local recovery_tmp
    recovery_tmp=$(mktemp /tmp/gargoyle-recovery-XXXXXX.txt)
    gen_recovery_codes "$recovery_tmp" 10 30 5
    while IFS= read -r code; do
      [ -z "$code" ] && continue
      local keyfile
      keyfile=$(mktemp /tmp/gargoyle-key-XXXXXX.txt)
      printf '%s' "$code" > "$keyfile"
      printf '%s' "$luks_pass" | sudo cryptsetup luksAddKey "${dev}3" "$keyfile" --key-file -
      rm -f "$keyfile"
    done < "$recovery_tmp"

    sudo mkdir -p /mnt/gargoyle_shared
    sudo mount "${dev}4" /mnt/gargoyle_shared
    sudo mkdir -p /mnt/gargoyle_shared/gargoyle
    sudo cp "$recovery_tmp" /mnt/gargoyle_shared/gargoyle/recovery_codes.txt
    sudo chmod 600 /mnt/gargoyle_shared/gargoyle/recovery_codes.txt || true
    sudo cp "$recovery_tmp" /mnt/gargoyle_persist/recovery_codes.txt
    sudo chmod 600 /mnt/gargoyle_persist/recovery_codes.txt || true
    rm -f "$recovery_tmp"
  fi
}

apply_usb_shared_layout() {
  local dev="$1" free_mb="$2" cluster_kb="$3"
  require_cmd sgdisk
  require_cmd mkfs.exfat

  echo "WARNING: This will erase $dev"
  read -rp "Type FORMAT to continue: " confirm
  [ "$confirm" = "FORMAT" ] || { echo "Cancelled"; exit 1; }

  local end="0"
  if [[ "$free_mb" =~ ^[0-9]+$ ]] && [ "$free_mb" -gt 0 ]; then
    end="-$free_mb"M
  fi
  if ! [[ "$cluster_kb" =~ ^[0-9]+$ ]]; then
    cluster_kb=512
  fi
  if [ "$cluster_kb" -lt 4 ]; then
    cluster_kb=512
  fi
  local cluster_sectors=$((cluster_kb * 2))

  sudo sgdisk --zap-all "$dev"
  sudo sgdisk -n 1:0:${end} -t 1:0700 -c 1:GARGOYLE_SHARED "$dev"
  local label="${usb_label:-GARGOYLE_SHARED}"
  sudo mkfs.exfat -s "$cluster_sectors" -n "$label" "${dev}1" || sudo mkfs.exfat -n "$label" "${dev}1"

  sudo mkdir -p /mnt/gargoyle_shared
  sudo mount "${dev}1" /mnt/gargoyle_shared
  sudo mkdir -p /mnt/gargoyle_shared/gargoyle/{data,downloads,logs,keys,shared,scripts}
}

write_pack_file() {
  local base="$1"
  local name="$2"
  local path="$base/tools/packs/$name.yaml"
  mkdir -p "$(dirname "$path")"
  case "$name" in
    ctf)
      cat > "$path" <<'EOF'
pack: ctf
tools:
  - name: nmap
    install: "apt:nmap"
  - name: sqlmap
    install: "apt:sqlmap"
  - name: ffuf
    install: "apt:ffuf"
  - name: gobuster
    install: "apt:gobuster"
  - name: gdb
    install: "apt:gdb"
  - name: radare2
    install: "apt:radare2"
  - name: binwalk
    install: "apt:binwalk"
  - name: exiftool
    install: "apt:exiftool"
  - name: wireshark-cli
    install: "apt:tshark"
EOF
      ;;
    anonymity)
      cat > "$path" <<'EOF'
pack: anonymity
tools:
  - name: tor
    install: "apt:tor"
  - name: proxychains4
    install: "apt:proxychains4"
  - name: dnsutils
    install: "apt:dnsutils"
EOF
      ;;
    ctf_emulate)
      cat > "$path" <<'EOF'
pack: ctf_emulate
tools:
  - name: nmap
    install: "apt:nmap"
  - name: sqlmap
    install: "apt:sqlmap"
  - name: ffuf
    install: "apt:ffuf"
  - name: gdb
    install: "apt:gdb"
  - name: radare2
    install: "apt:radare2"
  - name: torbrowser-launcher
    install: "apt:torbrowser-launcher"
  - name: firefox-esr
    install: "apt:firefox-esr"
  - name: bubblewrap
    install: "apt:bubblewrap"
EOF
      ;;
    ctf-ultimate)
      cat > "$path" <<'EOF'
pack: ctf-ultimate
description: "Full CTF pack: Web, Pwn, Rev, Crypto, Forensics"
tools:
  - name: nikto
    install: "apt:nikto"
  - name: dirb
    install: "apt:dirb"
  - name: wpscan
    install: "apt:wpscan"
  - name: hydra
    install: "apt:hydra"
  - name: burpsuite
    install: "apt:burpsuite"
  - name: wapiti
    install: "apt:wapiti"
  - name: whatweb
    install: "apt:whatweb"
  - name: gdb-peda
    install: "apt:gdb-peda"
  - name: ropper
    install: "apt:ropper"
  - name: ltrace
    install: "apt:ltrace"
  - name: strace
    install: "apt:strace"
  - name: checksec
    install: "apt:checksec"
  - name: radare2
    install: "apt:radare2"
  - name: ghidra
    install: "apt:ghidra"
  - name: binwalk
    install: "apt:binwalk"
  - name: exiftool
    install: "apt:exiftool"
  - name: steghide
    install: "apt:steghide"
  - name: stegseek
    install: "apt:stegseek"
  - name: foremost
    install: "apt:foremost"
  - name: zsteg
    install: "apt:zsteg"
  - name: strings
    install: "apt:binutils"
  - name: john
    install: "apt:john"
  - name: hashcat
    install: "apt:hashcat"
  - name: fcrackzip
    install: "apt:fcrackzip"
  - name: nmap
    install: "apt:nmap"
  - name: netcat
    install: "apt:netcat"
  - name: masscan
    install: "apt:masscan"
  - name: tshark
    install: "apt:tshark"
  - name: jq
    install: "apt:jq"
  - name: tmux
    install: "apt:tmux"
EOF
      ;;
    osint)
      cat > "$path" <<'EOF'
pack: osint
tools:
  - name: whois
    install: "apt:whois"
  - name: dnsutils
    install: "apt:dnsutils"
  - name: curl
    install: "apt:curl"
  - name: wget
    install: "apt:wget"
  - name: nmap
    install: "apt:nmap"
  - name: exiftool
    install: "apt:exiftool"
EOF
      ;;
    empty)
      cat > "$path" <<'EOF'
pack: empty
tools: []
EOF
      ;;
  esac
}

main() {
  echo "Gargoyle Installer Wizard (Linux)"

  local target
  target=$(prompt_menu "Install target" "USB" "Folder")

  local edition
  edition=$(prompt_menu "Edition" "public" "private")

  local op_mode
  op_mode=$(prompt_menu "Operation mode" "standard" "fullanon")

  local locale
  locale=$(prompt_menu "Language" "ru" "en")

  local ram_limit=2048
  local cpu_limit=2

  local dns_profile
  dns_profile=$(prompt_menu "DNS profile" "system" "xbox" "custom")
  local dns_custom=""
  if [ "$dns_profile" = "custom" ]; then
    dns_custom=$(prompt_input "Enter DNS-over-HTTPS URL or resolver" "")
  fi
  if [ "$dns_profile" = "xbox" ]; then
    dns_custom="https://xbox-dns.ru/dns-query"
  fi

  local wifi bt ports
  wifi=$(prompt_yesno "Enable Wi-Fi by default?" "yes")
  bt=$(prompt_yesno "Enable Bluetooth by default?" "no")
  ports=$(prompt_yesno "Open ports by default?" "no")
  local install_scripts
  install_scripts=$(prompt_yesno "Install Gargoyle Script (DSL) samples?" "yes")
  local usb_enabled
  usb_enabled=$(prompt_yesno "Enable USB access inside Gargoyle?" "no")
  local usb_read_only
  usb_read_only="no"
  if [ "$usb_enabled" = "yes" ]; then
    usb_read_only=$(prompt_yesno "USB read-only mode?" "yes")
  fi
  local ram_only
  ram_only=$(prompt_yesno "RAM-only session (no disk writes)?" "no")
  local auto_wipe_remove
  auto_wipe_remove=$(prompt_yesno "Auto wipe on USB removal?" "$([ "$op_mode" = "fullanon" ] && echo yes || echo no)")
  local auto_wipe_exit
  auto_wipe_exit=$(prompt_yesno "Auto wipe on exit?" "$([ "$op_mode" = "fullanon" ] && echo yes || echo no)")
  local gen_recovery
  gen_recovery=$(prompt_yesno "Generate recovery codes file (USB only recommended)?" "$([ "$target" = "USB" ] && echo yes || echo no)")
  if [ "$target" = "Folder" ] && [ "$gen_recovery" = "yes" ]; then
    echo "NOTE: recovery codes are intended for USB installs. Disabling for folder target."
    gen_recovery="no"
  fi

  local net_mode vpn_type vpn_profile gateway_ip tor_install tor_strict
  vpn_type=""
  vpn_profile=""
  gateway_ip=""
  proxy_engine=""
  proxy_config=""
  local doh_url=""
  local doh_listen="127.0.0.1:5353"
  if [ "$op_mode" = "fullanon" ]; then
    net_mode="direct"
    tor_install="yes"
    tor_strict="yes"
  else
    net_mode=$(prompt_menu "Network mode" "direct" "vpn" "gateway" "proxy")
    if [ "$net_mode" = "vpn" ]; then
      vpn_type=$(prompt_menu "VPN type" "openvpn" "wireguard")
      while true; do
        vpn_profile=$(prompt_input "VPN profile path" "")
        [ -n "$vpn_profile" ] && break
        echo "VPN profile path is required for vpn mode"
      done
    fi
    if [ "$net_mode" = "gateway" ]; then
      while true; do
        gateway_ip=$(prompt_input "Gateway IP (e.g., 192.168.1.1)" "")
        [ -n "$gateway_ip" ] && break
        echo "Gateway IP is required for gateway mode"
      done
    fi
    if [ "$net_mode" = "proxy" ]; then
      proxy_engine=$(prompt_menu "Proxy engine" "sing-box" "xray" "hiddify")
      while true; do
        proxy_config=$(prompt_input "Proxy config path" "")
        [ -n "$proxy_config" ] && break
        echo "Proxy config path is required for proxy mode"
      done
    fi
    tor_install=$(prompt_yesno "Install Tor (always-on)?" "yes")
    tor_strict="no"
    if [ "$tor_install" = "yes" ]; then
      tor_strict=$(prompt_yesno "Strict Tor mode (block non-Tor traffic)?" "no")
    fi
  fi

  local mac_spoof="yes"
  local mesh_onion="no"
  local mesh_discovery="no"
  local mesh_discovery_port=19998
  local mesh_discovery_key=""
  local mesh_auto_join="no"
  local mesh_chat="yes"
  local mesh_chat_listen=":19997"
  local mesh_chat_psk=""
  local mesh_chat_psk_file=""
  local mesh_clipboard="no"
  local mesh_clipboard_warn="yes"
  local mesh_tun_enabled="no"
  local mesh_tun_device="gargoyle0"
  local mesh_tun_cidr="10.42.0.1/24"
  local mesh_tun_peer_cidr="10.42.0.0/24"
  local mesh_padding=256
  local mesh_transport="tls"
  local mesh_metadata="standard"
  local mesh_onion_depth=3
  local mesh_relay_allowlist="[]"
  local hotspot_ssid=""
  local hotspot_password=""
  local hotspot_ifname=""
  local hotspot_shared="yes"
  local tor_trans_port=9040
  local tor_dns_port=9053
  local tor_use_bridges="no"
  local tor_transport=""
  local tor_bridge_lines="[]"
  local torrc_path=""
  local emulate_privacy="yes"
  local emulate_temp="ram"
  local emulate_downloads="downloads"
  local emulate_display="direct"
  local tunnel_type="frp"
  local tunnel_server=""
  local tunnel_token=""
  local tunnel_local_ip="127.0.0.1"
  local mail_mode="local"
  local mail_sink="yes"
  local mail_local="yes"
  local mail_sink_listen="127.0.0.1:1025"
  local mail_sink_ui="127.0.0.1:8025"
  local mail_mesh_enabled="yes"
  local mail_mesh_listen=":20025"
  local mail_mesh_psk=""
  local mail_mesh_psk_file=""
  local ui_theme="dark"
  local ui_boss_key="yes"
  local ui_boss_mode="update"
  local usb_label="GARGOYLE_SHARED"
  local tools_file="tools.yaml"
  local tools_auto="no"
  local tools_repo=""
  local copy_source="yes"
  local auto_build="yes"
  local update_url=""
  local update_channel="stable"
  local update_public_key=""
  local update_auto="no"
  local sync_enabled="no"
  local sync_target=""
  local sync_dir="./loot"
  local sync_psk=""
  local sync_psk_file=""
  local sync_transport="tls"
  local sync_padding=256
  local sync_depth=3
  local telegram_enabled="no"
  local telegram_bot_token=""
  local telegram_allowed_user=0
  local telegram_pairing_ttl=60
  local telegram_allow_cli="no"
  local telegram_allow_wipe="no"
  local telegram_allow_stats="yes"
  if [ "$op_mode" = "fullanon" ]; then
    mesh_onion="yes"
    mesh_discovery="no"
    mesh_chat="no"
    mesh_clipboard="no"
    mac_spoof="yes"
  fi

  local advanced
  advanced=$(prompt_advanced)
  if [ "$advanced" = "yes" ]; then
    ram_limit=$(prompt_input "RAM limit MB" "$ram_limit")
    cpu_limit=$(prompt_input "CPU limit" "$cpu_limit")
    tor_install=$(prompt_yesno "Tor always-on?" "$tor_install")
    if [ "$tor_install" = "yes" ]; then
      tor_strict=$(prompt_yesno "Tor strict kill-switch?" "$tor_strict")
    else
      tor_strict="no"
    fi
    tor_trans_port=$(prompt_input "Tor TransPort" "$tor_trans_port")
    tor_dns_port=$(prompt_input "Tor DNSPort" "$tor_dns_port")
    tor_use_bridges=$(prompt_yesno "Tor bridges enabled?" "$tor_use_bridges")
    if [ "$tor_use_bridges" = "yes" ]; then
      tor_transport=$(prompt_input "Tor transport (obfs4/meek/...)" "$tor_transport")
      tor_bridge_lines=$(prompt_input "Tor bridges (comma or ; separated)" "")
      tor_bridge_lines=$(yaml_list_flow "$tor_bridge_lines")
    else
      tor_transport=""
      tor_bridge_lines="[]"
    fi
    torrc_path=$(prompt_input "Torrc path (optional)" "$torrc_path")
    mac_spoof=$(prompt_yesno "MAC spoofing?" "$mac_spoof")
    ports=$(prompt_yesno "Open ports by default?" "$ports")
    doh_url=$(prompt_input "DoH URL (optional)" "$doh_url")
    doh_listen=$(prompt_input "DoH listen (default 127.0.0.1:5353)" "$doh_listen")
    mesh_onion=$(prompt_yesno "Mesh onion-only?" "$mesh_onion")
    mesh_discovery=$(prompt_yesno "Mesh discovery enabled?" "$mesh_discovery")
    mesh_discovery_port=$(prompt_input "Mesh discovery port" "$mesh_discovery_port")
    mesh_discovery_key=$(prompt_input "Mesh discovery key (optional)" "$mesh_discovery_key")
    mesh_auto_join=$(prompt_yesno "Mesh auto-join?" "$mesh_auto_join")
    mesh_chat=$(prompt_yesno "Mesh chat enabled?" "$mesh_chat")
    mesh_chat_listen=$(prompt_input "Mesh chat listen" "$mesh_chat_listen")
    mesh_chat_psk=$(prompt_input "Mesh chat PSK (optional)" "$mesh_chat_psk")
    mesh_chat_psk_file=$(prompt_input "Mesh chat PSK file (optional)" "$mesh_chat_psk_file")
    mesh_clipboard=$(prompt_yesno "Mesh clipboard share?" "$mesh_clipboard")
    mesh_clipboard_warn=$(prompt_yesno "Mesh clipboard warn?" "$mesh_clipboard_warn")
    mesh_transport=$(prompt_menu "Mesh transport" "tcp" "tls")
    mesh_metadata=$(prompt_menu "Mesh metadata" "off" "standard" "max")
    mesh_padding=$(prompt_input "Mesh padding bytes" "$mesh_padding")
    mesh_onion_depth=$(prompt_input "Mesh onion depth" "$mesh_onion_depth")
    mesh_tun_enabled=$(prompt_yesno "Mesh tun enabled?" "$mesh_tun_enabled")
    if [ "$mesh_tun_enabled" = "yes" ]; then
      mesh_tun_device=$(prompt_input "Tun device" "$mesh_tun_device")
      mesh_tun_cidr=$(prompt_input "Tun CIDR" "$mesh_tun_cidr")
      mesh_tun_peer_cidr=$(prompt_input "Tun peer CIDR" "$mesh_tun_peer_cidr")
    fi
    mesh_relay_allowlist=$(prompt_input "Relay allowlist tokens (comma/;)" "")
    mesh_relay_allowlist=$(yaml_list_flow "$mesh_relay_allowlist")
    hotspot_ssid=$(prompt_input "Hotspot SSID" "$hotspot_ssid")
    hotspot_password=$(prompt_input "Hotspot password" "$hotspot_password")
    hotspot_ifname=$(prompt_input "Hotspot ifname" "$hotspot_ifname")
    hotspot_shared=$(prompt_yesno "Hotspot shared/NAT?" "$hotspot_shared")
    emulate_privacy=$(prompt_yesno "Emulate privacy mode?" "$emulate_privacy")
    emulate_temp=$(prompt_menu "Emulate temp dir" "ram" "disk")
    emulate_downloads=$(prompt_input "Emulate downloads dir" "$emulate_downloads")
    emulate_display=$(prompt_menu "Emulate display server" "direct" "cage" "gamescope" "weston")
    tunnel_type=$(prompt_menu "Tunnel type" "frp" "relay" "wss")
    tunnel_server=$(prompt_input "Tunnel server" "$tunnel_server")
    tunnel_token=$(prompt_input "Tunnel token" "$tunnel_token")
    tunnel_local_ip=$(prompt_input "Tunnel local IP" "$tunnel_local_ip")
    mail_mode=$(prompt_menu "Mail mode" "local" "tunnel")
    mail_sink=$(prompt_yesno "Mail sink enabled?" "$mail_sink")
    mail_local=$(prompt_yesno "Mail local server enabled?" "$mail_local")
    mail_sink_listen=$(prompt_input "Mail sink listen" "$mail_sink_listen")
    mail_sink_ui=$(prompt_input "Mail sink UI" "$mail_sink_ui")
    mail_mesh_enabled=$(prompt_yesno "Mail mesh enabled?" "$mail_mesh_enabled")
    mail_mesh_listen=$(prompt_input "Mail mesh listen" "$mail_mesh_listen")
    mail_mesh_psk=$(prompt_input "Mail mesh PSK (optional)" "$mail_mesh_psk")
    mail_mesh_psk_file=$(prompt_input "Mail mesh PSK file" "$mail_mesh_psk_file")
    ui_theme=$(prompt_menu "UI theme" "dark" "light")
    ui_boss_key=$(prompt_yesno "Boss-key enabled?" "$ui_boss_key")
    ui_boss_mode=$(prompt_menu "Boss mode" "update" "htop" "blank")
    copy_source=$(prompt_yesno "Copy Gargoyle source to USB (offline build)?" "$copy_source")
    auto_build=$(prompt_yesno "Build gargoyle now (if Go installed)?" "$auto_build")
    usb_label=$(prompt_input "USB volume label (default $usb_label)" "$usb_label")
    tools_file=$(prompt_input "Tools pack file" "$tools_file")
    tools_auto=$(prompt_yesno "Auto install tools?" "$tools_auto")
    tools_repo=$(prompt_input "Tools repository URL (optional)" "$tools_repo")
    local tools_profile
    tools_profile=$(prompt_menu "Tools pack profile" "ctf (recommended)" "none" "anonymity" "ctf+emulate" "osint")
    case "$tools_profile" in
      "ctf (recommended)")
        tools_file="tools/packs/ctf.yaml"
        ;;
      "anonymity")
        tools_file="tools/packs/anonymity.yaml"
        ;;
      "ctf+emulate")
        tools_file="tools/packs/ctf_emulate.yaml"
        ;;
      "osint")
        tools_file="tools/packs/osint.yaml"
        ;;
      *)
        tools_file="tools/packs/empty.yaml"
        ;;
    esac
    install_scripts=$(prompt_yesno "Install Gargoyle Script (DSL) samples?" "$install_scripts")
    update_url=$(prompt_input "Update URL (optional)" "$update_url")
    update_channel=$(prompt_menu "Update channel" "stable" "beta" "dev")
    update_public_key=$(prompt_input "Update public key (optional)" "$update_public_key")
    update_auto=$(prompt_yesno "Auto updates?" "$update_auto")
    sync_enabled=$(prompt_yesno "Sync (loot) enabled?" "$sync_enabled")
    sync_target=$(prompt_input "Sync target (host:port)" "$sync_target")
    sync_dir=$(prompt_input "Sync dir" "$sync_dir")
    sync_psk=$(prompt_input "Sync PSK (optional)" "$sync_psk")
    sync_psk_file=$(prompt_input "Sync PSK file" "$sync_psk_file")
    sync_transport=$(prompt_menu "Sync transport" "tcp" "tls")
    sync_padding=$(prompt_input "Sync padding bytes" "$sync_padding")
    sync_depth=$(prompt_input "Sync depth" "$sync_depth")
    telegram_enabled=$(prompt_yesno "Telegram C2 enabled?" "$telegram_enabled")
    telegram_bot_token=$(prompt_input "Telegram bot token" "$telegram_bot_token")
    telegram_allowed_user=$(prompt_input "Telegram allowed user ID" "$telegram_allowed_user")
    telegram_pairing_ttl=$(prompt_input "Telegram pairing TTL (s)" "$telegram_pairing_ttl")
    telegram_allow_cli=$(prompt_yesno "Telegram allow CLI?" "$telegram_allow_cli")
    telegram_allow_wipe=$(prompt_yesno "Telegram allow wipe?" "$telegram_allow_wipe")
    telegram_allow_stats=$(prompt_yesno "Telegram allow stats?" "$telegram_allow_stats")
  fi

  if [ "$target" = "Folder" ]; then
    local folder
    folder=$(prompt_input "Install folder path" "$HOME/gargoyle")
    print_plan "Folder" "$folder" "" "" "" "" ""
    local action
    action=$(prompt_menu "Proceed?" "Proceed" "Dry-run (show plan only)" "Cancel")
    case "$action" in
      "Dry-run (show plan only)")
        echo "Dry-run complete. No changes applied."
        exit 0
        ;;
      "Cancel")
        echo "Cancelled."
        exit 1
        ;;
    esac
    mkdir -p "$folder"/{data,downloads,logs,keys,shared}
    if [ "$copy_source" = "yes" ]; then
      copy_source "$folder"
    fi
    if [ "$auto_build" = "yes" ]; then
      build_binaries "$folder"
    fi
    copy_binaries "$folder"
    write_start_sh "$folder"
    write_build_sh "$folder"
    write_config "$folder/gargoyle.yaml" "$edition" "$op_mode" "$locale" "$ram_limit" "$cpu_limit" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports" "$usb_enabled" "$usb_read_only" "$ram_only" "$auto_wipe_remove" "$auto_wipe_exit" "$net_mode" "$vpn_type" "$vpn_profile" "$gateway_ip" "$proxy_engine" "$proxy_config" "$tor_install" "$tor_strict" "$tor_trans_port" "$tor_dns_port" "$tor_use_bridges" "$tor_transport" "$tor_bridge_lines" "$torrc_path" "$mac_spoof" "$mesh_onion" "$mesh_discovery" "$mesh_discovery_port" "$mesh_discovery_key" "$mesh_auto_join" "$mesh_chat" "$mesh_chat_listen" "$mesh_chat_psk" "$mesh_chat_psk_file" "$mesh_clipboard" "$mesh_clipboard_warn" "$mesh_tun_enabled" "$mesh_tun_device" "$mesh_tun_cidr" "$mesh_tun_peer_cidr" "$mesh_padding" "$mesh_transport" "$mesh_metadata" "$mesh_onion_depth" "$mesh_relay_allowlist" "$hotspot_ssid" "$hotspot_password" "$hotspot_ifname" "$hotspot_shared" "$emulate_privacy" "$emulate_temp" "$emulate_downloads" "$emulate_display" "$tunnel_type" "$tunnel_server" "$tunnel_token" "$tunnel_local_ip" "$mail_mode" "$mail_sink" "$mail_local" "$mail_sink_listen" "$mail_sink_ui" "$mail_mesh_enabled" "$mail_mesh_listen" "$mail_mesh_psk" "$mail_mesh_psk_file" "$ui_theme" "$ui_boss_key" "$ui_boss_mode" "$tools_file" "$tools_auto" "$tools_repo" "$update_url" "$update_channel" "$update_public_key" "$update_auto" "$sync_enabled" "$sync_target" "$sync_dir" "$sync_psk" "$sync_psk_file" "$sync_transport" "$sync_padding" "$sync_depth" "$telegram_enabled" "$telegram_bot_token" "$telegram_allowed_user" "$telegram_pairing_ttl" "$telegram_allow_cli" "$telegram_allow_wipe" "$telegram_allow_stats" "$doh_url" "$doh_listen"
    if [[ "$tools_file" == tools/packs/* ]]; then
      pack_name=$(basename "$tools_file" .yaml)
      write_pack_file "$folder" "$pack_name"
    fi
    gen_identity_key "$folder/keys/identity.key"
    if [ "$install_scripts" = "yes" ]; then
      mkdir -p "$folder/scripts"
      write_sample_script "$folder/scripts/sample.gsl"
    fi
    echo "Folder install complete: $folder"
    exit 0
  fi

  local dev
  dev=$(pick_usb)
  if [ -z "$dev" ]; then
    echo "No USB device selected"
    exit 1
  fi

  local layout free_space
  layout=$(prompt_menu "USB layout" "Full (EFI+SYSTEM+PERSIST+SHARED)" "Shared-only (single exFAT)")
  free_space=$(prompt_input "Leave unallocated space at end (MB)" "0")
  local cluster_kb=512
  local action

  if [ "$layout" = "Shared-only (single exFAT)" ]; then
    print_plan "USB" "$dev" "$layout" "" "" "$free_space" "$cluster_kb"
    action=$(prompt_menu "Proceed?" "Proceed" "Dry-run (show plan only)" "Cancel")
    case "$action" in
      "Dry-run (show plan only)")
        echo "Dry-run complete. No changes applied."
        exit 0
        ;;
      "Cancel")
        echo "Cancelled."
        exit 1
        ;;
    esac
    apply_usb_shared_layout "$dev" "$free_space" "$cluster_kb"
    if [ "$copy_source" = "yes" ]; then
      copy_source "/mnt/gargoyle_shared/gargoyle"
    fi
    if [ "$auto_build" = "yes" ]; then
      build_binaries "/mnt/gargoyle_shared/gargoyle"
    fi
    copy_binaries "/mnt/gargoyle_shared/gargoyle"
    write_start_sh "/mnt/gargoyle_shared/gargoyle"
    write_build_sh "/mnt/gargoyle_shared/gargoyle"
    write_config "/mnt/gargoyle_shared/gargoyle/gargoyle.yaml" "$edition" "$op_mode" "$locale" "$ram_limit" "$cpu_limit" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports" "$usb_enabled" "$usb_read_only" "$ram_only" "$auto_wipe_remove" "$auto_wipe_exit" "$net_mode" "$vpn_type" "$vpn_profile" "$gateway_ip" "$proxy_engine" "$proxy_config" "$tor_install" "$tor_strict" "$tor_trans_port" "$tor_dns_port" "$tor_use_bridges" "$tor_transport" "$tor_bridge_lines" "$torrc_path" "$mac_spoof" "$mesh_onion" "$mesh_discovery" "$mesh_discovery_port" "$mesh_discovery_key" "$mesh_auto_join" "$mesh_chat" "$mesh_chat_listen" "$mesh_chat_psk" "$mesh_chat_psk_file" "$mesh_clipboard" "$mesh_clipboard_warn" "$mesh_tun_enabled" "$mesh_tun_device" "$mesh_tun_cidr" "$mesh_tun_peer_cidr" "$mesh_padding" "$mesh_transport" "$mesh_metadata" "$mesh_onion_depth" "$mesh_relay_allowlist" "$hotspot_ssid" "$hotspot_password" "$hotspot_ifname" "$hotspot_shared" "$emulate_privacy" "$emulate_temp" "$emulate_downloads" "$emulate_display" "$tunnel_type" "$tunnel_server" "$tunnel_token" "$tunnel_local_ip" "$mail_mode" "$mail_sink" "$mail_local" "$mail_sink_listen" "$mail_sink_ui" "$mail_mesh_enabled" "$mail_mesh_listen" "$mail_mesh_psk" "$mail_mesh_psk_file" "$ui_theme" "$ui_boss_key" "$ui_boss_mode" "$tools_file" "$tools_auto" "$tools_repo" "$update_url" "$update_channel" "$update_public_key" "$update_auto" "$sync_enabled" "$sync_target" "$sync_dir" "$sync_psk" "$sync_psk_file" "$sync_transport" "$sync_padding" "$sync_depth" "$telegram_enabled" "$telegram_bot_token" "$telegram_allowed_user" "$telegram_pairing_ttl" "$telegram_allow_cli" "$telegram_allow_wipe" "$telegram_allow_stats" "$doh_url" "$doh_listen"
    if [[ "$tools_file" == tools/packs/* ]]; then
      pack_name=$(basename "$tools_file" .yaml)
      write_pack_file "/mnt/gargoyle_shared/gargoyle" "$pack_name"
    fi
    gen_identity_key "/mnt/gargoyle_shared/gargoyle/keys/identity.key"
    if [ "$gen_recovery" = "yes" ]; then
      gen_recovery_codes "/mnt/gargoyle_shared/gargoyle/recovery_codes.txt" 10 30 5
    fi
    if [ "$install_scripts" = "yes" ]; then
      write_sample_script "/mnt/gargoyle_shared/gargoyle/scripts/sample.gsl"
    fi
    echo "USB shared-only layout complete. Mounted at /mnt/gargoyle_shared."
    exit 0
  fi

  local system_size persist_size
  system_size=$(prompt_input "System partition size (MB)" "4096")
  persist_size=$(prompt_input "Persistent partition size (MB)" "8192")

  print_plan "USB" "$dev" "$layout" "$system_size" "$persist_size" "$free_space" "$cluster_kb"
  action=$(prompt_menu "Proceed?" "Proceed" "Dry-run (show plan only)" "Cancel")
  case "$action" in
    "Dry-run (show plan only)")
      echo "Dry-run complete. No changes applied."
      exit 0
      ;;
    "Cancel")
      echo "Cancelled."
      exit 1
      ;;
  esac
  apply_usb_layout "$dev" "$system_size" "$persist_size" "$free_space" "$cluster_kb" "$gen_recovery"

  if [ "$copy_source" = "yes" ]; then
    copy_source "/mnt/gargoyle_persist"
  fi
  if [ "$auto_build" = "yes" ]; then
    build_binaries "/mnt/gargoyle_persist"
  fi
  copy_binaries "/mnt/gargoyle_persist"
  write_start_sh "/mnt/gargoyle_persist"
  write_build_sh "/mnt/gargoyle_persist"

  write_config "/mnt/gargoyle_persist/gargoyle.yaml" "$edition" "$op_mode" "$locale" "$ram_limit" "$cpu_limit" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports" "$usb_enabled" "$usb_read_only" "$ram_only" "$auto_wipe_remove" "$auto_wipe_exit" "$net_mode" "$vpn_type" "$vpn_profile" "$gateway_ip" "$proxy_engine" "$proxy_config" "$tor_install" "$tor_strict" "$tor_trans_port" "$tor_dns_port" "$tor_use_bridges" "$tor_transport" "$tor_bridge_lines" "$torrc_path" "$mac_spoof" "$mesh_onion" "$mesh_discovery" "$mesh_discovery_port" "$mesh_discovery_key" "$mesh_auto_join" "$mesh_chat" "$mesh_chat_listen" "$mesh_chat_psk" "$mesh_chat_psk_file" "$mesh_clipboard" "$mesh_clipboard_warn" "$mesh_tun_enabled" "$mesh_tun_device" "$mesh_tun_cidr" "$mesh_tun_peer_cidr" "$mesh_padding" "$mesh_transport" "$mesh_metadata" "$mesh_onion_depth" "$mesh_relay_allowlist" "$hotspot_ssid" "$hotspot_password" "$hotspot_ifname" "$hotspot_shared" "$emulate_privacy" "$emulate_temp" "$emulate_downloads" "$emulate_display" "$tunnel_type" "$tunnel_server" "$tunnel_token" "$tunnel_local_ip" "$mail_mode" "$mail_sink" "$mail_local" "$mail_sink_listen" "$mail_sink_ui" "$mail_mesh_enabled" "$mail_mesh_listen" "$mail_mesh_psk" "$mail_mesh_psk_file" "$ui_theme" "$ui_boss_key" "$ui_boss_mode" "$tools_file" "$tools_auto" "$tools_repo" "$update_url" "$update_channel" "$update_public_key" "$update_auto" "$sync_enabled" "$sync_target" "$sync_dir" "$sync_psk" "$sync_psk_file" "$sync_transport" "$sync_padding" "$sync_depth" "$telegram_enabled" "$telegram_bot_token" "$telegram_allowed_user" "$telegram_pairing_ttl" "$telegram_allow_cli" "$telegram_allow_wipe" "$telegram_allow_stats" "$doh_url" "$doh_listen"
  if [[ "$tools_file" == tools/packs/* ]]; then
    pack_name=$(basename "$tools_file" .yaml)
    write_pack_file "/mnt/gargoyle_persist" "$pack_name"
  fi
  gen_identity_key "/mnt/gargoyle_persist/keys/identity.key"
  if [ "$install_scripts" = "yes" ]; then
    mkdir -p "/mnt/gargoyle_persist/scripts"
    write_sample_script "/mnt/gargoyle_persist/scripts/sample.gsl"
  fi
  echo "USB layout complete. Persistent mounted at /mnt/gargoyle_persist."
}

main "$@"
