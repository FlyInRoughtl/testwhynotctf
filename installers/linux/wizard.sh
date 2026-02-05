#!/usr/bin/env bash
set -euo pipefail

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

write_config() {
  local path="$1" edition="$2" dns_profile="$3" dns_custom="$4" wifi="$5" bt="$6" ports="$7" usb_enabled="$8" usb_read_only="$9" ram_only="${10}" net_mode="${11}" vpn_type="${12}" vpn_profile="${13}" gateway_ip="${14}" tor_install="${15}" tor_strict="${16}" proxy_engine="${17}" proxy_config="${18}"
  cat > "$path" <<EOF
# Gargoyle config
system:
  ram_limit_mb: 2048
  cpu_limit: 2
  locale: "ru"
  edition: "$edition"

storage:
  persistent: true
  shared: true
  recovery_codes: "recovery_codes.txt"
  usb_enabled: $usb_enabled
  usb_read_only: $usb_read_only
  ram_only: $ram_only

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
  doh_url: ""
  doh_listen: "127.0.0.1:5353"
  tor: $tor_install
  tor_always_on: $tor_install
  tor_strict: $tor_strict
  mac_spoof: true
  wifi_enabled: $wifi
  bluetooth_enabled: $bt
  ports_open: $ports

security:
  identity_key_path: "keys/identity.key"
  identity_length: 256
  identity_group: 15

mesh:
  relay_url: ""
  onion_depth: 3
  metadata_level: "standard"

ui:
  theme: "dark"
  language: "ru"

emulate:
  privacy_mode: true
  temp_dir: "ram"
  downloads_dir: "downloads"

tunnel:
  type: "frp"
  server: ""
  token: ""

mail:
  mode: "local"
  sink: true
  local_server: true
  sink_listen: "127.0.0.1:1025"
  sink_ui: "127.0.0.1:8025"
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
  local dev="$1" system_size="$2" persist_size="$3" free_mb="$4" cluster_kb="$5"
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
    cluster_kb=256
  fi
  if [ "$cluster_kb" -lt 4 ]; then
    cluster_kb=256
  fi
  local cluster_sectors=$((cluster_kb * 2))

  sudo sgdisk --zap-all "$dev"
  sudo sgdisk -n 1:0:+512M -t 1:ef00 -c 1:GARGOYLE_EFI "$dev"
  sudo sgdisk -n 2:0:+${system_size}M -t 2:8300 -c 2:GARGOYLE_SYS "$dev"
  sudo sgdisk -n 3:0:+${persist_size}M -t 3:8300 -c 3:GARGOYLE_PERSIST "$dev"
  sudo sgdisk -n 4:0:${shared_end} -t 4:0700 -c 4:GARGOYLE_SHARED "$dev"

  sudo mkfs.vfat -F32 "${dev}1"
  sudo mkfs.ext4 -L GARGOYLE_SYS "${dev}2"

  sudo cryptsetup luksFormat "${dev}3"
  sudo cryptsetup open "${dev}3" gargoyle_persist
  sudo mkfs.ext4 -L GARGOYLE_PERSIST /dev/mapper/gargoyle_persist

  # exFAT cluster size: cluster_kb (default 256KB)
  sudo mkfs.exfat -s "$cluster_sectors" -n GARGOYLE_SHARED "${dev}4" || sudo mkfs.exfat -n GARGOYLE_SHARED "${dev}4"

  sudo mkdir -p /mnt/gargoyle_persist
  sudo mount /dev/mapper/gargoyle_persist /mnt/gargoyle_persist
  sudo mkdir -p /mnt/gargoyle_persist/{data,downloads,logs,keys,shared}
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
    cluster_kb=256
  fi
  if [ "$cluster_kb" -lt 4 ]; then
    cluster_kb=256
  fi
  local cluster_sectors=$((cluster_kb * 2))

  sudo sgdisk --zap-all "$dev"
  sudo sgdisk -n 1:0:${end} -t 1:0700 -c 1:GARGOYLE_SHARED "$dev"
  sudo mkfs.exfat -s "$cluster_sectors" -n GARGOYLE_SHARED "${dev}1" || sudo mkfs.exfat -n GARGOYLE_SHARED "${dev}1"

  sudo mkdir -p /mnt/gargoyle_shared
  sudo mount "${dev}1" /mnt/gargoyle_shared
  sudo mkdir -p /mnt/gargoyle_shared/gargoyle/{data,downloads,logs,keys,shared,scripts}
}

main() {
  echo "Gargoyle Installer Wizard (Linux)"

  local target
  target=$(prompt_menu "Install target" "USB" "Folder")

  local edition
  edition=$(prompt_menu "Edition" "public" "private")

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

  local net_mode vpn_type vpn_profile gateway_ip tor_install
  net_mode=$(prompt_menu "Network mode" "direct" "vpn" "gateway" "proxy")
  vpn_type=""
  vpn_profile=""
  gateway_ip=""
  proxy_engine=""
  proxy_config=""
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
    proxy_engine=$(prompt_menu "Proxy engine" "sing-box" "xray")
    while true; do
      proxy_config=$(prompt_input "Proxy config path" "")
      [ -n "$proxy_config" ] && break
      echo "Proxy config path is required for proxy mode"
    done
  fi
  tor_install=$(prompt_yesno "Install Tor (always-on)?" "yes")
  local tor_strict="no"
  if [ "$tor_install" = "yes" ]; then
    tor_strict=$(prompt_yesno "Strict Tor mode (block non-Tor traffic)?" "no")
  fi

  if [ "$target" = "Folder" ]; then
    local folder
    folder=$(prompt_input "Install folder path" "$HOME/gargoyle")
    mkdir -p "$folder"/{data,downloads,logs,keys,shared}
    write_config "$folder/gargoyle.yaml" "$edition" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports" "$usb_enabled" "$usb_read_only" "$ram_only" "$net_mode" "$vpn_type" "$vpn_profile" "$gateway_ip" "$tor_install" "$tor_strict" "$proxy_engine" "$proxy_config"
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
  local cluster_kb=256

  if [ "$layout" = "Shared-only (single exFAT)" ]; then
    apply_usb_shared_layout "$dev" "$free_space" "$cluster_kb"
    write_config "/mnt/gargoyle_shared/gargoyle/gargoyle.yaml" "$edition" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports" "$usb_enabled" "$usb_read_only" "$ram_only" "$net_mode" "$vpn_type" "$vpn_profile" "$gateway_ip" "$tor_install" "$tor_strict" "$proxy_engine" "$proxy_config"
    gen_identity_key "/mnt/gargoyle_shared/gargoyle/keys/identity.key"
    if [ "$install_scripts" = "yes" ]; then
      write_sample_script "/mnt/gargoyle_shared/gargoyle/scripts/sample.gsl"
    fi
    echo "USB shared-only layout complete. Mounted at /mnt/gargoyle_shared."
    exit 0
  fi

  local system_size persist_size
  system_size=$(prompt_input "System partition size (MB)" "4096")
  persist_size=$(prompt_input "Persistent partition size (MB)" "8192")

  apply_usb_layout "$dev" "$system_size" "$persist_size" "$free_space" "$cluster_kb"

  write_config "/mnt/gargoyle_persist/gargoyle.yaml" "$edition" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports" "$usb_enabled" "$usb_read_only" "$ram_only" "$net_mode" "$vpn_type" "$vpn_profile" "$gateway_ip" "$tor_install" "$tor_strict" "$proxy_engine" "$proxy_config"
  gen_identity_key "/mnt/gargoyle_persist/keys/identity.key"
  if [ "$install_scripts" = "yes" ]; then
    mkdir -p "/mnt/gargoyle_persist/scripts"
    write_sample_script "/mnt/gargoyle_persist/scripts/sample.gsl"
  fi
  echo "USB layout complete. Persistent mounted at /mnt/gargoyle_persist."
}

main "$@"
