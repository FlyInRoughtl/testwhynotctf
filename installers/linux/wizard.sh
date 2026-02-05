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
  local path="$1" edition="$2" dns_profile="$3" dns_custom="$4" wifi="$5" bt="$6" ports="$7"
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

network:
  proxy: ""
  dns_profile: "$dns_profile"
  dns_custom: "$dns_custom"
  tor: false
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
  local dev="$1" system_size="$2" persist_size="$3"
  require_cmd sgdisk
  require_cmd mkfs.ext4
  require_cmd mkfs.exfat
  require_cmd cryptsetup

  echo "WARNING: This will erase $dev"
  read -rp "Type FORMAT to continue: " confirm
  [ "$confirm" = "FORMAT" ] || { echo "Cancelled"; exit 1; }

  sudo sgdisk --zap-all "$dev"
  sudo sgdisk -n 1:0:+512M -t 1:ef00 -c 1:GARGOYLE_EFI "$dev"
  sudo sgdisk -n 2:0:+${system_size}M -t 2:8300 -c 2:GARGOYLE_SYS "$dev"
  sudo sgdisk -n 3:0:+${persist_size}M -t 3:8300 -c 3:GARGOYLE_PERSIST "$dev"
  sudo sgdisk -n 4:0:0 -t 4:0700 -c 4:GARGOYLE_SHARED "$dev"

  sudo mkfs.vfat -F32 "${dev}1"
  sudo mkfs.ext4 -L GARGOYLE_SYS "${dev}2"

  sudo cryptsetup luksFormat "${dev}3"
  sudo cryptsetup open "${dev}3" gargoyle_persist
  sudo mkfs.ext4 -L GARGOYLE_PERSIST /dev/mapper/gargoyle_persist

  # exFAT cluster size 512KB => 1024 sectors of 512 bytes
  sudo mkfs.exfat -s 1024 -n GARGOYLE_SHARED "${dev}4" || sudo mkfs.exfat -n GARGOYLE_SHARED "${dev}4"

  sudo mkdir -p /mnt/gargoyle_persist
  sudo mount /dev/mapper/gargoyle_persist /mnt/gargoyle_persist
  sudo mkdir -p /mnt/gargoyle_persist/{data,downloads,logs,keys,shared}
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

  if [ "$target" = "Folder" ]; then
    local folder
    folder=$(prompt_input "Install folder path" "$HOME/gargoyle")
    mkdir -p "$folder"/{data,downloads,logs,keys,shared}
    write_config "$folder/ctfvault.yaml" "$edition" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports"
    gen_identity_key "$folder/keys/identity.key"
    echo "Folder install complete: $folder"
    exit 0
  fi

  local dev
  dev=$(pick_usb)
  if [ -z "$dev" ]; then
    echo "No USB device selected"
    exit 1
  fi

  local system_size persist_size
  system_size=$(prompt_input "System partition size (MB)" "4096")
  persist_size=$(prompt_input "Persistent partition size (MB)" "8192")

  apply_usb_layout "$dev" "$system_size" "$persist_size"

  write_config "/mnt/gargoyle_persist/ctfvault.yaml" "$edition" "$dns_profile" "$dns_custom" "$wifi" "$bt" "$ports"
  gen_identity_key "/mnt/gargoyle_persist/keys/identity.key"
  echo "USB layout complete. Persistent mounted at /mnt/gargoyle_persist."
}

main "$@"
