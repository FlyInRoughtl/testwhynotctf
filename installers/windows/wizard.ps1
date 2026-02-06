# Gargoyle Installer Wizard (Windows, TUI)
param(
    [switch]$Quick
)
$ErrorActionPreference = "Stop"

$logPath = Join-Path (Get-Location) "installer.log"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
try {
    Start-Transcript -Path $logPath -Append | Out-Null
} catch {
    Write-Host "[installer] WARN: failed to start transcript: $_"
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    try { Stop-Transcript | Out-Null } catch {}
} | Out-Null

function Ask-Choice($title, $choices) {
    Write-Host ""; Write-Host $title -ForegroundColor Cyan
    for ($i = 0; $i -lt $choices.Count; $i++) {
        Write-Host "[$($i+1)] $($choices[$i])"
    }
    while ($true) {
        $sel = Read-Host "Select 1-$($choices.Count)"
        if ($sel -match '^[0-9]+$') {
            $idx = [int]$sel - 1
            if ($idx -ge 0 -and $idx -lt $choices.Count) {
                return $choices[$idx]
            }
        }
    }
}

function Ask-YesNo($question, $default = $true) {
    $hint = if ($default) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $ans = Read-Host "$question $hint"
        if ($ans -eq "" -and $default) { return $true }
        if ($ans -eq "" -and -not $default) { return $false }
        switch ($ans.ToLower()) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
        }
    }
}

function Ask-Advanced($question) {
    $ans = Read-Host "$question (press A for Advanced, Enter to continue)"
    if ($ans -match '^[Aa]$') { return $true }
    return $false
}

function Has-Cmd($name) {
    return (Get-Command $name -ErrorAction SilentlyContinue) -ne $null
}

function Find-VeraCrypt() {
    $cmd = Get-Command veracrypt -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $paths = @(
        "$env:ProgramFiles\\VeraCrypt\\VeraCrypt.exe",
        "$env:ProgramFiles(x86)\\VeraCrypt\\VeraCrypt.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function ConvertTo-PlainText([SecureString]$secure) {
    if (-not $secure) { return "" }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Format-YamlList($raw) {
    if (-not $raw) { return "[]" }
    $parts = $raw -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    if ($parts.Count -eq 0) { return "[]" }
    $quoted = $parts | ForEach-Object { '"' + $_.Replace('"','') + '"' }
    return "[" + ($quoted -join ",") + "]"
}

function Try-MountVeraCrypt($defaultContainer) {
    $vcPath = Find-VeraCrypt
    if (-not $vcPath) {
        return $null
    }
    $useVC = Ask-YesNo "Use VeraCrypt container for encrypted storage? (best-effort)" $false
    if (-not $useVC) {
        return $null
    }
    $container = Read-Host "Container path (default: $defaultContainer)"
    if (-not $container) { $container = $defaultContainer }
    $sizeGb = Read-Host "Size in GB for new container (default 4)"
    if (-not $sizeGb) { $sizeGb = "4" }
    $letter = Read-Host "Mount drive letter (e.g., G)"
    if (-not $letter) { $letter = "G" }
    $passwordSecure = Read-Host "VeraCrypt password" -AsSecureString
    $password = ConvertTo-PlainText $passwordSecure
    if (-not (Test-Path $container)) {
        $create = Ask-YesNo "Container not found. Create new?" $true
        if ($create) {
            try {
                & $vcPath /create $container /size "${sizeGb}G" /password $password /hash sha512 /encryption AES /filesystem NTFS /pim 0 /quick /silent | Out-Null
            } catch {
                Write-Host "VeraCrypt create failed: $_" -ForegroundColor Red
            }
        }
    }
    try {
        & $vcPath /v $container /l $letter /p $password /q /s | Out-Null
    } catch {
        Write-Host "VeraCrypt mount failed: $_" -ForegroundColor Red
    }
    $password = $null
    if (Test-Path "$letter`:") {
        return "$letter`:"
    }
    return $null
}

function Generate-IdentityKey($path, $length = 256, $group = 15) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=[]{}:;,.<>?/"
    $bytes = New-Object byte[] ($length)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $raw = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) {
        $raw.Append($alphabet[$b % $alphabet.Length]) | Out-Null
    }
    $formatted = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $formatted.Append($raw[$i]) | Out-Null
        if ((($i + 1) % $group) -eq 0 -and $i -ne ($raw.Length - 1)) {
            $formatted.Append("-") | Out-Null
        }
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
    $formatted.ToString() | Set-Content -Path $path -Encoding ascii
}

function Generate-RecoveryCodes($path, $count = 10, $length = 30, $group = 5) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $codes = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $count; $i++) {
        $raw = New-Object System.Text.StringBuilder
        for ($j = 0; $j -lt $length; $j++) {
            $idx = Get-Random -Minimum 0 -Maximum $alphabet.Length
            $raw.Append($alphabet[$idx]) | Out-Null
        }
        $formatted = New-Object System.Text.StringBuilder
        for ($k = 0; $k -lt $raw.Length; $k++) {
            $formatted.Append($raw[$k]) | Out-Null
            if ((($k + 1) % $group) -eq 0 -and $k -ne ($raw.Length - 1)) {
                $formatted.Append("-") | Out-Null
            }
        }
        $codes.Add($formatted.ToString()) | Out-Null
    }
    $codes | Set-Content -Path $path -Encoding ascii
}

function Write-SampleScript($path) {
    @"
# Gargoyle Script sample
print "Gargoyle Script: hello"
print "Starting relay on :18080"
relay.start :18080
sleep 500
print "Relay running"
# Example mesh send: mesh.send <src> <dst> <target> <psk> [depth]
# mesh.send ./file.txt file.txt 127.0.0.1:19999 secret 3
"@ | Set-Content -Path $path -Encoding ascii
}

function Copy-Binaries($destRoot) {
    $candidates = @(
        (Join-Path $repoRoot "gargoyle.exe"),
        (Join-Path $repoRoot "gargoylectl.exe"),
        (Join-Path $repoRoot "os\\ctfvault\\gargoyle.exe"),
        (Join-Path $repoRoot "os\\ctfvault\\gargoylectl.exe")
    )
    foreach ($bin in $candidates) {
        if (Test-Path $bin) {
            try {
                Copy-Item -Force $bin $destRoot
            } catch {
                Write-Host "WARN: failed to copy $bin -> $destRoot : $_" -ForegroundColor Yellow
            }
        }
    }
}

function Copy-Source($destRoot) {
    $src = Join-Path $repoRoot "os\\ctfvault"
    if (-not (Test-Path (Join-Path $src "go.mod"))) {
        Write-Host "WARN: source not found at $src" -ForegroundColor Yellow
        return
    }
    $dest = Join-Path $destRoot "src\\ctfvault"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $robocopy = Get-Command robocopy -ErrorAction SilentlyContinue
    if ($robocopy) {
        $exclude = @(".git", ".cache", "bin", "dist", "tmp", "node_modules")
        $xd = $exclude | ForEach-Object { "/XD `"$src\\$_`"" }
        $cmd = @("robocopy", "`"$src`"", "`"$dest`"", "/E", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS", "/NP") + $xd
        & cmd /c ($cmd -join " ") | Out-Null
    } else {
        Copy-Item -Recurse -Force $src $dest
    }
}

function Build-Binaries($destRoot) {
    if (-not (Has-Cmd "go")) {
        Write-Host "WARN: Go not found; skipping build." -ForegroundColor Yellow
        return
    }
    $src = Join-Path $destRoot "src\\ctfvault"
    if (-not (Test-Path (Join-Path $src "go.mod"))) {
        $src = Join-Path $repoRoot "os\\ctfvault"
    }
    if (-not (Test-Path (Join-Path $src "go.mod"))) {
        Write-Host "WARN: go.mod not found; cannot build." -ForegroundColor Yellow
        return
    }
    Push-Location $src
    try {
        go build -o (Join-Path $destRoot "gargoyle.exe") .\cmd\gargoyle
        go build -o (Join-Path $destRoot "gargoylectl.exe") .\cmd\gargoylectl
    } catch {
        Write-Host "WARN: build failed: $_" -ForegroundColor Yellow
    } finally {
        Pop-Location
    }
}

function Write-StartCmd($destRoot) {
    $path = Join-Path $destRoot "start.cmd"
    @"
@echo off
set GARGOYLE_HOME=%~dp0
cd /d %~dp0
if exist gargoyle.exe (
  gargoyle.exe start --tui --home %~dp0
) else (
  echo gargoyle.exe not found in this folder.
  echo Build it from the repo or copy gargoyle.exe here.
  echo Example: go build -o %~dp0gargoyle.exe .\\cmd\\gargoyle
)
pause
"@ | Set-Content -Path $path -Encoding ascii
}

function Write-BuildCmd($destRoot) {
    $path = Join-Path $destRoot "build.cmd"
    @"
@echo off
set ROOT=%~dp0
set SRC=%ROOT%src\ctfvault
if not exist "%SRC%\go.mod" (
  echo Source not found at %SRC%
  echo Copy source to %ROOT%src\ctfvault or run wizard with "copy source".
  pause
  exit /b 1
)
where go >nul 2>nul
if errorlevel 1 (
  echo Go not found. Install Go, then retry.
  pause
  exit /b 1
)
pushd "%SRC%"
go build -o "%ROOT%gargoyle.exe" .\cmd\gargoyle
go build -o "%ROOT%gargoylectl.exe" .\cmd\gargoylectl
popd
echo Build complete.
pause
"@ | Set-Content -Path $path -Encoding ascii
}

function Show-Plan($target, $location, $layout, $systemSize, $persistSize, $freeSpace, $clusterKb, $edition, $opMode, $dnsProfile, $torStrict, $usbEnabled, $usbReadOnly, $ramOnly, $toolsFile, $usbLabel) {
    Write-Host ""
    Write-Host "===== INSTALL PLAN =====" -ForegroundColor Yellow
    Write-Host "Target: $target"
    Write-Host "Location: $location"
    if ($layout) { Write-Host "USB layout: $layout" }
    if ($systemSize) { Write-Host "SYSTEM size: $systemSize MB" }
    if ($persistSize) { Write-Host "PERSIST size: $persistSize MB" }
    if ($freeSpace) { Write-Host "Free space: $freeSpace MB" }
    if ($clusterKb) { Write-Host "exFAT cluster: $clusterKb KB" }
    if ($usbLabel) { Write-Host "USB label: $usbLabel" }
    Write-Host "Edition: $edition"
    Write-Host "Mode: $opMode"
    Write-Host "DNS: $dnsProfile"
    Write-Host "Tor strict: $torStrict"
    Write-Host "USB enabled: $usbEnabled, USB read-only: $usbReadOnly"
    Write-Host "RAM-only: $ramOnly"
    Write-Host "Tools pack: $toolsFile"
    Write-Host "========================"
    Write-Host ""
}

function Write-PackFile($base, $name) {
    $dir = Join-Path $base "tools\\packs"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $path = Join-Path $dir "$name.yaml"
    switch ($name) {
        "ctf" {
            @"
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
"@ | Set-Content -Path $path -Encoding ascii
        }
        "anonymity" {
            @"
pack: anonymity
tools:
  - name: tor
    install: "apt:tor"
  - name: proxychains4
    install: "apt:proxychains4"
  - name: dnsutils
    install: "apt:dnsutils"
"@ | Set-Content -Path $path -Encoding ascii
        }
        "ctf_emulate" {
            @"
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
"@ | Set-Content -Path $path -Encoding ascii
        }
        "ctf-ultimate" {
            @"
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
"@ | Set-Content -Path $path -Encoding ascii
        }
        "osint" {
            @"
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
"@ | Set-Content -Path $path -Encoding ascii
        }
        default {
            @"
pack: empty
tools: []
"@ | Set-Content -Path $path -Encoding ascii
        }
    }
}

function Write-Config {
    param(
        $path, $edition, $opMode, $locale, $ramLimit, $cpuLimit, $dnsProfile, $dnsCustom, $wifi, $bt, $ports,
        $usbEnabled, $usbReadOnly, $ramOnly, $autoWipeRemove, $autoWipeExit, $netMode, $vpnType, $vpnProfile, $gatewayIP, $proxyEngine, $proxyConfig,
        $torInstall, $torStrict, $torTransPort, $torDnsPort, $torUseBridges, $torTransportName, $torBridgeLines, $torrcPath,
        $macSpoof, $meshOnion, $meshDiscovery, $meshDiscoveryPort, $meshDiscoveryKey, $meshAutoJoin, $meshChat,
        $meshChatListen, $meshChatPSK, $meshChatPSKFile, $meshClipboard, $meshClipboardWarn, $meshTunEnabled,
        $meshTunDevice, $meshTunCIDR, $meshTunPeerCIDR, $meshPadding, $meshTransport, $meshMetadata, $meshOnionDepth,
        $meshRelayAllowlist, $hotspotSSID, $hotspotPassword, $hotspotIfname, $hotspotShared, $emulatePrivacy,
        $emulateTemp, $emulateDownloads, $emulateDisplay, $tunnelType, $tunnelServer, $tunnelToken, $tunnelLocalIP,
        $mailMode, $mailSink, $mailLocal, $mailSinkListen, $mailSinkUI, $mailMeshEnabled, $mailMeshListen,
        $mailMeshPSK, $mailMeshPSKFile, $uiTheme, $uiBossKey, $uiBossMode, $toolsFile, $toolsAuto, $toolsRepo,
        $updateUrl, $updateChannel, $updatePublicKey, $updateAuto, $syncEnabled, $syncTarget, $syncDir, $syncPSK,
        $syncPSKFile, $syncTransport, $syncPadding, $syncDepth, $telegramEnabled, $telegramBotToken,
        $telegramAllowedUser, $telegramPairingTTL, $telegramAllowCLI, $telegramAllowWipe, $telegramAllowStats,
        $dohUrl, $dohListen
    )
    @"
# Gargoyle config
system:
  ram_limit_mb: $ramLimit
  cpu_limit: $cpuLimit
  locale: "$locale"
  edition: "$edition"
  mode: "$opMode"

storage:
  persistent: true
  shared: true
  recovery_codes: "recovery_codes.txt"
  usb_enabled: $usbEnabled
  usb_read_only: $usbReadOnly
  ram_only: $ramOnly
  auto_wipe_on_usb_remove: $autoWipeRemove
  auto_wipe_on_exit: $autoWipeExit

network:
  proxy: ""
  mode: "$netMode"
  vpn_type: "$vpnType"
  vpn_profile: "$vpnProfile"
  gateway_ip: "$gatewayIP"
  proxy_engine: "$proxyEngine"
  proxy_config: "$proxyConfig"
  dns_profile: "$dnsProfile"
  dns_custom: "$dnsCustom"
  doh_url: "$dohUrl"
  doh_listen: "$dohListen"
  tor: $torInstall
  tor_always_on: $torInstall
  tor_strict: $torStrict
  tor_trans_port: $torTransPort
  tor_dns_port: $torDnsPort
  tor_use_bridges: $torUseBridges
  tor_transport: "$torTransportName"
  tor_bridge_lines: $torBridgeLines
  torrc_path: "$torrcPath"
  mac_spoof: $macSpoof
  wifi_enabled: $wifi
  bluetooth_enabled: $bt
  ports_open: $ports

security:
  identity_key_path: "keys/identity.key"
  identity_length: 256
  identity_group: 15

mesh:
  relay_url: ""
  onion_depth: $meshOnionDepth
  metadata_level: "$meshMetadata"
  transport: "$meshTransport"
  padding_bytes: $meshPadding
  discovery_enabled: $meshDiscovery
  discovery_port: $meshDiscoveryPort
  discovery_key: "$meshDiscoveryKey"
  auto_join: $meshAutoJoin
  chat_enabled: $meshChat
  chat_listen: "$meshChatListen"
  chat_psk: "$meshChatPSK"
  chat_psk_file: "$meshChatPSKFile"
  clipboard_share: $meshClipboard
  clipboard_warn: $meshClipboardWarn
  tun_enabled: $meshTunEnabled
  tun_device: "$meshTunDevice"
  tun_cidr: "$meshTunCIDR"
  tun_peer_cidr: "$meshTunPeerCIDR"
  onion_only: $meshOnion
  relay_allowlist: $meshRelayAllowlist
  hotspot:
    ssid: "$hotspotSSID"
    password: "$hotspotPassword"
    ifname: "$hotspotIfname"
    shared: $hotspotShared

ui:
  theme: "$uiTheme"
  language: "$locale"
  boss_key: $uiBossKey
  boss_mode: "$uiBossMode"

emulate:
  privacy_mode: $emulatePrivacy
  temp_dir: "$emulateTemp"
  downloads_dir: "$emulateDownloads"
  display_server: "$emulateDisplay"

tunnel:
  type: "$tunnelType"
  server: "$tunnelServer"
  token: "$tunnelToken"
  local_ip: "$tunnelLocalIP"

mail:
  mode: "$mailMode"
  sink: $mailSink
  local_server: $mailLocal
  sink_listen: "$mailSinkListen"
  sink_ui: "$mailSinkUI"
  mesh_enabled: $mailMeshEnabled
  mesh_listen: "$mailMeshListen"
  mesh_psk: "$mailMeshPSK"
  mesh_psk_file: "$mailMeshPSKFile"

tools:
  file: "$toolsFile"
  auto_install: $toolsAuto
  repository: "$toolsRepo"

update:
  url: "$updateUrl"
  channel: "$updateChannel"
  public_key: "$updatePublicKey"
  auto: $updateAuto

sync:
  enabled: $syncEnabled
  target: "$syncTarget"
  dir: "$syncDir"
  psk: "$syncPSK"
  psk_file: "$syncPSKFile"
  transport: "$syncTransport"
  padding_bytes: $syncPadding
  depth: $syncDepth

telegram:
  enabled: $telegramEnabled
  bot_token: "$telegramBotToken"
  allowed_user_id: $telegramAllowedUser
  pairing_ttl: $telegramPairingTTL
  allow_cli: $telegramAllowCLI
  allow_wipe: $telegramAllowWipe
  allow_stats: $telegramAllowStats
"@ | Set-Content -Path $path -Encoding ascii
}

function Write-PostInstallSummary($homeRoot) {
    Write-Host ""
    Write-Host "===== INSTALL COMPLETE =====" -ForegroundColor Green
    Write-Host "Home: $homeRoot"
    if (Test-Path (Join-Path $homeRoot "gargoyle.exe")) {
        Write-Host "Binary: gargoyle.exe (OK)"
    } else {
        Write-Host "Binary: gargoyle.exe NOT FOUND" -ForegroundColor Yellow
        Write-Host "Run build.cmd inside this folder (requires Go) or re-run wizard with Go installed." -ForegroundColor Yellow
    }
    if (Test-Path (Join-Path $homeRoot "start.cmd")) {
        Write-Host "Start: start.cmd"
    }
    if (Test-Path (Join-Path $homeRoot "build.cmd")) {
        Write-Host "Build: build.cmd"
    }
    Write-Host "==========================="
    Write-Host ""
}

try {
    Write-Host "Gargoyle Installer Wizard (Windows)" -ForegroundColor Green
    Write-Host "Note: Full USB layout (ext4 + LUKS2) is only available on Linux."

    if ($Quick) {
        Write-Host "[quick] Running dependency installer (best-effort)..." -ForegroundColor Yellow
        try {
            & "$PSScriptRoot\\deps.ps1" | Out-Host
        } catch {
            Write-Host "[quick] deps failed: $_" -ForegroundColor Yellow
        }
    }

    if ($Quick) {
        $target = "USB (exFAT only, shared)"
        $edition = "public"
        $opMode = "standard"
        $locale = "ru"
        $ramLimit = 2048
        $cpuLimit = 2
        $dnsProfile = "system"
        $dnsCustom = ""
        $wifi = $true
        $bt = $false
        $ports = $false
        $installScripts = $true
        $usbEnabled = $false
        $usbReadOnly = $false
        $ramOnly = $false
        $autoWipeRemove = $false
        $autoWipeExit = $false
        $genRecovery = $true
    } else {
        $target = Ask-Choice "Install target" @("Folder (recommended on Windows)", "USB (exFAT only, shared)")

        $edition = Ask-Choice "Edition" @("public", "private")
        $opMode = Ask-Choice "Operation mode" @("standard", "fullanon")
        $locale = Ask-Choice "Language" @("ru", "en")
        $ramLimit = 2048
        $cpuLimit = 2
        $dnsProfile = Ask-Choice "DNS profile" @("system", "xbox", "custom")
        $dnsCustom = ""
        if ($dnsProfile -eq "custom") {
            $dnsCustom = Read-Host "Enter DNS-over-HTTPS URL or resolver"
        }
        if ($dnsProfile -eq "xbox") {
            $dnsCustom = "https://xbox-dns.ru/dns-query"
        }

        $wifi = Ask-YesNo "Enable Wi-Fi by default?" $true
        $bt = Ask-YesNo "Enable Bluetooth by default?" $false
        $ports = Ask-YesNo "Open ports by default?" $false
        $installScripts = Ask-YesNo "Install Gargoyle Script (DSL) samples?" $true
        $usbEnabled = Ask-YesNo "Enable USB access inside Gargoyle?" $false
        $usbReadOnly = $false
        if ($usbEnabled) {
            $usbReadOnly = Ask-YesNo "USB read-only mode?" $true
        }
        $ramOnly = Ask-YesNo "RAM-only session (no disk writes)?" $false
        $autoWipeRemove = Ask-YesNo "Auto wipe on USB removal?" ($opMode -eq "fullanon")
        $autoWipeExit = Ask-YesNo "Auto wipe on exit?" ($opMode -eq "fullanon")
        $genRecovery = Ask-YesNo "Generate recovery codes file (USB only recommended)?" ($target -like "USB*")
    }

$netMode = ""
$vpnType = ""
$vpnProfile = ""
$gatewayIP = ""
$proxyEngine = ""
$proxyConfig = ""
$dohUrl = ""
$dohListen = "127.0.0.1:5353"
$torTransPort = 9040
$torDnsPort = 9053
$torUseBridges = $false
$torTransport = ""
$torBridgeLines = "[]"
$torrcPath = ""
$meshDiscoveryPort = 19998
$meshDiscoveryKey = ""
$meshAutoJoin = $false
$meshChatListen = ":19997"
$meshChatPSK = ""
$meshChatPSKFile = ""
$meshClipboardWarn = $true
$meshTunEnabled = $false
$meshTunDevice = "gargoyle0"
$meshTunCIDR = "10.42.0.1/24"
$meshTunPeerCIDR = "10.42.0.0/24"
$meshPadding = 256
$meshTransport = "tls"
$meshMetadata = "standard"
$meshOnionDepth = 3
$meshRelayAllowlist = "[]"
$hotspotSSID = ""
$hotspotPassword = ""
$hotspotIfname = ""
$hotspotShared = $true
$emulatePrivacy = $true
$emulateTemp = "ram"
$emulateDownloads = "downloads"
$emulateDisplay = "direct"
$tunnelType = "frp"
$tunnelServer = ""
$tunnelToken = ""
$tunnelLocalIP = "127.0.0.1"
$mailMode = "local"
$mailSink = $true
$mailLocal = $true
$mailSinkListen = "127.0.0.1:1025"
$mailSinkUI = "127.0.0.1:8025"
$mailMeshEnabled = $true
$mailMeshListen = ":20025"
$mailMeshPSK = ""
$mailMeshPSKFile = ""
$uiTheme = "dark"
$uiBossKey = $true
$uiBossMode = "update"
$toolsFile = "tools.yaml"
$toolsAuto = $false
$toolsRepo = ""
$updateUrl = ""
$updateChannel = "stable"
$updatePublicKey = ""
$updateAuto = $false
$syncEnabled = $false
$syncTarget = ""
$syncDir = "./loot"
$syncPSK = ""
$syncPSKFile = ""
$syncTransport = "tls"
$syncPadding = 256
$syncDepth = 3
$telegramEnabled = $false
$telegramBotToken = ""
$telegramAllowedUser = 0
$telegramPairingTTL = 60
$telegramAllowCLI = $false
$telegramAllowWipe = $false
$telegramAllowStats = $true
$macSpoof = $true
$meshOnion = $false
$meshDiscovery = $false
$meshChat = $true
$meshClipboard = $false
$usbLabel = "GARGOYLE_SHARED"
$copySource = $true
$autoBuild = $true
if ($opMode -eq "fullanon") {
    $netMode = "direct"
    $torInstall = $true
    $torStrict = $true
    $macSpoof = $true
    $meshOnion = $true
    $meshDiscovery = $false
    $meshChat = $false
    $meshClipboard = $false
} elseif ($Quick) {
    $netMode = "direct"
    $torInstall = $true
    $torStrict = $false
    $toolsFile = "tools\\packs\\ctf.yaml"
    $toolsAuto = $false
} else {
    $netMode = Ask-Choice "Network mode" @("direct", "vpn", "gateway", "proxy")
    if ($netMode -eq "vpn") {
        $vpnType = Ask-Choice "VPN type" @("openvpn", "wireguard")
        $vpnProfile = Read-Host "VPN profile path"
        if (-not $vpnProfile) { throw "VPN profile path is required for VPN mode" }
    }
    if ($netMode -eq "gateway") {
        $gatewayIP = Read-Host "Gateway IP (e.g., 192.168.1.1)"
        if (-not $gatewayIP) { throw "Gateway IP is required for gateway mode" }
    }
    if ($netMode -eq "proxy") {
        $proxyEngine = Ask-Choice "Proxy engine" @("sing-box", "xray", "hiddify")
        $proxyConfig = Read-Host "Proxy config path"
        if (-not $proxyConfig) { throw "Proxy config path is required for proxy mode" }
    }
    $torInstall = Ask-YesNo "Install Tor (always-on)?" $true
    $torStrict = $false
    if ($torInstall) {
        $torStrict = Ask-YesNo "Strict Tor mode (block non-Tor traffic)?" $false
    }
}

if (-not $Quick) {
    $advanced = Ask-Advanced "Advanced privacy/mesh settings?"
} else {
    $advanced = $false
}
if ($advanced) {
    $ramLimit = Read-Host "RAM limit MB (default $ramLimit)"
    if (-not $ramLimit) { $ramLimit = 2048 }
    $cpuLimit = Read-Host "CPU limit (default $cpuLimit)"
    if (-not $cpuLimit) { $cpuLimit = 2 }
    $torInstall = Ask-YesNo "Tor always-on?" $torInstall
    if ($torInstall) {
        $torStrict = Ask-YesNo "Tor strict kill-switch?" $torStrict
    } else {
        $torStrict = $false
    }
    $torTransPort = Read-Host "Tor TransPort (default $torTransPort)"
    if (-not $torTransPort) { $torTransPort = 9040 }
    $torDnsPort = Read-Host "Tor DNSPort (default $torDnsPort)"
    if (-not $torDnsPort) { $torDnsPort = 9053 }
    $torUseBridges = Ask-YesNo "Tor bridges enabled?" $torUseBridges
    if ($torUseBridges) {
        $torTransport = Read-Host "Tor transport (obfs4/meek/..)"
        $torBridgeLines = Format-YamlList (Read-Host "Tor bridges (comma/;)")
    } else {
        $torTransport = ""
        $torBridgeLines = "[]"
    }
    $torrcPath = Read-Host "Torrc path (optional)"
    $macSpoof = Ask-YesNo "MAC spoofing?" $macSpoof
    $ports = Ask-YesNo "Open ports by default?" $ports
    $dohUrl = Read-Host "DoH URL (optional)"
    $dohListen = Read-Host "DoH listen (default $dohListen)"
    if (-not $dohListen) { $dohListen = "127.0.0.1:5353" }
    $meshOnion = Ask-YesNo "Mesh onion-only?" $meshOnion
    $meshDiscovery = Ask-YesNo "Mesh discovery enabled?" $meshDiscovery
    $meshDiscoveryPort = Read-Host "Mesh discovery port (default $meshDiscoveryPort)"
    if (-not $meshDiscoveryPort) { $meshDiscoveryPort = 19998 }
    $meshDiscoveryKey = Read-Host "Mesh discovery key (optional)"
    $meshAutoJoin = Ask-YesNo "Mesh auto-join?" $meshAutoJoin
    $meshChat = Ask-YesNo "Mesh chat enabled?" $meshChat
    $meshChatListen = Read-Host "Mesh chat listen (default $meshChatListen)"
    if (-not $meshChatListen) { $meshChatListen = ":19997" }
    $meshChatPSK = Read-Host "Mesh chat PSK (optional)"
    $meshChatPSKFile = Read-Host "Mesh chat PSK file (optional)"
    $meshClipboard = Ask-YesNo "Mesh clipboard share?" $meshClipboard
    $meshClipboardWarn = Ask-YesNo "Mesh clipboard warn?" $meshClipboardWarn
    $meshTransport = Ask-Choice "Mesh transport" @("tcp", "tls")
    $meshMetadata = Ask-Choice "Mesh metadata" @("off", "standard", "max")
    $meshPadding = Read-Host "Mesh padding bytes (default $meshPadding)"
    if (-not $meshPadding) { $meshPadding = 256 }
    $meshOnionDepth = Read-Host "Mesh onion depth (default $meshOnionDepth)"
    if (-not $meshOnionDepth) { $meshOnionDepth = 3 }
    $meshTunEnabled = Ask-YesNo "Mesh tun enabled?" $meshTunEnabled
    if ($meshTunEnabled) {
        $meshTunDevice = Read-Host "Tun device (default $meshTunDevice)"
        if (-not $meshTunDevice) { $meshTunDevice = "gargoyle0" }
        $meshTunCIDR = Read-Host "Tun CIDR (default $meshTunCIDR)"
        if (-not $meshTunCIDR) { $meshTunCIDR = "10.42.0.1/24" }
        $meshTunPeerCIDR = Read-Host "Tun peer CIDR (default $meshTunPeerCIDR)"
        if (-not $meshTunPeerCIDR) { $meshTunPeerCIDR = "10.42.0.0/24" }
    }
    $meshRelayAllowlist = Format-YamlList (Read-Host "Relay allowlist tokens (comma/;)")
    $hotspotSSID = Read-Host "Hotspot SSID"
    $hotspotPassword = Read-Host "Hotspot password"
    $hotspotIfname = Read-Host "Hotspot ifname"
    $hotspotShared = Ask-YesNo "Hotspot shared/NAT?" $hotspotShared
    $emulatePrivacy = Ask-YesNo "Emulate privacy mode?" $emulatePrivacy
    $emulateTemp = Ask-Choice "Emulate temp dir" @("ram", "disk")
    $emulateDownloads = Read-Host "Emulate downloads dir"
    if (-not $emulateDownloads) { $emulateDownloads = "downloads" }
    $emulateDisplay = Ask-Choice "Emulate display server" @("direct", "cage", "gamescope", "weston")
    $tunnelType = Ask-Choice "Tunnel type" @("frp", "relay", "wss")
    $tunnelServer = Read-Host "Tunnel server"
    $tunnelToken = Read-Host "Tunnel token"
    $tunnelLocalIP = Read-Host "Tunnel local IP"
    if (-not $tunnelLocalIP) { $tunnelLocalIP = "127.0.0.1" }
    $mailMode = Ask-Choice "Mail mode" @("local", "tunnel")
    $mailSink = Ask-YesNo "Mail sink enabled?" $mailSink
    $mailLocal = Ask-YesNo "Mail local server enabled?" $mailLocal
    $mailSinkListen = Read-Host "Mail sink listen"
    if (-not $mailSinkListen) { $mailSinkListen = "127.0.0.1:1025" }
    $mailSinkUI = Read-Host "Mail sink UI"
    if (-not $mailSinkUI) { $mailSinkUI = "127.0.0.1:8025" }
    $mailMeshEnabled = Ask-YesNo "Mail mesh enabled?" $mailMeshEnabled
    $mailMeshListen = Read-Host "Mail mesh listen"
    if (-not $mailMeshListen) { $mailMeshListen = ":20025" }
    $mailMeshPSK = Read-Host "Mail mesh PSK"
    $mailMeshPSKFile = Read-Host "Mail mesh PSK file"
    $uiTheme = Ask-Choice "UI theme" @("dark", "light")
    $uiBossKey = Ask-YesNo "Boss-key enabled?" $uiBossKey
    $uiBossMode = Ask-Choice "Boss mode" @("update", "htop", "blank")
    $copySource = Ask-YesNo "Copy Gargoyle source to USB (offline build)?" $copySource
    $autoBuild = Ask-YesNo "Build gargoyle.exe now (if Go installed)?" $autoBuild
    $usbLabel = Read-Host "USB volume label (default $usbLabel)"
    if (-not $usbLabel) { $usbLabel = "GARGOYLE_SHARED" }
    $toolsProfile = Ask-Choice "Tools pack profile" @("ctf (recommended)", "none", "anonymity", "ctf+emulate", "osint")
    switch ($toolsProfile) {
        "ctf (recommended)" { $toolsFile = "tools\\packs\\ctf.yaml" }
        "anonymity" { $toolsFile = "tools\\packs\\anonymity.yaml" }
        "ctf+emulate" { $toolsFile = "tools\\packs\\ctf_emulate.yaml" }
        "osint" { $toolsFile = "tools\\packs\\osint.yaml" }
        default { $toolsFile = "tools\\packs\\empty.yaml" }
    }
    $toolsAuto = Ask-YesNo "Auto install tools?" $toolsAuto
    $toolsRepo = Read-Host "Tools repository URL (optional)"
    $updateUrl = Read-Host "Update URL (optional)"
    $updateChannel = Ask-Choice "Update channel" @("stable", "beta", "dev")
    $updatePublicKey = Read-Host "Update public key"
    $updateAuto = Ask-YesNo "Auto updates?" $updateAuto
    $syncEnabled = Ask-YesNo "Sync (loot) enabled?" $syncEnabled
    $syncTarget = Read-Host "Sync target (host:port)"
    $syncDir = Read-Host "Sync dir"
    if (-not $syncDir) { $syncDir = "./loot" }
    $syncPSK = Read-Host "Sync PSK"
    $syncPSKFile = Read-Host "Sync PSK file"
    $syncTransport = Ask-Choice "Sync transport" @("tcp", "tls")
    $syncPadding = Read-Host "Sync padding bytes (default $syncPadding)"
    if (-not $syncPadding) { $syncPadding = 256 }
    $syncDepth = Read-Host "Sync depth (default $syncDepth)"
    if (-not $syncDepth) { $syncDepth = 3 }
    $telegramEnabled = Ask-YesNo "Telegram C2 enabled?" $telegramEnabled
    $telegramBotToken = Read-Host "Telegram bot token"
    $telegramAllowedUser = Read-Host "Telegram allowed user ID"
    if (-not $telegramAllowedUser) { $telegramAllowedUser = 0 }
    $telegramPairingTTL = Read-Host "Telegram pairing TTL (s)"
    if (-not $telegramPairingTTL) { $telegramPairingTTL = 60 }
    $telegramAllowCLI = Ask-YesNo "Telegram allow CLI?" $telegramAllowCLI
    $telegramAllowWipe = Ask-YesNo "Telegram allow wipe?" $telegramAllowWipe
    $telegramAllowStats = Ask-YesNo "Telegram allow stats?" $telegramAllowStats
}

    if ($target -like "Folder*") {
    $folder = Read-Host "Enter install folder path"
    if (-not $folder) { throw "Folder path is required" }
    Show-Plan "Folder" $folder "" "" "" "" "" $edition $opMode $dnsProfile $torStrict $usbEnabled $usbReadOnly $ramOnly $toolsFile ""
    $action = Ask-Choice "Proceed?" @("Proceed", "Dry-run (show plan only)", "Cancel")
    if ($action -like "Dry-run*") { Write-Host "Dry-run complete. No changes applied." -ForegroundColor Yellow; exit 0 }
    if ($action -like "Cancel*") { throw "Cancelled" }
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    $homeRoot = $folder
    $vcRoot = Try-MountVeraCrypt (Join-Path $folder "gargoyle.hc")
    if ($vcRoot) {
        $homeRoot = Join-Path $vcRoot "gargoyle"
    }
    foreach ($dir in @("data","downloads","logs","keys","shared")) {
        New-Item -ItemType Directory -Force -Path (Join-Path $homeRoot $dir) | Out-Null
    }
    if ($genRecovery) {
        Generate-RecoveryCodes (Join-Path $homeRoot "recovery_codes.txt") 10 30 5
    }
    if ($copySource) { Copy-Source $homeRoot }
    if ($autoBuild) { Build-Binaries $homeRoot }
    Copy-Binaries $homeRoot
    Write-StartCmd $homeRoot
    Write-BuildCmd $homeRoot
    Write-Config (Join-Path $homeRoot "gargoyle.yaml") $edition $opMode $locale $ramLimit $cpuLimit $dnsProfile $dnsCustom $wifi $bt $ports $usbEnabled $usbReadOnly $ramOnly $autoWipeRemove $autoWipeExit $netMode $vpnType $vpnProfile $gatewayIP $proxyEngine $proxyConfig $torInstall $torStrict $torTransPort $torDnsPort $torUseBridges $torTransport $torBridgeLines $torrcPath $macSpoof $meshOnion $meshDiscovery $meshDiscoveryPort $meshDiscoveryKey $meshAutoJoin $meshChat $meshChatListen $meshChatPSK $meshChatPSKFile $meshClipboard $meshClipboardWarn $meshTunEnabled $meshTunDevice $meshTunCIDR $meshTunPeerCIDR $meshPadding $meshTransport $meshMetadata $meshOnionDepth $meshRelayAllowlist $hotspotSSID $hotspotPassword $hotspotIfname $hotspotShared $emulatePrivacy $emulateTemp $emulateDownloads $emulateDisplay $tunnelType $tunnelServer $tunnelToken $tunnelLocalIP $mailMode $mailSink $mailLocal $mailSinkListen $mailSinkUI $mailMeshEnabled $mailMeshListen $mailMeshPSK $mailMeshPSKFile $uiTheme $uiBossKey $uiBossMode $toolsFile $toolsAuto $toolsRepo $updateUrl $updateChannel $updatePublicKey $updateAuto $syncEnabled $syncTarget $syncDir $syncPSK $syncPSKFile $syncTransport $syncPadding $syncDepth $telegramEnabled $telegramBotToken $telegramAllowedUser $telegramPairingTTL $telegramAllowCLI $telegramAllowWipe $telegramAllowStats $dohUrl $dohListen
    if ($toolsFile -like "tools\\packs\\*") {
        $pack = [System.IO.Path]::GetFileNameWithoutExtension($toolsFile)
        Write-PackFile $homeRoot $pack
    }
    Generate-IdentityKey (Join-Path $homeRoot "keys\identity.key") 256 15
    if ($installScripts) {
        $scriptsDir = Join-Path $homeRoot "scripts"
        New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null
        Write-SampleScript (Join-Path $scriptsDir "sample.gsl")
    }
    Write-Host "Folder install complete: $homeRoot" -ForegroundColor Green
    Write-PostInstallSummary $homeRoot
    Read-Host "Press Enter to exit"
    exit 0
    }

# USB (exFAT only on Windows)
$disks = Get-Disk | Where-Object BusType -eq 'USB'
if (-not $disks) {
    throw "No USB disks found"
}
Write-Host "USB disks:" -ForegroundColor Cyan
foreach ($d in $disks) {
    Write-Host ("Disk {0}: {1} {2}GB" -f $d.Number, $d.FriendlyName, [math]::Round($d.Size/1GB,2))
}
$diskNum = $null
while ($true) {
    $diskNum = Read-Host "Enter disk number to format as exFAT (THIS ERASES DATA)"
    if ($diskNum -match '^[0-9]+$') {
        $diskNum = [int]$diskNum
        $testDisk = Get-Disk -Number $diskNum -ErrorAction SilentlyContinue
        if ($testDisk) { break }
    }
    Write-Host "Invalid input. Enter a disk number from the list above (e.g., 1). Filesystem is already exFAT." -ForegroundColor Red
}
$leaveFree = Read-Host "Leave unallocated space at end (MB, default 0)"
if (-not $leaveFree) { $leaveFree = 0 }
$leaveFreeMB = 0
if ($leaveFree -match '^[0-9]+$') { $leaveFreeMB = [int64]$leaveFree }
$layout = "Shared-only (exFAT)"
Show-Plan "USB" ("Disk " + $diskNum) $layout "" "" $leaveFreeMB 512 $edition $opMode $dnsProfile $torStrict $usbEnabled $usbReadOnly $ramOnly $toolsFile $usbLabel
$action = Ask-Choice "Proceed?" @("Proceed", "Dry-run (show plan only)", "Cancel")
if ($action -like "Dry-run*") { Write-Host "Dry-run complete. No changes applied." -ForegroundColor Yellow; exit 0 }
if ($action -like "Cancel*") { throw "Cancelled" }
$confirm = Read-Host "Type FORMAT to confirm"
if ($confirm -ne "FORMAT") { throw "Cancelled" }

$disk = Get-Disk -Number $diskNum
$disk | Set-Disk -IsReadOnly $false
$disk | Clear-Disk -RemoveData -Confirm:$false
if ($leaveFreeMB -gt 0) {
    $size = $disk.Size - ($leaveFreeMB * 1MB)
    if ($size -le 0) { throw "Leave free space too large" }
    $part = New-Partition -DiskNumber $diskNum -Size $size -AssignDriveLetter
} else {
    $part = New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter
}
Format-Volume -Partition $part -FileSystem exFAT -AllocationUnitSize 524288 -NewFileSystemLabel $usbLabel -Confirm:$false

$drive = $part.DriveLetter
if ($drive) {
    $homeRoot = "$drive`:\gargoyle"
    $vcRoot = Try-MountVeraCrypt "$drive`:\gargoyle.hc"
    if ($vcRoot) {
        $homeRoot = Join-Path $vcRoot "gargoyle"
    }
    New-Item -ItemType Directory -Force -Path $homeRoot | Out-Null
    foreach ($dir in @("data","downloads","logs","keys","shared","scripts")) {
        New-Item -ItemType Directory -Force -Path (Join-Path $homeRoot $dir) | Out-Null
    }
    if ($genRecovery) {
        Generate-RecoveryCodes (Join-Path $homeRoot "recovery_codes.txt") 10 30 5
    }
    if ($copySource) { Copy-Source $homeRoot }
    if ($autoBuild) { Build-Binaries $homeRoot }
    Copy-Binaries $homeRoot
    Write-StartCmd $homeRoot
    Write-BuildCmd $homeRoot
    Write-Config (Join-Path $homeRoot "gargoyle.yaml") $edition $opMode $locale $ramLimit $cpuLimit $dnsProfile $dnsCustom $wifi $bt $ports $usbEnabled $usbReadOnly $ramOnly $autoWipeRemove $autoWipeExit $netMode $vpnType $vpnProfile $gatewayIP $proxyEngine $proxyConfig $torInstall $torStrict $torTransPort $torDnsPort $torUseBridges $torTransport $torBridgeLines $torrcPath $macSpoof $meshOnion $meshDiscovery $meshDiscoveryPort $meshDiscoveryKey $meshAutoJoin $meshChat $meshChatListen $meshChatPSK $meshChatPSKFile $meshClipboard $meshClipboardWarn $meshTunEnabled $meshTunDevice $meshTunCIDR $meshTunPeerCIDR $meshPadding $meshTransport $meshMetadata $meshOnionDepth $meshRelayAllowlist $hotspotSSID $hotspotPassword $hotspotIfname $hotspotShared $emulatePrivacy $emulateTemp $emulateDownloads $emulateDisplay $tunnelType $tunnelServer $tunnelToken $tunnelLocalIP $mailMode $mailSink $mailLocal $mailSinkListen $mailSinkUI $mailMeshEnabled $mailMeshListen $mailMeshPSK $mailMeshPSKFile $uiTheme $uiBossKey $uiBossMode $toolsFile $toolsAuto $toolsRepo $updateUrl $updateChannel $updatePublicKey $updateAuto $syncEnabled $syncTarget $syncDir $syncPSK $syncPSKFile $syncTransport $syncPadding $syncDepth $telegramEnabled $telegramBotToken $telegramAllowedUser $telegramPairingTTL $telegramAllowCLI $telegramAllowWipe $telegramAllowStats $dohUrl $dohListen
    if ($toolsFile -like "tools\\packs\\*") {
        $pack = [System.IO.Path]::GetFileNameWithoutExtension($toolsFile)
        Write-PackFile $homeRoot $pack
    }
    Generate-IdentityKey (Join-Path $homeRoot "keys\identity.key") 256 15
    if ($installScripts) {
        Write-SampleScript (Join-Path $homeRoot "scripts\sample.gsl")
    }

    if (-not $vcRoot) {
        $enableBitLocker = Ask-YesNo "Enable BitLocker on this USB? (requires admin/Pro)" $false
        if ($enableBitLocker) {
            $bitlocker = Get-Command manage-bde -ErrorAction SilentlyContinue
            if ($bitlocker) {
                Write-Host "Enabling BitLocker on ${drive}:\\" -ForegroundColor Yellow
                try {
                    & manage-bde -on "$drive`:" -RecoveryPassword | Out-Host
                } catch {
                    Write-Host "BitLocker failed: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "manage-bde not found (BitLocker unavailable)" -ForegroundColor Red
            }
        }
    }
    Write-Host "USB formatted as exFAT shared. Full ext4/LUKS layout requires Linux wizard." -ForegroundColor Yellow
    Write-PostInstallSummary $homeRoot
    Read-Host "Press Enter to exit"
}
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "See installer.log in $(Get-Location)" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}
