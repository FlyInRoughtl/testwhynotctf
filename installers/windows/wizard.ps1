# Gargoyle Installer Wizard (Windows, TUI)
$ErrorActionPreference = "Stop"

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

function Write-Config($path, $edition, $dnsProfile, $dnsCustom, $wifi, $bt, $ports, $usbEnabled, $usbReadOnly, $ramOnly, $netMode, $vpnType, $vpnProfile, $gatewayIP, $proxyEngine, $proxyConfig, $torInstall, $torStrict) {
    @"
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
  usb_enabled: $usbEnabled
  usb_read_only: $usbReadOnly
  ram_only: $ramOnly

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
  doh_url: ""
  doh_listen: "127.0.0.1:5353"
  tor: $torInstall
  tor_always_on: $torInstall
  tor_strict: $torStrict
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
  transport: "tls"
  padding_bytes: 256

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
  local_ip: "127.0.0.1"

mail:
  mode: "local"
  sink: true
  local_server: true
  sink_listen: "127.0.0.1:1025"
  sink_ui: "127.0.0.1:8025"
  mesh_enabled: true
  mesh_listen: ":20025"
  mesh_psk: ""
  mesh_psk_file: ""
"@ | Set-Content -Path $path -Encoding ascii
}

Write-Host "Gargoyle Installer Wizard (Windows)" -ForegroundColor Green
Write-Host "Note: Full USB layout (ext4 + LUKS2) is only available on Linux."

$target = Ask-Choice "Install target" @("Folder (recommended on Windows)", "USB (exFAT only, shared)")

$edition = Ask-Choice "Edition" @("public", "private")
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

$netMode = Ask-Choice "Network mode" @("direct", "vpn", "gateway", "proxy")
$vpnType = ""
$vpnProfile = ""
$gatewayIP = ""
$proxyEngine = ""
$proxyConfig = ""
if ($netMode -eq "vpn") {
    $vpnType = Ask-Choice "VPN type" @("openvpn", "wireguard")
    $vpnProfile = Read-Host "VPN profile path"
    if (-not $vpnProfile) { throw "VPN profile path is required for VPN mode" }
}
if ($netMode -eq "gateway") {
    $gatewayIP = Read-Host "Gateway IP (e.g., 192.168.1.1)"
    if (-not $gatewayIP) { throw "Gateway IP is required for gateway mode" }
}
$netMode = $netMode
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

if ($target -like "Folder*") {
    $folder = Read-Host "Enter install folder path"
    if (-not $folder) { throw "Folder path is required" }
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    $homeRoot = $folder
    $vcRoot = Try-MountVeraCrypt (Join-Path $folder "gargoyle.hc")
    if ($vcRoot) {
        $homeRoot = Join-Path $vcRoot "gargoyle"
    }
    foreach ($dir in @("data","downloads","logs","keys","shared")) {
        New-Item -ItemType Directory -Force -Path (Join-Path $homeRoot $dir) | Out-Null
    }
    Write-Config (Join-Path $homeRoot "gargoyle.yaml") $edition $dnsProfile $dnsCustom $wifi $bt $ports $usbEnabled $usbReadOnly $ramOnly $netMode $vpnType $vpnProfile $gatewayIP $proxyEngine $proxyConfig $torInstall $torStrict
    Generate-IdentityKey (Join-Path $homeRoot "keys\identity.key") 256 15
    if ($installScripts) {
        $scriptsDir = Join-Path $homeRoot "scripts"
        New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null
        Write-SampleScript (Join-Path $scriptsDir "sample.gsl")
    }
    Write-Host "Folder install complete: $homeRoot" -ForegroundColor Green
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
$diskNum = Read-Host "Enter disk number to format as exFAT (THIS ERASES DATA)"
$leaveFree = Read-Host "Leave unallocated space at end (MB, default 0)"
if (-not $leaveFree) { $leaveFree = 0 }
$leaveFreeMB = 0
if ($leaveFree -match '^[0-9]+$') { $leaveFreeMB = [int64]$leaveFree }
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
Format-Volume -Partition $part -FileSystem exFAT -AllocationUnitSize 262144 -NewFileSystemLabel "GARGOYLE_SHARED" -Confirm:$false

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
    Write-Config (Join-Path $homeRoot "gargoyle.yaml") $edition $dnsProfile $dnsCustom $wifi $bt $ports $usbEnabled $usbReadOnly $ramOnly $netMode $vpnType $vpnProfile $gatewayIP $proxyEngine $proxyConfig $torInstall $torStrict
    Generate-IdentityKey (Join-Path $homeRoot "keys\identity.key") 256 15
    if ($installScripts) {
        Write-SampleScript (Join-Path $homeRoot "scripts\sample.gsl")
    }

    if (-not $vcRoot) {
        $enableBitLocker = Ask-YesNo "Enable BitLocker on this USB? (requires admin/Pro)" $false
        if ($enableBitLocker) {
            $bitlocker = Get-Command manage-bde -ErrorAction SilentlyContinue
            if ($bitlocker) {
                Write-Host "Enabling BitLocker on $drive:`\" -ForegroundColor Yellow
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
}

Write-Host "USB formatted as exFAT shared. Full ext4/LUKS layout requires Linux wizard." -ForegroundColor Yellow
