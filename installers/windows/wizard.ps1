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

function Write-Config($path, $edition, $dnsProfile, $dnsCustom, $wifi, $bt, $ports) {
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

network:
  proxy: ""
  dns_profile: "$dnsProfile"
  dns_custom: "$dnsCustom"
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

if ($target -like "Folder*") {
    $folder = Read-Host "Enter install folder path"
    if (-not $folder) { throw "Folder path is required" }
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    foreach ($dir in @("data","downloads","logs","keys","shared")) {
        New-Item -ItemType Directory -Force -Path (Join-Path $folder $dir) | Out-Null
    }
    Write-Config (Join-Path $folder "ctfvault.yaml") $edition $dnsProfile $dnsCustom $wifi $bt $ports
    Generate-IdentityKey (Join-Path $folder "keys\identity.key") 256 15
    Write-Host "Folder install complete: $folder" -ForegroundColor Green
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
$confirm = Read-Host "Type FORMAT to confirm"
if ($confirm -ne "FORMAT") { throw "Cancelled" }

$disk = Get-Disk -Number $diskNum
$disk | Set-Disk -IsReadOnly $false
$disk | Clear-Disk -RemoveData -Confirm:$false
$part = New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter
Format-Volume -Partition $part -FileSystem exFAT -AllocationUnitSize 524288 -NewFileSystemLabel "GARGOYLE_SHARED" -Confirm:$false

Write-Host "USB formatted as exFAT shared. Full ext4/LUKS layout requires Linux wizard." -ForegroundColor Yellow
