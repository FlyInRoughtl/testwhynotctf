param(
    [switch]$SkipOptional = $false
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
$ctfDir = Join-Path $root "os\\ctfvault"

function Has-Cmd($name) {
    return (Get-Command $name -ErrorAction SilentlyContinue) -ne $null
}

Write-Host "[deps] Gargoyle Windows dependencies (best-effort)"

if (-not (Has-Cmd "go")) {
    if (Has-Cmd "winget") {
        Write-Host "[deps] Installing Go via winget..."
        try {
            winget install --id GoLang.Go -e --accept-source-agreements --accept-package-agreements
        } catch {
            Write-Host "[deps] WARN: winget install failed: $_"
        }
    } else {
        Write-Host "[deps] Go not found and winget missing. Install Go 1.24+ manually."
    }
} else {
    Write-Host "[deps] Go already installed."
}

if (Has-Cmd "winget") {
    $packages = @(
        @{ id = "WireGuard.WireGuard"; required = $true; note = "WireGuard VPN support" },
        @{ id = "TorProject.TorBrowser"; required = $false; note = "Tor Browser (provides tor binaries)" },
        @{ id = "IDRIX.VeraCrypt"; required = $false; note = "Encrypted containers on Windows" },
        @{ id = "7zip.7zip"; required = $false; note = "Archive utility (optional)" }
    )

    foreach ($pkg in $packages) {
        if ($SkipOptional -and -not $pkg.required) {
            Write-Host "[deps] Skipping optional package $($pkg.id)."
            continue
        }

        Write-Host "[deps] Installing $($pkg.id) - $($pkg.note)"
        try {
            winget install --id $pkg.id -e --accept-source-agreements --accept-package-agreements
        } catch {
            Write-Host "[deps] WARN: winget install failed for $($pkg.id): $_"
        }
    }
} else {
    Write-Host "[deps] winget not found. Skipping Windows package installs."
}

if (Test-Path $ctfDir) {
    Write-Host "[deps] Downloading Go modules..."
    Push-Location $ctfDir
    try {
        go mod download
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[deps] WARN: $ctfDir not found"
}

Write-Host "[deps] Done."
