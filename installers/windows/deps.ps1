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
