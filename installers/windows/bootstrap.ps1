# Gargoyle bootstrap (Windows)
$ErrorActionPreference = "Stop"

function Ensure-Go {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        return
    }
    Write-Host "Go not found. Attempting to install via winget..."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget is not available. Install Go manually from https://go.dev/dl/" -ForegroundColor Yellow
        throw "Go is required"
    }
    winget install --id GoLang.Go -e --source winget
}

Ensure-Go

try {
    $root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
    $proj = Join-Path $root "os\ctfvault"
    $bin = Join-Path $proj "bin"

    New-Item -ItemType Directory -Force -Path $bin | Out-Null

    Push-Location $proj
    go mod download
    go build -o "$bin\gargoyle.exe" .\cmd\gargoyle
    go build -o "$bin\gargoylectl.exe" .\cmd\gargoylectl
    Pop-Location

    Write-Host "Build complete: $bin" -ForegroundColor Green
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    throw
}
