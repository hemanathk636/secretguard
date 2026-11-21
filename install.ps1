# SecretGuard 1-Line Universal Installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/hemanathk636/secretguard/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "hemanathk636/secretguard"
$InstallDir = Join-Path $HOME ".secretguard\bin"
$ExePath = Join-Path $InstallDir "secretguard.exe"

Write-Host "🛡️  Installing SecretGuard for Windows..." -ForegroundColor Cyan

# Ensure install directory exists
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Determine release tag
$Tag = "v0.3.11"
try {
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -TimeoutSec 5
    if ($Release.tag_name) {
        $Tag = $Release.tag_name
    }
} catch {
    # Fallback to current tag if rate-limited
}

$ZipUrl = "https://github.com/$Repo/releases/download/$Tag/secretguard-x86_64-pc-windows-msvc.zip"
$TempZip = Join-Path $env:TEMP "secretguard-$Tag.zip"
$TempExtract = Join-Path $env:TEMP "secretguard_extract_$((Get-Random))"

Write-Host "📦 Downloading SecretGuard ($Tag)..." -ForegroundColor Gray
try {
    Invoke-WebRequest -Uri $ZipUrl -OutFile $TempZip -UseBasicParsing
    Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force
    
    # Locate binary in extracted folder
    $ExtractedBin = Get-ChildItem -Path $TempExtract -Filter "secretguard.exe" -Recurse | Select-Object -First 1
    if ($ExtractedBin) {
        Copy-Item -Path $ExtractedBin.FullName -Destination $ExePath -Force
    } else {
        throw "Binary secretguard.exe not found in archive"
    }
} catch {
    Write-Host "⚠️  Direct binary download failed ($($_.Exception.Message)). Falling back to Cargo install..." -ForegroundColor Yellow
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        cargo install secretguard
    } else {
        Write-Error "Could not install SecretGuard. Please install Rust & Cargo, or manually download from: https://github.com/$Repo/releases"
        return
    }
} finally {
    if (Test-Path $TempZip) { Remove-Item -Path $TempZip -Force -ErrorAction SilentlyContinue }
    if (Test-Path $TempExtract) { Remove-Item -Path $TempExtract -Recurse -Force -ErrorAction SilentlyContinue }
}

# Ensure ~/.secretguard/bin is in User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "🔧 Adding $InstallDir to User PATH..." -ForegroundColor Gray
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:PATH = "$env:PATH;$InstallDir"
}

Write-Host "✅ SecretGuard ($Tag) installed successfully!" -ForegroundColor Green
Write-Host "📁 Location: $ExePath" -ForegroundColor DarkGray

try {
    & "$ExePath" --help | Select-Object -First 3 | Out-Null
    Write-Host "`n🚀 Quick Start:" -ForegroundColor Cyan
    Write-Host "   secretguard hook pwsh        # Install PowerShell pre-exec secret hook"
    Write-Host "   secretguard scan .           # Scan current project for leaked keys"
    Write-Host "   secretguard doctor           # Verify engine latency & health"
} catch {}
