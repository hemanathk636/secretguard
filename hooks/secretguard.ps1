# SecretGuard PowerShell Integration Hook
# Add to your $PROFILE:
# . "path\to\secretguard.ps1"

function Invoke-SecretGuardCheck {
    param([string]$Line)
    
    if ([string]::IsNullOrWhiteSpace($Line) -or $Line.Length -lt 15) {
        return $true
    }

    $sanitized = secretguard sanitize "$Line" 2>$null
    if ($LASTEXITCODE -eq 1) {
        Write-Host "[secretguard] 🚨 Secret intercepted and masked!" -ForegroundColor Yellow
        return $false
    }
    return $true
}
