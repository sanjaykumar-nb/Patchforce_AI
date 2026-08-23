# PatchForge AI - Phase 0 Environment Verification (PowerShell Wrapper)
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " PatchForge AI: Launching Environment Verification... " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

$pythonCmd = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
}

if ($pythonCmd) {
    $scriptPath = Join-Path $PSScriptRoot "verify_env.py"
    Invoke-Expression "$pythonCmd `"$scriptPath`""
} else {
    Write-Host "`n[FAIL] Python 3.10+ runtime was not detected in PATH or Python Launcher (py)." -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://www.python.org/downloads/ and ensure 'Add Python to PATH' is checked.`n" -ForegroundColor Yellow
}
