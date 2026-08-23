# PatchForge AI - Automatic Prerequisites Installer for Windows
# Run this script in PowerShell (Run as Administrator recommended)

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " PatchForge AI: Installing Prerequisites via winget   " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# 1. Install Git
Write-Host "`n[1/3] Checking & Installing Git for Windows..." -ForegroundColor Yellow
winget install --id Git.Git -e --source winget --accept-source-agreements --accept-package-agreements --silent

# 2. Install Node.js LTS
Write-Host "`n[2/3] Checking & Installing Node.js LTS..." -ForegroundColor Yellow
winget install --id OpenJS.NodeJS.LTS -e --source winget --accept-source-agreements --accept-package-agreements --silent

# 3. Install Ollama
Write-Host "`n[3/3] Checking & Installing Ollama..." -ForegroundColor Yellow
winget install --id Ollama.Ollama -e --source winget --accept-source-agreements --accept-package-agreements --silent

Write-Host "`n======================================================" -ForegroundColor Green
Write-Host " Installations triggered! " -ForegroundColor Green
Write-Host " Please close and reopen your PowerShell/Terminal to refresh PATH." -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
