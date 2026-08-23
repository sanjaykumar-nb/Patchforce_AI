# PatchForge AI - Windows PowerShell Automation Manager
param (
    [Parameter(Position=0)]
    [string]$Command = "help"
)

function Show-Help {
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host " PatchForge AI: Automation Manager (PowerShell)        " -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "  .\manage.ps1 infra-up     - Start PostgreSQL & Redis in Docker" -ForegroundColor Yellow
    Write-Host "  .\manage.ps1 infra-down   - Stop background Docker services" -ForegroundColor Yellow
    Write-Host "  .\manage.ps1 infra-all    - Start all services (Postgres, Redis, Ollama)" -ForegroundColor Yellow
    Write-Host "  .\manage.ps1 verify       - Run environment verification script" -ForegroundColor Yellow
    Write-Host "  .\manage.ps1 test         - Run backend pytest test suite" -ForegroundColor Yellow
    Write-Host "  .\manage.ps1 clean        - Clean __pycache__ and temp files" -ForegroundColor Yellow
    Write-Host "======================================================" -ForegroundColor Cyan
}

switch ($Command.ToLower()) {
    "infra-up" {
        Write-Host "Starting PostgreSQL and Redis containers..." -ForegroundColor Green
        docker compose up -d postgres redis
    }
    "infra-down" {
        Write-Host "Stopping Docker containers..." -ForegroundColor Yellow
        docker compose down
    }
    "infra-all" {
        Write-Host "Starting all Docker Compose services..." -ForegroundColor Green
        docker compose up -d
    }
    "verify" {
        py scripts\verify_env.py
    }
    "clean" {
        Write-Host "Cleaning cache files..." -ForegroundColor Yellow
        Get-ChildItem -Path . -Include __pycache__, .pytest_cache -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Clean completed." -ForegroundColor Green
    }
    default {
        Show-Help
    }
}
