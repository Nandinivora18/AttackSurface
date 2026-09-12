#!/usr/bin/env pwsh
# SentinelScan — Start all services for local development
# Usage: .\scripts\dev.ps1

Write-Host "`n🛡  SentinelScan Dev Startup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor DarkCyan

# Check prerequisites
function Check-Command($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Host "❌  '$name' not found. Please install it first." -ForegroundColor Red
        exit 1
    }
    Write-Host "✅  $name found" -ForegroundColor Green
}

Write-Host "`nChecking prerequisites..." -ForegroundColor Yellow
Check-Command "docker"
Check-Command "node"
Check-Command "python"

# Start Docker services (Postgres + Redis)
Write-Host "`n🐳  Starting Docker services (Postgres + Redis)..." -ForegroundColor Cyan
docker compose -f docker/docker-compose.yml up postgres redis -d

Write-Host "⏳  Waiting for Postgres to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check .env
if (-not (Test-Path "backend\.env")) {
    Write-Host "`n⚠️  backend\.env not found — copying from .env.example" -ForegroundColor Yellow
    Copy-Item "backend\.env.example" "backend\.env"
    Write-Host "📝  Please update backend\.env with your settings" -ForegroundColor Yellow
}

# Start backend
Write-Host "`n🐍  Starting FastAPI backend on http://localhost:8000 ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", @"
    cd '$PWD\backend'
    if (-not (Test-Path '.venv')) {
        python -m venv .venv
        Write-Host 'Created virtual environment'
    }
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt -q
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"@

Start-Sleep -Seconds 3

# Start ARQ worker (required for executing passive scans)
$existingWorker = Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%run_worker.py%'" -ErrorAction SilentlyContinue
if (-not $existingWorker) {
    Write-Host "`n⚙️   Starting ARQ worker..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", @"
        cd '$PWD\backend'
        .\.venv\Scripts\Activate.ps1
        python run_worker.py
"@
} else {
    Write-Host "`n⚙️   ARQ worker already running" -ForegroundColor Green
}

Start-Sleep -Seconds 2

# Start frontend
Write-Host "⚛️   Starting Next.js frontend on http://localhost:3000 ..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", @"
    cd '$PWD\frontend'
    if (-not (Test-Path 'node_modules')) {
        npm install
    }
    npm run dev
"@

Write-Host "`n✨  All services starting!" -ForegroundColor Green
Write-Host "   Frontend : http://localhost:3000" -ForegroundColor White
Write-Host "   Backend  : http://localhost:8000" -ForegroundColor White
Write-Host "   Worker   : ARQ (run_worker.py)" -ForegroundColor White
Write-Host "   API Docs : http://localhost:8000/api/docs" -ForegroundColor White
Write-Host "   Postgres : localhost:5432" -ForegroundColor White
Write-Host "   Redis    : localhost:6379" -ForegroundColor White
Write-Host "`n💡  To stop: docker compose -f docker/docker-compose.yml down`n" -ForegroundColor DarkGray
