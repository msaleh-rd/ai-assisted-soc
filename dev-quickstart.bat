@echo off
REM Developer Quick Start Script for AI-Native SOC Platform
REM This script spins up only the infrastructure databases in Docker
REM and runs the Python applications locally using your existing .venv

echo.
echo ===========================================
echo AI-Native SOC Platform - Developer Setup
echo ===========================================
echo.

cd /d "%~dp0"

REM 1. Start only the infrastructure in Docker (skips building the heavy API/Worker images)
echo Starting infrastructure (Postgres, Neo4j, Redis, Temporal) with Docker Compose...
docker-compose up -d postgres neo4j redis temporal temporal-postgresql temporal-admin-tools temporal-ui

echo.
echo Waiting for infrastructure to be ready (15 seconds)...
timeout /t 15

REM 2. Start the local Temporal Worker in the background
echo Starting local Temporal Worker...
start "SOC Temporal Worker" cmd /c "set USE_TEMPORAL=true&& set TEMPORAL_HOST=localhost:7233&& .venv\Scripts\python.exe -m backend.services.temporal_worker"

REM 3. Start the local FastAPI backend
echo Starting local FastAPI API...
start "SOC API" cmd /c "set USE_TEMPORAL=true&& set TEMPORAL_HOST=localhost:7233&& set PYTHONIOENCODING=utf-8&& .venv\Scripts\uvicorn.exe backend.main:app --host 0.0.0.0 --port 8000"

echo.
echo [OK] All services are booting up!
echo.
echo The Temporal Worker and API have been launched in separate command prompt windows using your local .venv.
echo.
echo ===========================================
echo Next Steps:
echo ===========================================
echo 1. API Documentation: http://localhost:8000/docs
echo 2. Temporal UI:       http://localhost:8080
echo 3. SOC UI:            http://localhost:8000/ui
echo.
pause
