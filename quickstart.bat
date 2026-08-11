@echo off
REM Quick Start Script for AI-Native SOC Platform Phase 1 (Windows)

echo.
echo ===========================================
echo AI-Native SOC Platform - Phase 1 Setup
echo ===========================================
echo.

REM Check for Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not installed. Please install Docker to continue.
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker Compose is not installed. Please install Docker Compose to continue.
    exit /b 1
)

echo [OK] Docker and Docker Compose are installed
echo.

REM Go to project directory
cd /d "%~dp0"
echo Project directory: %cd%
echo.

REM Build and start services
echo Starting services with Docker Compose...
docker-compose down -v 2>nul
docker-compose up -d

REM Wait for services
echo Waiting for services to be ready...
timeout /t 30

REM Check API health
echo Checking API health...
curl -s http://localhost:8000/health >nul
if errorlevel 1 (
    echo WARNING: API service might not be ready yet. Trying again in 10 seconds...
    timeout /t 10
)

echo.
echo [OK] All services are running!
echo.
echo ===========================================
echo Next Steps:
echo ===========================================
echo.
echo 1. API Documentation (Interactive Docs):
echo    http://localhost:8000/docs
echo.
echo 2. Test Alert Ingestion:
echo    curl -X POST "http://localhost:8000/api/v1/alerts/ingest" ^
echo      -H "Content-Type: application/json" ^
echo      -d "{\"source\": \"crowdstrike\", \"raw_alert\": {...}}"
echo.
echo 3. View Service Stats:
echo    curl http://localhost:8000/api/v1/alerts/stats
echo.
echo 4. PostgreSQL Connection:
echo    docker-compose exec postgres psql -U soc_user -d soc_platform
echo.
echo 5. Neo4j Browser:
echo    http://localhost:7474 (user: neo4j, password: soc_password)
echo.
echo 6. View Logs:
echo    docker-compose logs -f api
echo.
echo 7. Run Tests:
echo    pip install -r requirements.txt
echo    pytest backend/tests/ -v
echo.
echo 8. Stop Services:
echo    docker-compose down
echo.
echo For more details, see GETTING_STARTED.md
echo.
