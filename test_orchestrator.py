import asyncio
from backend.services.orchestrator import OrchestratorAgent

async def main():
    agent = OrchestratorAgent()
    
    alert = {
        "id": "alert-123",
        "name": "Suspicious Login",
        "description": "Multiple failed logins followed by success",
        "source": "Active Directory",
        "timestamp": "2026-08-17T12:00:00Z"
    }
    
    async for event in agent.execute_stream("Investigate Suspicious Login", alert):
        print(event.strip())

if __name__ == "__main__":
    asyncio.run(main())
