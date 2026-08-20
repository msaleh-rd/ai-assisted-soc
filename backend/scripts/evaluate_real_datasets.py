import os
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Tuple

from backend.services.orchestrator import OrchestratorAgent

CAM_LDS_DIR = r"D:\projects\sxsecurityinvestigator\data\logs\CAM-LDS-team-messy"
APT29_DIR = r"D:\projects\sxsecurityinvestigator\data\logs\APT29-Full_attack_chain"

def extract_cam_lds_alerts(max_alerts: int = 10) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Extract security alerts from CAM-LDS Wazuh alerts and ground truth.
    """
    wazuh_file = os.path.join(CAM_LDS_DIR, "security", "wazuh__alerts_alerts.json")
    ground_truth_file = os.path.join(CAM_LDS_DIR, "benchmark_ground_truth.json")
    
    gt = {}
    if os.path.exists(ground_truth_file):
        with open(ground_truth_file, "r", encoding="utf-8") as f:
            gt = json.load(f)
    
    extracted_alerts = []
    if os.path.exists(wazuh_file):
        with open(wazuh_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    raw = json.loads(line.strip())
                    rule = raw.get("rule", {})
                    level = int(rule.get("level", 0))
                    desc = rule.get("description", "")
                    full_log = raw.get("full_log", "")
                    
                    is_target = (
                        level >= 7 or 
                        any(art.lower() in full_log.lower() or art.lower() in desc.lower() for art in gt.get("artifacts", []))
                    )
                    
                    if is_target:
                        agent_info = raw.get("agent", {})
                        norm_alert = {
                            "alert_id": f"wazuh_{raw.get('id', 'unknown')}",
                            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
                            "severity": min(level, 5),
                            "severity_name": "Critical" if level >= 10 else "High" if level >= 7 else "Medium",
                            "computer_name": agent_info.get("name", "inetfw"),
                            "ip_address": agent_info.get("ip", "192.168.100.23"),
                            "user_name": "root" if "root" in full_log else "analyst",
                            "description": desc,
                            "raw_log": full_log or json.dumps(raw),
                            "source": "Wazuh SIEM",
                            "metadata": {
                                "rule_id": rule.get("id"),
                                "rule_groups": rule.get("groups", []),
                                "mitre": rule.get("mitre", {}).get("id", [])
                            }
                        }
                        extracted_alerts.append(norm_alert)
                        if len(extracted_alerts) >= max_alerts:
                            break
                except Exception:
                    pass
    return extracted_alerts, gt

def extract_apt29_alerts(max_alerts: int = 5) -> List[Dict[str, Any]]:
    """
    Extract security alerts from APT29 attack chain annotations.
    """
    ann_file = os.path.join(APT29_DIR, "annotation-attack.csv")
    alerts = []
    
    if os.path.exists(ann_file):
        with open(ann_file, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i == 0 or not line.strip():
                    continue
                parts = line.strip().split(";")
                if len(parts) >= 4:
                    step_id = parts[0]
                    host = parts[1]
                    proc_or_file = parts[2]
                    desc = parts[3]
                    
                    alert = {
                        "alert_id": f"apt29_step_{step_id}",
                        "timestamp": "2024-12-06T02:06:15Z",
                        "severity": 5 if "exploit" in desc.lower() or "exfiltrate" in desc.lower() else 4,
                        "severity_name": "Critical" if "exfiltrate" in desc.lower() else "High",
                        "computer_name": host,
                        "ip_address": "192.168.0.4" if host == "UserWorkstation" else "192.168.0.5",
                        "user_name": "vagrant" if host == "UserWorkstation" else "SYSTEM",
                        "file_name": proc_or_file,
                        "file_path": f"C:\\Users\\vagrant\\{proc_or_file}" if host == "UserWorkstation" else f"/tmp/{proc_or_file}",
                        "description": desc,
                        "source": "Sysmon / EDR"
                    }
                    alerts.append(alert)
                    if len(alerts) >= max_alerts:
                        break
    return alerts

async def test_dataset_investigation(name: str, alert: Dict[str, Any], ground_truth: Dict[str, Any] = None):
    print(f"\n=======================================================")
    print(f"TESTING AGENTIC INVESTIGATION ON: {name}")
    print(f"Alert ID: {alert['alert_id']} | Host: {alert['computer_name']} | Desc: {alert['description']}")
    print(f"=======================================================")
    
    agent = OrchestratorAgent()
    task = f"Investigate {alert['description']} on {alert['computer_name']}"
    
    final_synthesis = None
    reports = {}
    
    async for event in agent.execute_stream(task, alert, use_ai_planner=True):
        lines = event.strip().split("\n")
        if len(lines) >= 2 and lines[1].startswith("data: "):
            evt_type = lines[0].replace("event: ", "").strip()
            data = json.loads(lines[1][6:])
            
            if evt_type == "plan_created":
                print(f"  -> Dynamic Plan Created: {len(data.get('plan', []))} agents scheduled")
            elif evt_type == "agent_start":
                print(f"  -> Executing: {data.get('agent_name')}...")
            elif evt_type == "agent_complete":
                t_id = data.get("task_id")
                report = data.get("report", {})
                reports[t_id] = report
                print(f"     [OK] {report.get('agent_name')} completed (confidence: {report.get('confidence')})")
            elif evt_type == "run_complete":
                final_synthesis = data.get("synthesis", {})
                print(f"\n  === Final Autonomous Synthesis ===")
                print(f"  Verdict: {final_synthesis.get('verdict')}")
                print(f"  Executive Summary: {final_synthesis.get('executive_summary')}")
                print(f"  Confidence Score: {final_synthesis.get('confidence_score')}")
                print(f"  Key Findings: {final_synthesis.get('key_findings')}")
                print(f"  Recommended Actions: {len(final_synthesis.get('recommended_immediate_actions', []))} containment actions")

    # Evaluation against ground truth if provided
    if ground_truth:
        print("\n  --- Benchmark Ground-Truth Comparison ---")
        expected_hosts = ground_truth.get("hosts", [])
        expected_artifacts = ground_truth.get("artifacts", [])
        
        detected_entities = []
        for r in reports.values():
            for e in r.get("findings", {}).get("entities_identified", []):
                detected_entities.append(e.get("id"))
        
        print(f"  Ground Truth Target Hosts: {expected_hosts}")
        print(f"  Ground Truth Artifacts: {expected_artifacts}")
        print(f"  Detected Entities by Agents: {detected_entities}")

async def main():
    print("1. Extracting test alerts from CAM-LDS...")
    cam_alerts, cam_gt = extract_cam_lds_alerts(max_alerts=2)
    print(f"Extracted {len(cam_alerts)} alerts from CAM-LDS.")
    
    print("2. Extracting test alerts from APT29...")
    apt_alerts = extract_apt29_alerts(max_alerts=2)
    print(f"Extracted {len(apt_alerts)} alerts from APT29.")
    
    # Test 1: CAM-LDS Alert
    if cam_alerts:
        await test_dataset_investigation("CAM-LDS Dataset (Scenario 3)", cam_alerts[0], cam_gt)
    
    # Test 2: APT29 Alert
    if apt_alerts:
        await test_dataset_investigation("APT29 Dataset (Full Attack Chain)", apt_alerts[0])

if __name__ == "__main__":
    asyncio.run(main())
