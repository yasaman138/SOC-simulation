"""Unit tests for AlertStore and Alert Models."""

from src.detection.models import (
    AffectedEntities,
    Alert,
    AlertQuery,
    AlertStatus,
    MitreAttackInfo,
    MitreTactic,
)
from src.detection.storage import AlertStore
from src.siem.models import EventSeverity


def test_alert_store_add_and_query():
    store = AlertStore()
    alert1 = Alert(
        rule_id="DET-AUTH-001",
        rule_name="Multiple Failed Logons",
        severity=EventSeverity.HIGH,
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            technique_id="T1110.001",
            technique_name="Password Guessing",
        ),
        title="Brute force detected",
        description="Multiple failed logins from 172.28.20.25",
        affected_entities=AffectedEntities(
            host="dc01", user="jdoe", ip="172.28.20.25"
        ),
    )
    alert2 = Alert(
        rule_id="DET-PS-001",
        rule_name="Encoded PowerShell",
        severity=EventSeverity.CRITICAL,
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.EXECUTION,
            technique_id="T1059.001",
            technique_name="PowerShell",
        ),
        title="Base64 Encoded PowerShell",
        description="powershell.exe -enc execution",
        affected_entities=AffectedEntities(
            host="srv01", user="sysadmin", process="powershell.exe"
        ),
    )

    id1 = store.add_alert(alert1)
    id2 = store.add_alert(alert2)
    assert store.count() == 2

    # Query by severity
    crit = store.query_alerts(AlertQuery(severity=EventSeverity.CRITICAL))
    assert len(crit) == 1
    assert crit[0].id == id2

    # Query by rule_id
    auth = store.query_alerts(AlertQuery(rule_id="DET-AUTH-001"))
    assert len(auth) == 1
    assert auth[0].id == id1

    # Query by user search
    search = store.query_alerts(AlertQuery(search="jdoe"))
    assert len(search) == 1
    assert search[0].rule_id == "DET-AUTH-001"

    # Status update
    updated = store.update_status(
        id1, AlertStatus.INVESTIGATING, note="SOC analyst reviewing logon logs"
    )
    assert updated is True
    retrieved = store.get_alert(id1)
    assert retrieved.status == AlertStatus.INVESTIGATING
    assert retrieved.context["status_note"] == "SOC analyst reviewing logon logs"

    # Stats
    stats = store.get_stats()
    assert stats["total_alerts"] == 2
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["by_tactic"]["Execution"] == 1
    assert stats["by_tactic"]["Credential Access"] == 1
    assert stats["by_status"]["investigating"] == 1

    # Clear
    store.clear()
    assert store.count() == 0
