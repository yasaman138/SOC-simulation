"""Unit Tests for Safe Response Automation, Guardrails, Idempotency, and Audit Logging."""

import pytest
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.response.automation import ResponseAutomationEngine
from src.response.models import (
    IndicatorType,
    ResponseActionResult,
    ResponseActionType,
)
from src.response.storage import AuditStore
from src.siem.collector import SIEMCollector
from src.siem.storage import EventStore


@pytest.fixture
def response_fixture():
    event_store = EventStore()
    collector = SIEMCollector(store=event_store)
    audit_store = AuditStore()
    ad = ActiveDirectoryServer(siem_collector=collector)
    linux = LinuxServerService(siem_collector=collector)
    engine = ResponseAutomationEngine(
        audit_store=audit_store,
        siem_collector=collector,
        ad_server=ad,
        linux_service=linux,
    )
    return engine, audit_store, ad, linux, event_store


def test_disable_and_enable_user(response_fixture):
    engine, audit_store, ad, _, _ = response_fixture

    # Ensure user exists and enabled initially
    assert ad.get_user("jdoe").userAccountControl != 514

    # 1. Disable user
    res1 = engine.disable_user(
        username="jdoe",
        actor="soar_automation",
        reason="Incident containment test",
        incident_id="INC-001",
    )
    assert res1.result == ResponseActionResult.SUCCESS
    assert res1.action == ResponseActionType.DISABLE_USER
    assert res1.target == "jdoe"
    assert ad.get_user("jdoe").userAccountControl == 514
    assert "jdoe" in engine._disabled_users

    # 2. Idempotency check: re-disabling
    res2 = engine.disable_user(
        username="jdoe",
        actor="soar_automation",
        reason="Duplicate containment call",
    )
    assert res2.result == ResponseActionResult.ALREADY_APPLIED

    # 3. Enable user
    res3 = engine.enable_user(
        username="jdoe",
        actor="soc_analyst",
        reason="Recovery verified",
    )
    assert res3.result == ResponseActionResult.SUCCESS
    assert res3.action == ResponseActionType.ENABLE_USER
    assert ad.get_user("jdoe").userAccountControl == 512
    assert "jdoe" not in engine._disabled_users


def test_guardrails_protect_critical_accounts(response_fixture):
    engine, _, _, _, _ = response_fixture

    res_root = engine.disable_user(username="root")
    assert res_root.result == ResponseActionResult.BLOCKED_BY_POLICY
    assert "Protected account" in res_root.details["error"]

    res_krbtgt = engine.disable_user(username="krbtgt")
    assert res_krbtgt.result == ResponseActionResult.BLOCKED_BY_POLICY


def test_isolate_and_unisolate_endpoint(response_fixture):
    engine, _, _, _, _ = response_fixture
    target = "srv01.corp.enterprise.local"

    # 1. Isolate endpoint
    res1 = engine.isolate_endpoint(
        hostname_or_ip=target,
        actor="soar_automation",
        reason="Malware containment",
        incident_id="INC-002",
    )
    assert res1.result == ResponseActionResult.SUCCESS
    assert res1.action == ResponseActionType.ISOLATE_ENDPOINT
    assert target.lower() in engine._isolated_endpoints

    # 2. Idempotency check
    res2 = engine.isolate_endpoint(hostname_or_ip=target)
    assert res2.result == ResponseActionResult.ALREADY_APPLIED

    # 3. Unisolate endpoint
    res3 = engine.unisolate_endpoint(
        hostname_or_ip=target,
        actor="soc_analyst",
        reason="Remediation complete",
    )
    assert res3.result == ResponseActionResult.SUCCESS
    assert target.lower() not in engine._isolated_endpoints


def test_guardrails_protect_critical_infra_and_external_targets(response_fixture):
    engine, _, _, _, _ = response_fixture

    # Domain Controller cannot be isolated without force_critical=True
    res_dc = engine.isolate_endpoint(
        hostname_or_ip="dc01.corp.enterprise.local", force_critical=False
    )
    assert res_dc.result == ResponseActionResult.BLOCKED_BY_POLICY

    # External unauthorized targets are blocked
    res_ext = engine.isolate_endpoint(hostname_or_ip="external.attacker.com")
    assert res_ext.result == ResponseActionResult.BLOCKED_BY_POLICY


def test_block_and_unblock_ioc(response_fixture):
    engine, _, _, _, _ = response_fixture
    c2_ip = "198.51.100.42"

    # 1. Block IOC
    res1 = engine.block_ioc(
        ioc_type=IndicatorType.IP,
        value=c2_ip,
        actor="soar_automation",
        reason="C2 traffic containment",
    )
    assert res1.result == ResponseActionResult.SUCCESS
    assert c2_ip in engine._blocked_iocs

    # 2. Idempotency check
    res2 = engine.block_ioc(
        ioc_type=IndicatorType.IP,
        value=c2_ip,
    )
    assert res2.result == ResponseActionResult.ALREADY_APPLIED

    # 3. Internal essential IP protection guardrail
    res_guard = engine.block_ioc(
        ioc_type=IndicatorType.IP,
        value="172.28.20.10",
    )
    assert res_guard.result == ResponseActionResult.BLOCKED_BY_POLICY

    # 4. Unblock IOC
    res3 = engine.unblock_ioc(value=c2_ip)
    assert res3.result == ResponseActionResult.SUCCESS
    assert c2_ip not in engine._blocked_iocs


def test_terminate_process_and_guardrails(response_fixture):
    engine, _, _, _, _ = response_fixture

    # 1. Terminate malicious process
    res1 = engine.terminate_process(
        hostname="srv01.corp.enterprise.local",
        pid=14200,
        process_name="shred",
        reason="Destructive tool kill",
    )
    assert res1.result == ResponseActionResult.SUCCESS
    assert 14200 in engine._terminated_pids

    # 2. Guardrail: Cannot terminate PID 1 or systemd
    res_init = engine.terminate_process(
        hostname="srv01.corp.enterprise.local",
        pid=1,
    )
    assert res_init.result == ResponseActionResult.BLOCKED_BY_POLICY

    res_systemd = engine.terminate_process(
        hostname="srv01.corp.enterprise.local",
        process_name="systemd",
    )
    assert res_systemd.result == ResponseActionResult.BLOCKED_BY_POLICY


def test_forensics_collection_and_session_revocation(response_fixture):
    engine, _, _, _, _ = response_fixture

    # 1. Forensic metadata collection
    res_for = engine.collect_forensics(
        hostname="srv01.corp.enterprise.local",
        reason="Preserve volatile artifacts",
    )
    assert res_for.result == ResponseActionResult.SUCCESS
    assert "forensic_bundle" in res_for.details

    # 2. Revoke user sessions
    res_rev = engine.revoke_user_sessions(
        username="sysadmin",
        reason="Compromised credentials purge",
    )
    assert res_rev.result == ResponseActionResult.SUCCESS
    assert res_rev.details["kerberos_tickets_purged"] is True


def test_rollback_action(response_fixture):
    engine, audit_store, _, _, _ = response_fixture

    # 1. Disable user
    res_dis = engine.disable_user(username="jdoe")
    assert "jdoe" in engine._disabled_users

    # 2. Rollback the disable action using audit ID
    res_roll = engine.rollback_action(
        audit_id=res_dis.id,
        actor="soc_analyst",
        reason="Test rollback",
    )
    assert res_roll.result == ResponseActionResult.SUCCESS
    assert "jdoe" not in engine._disabled_users


def test_mandatory_audit_trail_and_siem_telemetry(response_fixture):
    engine, audit_store, _, _, event_store = response_fixture

    engine.disable_user(
        username="jdoe",
        actor="soar_agent",
        reason="Auditability test",
    )

    # Verify recorded in AuditStore
    assert audit_store.count() == 1
    entry = audit_store.list_entries()[0]
    assert entry.action == ResponseActionType.DISABLE_USER
    assert entry.actor == "soar_agent"
    assert entry.target == "jdoe"
    assert entry.reason == "Auditability test"
    assert entry.result == ResponseActionResult.SUCCESS

    # Verify SIEM received audit telemetry event
    events = event_store.query_events()
    audit_events = [e for e in events if e.event.dataset == "enterprise.soar_audit"]
    assert len(audit_events) == 1
    assert "SOAR Response Action" in audit_events[0].message
