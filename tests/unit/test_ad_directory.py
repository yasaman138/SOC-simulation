"""Unit tests for Active Directory Domain Services."""

from src.siem.models import EventCategory, EventOutcome


def test_ad_seed_hierarchy(ad_server):
    assert len(ad_server.ous) >= 8
    assert len(ad_server.groups) >= 6
    assert len(ad_server.users) >= 7

    # Verify domain admins exist
    da_group = ad_server.get_group("Domain Admins")
    assert da_group is not None
    assert "da_johnson" in da_group.members
    assert "Administrator" in da_group.members


def test_ad_search_and_filter(ad_server):
    users_fin = ad_server.search_users(department="Finance")
    assert len(users_fin) == 1
    assert users_fin[0].sAMAccountName == "jdoe"

    spn_users = ad_server.list_spn_accounts()
    assert len(spn_users) >= 2
    spn_names = [u.sAMAccountName for u in spn_users]
    assert "svc_sql" in spn_names
    assert "svc_backup" in spn_names


def test_ad_authentication_success_and_telemetry(ad_server, event_store):
    initial_count = event_store.count()
    result = ad_server.authenticate_user("jdoe", "LabPassword123!")
    assert result is True
    assert event_store.count() == initial_count + 1

    events = event_store.query_events(
        type("Query", (), {"category": EventCategory.AUTHENTICATION, "action": None, "severity": None, "host_name": None, "source_ip": None, "user_name": "jdoe", "search": None, "limit": 10, "offset": 0})()
    )
    assert len(events) >= 1
    assert events[0].event.outcome == EventOutcome.SUCCESS
    assert events[0].event.action == "ad.logon.success"


def test_ad_authentication_failure_and_telemetry(ad_server, event_store):
    initial_count = event_store.count()
    result = ad_server.authenticate_user("jdoe", "BadPassword456!")
    assert result is False
    assert event_store.count() == initial_count + 1

    events = event_store.query_events(
        type("Query", (), {"category": EventCategory.AUTHENTICATION, "action": "failed", "severity": None, "host_name": None, "source_ip": None, "user_name": "jdoe", "search": None, "limit": 10, "offset": 0})()
    )
    assert len(events) >= 1
    assert events[0].event.outcome == EventOutcome.FAILURE


def test_kerberos_tgs_request(ad_server, event_store):
    ticket = ad_server.request_kerberos_tgs(
        client_user="jdoe",
        spn="MSSQLSvc/db01.corp.enterprise.local:1433",
    )
    assert ticket is not None
    assert ticket.service_principal_name == "MSSQLSvc/db01.corp.enterprise.local:1433"
    assert ticket.encryption_type == "rc4-hmac"
    assert "$krb5tgs$" in ticket.hash_material
