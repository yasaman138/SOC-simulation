"""Unit tests for Linux Server Infrastructure."""

from src.siem.models import EventCategory, EventOutcome


def test_ssh_login_success(linux_service, event_store):
    initial_count = event_store.count()
    result = linux_service.simulate_ssh_login("sysadmin", password="LinuxAdminLab2026!")
    assert result is True
    assert event_store.count() >= initial_count + 1


def test_ssh_root_login_denied_by_policy(linux_service):
    result = linux_service.simulate_ssh_login("root", password="anypassword")
    assert result is False


def test_command_execution_auditd_logging(linux_service, event_store):
    initial_count = event_store.count()
    res = linux_service.simulate_command_execution("sysadmin", "cat /etc/passwd", is_sudo=True)
    assert res["logged"] is True
    assert res["suspicious"] is True
    assert event_store.count() >= initial_count + 1
