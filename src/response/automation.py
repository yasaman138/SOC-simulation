"""Safe Response Automation & Containment Engine with Mandatory Auditability."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from src.core.logging import get_logger
from src.core.topology import EnterpriseLabTopology
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.response.models import (
    AuditLogEntry,
    IndicatorType,
    ResponseActionResult,
    ResponseActionType,
)
from src.response.storage import AuditStore
from src.siem.collector import SIEMCollector
from src.siem.models import (
    ECSEvent,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    HostInfo,
    UserInfo,
)
from src.simulation.safety import LabSafetyGuardrail

logger = get_logger("response.automation")


class ResponseAutomationEngine:
    """Enterprise Incident Response Automation & Containment Engine."""

    def __init__(
        self,
        audit_store: Optional[AuditStore] = None,
        siem_collector: Optional[SIEMCollector] = None,
        ad_server: Optional[ActiveDirectoryServer] = None,
        linux_service: Optional[LinuxServerService] = None,
        topology: Optional[EnterpriseLabTopology] = None,
    ):
        self.audit_store = audit_store or AuditStore()
        self.siem_collector = siem_collector
        self.ad_server = ad_server
        self.linux_service = linux_service
        self.topology = topology or EnterpriseLabTopology()

        # In-memory runtime state for automated containment & blocking
        self._disabled_users: Set[str] = set()
        self._isolated_endpoints: Set[str] = set()
        self._blocked_iocs: Dict[str, IndicatorType] = {}
        self._terminated_pids: Set[int] = set()

    def disable_user(
        self,
        username: str,
        actor: str = "soar_automation",
        reason: str = "Compromised account containment",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Disable a compromised user account in Active Directory and Linux systems."""
        clean_user = username.strip()

        # Permission / Policy Guardrail
        if clean_user.lower() in ("root", "krbtgt"):
            return self._record_audit(
                action=ResponseActionType.DISABLE_USER,
                actor=actor,
                target=clean_user,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Protected account '{clean_user}' cannot be automatically disabled."},
            )

        # Idempotency Check
        if clean_user.lower() in self._disabled_users:
            return self._record_audit(
                action=ResponseActionType.DISABLE_USER,
                actor=actor,
                target=clean_user,
                reason=reason,
                result=ResponseActionResult.ALREADY_APPLIED,
                details={"message": f"User '{clean_user}' is already disabled."},
            )

        # Apply action against Active Directory if available
        ad_disabled = False
        if self.ad_server and clean_user in self.ad_server.users:
            with self.ad_server._lock:
                self.ad_server.users[clean_user].userAccountControl = 514  # ACCOUNT_DISABLED
                ad_disabled = True

        self._disabled_users.add(clean_user.lower())

        return self._record_audit(
            action=ResponseActionType.DISABLE_USER,
            actor=actor,
            target=clean_user,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={
                "incident_id": incident_id,
                "ad_account_disabled": ad_disabled,
                "status": "ACCOUNT_DISABLED",
            },
            rollback_available=True,
            rollback_data={"username": clean_user},
        )

    def enable_user(
        self,
        username: str,
        actor: str = "soc_analyst",
        reason: str = "Remediation verified, restoring user access",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Re-enable a previously disabled user account."""
        clean_user = username.strip()

        if clean_user.lower() not in self._disabled_users:
            return self._record_audit(
                action=ResponseActionType.ENABLE_USER,
                actor=actor,
                target=clean_user,
                reason=reason,
                result=ResponseActionResult.NO_OP,
                details={"message": f"User '{clean_user}' is not disabled."},
            )

        self._disabled_users.discard(clean_user.lower())

        if self.ad_server and clean_user in self.ad_server.users:
            with self.ad_server._lock:
                self.ad_server.users[clean_user].userAccountControl = 512  # NORMAL_ACCOUNT

        return self._record_audit(
            action=ResponseActionType.ENABLE_USER,
            actor=actor,
            target=clean_user,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={"incident_id": incident_id, "status": "ACCOUNT_ENABLED"},
        )

    def isolate_endpoint(
        self,
        hostname_or_ip: str,
        actor: str = "soar_automation",
        reason: str = "Host containment during active incident",
        incident_id: Optional[str] = None,
        force_critical: bool = False,
    ) -> AuditLogEntry:
        """Isolate an infected endpoint from the lab network (allowing only management traffic)."""
        target = hostname_or_ip.strip()

        # Lab Boundary Guardrail
        try:
            LabSafetyGuardrail.assert_safe_target(target)
        except Exception as e:
            return self._record_audit(
                action=ResponseActionType.ISOLATE_ENDPOINT,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Target outside allowed lab boundary: {e}"},
            )

        # Protect Domain Controller / SIEM from accidental uncoordinated isolation
        if not force_critical and any(crit in target.lower() for crit in ["dc01", "172.28.20.10", "siem"]):
            return self._record_audit(
                action=ResponseActionType.ISOLATE_ENDPOINT,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": "Isolation of critical Domain Controller or SIEM requires explicit override (force_critical=True)."},
            )

        if target.lower() in self._isolated_endpoints:
            return self._record_audit(
                action=ResponseActionType.ISOLATE_ENDPOINT,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.ALREADY_APPLIED,
                details={"message": f"Endpoint '{target}' is already isolated."},
            )

        self._isolated_endpoints.add(target.lower())

        return self._record_audit(
            action=ResponseActionType.ISOLATE_ENDPOINT,
            actor=actor,
            target=target,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={
                "incident_id": incident_id,
                "isolation_policy": "DROP_ALL_EXCEPT_SOC_MANAGEMENT_PORT_22_443",
                "status": "HOST_ISOLATED",
            },
            rollback_available=True,
            rollback_data={"target": target},
        )

    def unisolate_endpoint(
        self,
        hostname_or_ip: str,
        actor: str = "soc_analyst",
        reason: str = "Host cleaned and verified, removing network isolation",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Remove network isolation and restore normal connectivity to an endpoint."""
        target = hostname_or_ip.strip()

        if target.lower() not in self._isolated_endpoints:
            return self._record_audit(
                action=ResponseActionType.UNISOLATE_ENDPOINT,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.NO_OP,
                details={"message": f"Endpoint '{target}' is not currently isolated."},
            )

        self._isolated_endpoints.discard(target.lower())

        return self._record_audit(
            action=ResponseActionType.UNISOLATE_ENDPOINT,
            actor=actor,
            target=target,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={"incident_id": incident_id, "status": "HOST_UNISOLATED"},
        )

    def block_ioc(
        self,
        ioc_type: IndicatorType,
        value: str,
        actor: str = "soar_automation",
        reason: str = "Perimeter IOC block for containment",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Block a malicious IP, domain, URL, or hash at perimeter firewalls/proxies."""
        val = value.strip()

        # Guardrail: Cannot block critical internal lab infrastructure
        if val in ("172.28.20.10", "172.28.20.20", "127.0.0.1", "localhost"):
            return self._record_audit(
                action=ResponseActionType.BLOCK_IOC,
                actor=actor,
                target=val,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Cannot block essential internal address {val}."},
            )

        if val in self._blocked_iocs:
            return self._record_audit(
                action=ResponseActionType.BLOCK_IOC,
                actor=actor,
                target=val,
                reason=reason,
                result=ResponseActionResult.ALREADY_APPLIED,
                details={"message": f"IOC '{val}' ({ioc_type.value}) is already blocked."},
            )

        self._blocked_iocs[val] = ioc_type

        return self._record_audit(
            action=ResponseActionType.BLOCK_IOC,
            actor=actor,
            target=val,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={
                "incident_id": incident_id,
                "ioc_type": ioc_type.value,
                "block_action": "PERIMETER_DROP / SINKHOLE",
                "status": "IOC_BLOCKED",
            },
            rollback_available=True,
            rollback_data={"ioc_type": ioc_type.value, "value": val},
        )

    def unblock_ioc(
        self,
        value: str,
        actor: str = "soc_analyst",
        reason: str = "IOC deemed benign or false positive",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Unblock a previously blocked IOC."""
        val = value.strip()

        if val not in self._blocked_iocs:
            return self._record_audit(
                action=ResponseActionType.UNBLOCK_IOC,
                actor=actor,
                target=val,
                reason=reason,
                result=ResponseActionResult.NO_OP,
                details={"message": f"IOC '{val}' is not currently blocked."},
            )

        ioc_type = self._blocked_iocs.pop(val)

        return self._record_audit(
            action=ResponseActionType.UNBLOCK_IOC,
            actor=actor,
            target=val,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={"incident_id": incident_id, "ioc_type": ioc_type.value, "status": "IOC_UNBLOCKED"},
        )

    def terminate_process(
        self,
        hostname: str,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        actor: str = "soar_automation",
        reason: str = "Malicious process execution containment",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Safely terminate a malicious or unauthorized process on a lab endpoint."""
        clean_host = hostname.strip()
        target = f"{clean_host}:{pid if pid is not None else process_name}"

        # Lab Boundary Guardrail
        try:
            LabSafetyGuardrail.assert_safe_target(clean_host)
        except Exception as e:
            return self._record_audit(
                action=ResponseActionType.TERMINATE_PROCESS,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Target outside allowed lab boundary: {e}"},
            )

        # Guardrails: Cannot terminate init system (PID <= 2) or vital daemons
        if pid is not None and (pid <= 2):
            return self._record_audit(
                action=ResponseActionType.TERMINATE_PROCESS,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Cannot terminate protected system PID {pid}."},
            )

        if process_name and process_name.lower() in ("systemd", "init", "launchd", "kthreadd"):
            return self._record_audit(
                action=ResponseActionType.TERMINATE_PROCESS,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Cannot terminate system initialization daemon '{process_name}'."},
            )

        if pid is not None:
            self._terminated_pids.add(pid)

        return self._record_audit(
            action=ResponseActionType.TERMINATE_PROCESS,
            actor=actor,
            target=target,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={
                "incident_id": incident_id,
                "hostname": clean_host,
                "pid": pid,
                "process_name": process_name,
                "signal": "SIGKILL (9)",
                "status": "PROCESS_TERMINATED",
            },
        )

    def collect_forensics(
        self,
        hostname: str,
        actor: str = "soar_automation",
        reason: str = "Forensic artifact preservation",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Gather digital forensic snapshot and system integrity metadata."""
        clean_host = hostname.strip()

        # Lab Boundary Guardrail
        try:
            LabSafetyGuardrail.assert_safe_target(clean_host)
        except Exception as e:
            return self._record_audit(
                action=ResponseActionType.COLLECT_FORENSICS,
                actor=actor,
                target=clean_host,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Target outside allowed lab boundary: {e}"},
            )

        forensic_bundle = {
            "hostname": clean_host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "collected_artifacts": [
                "/var/log/audit/audit.log",
                "/var/log/secure",
                "/var/log/syslog",
                "C:\\Windows\\System32\\Winevt\\Logs\\Security.evtx",
                "C:\\Windows\\System32\\Winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
            ],
            "process_tree_snapshot_pids": [1, 800, 1050, 14200],
            "active_tcp_connections": 12,
            "md5_fingerprints": {
                "memory_dump": "d41d8cd98f00b204e9800998ecf8427e",
                "log_archive": "7a3562e84d6b637996c0ca3458b9f36f",
            },
        }

        return self._record_audit(
            action=ResponseActionType.COLLECT_FORENSICS,
            actor=actor,
            target=clean_host,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={
                "incident_id": incident_id,
                "forensic_bundle": forensic_bundle,
                "status": "FORENSICS_COLLECTED",
            },
        )

    def revoke_user_sessions(
        self,
        username: str,
        actor: str = "soar_automation",
        reason: str = "Revoking active Kerberos and SSH tokens",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Revoke active tokens, Kerberos tickets, and sessions for a compromised account."""
        clean_user = username.strip()

        if not clean_user:
            return self._record_audit(
                action=ResponseActionType.REVOKE_SESSIONS,
                actor=actor,
                target=username,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": "Username cannot be empty."},
            )

        return self._record_audit(
            action=ResponseActionType.REVOKE_SESSIONS,
            actor=actor,
            target=clean_user,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={
                "incident_id": incident_id,
                "kerberos_tickets_purged": True,
                "active_ssh_sessions_killed": True,
                "status": "SESSIONS_REVOKED",
            },
        )

    def restore_backup(
        self,
        hostname: str,
        file_path: str,
        actor: str = "soc_analyst",
        reason: str = "Remediation: Restoring clean file from verified golden baseline",
        incident_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Restore an altered, shredded, or encrypted file from verified backup."""
        clean_host = hostname.strip()
        clean_path = file_path.strip()
        target = f"{clean_host}:{clean_path}"

        # Lab Boundary Guardrail
        try:
            LabSafetyGuardrail.assert_safe_target(clean_host)
        except Exception as e:
            return self._record_audit(
                action=ResponseActionType.RESTORE_BACKUP,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Target outside allowed lab boundary: {e}"},
            )

        # Directory Traversal & Critical Path Guardrail
        if ".." in clean_path or clean_path.startswith("/etc/shadow") or clean_path.startswith("/etc/sudoers"):
            return self._record_audit(
                action=ResponseActionType.RESTORE_BACKUP,
                actor=actor,
                target=target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Restoration path '{clean_path}' blocked by security policy (directory traversal or protected system path)."},
            )

        return self._record_audit(
            action=ResponseActionType.RESTORE_BACKUP,
            actor=actor,
            target=target,
            reason=reason,
            result=ResponseActionResult.SUCCESS,
            details={
                "incident_id": incident_id,
                "file_path": clean_path,
                "restored_from": "backup_repo_baseline",
                "status": "FILE_RESTORED",
            },
        )

    def rollback_action(
        self,
        audit_id: str,
        actor: str = "soc_analyst",
        reason: str = "Rollback response action",
    ) -> AuditLogEntry:
        """Perform verified rollback of a reversible response action."""
        matching = [e for e in self.audit_store._entries if e.id == audit_id]
        if not matching:
            return self._record_audit(
                action=ResponseActionType.ENABLE_USER,
                actor=actor,
                target=audit_id,
                reason=reason,
                result=ResponseActionResult.FAILED,
                details={"error": f"Audit ID {audit_id} not found for rollback."},
            )

        original_entry = matching[0]
        if not original_entry.rollback_available or not original_entry.rollback_data:
            return self._record_audit(
                action=original_entry.action,
                actor=actor,
                target=original_entry.target,
                reason=reason,
                result=ResponseActionResult.BLOCKED_BY_POLICY,
                details={"error": f"Action {original_entry.action.value} is not marked reversible."},
            )

        if original_entry.action == ResponseActionType.DISABLE_USER:
            return self.enable_user(
                username=original_entry.rollback_data["username"],
                actor=actor,
                reason=f"Rollback of audit entry {audit_id}: {reason}",
            )
        elif original_entry.action == ResponseActionType.ISOLATE_ENDPOINT:
            return self.unisolate_endpoint(
                hostname_or_ip=original_entry.rollback_data["target"],
                actor=actor,
                reason=f"Rollback of audit entry {audit_id}: {reason}",
            )
        elif original_entry.action == ResponseActionType.BLOCK_IOC:
            return self.unblock_ioc(
                value=original_entry.rollback_data["value"],
                actor=actor,
                reason=f"Rollback of audit entry {audit_id}: {reason}",
            )
        else:
            return self._record_audit(
                action=original_entry.action,
                actor=actor,
                target=original_entry.target,
                reason=reason,
                result=ResponseActionResult.FAILED,
                details={"error": "Unsupported rollback action type."},
            )

    def _record_audit(
        self,
        action: ResponseActionType,
        actor: str,
        target: str,
        reason: str,
        result: ResponseActionResult,
        details: Optional[Dict[str, Any]] = None,
        rollback_available: bool = False,
        rollback_data: Optional[Dict[str, Any]] = None,
    ) -> AuditLogEntry:
        """Create, store, and publish audit log entry."""
        entry = AuditLogEntry(
            action=action,
            actor=actor,
            target=target,
            reason=reason,
            result=result,
            details=details or {},
            rollback_available=rollback_available,
            rollback_data=rollback_data,
        )
        self.audit_store.log(entry)

        # Emit audit telemetry to SIEM collector if attached
        if self.siem_collector:
            ecs_event = ECSEvent(
                timestamp=datetime.now(timezone.utc),
                event=EventMetadata(
                    category=EventCategory.SYSTEM,
                    action="response.action.executed",
                    outcome=EventOutcome.SUCCESS
                    if result == ResponseActionResult.SUCCESS
                    else EventOutcome.FAILURE,
                    severity=EventSeverity.INFORMATIONAL
                    if result == ResponseActionResult.SUCCESS
                    else EventSeverity.HIGH,
                    dataset="enterprise.soar_audit",
                ),
                user=UserInfo(name=actor),
                message=f"SOAR Response Action [{action.value}] on target '{target}' by actor '{actor}': Result={result.value}. Reason: {reason}",
                custom=entry.to_dict(),
            )
            self.siem_collector.ingest_event(ecs_event)

        return entry
