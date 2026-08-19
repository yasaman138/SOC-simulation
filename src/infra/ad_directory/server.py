"""Active Directory Domain Controller and LDAP/Kerberos Service Emulator."""

import hashlib
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from src.core.logging import get_logger
from src.infra.ad_directory.schema import (
    ADComputer,
    ADGroup,
    ADOrganizationalUnit,
    ADUser,
    KerberosTicket,
)
from src.infra.ad_directory.seed_data import (
    DEFAULT_COMPUTERS,
    DEFAULT_GROUPS,
    DEFAULT_ORGANIZATIONAL_UNITS,
    DEFAULT_USERS,
)
from src.siem.collector import SIEMCollector
from src.siem.models import (
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    HostInfo,
    UserInfo,
)

logger = get_logger("infra.ad_directory")


class ActiveDirectoryServer:
    """Active Directory Domain Controller service emulator."""

    def __init__(
        self,
        domain_name: str = "CORP.ENTERPRISE.LOCAL",
        netbios_name: str = "CORP",
        dc_hostname: str = "dc01.corp.enterprise.local",
        dc_ip: str = "172.28.20.10",
        siem_collector: Optional[SIEMCollector] = None,
    ):
        self.domain_name = domain_name
        self.netbios_name = netbios_name
        self.dc_hostname = dc_hostname
        self.dc_ip = dc_ip
        self.siem_collector = siem_collector

        self._lock = threading.Lock()
        self.ous: Dict[str, ADOrganizationalUnit] = {}
        self.users: Dict[str, ADUser] = {}
        self.groups: Dict[str, ADGroup] = {}
        self.computers: Dict[str, ADComputer] = {}

        self._initialize_seed_data()

    def _initialize_seed_data(self):
        """Populate AD with baseline enterprise schema and objects."""
        for ou in DEFAULT_ORGANIZATIONAL_UNITS:
            self.ous[ou.dn] = ou.model_copy()

        for group in DEFAULT_GROUPS:
            self.groups[group.sAMAccountName] = group.model_copy()

        for user in DEFAULT_USERS:
            self.users[user.sAMAccountName] = user.model_copy()

        for computer in DEFAULT_COMPUTERS:
            self.computers[computer.sAMAccountName] = computer.model_copy()

    def search_users(
        self,
        sam_account_name: Optional[str] = None,
        department: Optional[str] = None,
        has_spn: Optional[bool] = None,
        is_admin: Optional[bool] = None,
    ) -> List[ADUser]:
        """Search users based on criteria (simulating LDAP directory search)."""
        with self._lock:
            results = list(self.users.values())

        if sam_account_name:
            # Case-insensitive search
            results = [
                u
                for u in results
                if sam_account_name.lower() in u.sAMAccountName.lower()
            ]

        if department:
            results = [
                u
                for u in results
                if u.department
                and department.lower() in u.department.lower()
            ]

        if has_spn is not None:
            results = [
                u
                for u in results
                if (len(u.servicePrincipalNames) > 0) == has_spn
            ]

        if is_admin is not None:
            results = [u for u in results if u.is_admin == is_admin]

        return results

    def get_user(self, sam_account_name: str) -> Optional[ADUser]:
        """Retrieve a specific user by sAMAccountName."""
        with self._lock:
            for username, user in self.users.items():
                if username.lower() == sam_account_name.lower():
                    return user.model_copy()
        return None

    def get_group(self, group_name: str) -> Optional[ADGroup]:
        """Retrieve a specific group by name."""
        with self._lock:
            for gname, group in self.groups.items():
                if gname.lower() == group_name.lower():
                    return group.model_copy()
        return None

    def list_spn_accounts(self) -> List[ADUser]:
        """List all user accounts configured with Service Principal Names (Kerberoastable targets)."""
        return self.search_users(has_spn=True)

    def authenticate_user(
        self,
        username: str,
        password: str,
        source_ip: str = "172.28.20.25",
        workstation_name: str = "WKSTN-WIN10",
    ) -> bool:
        """Authenticate user credentials and emit Windows EventLog security telemetry."""
        user = self.get_user(username)

        if not user:
            # Event ID 4625: An account failed to log on (Unknown User)
            self._emit_auth_telemetry(
                event_id=4625,
                action="ad.logon.failed",
                outcome=EventOutcome.FAILURE,
                severity=EventSeverity.MEDIUM,
                username=username,
                source_ip=source_ip,
                workstation_name=workstation_name,
                message=f"Logon failure for user '{username}': Unknown user name or bad password.",
            )
            return False

        # Check password hash (In lab, passwords match demo format)
        is_valid = len(password) > 0 and (
            password in user.password_hash or password == "LabPassword123!"
        )

        if is_valid:
            # Event ID 4624: An account was successfully logged on
            with self._lock:
                actual_user = self.users[user.sAMAccountName]
                actual_user.lastLogonTimestamp = datetime.now(timezone.utc)
                actual_user.badPasswordCount = 0

            self._emit_auth_telemetry(
                event_id=4624,
                action="ad.logon.success",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.INFORMATIONAL,
                username=user.sAMAccountName,
                source_ip=source_ip,
                workstation_name=workstation_name,
                message=f"Successful logon for user '{user.sAMAccountName}' ({user.displayName}).",
            )
            return True
        else:
            # Event ID 4625: Bad password
            with self._lock:
                actual_user = self.users[user.sAMAccountName]
                actual_user.badPasswordCount += 1

            self._emit_auth_telemetry(
                event_id=4625,
                action="ad.logon.failed",
                outcome=EventOutcome.FAILURE,
                severity=EventSeverity.MEDIUM,
                username=user.sAMAccountName,
                source_ip=source_ip,
                workstation_name=workstation_name,
                message=f"Logon failure for user '{user.sAMAccountName}': Bad password.",
            )
            return False

    def request_kerberos_tgs(
        self,
        client_user: str,
        spn: str,
        source_ip: str = "172.28.20.25",
    ) -> Optional[KerberosTicket]:
        """Simulate Kerberos TGS-REQ / TGS-REP service ticket issuance."""
        target_account: Optional[ADUser] = None
        for u in self.users.values():
            if spn in u.servicePrincipalNames:
                target_account = u
                break

        if not target_account:
            logger.warning(
                f"Kerberos TGS request for non-existent SPN: {spn}"
            )
            return None

        ticket_id = f"TGS-{uuid4().hex[:8].upper()}"
        # Generate simulated RC4/AES hash string for Kerberoasting detection
        hash_seed = f"{target_account.sAMAccountName}:{spn}:{self.domain_name}"
        simulated_hash = (
            f"$krb5tgs$23$*{target_account.sAMAccountName}*${self.domain_name}*${spn}*"
            + hashlib.sha256(hash_seed.encode()).hexdigest()
        )

        ticket = KerberosTicket(
            ticket_id=ticket_id,
            client_name=client_user,
            service_principal_name=spn,
            realm=self.domain_name,
            encryption_type="rc4-hmac",
            hash_material=simulated_hash,
        )

        # Event ID 4769: A Kerberos service ticket was requested
        self._emit_auth_telemetry(
            event_id=4769,
            action="ad.kerberos.tgs_request",
            outcome=EventOutcome.SUCCESS,
            severity=EventSeverity.LOW,
            username=client_user,
            source_ip=source_ip,
            workstation_name="WKSTN-WIN10",
            message=f"Kerberos TGS ticket requested by '{client_user}' for SPN '{spn}' (Service User: {target_account.sAMAccountName}).",
            custom_data={
                "spn": spn,
                "service_account": target_account.sAMAccountName,
                "encryption_type": "rc4-hmac",
                "ticket_id": ticket_id,
            },
        )

        return ticket

    def _emit_auth_telemetry(
        self,
        event_id: int,
        action: str,
        outcome: EventOutcome,
        severity: EventSeverity,
        username: str,
        source_ip: str,
        workstation_name: str,
        message: str,
        custom_data: Optional[Dict[str, Any]] = None,
    ):
        """Send Windows Security Event to SIEM collector."""
        if not self.siem_collector:
            return

        payload_custom = {
            "windows": {
                "event_id": event_id,
                "channel": "Security",
                "provider_name": "Microsoft-Windows-Security-Auditing",
            },
            "workstation": workstation_name,
        }
        if custom_data:
            payload_custom.update(custom_data)

        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.DIRECTORY_SERVICE
                if event_id in (4768, 4769)
                else EventCategory.AUTHENTICATION,
                action=action,
                outcome=outcome,
                severity=severity,
                dataset="windows.security_auditing",
            ),
            host=HostInfo(
                name=self.dc_hostname,
                ip=self.dc_ip,
                os="Windows Server 2022 Datacenter",
            ),
            source=EndpointInfo(ip=source_ip),
            destination=EndpointInfo(ip=self.dc_ip, port=88),
            user=UserInfo(
                name=username,
                domain=self.netbios_name,
            ),
            message=message,
            custom=payload_custom,
        )
        self.siem_collector.ingest_event(event)
