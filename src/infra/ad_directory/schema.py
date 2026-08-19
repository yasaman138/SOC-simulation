"""Active Directory Schema and Domain Object Models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UserAccountControl(int, Enum):
    NORMAL_ACCOUNT = 512
    DONT_EXPIRE_PASSWORD = 66048
    ACCOUNT_DISABLED = 514


class ADOrganizationalUnit(BaseModel):
    """AD Organizational Unit (OU) definition."""

    name: str
    dn: str
    description: str
    guid: str


class ADUser(BaseModel):
    """Active Directory User Account."""

    sAMAccountName: str
    userPrincipalName: str
    displayName: str
    distinguishedName: str
    mail: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    memberOf: List[str] = Field(default_factory=list)
    servicePrincipalNames: List[str] = Field(default_factory=list)
    userAccountControl: int = UserAccountControl.NORMAL_ACCOUNT.value
    password_hash: str = ""
    is_admin: bool = False
    admin_tier: Optional[int] = None  # Tier 0 (Domain Admin), Tier 1 (Server Admin), Tier 2 (Workstation)
    badPasswordCount: int = 0
    lastLogonTimestamp: Optional[datetime] = None


class ADGroup(BaseModel):
    """Active Directory Security Group."""

    sAMAccountName: str
    distinguishedName: str
    description: str
    groupScope: str = "Global"
    groupType: str = "Security"
    members: List[str] = Field(default_factory=list)  # list of sAMAccountNames
    is_privileged: bool = False


class ADComputer(BaseModel):
    """Active Directory Computer Object."""

    sAMAccountName: str
    distinguishedName: str
    dNSHostName: str
    operatingSystem: str
    ipAddress: str
    memberOf: List[str] = Field(default_factory=list)


class KerberosTicket(BaseModel):
    """Simulated Kerberos Ticket-Granting Service (TGS) ticket response."""

    ticket_id: str
    client_name: str
    service_principal_name: str
    realm: str
    encryption_type: str = "rc4-hmac"  # Kerberoastable default
    hash_material: str
    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
