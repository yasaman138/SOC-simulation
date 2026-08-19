"""Detection Rules Catalog and Registry Initializer."""

from typing import List
from src.detection.models import DetectionRule
from src.detection.rules.authentication import (
    BruteForceAuthenticationRule,
    SuspiciousRemoteLogonRule,
    UnauthorizedAccountLogonRule,
)
from src.detection.rules.credential_access import (
    KerberoastingDetectionRule,
    LinuxShadowFileAccessRule,
    LSASSDumpDetectionRule,
)
from src.detection.rules.lateral_movement import (
    CrossSubnetSSHLateralRule,
    RemoteServiceExecutionRule,
    RemoteWinRMExecutionRule,
)
from src.detection.rules.persistence import (
    BackdoorAccountCreationRule,
    LinuxCronPersistenceRule,
    RegistryRunKeyPersistenceRule,
)
from src.detection.rules.powershell import (
    EncodedPowerShellRule,
    PowerShellDownloadCradleRule,
    PowerShellPolicyBypassRule,
)
from src.detection.rules.privilege_escalation import (
    SQLInjectionPrivilegeEscalationRule,
    SUIDBinaryAbuseRule,
    SudoersModificationRule,
)
from src.detection.rules.process_execution import (
    LOLBinAbuseDetectionRule,
    ReverseShellDetectionRule,
    WebProcessSpawnRule,
)


def get_default_rules() -> List[DetectionRule]:
    """Instantiate and return the baseline enterprise detection rules suite."""
    return [
        # Authentication
        BruteForceAuthenticationRule(),
        UnauthorizedAccountLogonRule(),
        SuspiciousRemoteLogonRule(),
        # PowerShell
        EncodedPowerShellRule(),
        PowerShellDownloadCradleRule(),
        PowerShellPolicyBypassRule(),
        # Credential Access
        KerberoastingDetectionRule(),
        LinuxShadowFileAccessRule(),
        LSASSDumpDetectionRule(),
        # Process Execution
        ReverseShellDetectionRule(),
        LOLBinAbuseDetectionRule(),
        WebProcessSpawnRule(),
        # Privilege Escalation
        SudoersModificationRule(),
        SUIDBinaryAbuseRule(),
        SQLInjectionPrivilegeEscalationRule(),
        # Lateral Movement
        RemoteServiceExecutionRule(),
        CrossSubnetSSHLateralRule(),
        RemoteWinRMExecutionRule(),
        # Persistence
        LinuxCronPersistenceRule(),
        RegistryRunKeyPersistenceRule(),
        BackdoorAccountCreationRule(),
    ]
