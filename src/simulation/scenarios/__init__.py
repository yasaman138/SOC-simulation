"""Attack Simulation & Benign Scenarios Catalog."""

from typing import List
from src.simulation.models import BaseScenario
from src.simulation.scenarios.benign import (
    BenignADDirectoryLookupScenario,
    BenignApplicationLogArchiveScenario,
    BenignEmployeeDirectorySearchScenario,
    BenignLinuxAdminSSHScenario,
    BenignNetworkPingToolScenario,
    BenignPortalLoginScenario,
    BenignSystemAdminCommandsScenario,
)
from src.simulation.scenarios.collection import (
    BOLADocumentHarvestingScenario,
    DataStagingAndArchiveScenario,
)
from src.simulation.scenarios.command_and_control import (
    C2BeaconingScenario,
    IngressToolTransferScenario,
    PowerShellDownloadCradleScenario,
)
from src.simulation.scenarios.credential_access import (
    BruteForceAuthScenario,
    KerberoastingScenario,
    LSASSDumpScenario,
    ShadowFileAccessScenario,
)
from src.simulation.scenarios.discovery import (
    ActiveDirectoryDiscoveryScenario,
    NetworkPortScanDiscoveryScenario,
    SystemInfoDiscoveryScenario,
)
from src.simulation.scenarios.execution import (
    EncodedPowerShellScenario,
    ReverseShellExecutionScenario,
    WebCommandInjectionScenario,
)
from src.simulation.scenarios.impact import (
    DataDestructionRansomwareScenario,
    ServiceTerminationScenario,
)
from src.simulation.scenarios.initial_access import (
    SQLInjectionInitialAccessScenario,
    UnauthorizedRootLogonScenario,
)
from src.simulation.scenarios.lateral_movement import (
    CrossSubnetSSHLateralScenario,
    CrossZoneDCRemoteLogonScenario,
    RemoteServicePsExecScenario,
    RemoteWinRMScenario,
)
from src.simulation.scenarios.persistence import (
    BackdoorAccountCreationScenario,
    LinuxCronPersistenceScenario,
    RegistryRunKeyPersistenceScenario,
)
from src.simulation.scenarios.privilege_escalation import (
    SUIDBinaryAbuseScenario,
    SudoersModificationScenario,
)


def get_all_scenarios() -> List[BaseScenario]:
    """Instantiate and return the complete suite of attack simulations and benign controls."""
    return [
        # 1. Initial Access
        SQLInjectionInitialAccessScenario(),
        UnauthorizedRootLogonScenario(),
        # 2. Execution
        WebCommandInjectionScenario(),
        ReverseShellExecutionScenario(),
        EncodedPowerShellScenario(),
        # 3. Persistence
        LinuxCronPersistenceScenario(),
        RegistryRunKeyPersistenceScenario(),
        BackdoorAccountCreationScenario(),
        # 4. Privilege Escalation
        SudoersModificationScenario(),
        SUIDBinaryAbuseScenario(),
        # 5. Credential Access
        KerberoastingScenario(),
        ShadowFileAccessScenario(),
        LSASSDumpScenario(),
        BruteForceAuthScenario(),
        # 6. Discovery
        ActiveDirectoryDiscoveryScenario(),
        NetworkPortScanDiscoveryScenario(),
        SystemInfoDiscoveryScenario(),
        # 7. Lateral Movement
        CrossSubnetSSHLateralScenario(),
        RemoteServicePsExecScenario(),
        RemoteWinRMScenario(),
        CrossZoneDCRemoteLogonScenario(),
        # 8. Command and Control
        IngressToolTransferScenario(),
        PowerShellDownloadCradleScenario(),
        C2BeaconingScenario(),
        # 9. Collection
        DataStagingAndArchiveScenario(),
        BOLADocumentHarvestingScenario(),
        # 10. Impact
        ServiceTerminationScenario(),
        DataDestructionRansomwareScenario(),
        # Benign Negative Controls (False Positive Validation)
        BenignPortalLoginScenario(),
        BenignLinuxAdminSSHScenario(),
        BenignNetworkPingToolScenario(),
        BenignEmployeeDirectorySearchScenario(),
        BenignSystemAdminCommandsScenario(),
        BenignADDirectoryLookupScenario(),
        BenignApplicationLogArchiveScenario(),
    ]
