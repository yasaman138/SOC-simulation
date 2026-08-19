#!/usr/bin/env bash
# ==============================================================================
# Enterprise Attack Detection & Response Lab - Bootstrap Script
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo "Initializing Enterprise Attack Detection & Response Lab (Phase 1)"
echo "======================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

# 1. Verify Python version
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed or not in PATH."
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Detected Python ${PY_VER}"

# 2. Check for .env.example
if [ ! -f ".env.example" ]; then
    echo "[-] Error: .env.example not found!"
    exit 1
fi
echo "[+] Found .env.example configuration template"

# 3. Create required runtime directories
mkdir -p data logs run
echo "[+] Verified runtime data and logging directories"

# 4. Check dependencies
echo "[+] Checking required Python packages..."
python3 -c "import fastapi, uvicorn, pydantic, sqlalchemy, httpx, pytest; print('    All core dependencies available')" || {
    echo "[-] Warning: Some dependencies may be missing. Run: pip install -r requirements.txt"
}

# 5. Validate topology and seed configuration
echo "[+] Validating baseline network topology and Active Directory seed data..."
python3 -c "
from src.core.config import settings
from src.core.topology import EnterpriseLabTopology
from src.infra.ad_directory.server import ActiveDirectoryServer

settings.validate_networks()
topo = EnterpriseLabTopology()
errors = topo.validate_node_ip_allocations()
if errors:
    raise ValueError(f'Topology errors: {errors}')
ad = ActiveDirectoryServer()
assert len(ad.users) >= 7, 'AD user count invalid'
assert len(ad.groups) >= 6, 'AD group count invalid'
print('    Topology and Active Directory structure validated successfully')
"

echo "======================================================================"
echo "[+] Enterprise Lab Bootstrap completed successfully!"
echo "======================================================================"
