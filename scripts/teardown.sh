#!/usr/bin/env bash
# ==============================================================================
# Enterprise Attack Detection & Response Lab - Teardown Script
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo "Tearing Down Enterprise Attack Detection & Response Lab Environment"
echo "======================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

# 1. Stop and remove Docker containers if docker compose is active
if command -v docker &> /dev/null; then
    if docker compose version &> /dev/null; then
        echo "[+] Attempting to stop Docker Compose services..."
        docker compose down -v --remove-orphans 2>/dev/null || true
    fi
fi

# 2. Clean temporary runtime artifacts safely
echo "[+] Cleaning temporary lab runtime files..."
rm -rf data/*.db logs/*.log run/*.pid 2>/dev/null || true

# 3. Clean Python bytecode and pytest cache
echo "[+] Cleaning python build caches..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
rm -rf .pytest_cache .coverage htmlcov 2>/dev/null || true

echo "======================================================================"
echo "[+] Enterprise Lab Teardown and Cleanup completed successfully."
echo "======================================================================"
