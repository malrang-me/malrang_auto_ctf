#!/bin/bash
# setup_ghidra.sh — Install Ghidra headless on WSL
# Usage: wsl bash tools/setup_ghidra.sh

set -e

GHIDRA_VERSION="12.0.4"
GHIDRA_DATE="20260303"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
INSTALL_DIR="/opt/ghidra"

echo "[setup] Checking Java..."
if ! command -v java &>/dev/null; then
    echo "[setup] Installing JDK 21..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq openjdk-21-jdk-headless wget unzip curl
fi
java --version 2>&1 | head -1

echo "[setup] Downloading Ghidra ${GHIDRA_VERSION}..."
cd ~
if [ ! -f "ghidra.zip" ]; then
    curl -L -# -o ghidra.zip "${GHIDRA_URL}"
fi

echo "[setup] Extracting..."
sudo rm -rf "${INSTALL_DIR}"
sudo unzip -q ~/ghidra.zip -d /opt/
sudo mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC "${INSTALL_DIR}"

echo "[setup] Setting permissions..."
sudo chmod +x "${INSTALL_DIR}/support/analyzeHeadless"

# Add to PATH
if ! grep -q "GHIDRA_HOME" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Ghidra headless" >> ~/.bashrc
    echo "export GHIDRA_HOME=${INSTALL_DIR}" >> ~/.bashrc
    echo 'export PATH="$PATH:${GHIDRA_HOME}/support"' >> ~/.bashrc
fi

echo "[setup] Verifying..."
"${INSTALL_DIR}/support/analyzeHeadless" --help 2>&1 | head -3

echo ""
echo "============================="
echo "  Ghidra ${GHIDRA_VERSION} installed!"
echo "  GHIDRA_HOME=${INSTALL_DIR}"
echo "  analyzeHeadless: ${INSTALL_DIR}/support/analyzeHeadless"
echo "============================="
echo ""
echo "Test: wsl python3 tools/ghidra_decompile.py <binary> --func main --stdout"
