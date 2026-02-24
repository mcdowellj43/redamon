#!/bin/bash
set -e

echo "[*] Starting RedAmon MCP container..."

# Ensure Metasploit database is running
echo "[*] Initializing Metasploit database..."
msfdb init 2>/dev/null || true

# Update Metasploit modules if enabled (default: true)
if [ "${MSF_AUTO_UPDATE:-true}" = "true" ]; then
    echo "[*] Updating Metasploit modules (this may take a minute)..."
    msfconsole -q -x "msfupdate; exit" 2>/dev/null || \
        apt-get update -qq && apt-get install -y -qq metasploit-framework 2>/dev/null || \
        echo "[!] Metasploit update failed, continuing with existing modules"
    echo "[*] Metasploit update complete"
else
    echo "[*] Skipping Metasploit update (MSF_AUTO_UPDATE=false)"
fi

# Update nuclei templates if enabled
if [ "${NUCLEI_AUTO_UPDATE:-true}" = "true" ]; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || echo "[!] Nuclei template update failed"
fi

echo "[*] Starting MCP servers..."
exec python3 run_servers.py "$@"