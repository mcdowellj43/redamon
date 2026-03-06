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

# Start tunnels in background (both can run simultaneously — project setting controls which one the agent uses)
TUNNEL_STARTED=false

if [ -n "${NGROK_AUTHTOKEN:-}" ]; then
    echo "[*] Starting ngrok TCP tunnel on port 4444..."
    mkdir -p /root/.config/ngrok
    cat > /root/.config/ngrok/ngrok.yml <<NGROK_CFG
version: "3"
agent:
  authtoken: ${NGROK_AUTHTOKEN}
  web_addr: 0.0.0.0:4040
NGROK_CFG
    ngrok tcp 4444 --config /root/.config/ngrok/ngrok.yml --log=stdout --log-level=info > /var/log/ngrok.log 2>&1 &
    echo "[*] ngrok started (API at http://0.0.0.0:4040)"
    TUNNEL_STARTED=true
fi

if [ -n "${CHISEL_SERVER_URL:-}" ]; then
    echo "[*] Starting chisel reverse tunnel to ${CHISEL_SERVER_URL}..."
    CHISEL_AUTH_FLAG=""
    if [ -n "${CHISEL_AUTH:-}" ]; then
        CHISEL_AUTH_FLAG="--auth ${CHISEL_AUTH}"
    fi
    chisel client ${CHISEL_AUTH_FLAG} "${CHISEL_SERVER_URL}" \
        R:4444:localhost:4444 \
        R:8080:localhost:8080 \
        > /var/log/chisel.log 2>&1 &
    echo "[*] chisel started (tunneling ports 4444 + 8080 to VPS)"
    TUNNEL_STARTED=true
fi

if [ "${TUNNEL_STARTED}" = "false" ]; then
    echo "[*] Skipping tunnel (no NGROK_AUTHTOKEN or CHISEL_SERVER_URL set)"
fi

echo "[*] Starting MCP servers..."
exec python3 run_servers.py "$@"