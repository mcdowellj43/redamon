"""
RedAmon - Port Scanner Module

Fast, lightweight port scanning.
Runs via Docker for consistent environment and no installation required.

Features:
- SYN and CONNECT scan modes
- Service detection
- CDN/WAF detection
- Passive mode via Shodan InternetDB
- JSON output with structured results
"""

import json
import subprocess
import shutil
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import IANA service lookup (15,000+ services from official registry)
from helpers.iana_services import get_service_name_friendly as get_service_name

# Settings are passed from main.py to avoid multiple database queries


# =============================================================================
# Docker Helper Functions
# =============================================================================

def is_docker_installed() -> bool:
    """Check if Docker is installed."""
    return shutil.which("docker") is not None


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        # Most basic check - if docker --version works, Docker is available
        # The actual container execution will fail/succeed on its own
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def pull_docker_image(docker_image: str, tool_name: str) -> bool:
    """Pull a Docker image if not present."""
    print(f"    [*] Checking {tool_name} Docker image: {docker_image}")

    # Check if image exists
    result = subprocess.run(
        ["docker", "images", "-q", docker_image],
        capture_output=True,
        text=True
    )

    if result.stdout.strip():
        print(f"    [✓] Image already available")
        return True

    print(f"    [*] Pulling image (this may take a moment)...")
    result = subprocess.run(
        ["docker", "pull", docker_image],
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode == 0:
        print(f"    [✓] Image pulled successfully")
        return True
    else:
        print(f"    [!] Failed to pull image: {result.stderr[:200]}")
        return False


def is_tor_running() -> bool:
    """Check if Tor SOCKS proxy is available."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False


# =============================================================================
# Target Extraction
# =============================================================================

def extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract IPs and hostnames from recon data.

    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    unique_ips = set()
    unique_hostnames = set()
    ip_to_hostnames = {}

    dns_data = recon_data.get("dns", {})

    # Extract from root domain
    domain_dns = dns_data.get("domain", {})
    domain_name = recon_data.get("domain", "")

    if domain_name:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])

        if ipv4_list or ipv6_list:
            unique_hostnames.add(domain_name)
            for ip in ipv4_list + ipv6_list:
                unique_ips.add(ip)
                if ip not in ip_to_hostnames:
                    ip_to_hostnames[ip] = []
                if domain_name not in ip_to_hostnames[ip]:
                    ip_to_hostnames[ip].append(domain_name)

    # Extract from subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, sub_data in subdomains_dns.items():
        if not sub_data.get("has_records", False):
            continue

        sub_ips = sub_data.get("ips", {})
        ipv4_list = sub_ips.get("ipv4", [])
        ipv6_list = sub_ips.get("ipv6", [])

        if ipv4_list or ipv6_list:
            unique_hostnames.add(subdomain)
            for ip in ipv4_list + ipv6_list:
                unique_ips.add(ip)
                if ip not in ip_to_hostnames:
                    ip_to_hostnames[ip] = []
                if subdomain not in ip_to_hostnames[ip]:
                    ip_to_hostnames[ip].append(subdomain)

    return unique_ips, unique_hostnames, ip_to_hostnames


# =============================================================================
# Naabu Command Builder
# =============================================================================

def get_host_path(container_path: str) -> str:
    """
    Convert container path to host path for Docker-in-Docker volume mounts.

    When running inside a container with mounted volumes, sibling containers
    need host paths, not container paths. This function translates paths
    using the HOST_RECON_OUTPUT_PATH environment variable.

    The recon container mounts: ./output:/app/recon/output
    So /app/recon/output/* inside the container maps to <host>/recon/output/* on host.

    /tmp/redamon is mounted to the same path inside and outside, so no translation needed.
    """
    # /tmp/redamon paths are the same inside and outside the container
    if container_path.startswith("/tmp/redamon"):
        return container_path

    host_output_path = os.environ.get("HOST_RECON_OUTPUT_PATH", "")
    container_output_path = "/app/recon/output"

    if host_output_path and container_path.startswith(container_output_path):
        # Replace container path with host path
        return container_path.replace(container_output_path, host_output_path, 1)

    # If not in container or path doesn't match, return as-is
    return container_path


def build_naabu_command(targets_file: str, output_file: str, settings: dict, use_proxy: bool = False) -> List[str]:
    """
    Build the Docker command for running Naabu.

    Args:
        targets_file: Path to file containing targets (one per line)
        output_file: Path for JSON output
        settings: Settings dictionary from main.py
        use_proxy: Whether to use Tor proxy

    Returns:
        List of command arguments
    """
    # Extract settings from passed dict
    NAABU_DOCKER_IMAGE = settings.get('NAABU_DOCKER_IMAGE', 'projectdiscovery/naabu:latest')
    NAABU_TOP_PORTS = settings.get('NAABU_TOP_PORTS', '1000')
    NAABU_CUSTOM_PORTS = settings.get('NAABU_CUSTOM_PORTS', '')
    NAABU_RATE_LIMIT = settings.get('NAABU_RATE_LIMIT', 1000)
    NAABU_THREADS = settings.get('NAABU_THREADS', 25)
    NAABU_TIMEOUT = settings.get('NAABU_TIMEOUT', 10000)
    NAABU_RETRIES = settings.get('NAABU_RETRIES', 1)
    NAABU_SCAN_TYPE = settings.get('NAABU_SCAN_TYPE', 's')
    NAABU_EXCLUDE_CDN = settings.get('NAABU_EXCLUDE_CDN', False)
    NAABU_DISPLAY_CDN = settings.get('NAABU_DISPLAY_CDN', True)
    NAABU_SKIP_HOST_DISCOVERY = settings.get('NAABU_SKIP_HOST_DISCOVERY', True)
    NAABU_VERIFY_PORTS = settings.get('NAABU_VERIFY_PORTS', True)
    NAABU_PASSIVE_MODE = settings.get('NAABU_PASSIVE_MODE', False)

    # Convert container paths to host paths for sibling container volume mounts
    targets_host_path = get_host_path(str(Path(targets_file).parent))
    output_host_path = get_host_path(str(Path(output_file).parent))

    targets_filename = Path(targets_file).name
    output_filename = Path(output_file).name

    # Build Docker command
    # Note: Naabu requires --net=host for proper packet handling
    cmd = [
        "docker", "run", "--rm",
        "--net=host",  # Required for SYN scans
        "-v", f"{targets_host_path}:/targets:ro",
        "-v", f"{output_host_path}:/output",
    ]

    # Add image
    cmd.append(NAABU_DOCKER_IMAGE)

    # Input/Output
    cmd.extend(["-list", f"/targets/{targets_filename}"])
    cmd.extend(["-o", f"/output/{output_filename}"])
    cmd.append("-json")
    cmd.append("-silent")

    # Port configuration
    if NAABU_CUSTOM_PORTS:
        cmd.extend(["-p", NAABU_CUSTOM_PORTS])
    elif NAABU_TOP_PORTS:
        cmd.extend(["-top-ports", str(NAABU_TOP_PORTS)])

    # Scan type
    cmd.extend(["-scan-type", NAABU_SCAN_TYPE])

    # Performance settings
    cmd.extend(["-rate", str(NAABU_RATE_LIMIT)])
    cmd.extend(["-c", str(NAABU_THREADS)])
    cmd.extend(["-timeout", str(NAABU_TIMEOUT)])
    cmd.extend(["-retries", str(NAABU_RETRIES)])

    # Feature flags
    if NAABU_EXCLUDE_CDN:
        cmd.append("-exclude-cdn")

    if NAABU_DISPLAY_CDN:
        cmd.append("-cdn")

    if NAABU_SKIP_HOST_DISCOVERY:
        cmd.append("-Pn")

    if NAABU_VERIFY_PORTS:
        cmd.append("-verify")

    if NAABU_PASSIVE_MODE:
        cmd.append("-passive")

    # Proxy support (naabu expects just ip:port for socks5 proxy)
    if use_proxy:
        cmd.extend(["-proxy", "127.0.0.1:9050"])

    return cmd


# =============================================================================
# Nmap Command Builder
# =============================================================================

def build_nmap_command(targets_file: str, output_file: str, settings: dict, use_proxy: bool = False) -> List[str]:
    """
    Build the Docker command for running Nmap.

    Args:
        targets_file: Path to file containing targets (one per line)
        output_file: Path for XML output
        settings: Settings dictionary from main.py
        use_proxy: Whether to use Tor proxy

    Returns:
        List of command arguments
    """
    # Extract settings from passed dict
    NMAP_DOCKER_IMAGE = settings.get('NMAP_DOCKER_IMAGE', 'instrumentisto/nmap:latest')
    NMAP_PORTS = settings.get('NMAP_PORTS', '1-10000')
    NMAP_TOP_PORTS = settings.get('NMAP_TOP_PORTS', '')
    NMAP_SCAN_TYPE = settings.get('NMAP_SCAN_TYPE', 'sS')
    NMAP_TIMING = settings.get('NMAP_TIMING', 'T4')
    NMAP_HOST_TIMEOUT = settings.get('NMAP_HOST_TIMEOUT', '30m')
    NMAP_MAX_RETRIES = settings.get('NMAP_MAX_RETRIES', 1)
    NMAP_MIN_RATE = settings.get('NMAP_MIN_RATE', '')
    NMAP_MAX_RATE = settings.get('NMAP_MAX_RATE', '')
    NMAP_SKIP_HOST_DISCOVERY = settings.get('NMAP_SKIP_HOST_DISCOVERY', True)
    NMAP_SERVICE_DETECTION = settings.get('NMAP_SERVICE_DETECTION', False)
    NMAP_VERSION_DETECTION = settings.get('NMAP_VERSION_DETECTION', False)
    NMAP_OS_DETECTION = settings.get('NMAP_OS_DETECTION', False)
    NMAP_SCRIPT_SCAN = settings.get('NMAP_SCRIPT_SCAN', False)
    NMAP_FRAGMENT_PACKETS = settings.get('NMAP_FRAGMENT_PACKETS', False)
    NMAP_DECOY_SCAN = settings.get('NMAP_DECOY_SCAN', False)
    NMAP_SOURCE_PORT = settings.get('NMAP_SOURCE_PORT', '')
    NMAP_DATA_LENGTH = settings.get('NMAP_DATA_LENGTH', '')

    # Convert container paths to host paths for sibling container volume mounts
    targets_host_path = get_host_path(str(Path(targets_file).parent))
    output_host_path = get_host_path(str(Path(output_file).parent))

    targets_filename = Path(targets_file).name
    output_filename = Path(output_file).name

    # Build Docker command
    cmd = [
        "docker", "run", "--rm",
        "--net=host",  # Required for raw socket scans
        "-v", f"{targets_host_path}:/targets:ro",
        "-v", f"{output_host_path}:/output",
    ]

    # Add image
    cmd.append(NMAP_DOCKER_IMAGE)

    # Scan type
    if NMAP_SCAN_TYPE:
        cmd.extend([f"-{NMAP_SCAN_TYPE}"])

    # Timing
    if NMAP_TIMING:
        cmd.extend([f"-{NMAP_TIMING}"])

    # Port specification
    if NMAP_TOP_PORTS:
        cmd.extend(["--top-ports", str(NMAP_TOP_PORTS)])
    elif NMAP_PORTS:
        cmd.extend(["-p", NMAP_PORTS])

    # Host discovery
    if NMAP_SKIP_HOST_DISCOVERY:
        cmd.append("-Pn")

    # Service/version detection
    if NMAP_SERVICE_DETECTION:
        cmd.append("-sV")
    if NMAP_VERSION_DETECTION and not NMAP_SERVICE_DETECTION:
        cmd.append("-sV")
    if NMAP_OS_DETECTION:
        cmd.append("-O")
    if NMAP_SCRIPT_SCAN:
        cmd.append("-sC")

    # Performance tuning
    if NMAP_HOST_TIMEOUT:
        cmd.extend(["--host-timeout", NMAP_HOST_TIMEOUT])
    if NMAP_MAX_RETRIES:
        cmd.extend(["--max-retries", str(NMAP_MAX_RETRIES)])
    if NMAP_MIN_RATE:
        cmd.extend(["--min-rate", str(NMAP_MIN_RATE)])
    if NMAP_MAX_RATE:
        cmd.extend(["--max-rate", str(NMAP_MAX_RATE)])

    # Evasion techniques
    if NMAP_FRAGMENT_PACKETS:
        cmd.append("-f")
    if NMAP_SOURCE_PORT:
        cmd.extend(["--source-port", str(NMAP_SOURCE_PORT)])
    if NMAP_DATA_LENGTH:
        cmd.extend(["--data-length", str(NMAP_DATA_LENGTH)])
    if NMAP_DECOY_SCAN:
        cmd.extend(["-D", "RND:10"])

    # Proxy support
    if use_proxy:
        cmd.extend(["--proxies", "socks4://127.0.0.1:9050"])

    # Input/Output
    cmd.extend(["-iL", f"/targets/{targets_filename}"])
    cmd.extend(["-oX", f"/output/{output_filename}"])

    # Disable interactive features
    cmd.append("--disable-arp-ping")

    return cmd


# =============================================================================
# Result Parsing
# =============================================================================

def parse_naabu_output(output_file: str) -> Dict:
    """
    Parse Naabu JSON Lines output into structured format.

    Naabu outputs one JSON object per line:
    {"host":"example.com","ip":"93.184.216.34","port":80}
    {"host":"example.com","ip":"93.184.216.34","port":443}

    Returns:
        Structured dictionary with by_host, by_ip, and summary sections
    """
    by_host = {}
    by_ip = {}
    all_ports = set()

    if not Path(output_file).exists():
        return {
            "by_host": {},
            "by_ip": {},
            "all_ports": [],
            "summary": {
                "hosts_scanned": 0,
                "ips_scanned": 0,
                "hosts_with_open_ports": 0,
                "total_open_ports": 0,
                "unique_ports": [],
                "unique_port_count": 0,
                "cdn_hosts": 0
            }
        }

    with open(output_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = entry.get("host", "")
            ip = entry.get("ip", "")
            port = entry.get("port")
            cdn = entry.get("cdn", "")
            cdn_name = entry.get("cdn-name", "")

            if port:
                all_ports.add(port)

            # Organize by host
            if host:
                if host not in by_host:
                    by_host[host] = {
                        "host": host,
                        "ip": ip,
                        "ports": [],
                        "port_details": [],
                        "cdn": cdn_name if cdn_name else None,
                        "is_cdn": bool(cdn or cdn_name)
                    }

                if port and port not in by_host[host]["ports"]:
                    by_host[host]["ports"].append(port)

                    # Determine service based on common port mappings
                    service = get_service_name(port)
                    by_host[host]["port_details"].append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service
                    })

            # Organize by IP
            if ip:
                if ip not in by_ip:
                    by_ip[ip] = {
                        "ip": ip,
                        "hostnames": [],
                        "ports": [],
                        "cdn": cdn_name if cdn_name else None,
                        "is_cdn": bool(cdn or cdn_name)
                    }

                if host and host not in by_ip[ip]["hostnames"]:
                    by_ip[ip]["hostnames"].append(host)

                if port and port not in by_ip[ip]["ports"]:
                    by_ip[ip]["ports"].append(port)

    # Sort ports
    for host in by_host:
        by_host[host]["ports"].sort()
        by_host[host]["port_details"].sort(key=lambda x: x["port"])

    for ip in by_ip:
        by_ip[ip]["ports"].sort()

    all_ports_sorted = sorted(list(all_ports))

    # Build summary
    summary = {
        "hosts_scanned": len(by_host),
        "ips_scanned": len(by_ip),
        "hosts_with_open_ports": len([h for h in by_host.values() if h["ports"]]),
        "total_open_ports": sum(len(h["ports"]) for h in by_host.values()),
        "unique_ports": all_ports_sorted,
        "unique_port_count": len(all_ports_sorted),
        "cdn_hosts": len([h for h in by_host.values() if h.get("is_cdn")])
    }

    return {
        "by_host": by_host,
        "by_ip": by_ip,
        "all_ports": all_ports_sorted,
        "summary": summary
    }


def parse_nmap_output(output_file: str) -> Dict:
    """
    Parse Nmap XML output into structured format compatible with existing code.

    Returns:
        Structured dictionary with by_host, by_ip, and summary sections
    """
    import xml.etree.ElementTree as ET

    by_host = {}
    by_ip = {}
    all_ports = set()

    if not Path(output_file).exists():
        return {
            "by_host": {},
            "by_ip": {},
            "all_ports": [],
            "summary": {
                "hosts_scanned": 0,
                "ips_scanned": 0,
                "hosts_with_open_ports": 0,
                "total_open_ports": 0,
                "unique_ports": [],
                "unique_port_count": 0,
                "cdn_hosts": 0
            }
        }

    try:
        tree = ET.parse(output_file)
        root = tree.getroot()
    except ET.ParseError:
        return {
            "by_host": {},
            "by_ip": {},
            "all_ports": [],
            "summary": {
                "hosts_scanned": 0,
                "ips_scanned": 0,
                "hosts_with_open_ports": 0,
                "total_open_ports": 0,
                "unique_ports": [],
                "unique_port_count": 0,
                "cdn_hosts": 0
            }
        }

    for host_elem in root.findall('host'):
        # Get IP address
        ip = None
        for address in host_elem.findall('address'):
            if address.get('addrtype') == 'ipv4':
                ip = address.get('addr')
                break

        if not ip:
            continue

        # Get hostname if available
        hostname = ip  # Default to IP
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', ip)

        # Parse ports
        ports_elem = host_elem.find('ports')
        if ports_elem is None:
            continue

        host_ports = []
        port_details = []

        for port_elem in ports_elem.findall('port'):
            port_num = int(port_elem.get('portid'))
            protocol = port_elem.get('protocol', 'tcp')

            state_elem = port_elem.find('state')
            if state_elem is None:
                continue

            state = state_elem.get('state')
            if state not in ['open', 'open|filtered']:
                continue

            # Get service information
            service_name = 'unknown'
            service_elem = port_elem.find('service')
            if service_elem is not None:
                service_name = service_elem.get('name', 'unknown')
            else:
                # Use IANA lookup as fallback
                service_name = get_service_name(port_num)

            host_ports.append(port_num)
            all_ports.add(port_num)

            port_details.append({
                "port": port_num,
                "protocol": protocol,
                "service": service_name
            })

        if host_ports:
            # Organize by host
            by_host[hostname] = {
                "host": hostname,
                "ip": ip,
                "ports": sorted(host_ports),
                "port_details": sorted(port_details, key=lambda x: x["port"]),
                "cdn": None,
                "is_cdn": False
            }

            # Organize by IP
            if ip not in by_ip:
                by_ip[ip] = {
                    "ip": ip,
                    "hostnames": [],
                    "ports": [],
                    "cdn": None,
                    "is_cdn": False
                }

            if hostname != ip and hostname not in by_ip[ip]["hostnames"]:
                by_ip[ip]["hostnames"].append(hostname)

            for port in host_ports:
                if port not in by_ip[ip]["ports"]:
                    by_ip[ip]["ports"].append(port)

    # Sort IP ports
    for ip in by_ip:
        by_ip[ip]["ports"].sort()

    all_ports_sorted = sorted(list(all_ports))

    # Build summary
    summary = {
        "hosts_scanned": len(by_host),
        "ips_scanned": len(by_ip),
        "hosts_with_open_ports": len([h for h in by_host.values() if h["ports"]]),
        "total_open_ports": sum(len(h["ports"]) for h in by_host.values()),
        "unique_ports": all_ports_sorted,
        "unique_port_count": len(all_ports_sorted),
        "cdn_hosts": 0  # Nmap doesn't detect CDN by default
    }

    return {
        "by_host": by_host,
        "by_ip": by_ip,
        "all_ports": all_ports_sorted,
        "summary": summary
    }


# =============================================================================
# File Ownership Handling
# =============================================================================

def get_real_user_ids() -> tuple:
    """Get the real user/group IDs (handles sudo)."""
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')

    if sudo_uid and sudo_gid:
        return (int(sudo_uid), int(sudo_gid))
    return (os.getuid(), os.getgid())


def fix_file_ownership(file_path: Path) -> None:
    """Fix file ownership for files created by Docker (as root)."""
    try:
        uid, gid = get_real_user_ids()
        os.chown(str(file_path), uid, gid)
    except Exception:
        pass  # Silently ignore if we can't change ownership


# =============================================================================
# Main Scan Function
# =============================================================================

def run_nmap_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Run Nmap port scan on targets from recon data.
    """
    print("\n" + "="*60)
    print("NMAP PORT SCANNER")
    print("="*60)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    NMAP_DOCKER_IMAGE = settings.get('NMAP_DOCKER_IMAGE', 'instrumentisto/nmap:latest')
    NMAP_PORTS = settings.get('NMAP_PORTS', '1-10000')
    NMAP_TOP_PORTS = settings.get('NMAP_TOP_PORTS', '')
    NMAP_SCAN_TYPE = settings.get('NMAP_SCAN_TYPE', 'sS')
    NMAP_TIMING = settings.get('NMAP_TIMING', 'T4')
    USE_TOR_FOR_RECON = settings.get('USE_TOR_FOR_RECON', False)

    # Check Docker
    if not is_docker_installed():
        print("[!] Docker is not installed. Please install Docker first.")
        return recon_data

    if not is_docker_running():
        print("[!] Docker daemon is not running. Please start Docker.")
        return recon_data

    # Pull image if needed
    if not pull_docker_image(NMAP_DOCKER_IMAGE, "Nmap"):
        print("[!] Failed to get Nmap Docker image")
        return recon_data

    # Check Tor if enabled
    use_proxy = False
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            print("    [✓] Tor proxy detected - enabling anonymous scanning")
            use_proxy = True
        else:
            print("    [!] Tor not running - scanning without proxy")

    # Extract targets
    print("\n[*] Extracting targets from recon data...")
    unique_ips, unique_hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data)

    # Combine targets - prefer hostnames for better accuracy
    all_targets = list(unique_hostnames) + [ip for ip in unique_ips if ip not in [
        h_ip for h in unique_hostnames for h_ip in ip_to_hostnames.get(h, [])
    ]]

    if not all_targets:
        print("[!] No targets found in recon data")
        return recon_data

    print(f"    [*] Found {len(unique_hostnames)} hostnames and {len(unique_ips)} IPs")
    print(f"    [*] Total targets to scan: {len(all_targets)}")

    # Create temp directory for scan files
    scan_temp_dir = Path("/tmp/redamon/.nmap_temp")
    scan_temp_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Write targets file
        targets_file = scan_temp_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            for target in all_targets:
                f.write(f"{target}\n")

        # Set output file
        nmap_output = scan_temp_dir / "nmap_output.xml"

        # Build and run command
        cmd = build_nmap_command(str(targets_file), str(nmap_output), settings, use_proxy)

        print(f"\n[*] Starting Nmap scan...")
        print(f"    [*] Scan type: -{NMAP_SCAN_TYPE}")
        print(f"    [*] Ports: {NMAP_TOP_PORTS if NMAP_TOP_PORTS else NMAP_PORTS}")
        print(f"    [*] Timing: -{NMAP_TIMING}")
        print(f"    [*] Host timeout: {settings.get('NMAP_HOST_TIMEOUT', '30m')}")
        print(f"    [*] Max retries: {settings.get('NMAP_MAX_RETRIES', 1)}")
        print(f"    [*] Skip host discovery: {settings.get('NMAP_SKIP_HOST_DISCOVERY', True)}")

        start_time = datetime.now()

        # Execute scan
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        _, stderr = process.communicate(timeout=3600)  # 1 hour timeout

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        if process.returncode != 0:
            print(f"    [!] Scan failed: {stderr[:200] if stderr else 'Unknown error'}")
            return recon_data

        if not nmap_output.exists():
            print(f"    [!] Scan completed but no output file generated")
            return recon_data

        # Parse results
        print(f"\n[*] Parsing results...")
        results = parse_nmap_output(str(nmap_output))

        # Build final structure
        nmap_results = {
            "scan_metadata": {
                "scan_timestamp": start_time.isoformat(),
                "scan_duration_seconds": round(duration, 2),
                "docker_image": NMAP_DOCKER_IMAGE,
                "scan_type": NMAP_SCAN_TYPE.replace('s', 'SYN ').replace('T', 'TCP Connect '),
                "scan_type_fallback": False,
                "ports_config": NMAP_TOP_PORTS if NMAP_TOP_PORTS else NMAP_PORTS,
                "timing": NMAP_TIMING,
                "passive_mode": False,
                "proxy_used": use_proxy,
                "total_targets": len(all_targets),
                "cdn_exclusion": False
            },
            "by_host": results["by_host"],
            "by_ip": results["by_ip"],
            "all_ports": results["all_ports"],
            "ip_to_hostnames": ip_to_hostnames,
            "summary": results["summary"]
        }

        # Print summary
        summary = results["summary"]
        print(f"\n[✓] Scan completed in {duration:.1f} seconds")
        print(f"    [*] Hosts with open ports: {summary['hosts_with_open_ports']}")
        print(f"    [*] Total open ports found: {summary['total_open_ports']}")
        print(f"    [*] Unique ports: {summary['unique_port_count']}")

        if results["all_ports"]:
            print(f"    [*] Ports discovered: {', '.join(map(str, results['all_ports'][:20]))}" +
                  (f"... (+{len(results['all_ports'])-20} more)" if len(results['all_ports']) > 20 else ""))

        # Add to recon_data
        recon_data["port_scan"] = nmap_results

        # Save incrementally
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2, default=str)
            fix_file_ownership(output_file)
            print(f"\n[✓] Results saved to {output_file}")

        return recon_data

    except subprocess.TimeoutExpired:
        print("[!] Scan timed out after 1 hour")
        return recon_data
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        return recon_data
    finally:
        # Cleanup temp files
        try:
            if scan_temp_dir.exists():
                for f in scan_temp_dir.iterdir():
                    f.unlink()
                scan_temp_dir.rmdir()
        except Exception:
            pass


def run_port_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Main entry point for port scanning. Routes to appropriate scanner based on settings.
    """
    scanner = settings.get('PORT_SCANNER', 'nmap').lower() if settings else 'nmap'
    if scanner == 'nmap':
        return run_nmap_scan(recon_data, output_file, settings)
    else:
        return run_naabu_scan(recon_data, output_file, settings)


def run_naabu_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Run Naabu port scan on targets from recon data (legacy support).

    Args:
        recon_data: Dictionary containing DNS/subdomain data
        output_file: Path to save enriched results (optional)
        settings: Settings dictionary from main.py

    Returns:
        Enriched recon_data with "port_scan" section added
    """
    print("\n" + "="*60)
    print("NAABU PORT SCANNER")
    print("="*60)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    NAABU_DOCKER_IMAGE = settings.get('NAABU_DOCKER_IMAGE', 'projectdiscovery/naabu:latest')
    NAABU_TOP_PORTS = settings.get('NAABU_TOP_PORTS', '1000')
    NAABU_CUSTOM_PORTS = settings.get('NAABU_CUSTOM_PORTS', '')
    NAABU_RATE_LIMIT = settings.get('NAABU_RATE_LIMIT', 1000)
    NAABU_SCAN_TYPE = settings.get('NAABU_SCAN_TYPE', 's')
    NAABU_EXCLUDE_CDN = settings.get('NAABU_EXCLUDE_CDN', False)
    NAABU_PASSIVE_MODE = settings.get('NAABU_PASSIVE_MODE', False)
    USE_TOR_FOR_RECON = settings.get('USE_TOR_FOR_RECON', False)

    # Check Docker
    if not is_docker_installed():
        print("[!] Docker is not installed. Please install Docker first.")
        return recon_data

    if not is_docker_running():
        print("[!] Docker daemon is not running. Please start Docker.")
        return recon_data

    # Pull image if needed
    if not pull_docker_image(NAABU_DOCKER_IMAGE, "Naabu"):
        print("[!] Failed to get Naabu Docker image")
        return recon_data

    # Check Tor if enabled
    use_proxy = False
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            print("    [✓] Tor proxy detected - enabling anonymous scanning")
            use_proxy = True
        else:
            print("    [!] Tor not running - scanning without proxy")

    # Extract targets
    print("\n[*] Extracting targets from recon data...")
    unique_ips, unique_hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data)

    # Combine targets - prefer hostnames for better accuracy
    all_targets = list(unique_hostnames) + [ip for ip in unique_ips if ip not in [
        h_ip for h in unique_hostnames for h_ip in ip_to_hostnames.get(h, [])
    ]]

    if not all_targets:
        print("[!] No targets found in recon data")
        return recon_data

    print(f"    [*] Found {len(unique_hostnames)} hostnames and {len(unique_ips)} IPs")
    print(f"    [*] Total targets to scan: {len(all_targets)}")

    # Create temp directory for scan files
    # Use /tmp/redamon to avoid spaces in paths (snap Docker issue)
    scan_temp_dir = Path("/tmp/redamon/.naabu_temp")
    scan_temp_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Write targets file
        targets_file = scan_temp_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            for target in all_targets:
                f.write(f"{target}\n")

        # Set output file
        naabu_output = scan_temp_dir / "naabu_output.json"

        # Build and run command
        cmd = build_naabu_command(str(targets_file), str(naabu_output), settings, use_proxy)

        print(f"\n[*] Starting Naabu scan...")
        print(f"    [*] Scan type: {'SYN' if NAABU_SCAN_TYPE == 's' else 'CONNECT'}")
        print(f"    [*] Ports: {NAABU_CUSTOM_PORTS if NAABU_CUSTOM_PORTS else f'top {NAABU_TOP_PORTS}'}")
        print(f"    [*] Rate limit: {NAABU_RATE_LIMIT} pps")
        print(f"    [*] Threads: {settings.get('NAABU_THREADS', 25)}")
        print(f"    [*] Timeout: {settings.get('NAABU_TIMEOUT', 10000)}ms")
        print(f"    [*] Retries: {settings.get('NAABU_RETRIES', 1)}")
        print(f"    [*] Exclude CDN: {NAABU_EXCLUDE_CDN}")
        print(f"    [*] Skip host discovery: {settings.get('NAABU_SKIP_HOST_DISCOVERY', True)}")
        print(f"    [*] Verify ports: {settings.get('NAABU_VERIFY_PORTS', True)}")

        if NAABU_PASSIVE_MODE:
            print(f"    [*] Mode: PASSIVE (Shodan InternetDB)")

        start_time = datetime.now()

        # Execute scan with fallback mechanism
        scan_succeeded = False
        actual_scan_type = NAABU_SCAN_TYPE

        for attempt, scan_type in enumerate([NAABU_SCAN_TYPE, 'c'] if NAABU_SCAN_TYPE == 's' else [NAABU_SCAN_TYPE]):
            if attempt > 0:
                # Retry with CONNECT scan after SYN scan failed
                print(f"\n    [*] Retrying with CONNECT scan...")
                settings_copy = settings.copy()
                settings_copy['NAABU_SCAN_TYPE'] = 'c'
                cmd = build_naabu_command(str(targets_file), str(naabu_output), settings_copy, use_proxy)
                actual_scan_type = 'c'

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            _, stderr = process.communicate(timeout=1800)  # 30 min timeout

            # Check for SIGSEGV crash (common in SYN mode)
            if 'SIGSEGV' in stderr or 'segmentation' in stderr.lower():
                print(f"    [!] Scan crashed (SIGSEGV) - naabu binary error")
                if scan_type == 's' and attempt == 0:
                    print(f"    [*] SYN scan requires raw sockets - will try CONNECT scan")
                    continue  # Try CONNECT scan
                else:
                    break  # No more fallbacks

            if process.returncode == 0 or naabu_output.exists():
                scan_succeeded = True
                break

            if stderr and attempt == 0 and scan_type == 's':
                print(f"    [!] SYN scan failed: {stderr[:150] if stderr else 'Unknown error'}")
                continue  # Try CONNECT scan

            print(f"    [!] Scan failed: {stderr[:200] if stderr else 'Unknown error'}")
            break

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        if not scan_succeeded and not naabu_output.exists():
            print(f"    [!] All scan attempts failed")
            return recon_data

        # Parse results
        print(f"\n[*] Parsing results...")
        results = parse_naabu_output(str(naabu_output))

        # Build final structure
        naabu_results = {
            "scan_metadata": {
                "scan_timestamp": start_time.isoformat(),
                "scan_duration_seconds": round(duration, 2),
                "docker_image": NAABU_DOCKER_IMAGE,
                "scan_type": "syn" if actual_scan_type == "s" else "connect",
                "scan_type_fallback": actual_scan_type != NAABU_SCAN_TYPE,
                "ports_config": NAABU_CUSTOM_PORTS if NAABU_CUSTOM_PORTS else f"top-{NAABU_TOP_PORTS}",
                "rate_limit": NAABU_RATE_LIMIT,
                "passive_mode": NAABU_PASSIVE_MODE,
                "proxy_used": use_proxy,
                "total_targets": len(all_targets),
                "cdn_exclusion": NAABU_EXCLUDE_CDN
            },
            "by_host": results["by_host"],
            "by_ip": results["by_ip"],
            "all_ports": results["all_ports"],
            "ip_to_hostnames": ip_to_hostnames,
            "summary": results["summary"]
        }

        # Print summary
        summary = results["summary"]
        print(f"\n[✓] Scan completed in {duration:.1f} seconds")
        if actual_scan_type != NAABU_SCAN_TYPE:
            print(f"    [*] Note: Used CONNECT scan (SYN scan crashed)")
        print(f"    [*] Hosts with open ports: {summary['hosts_with_open_ports']}")
        print(f"    [*] Total open ports found: {summary['total_open_ports']}")
        print(f"    [*] Unique ports: {summary['unique_port_count']}")

        if summary.get('cdn_hosts', 0) > 0:
            print(f"    [*] CDN-protected hosts: {summary['cdn_hosts']}")

        if results["all_ports"]:
            print(f"    [*] Ports discovered: {', '.join(map(str, results['all_ports'][:20]))}" +
                  (f"... (+{len(results['all_ports'])-20} more)" if len(results['all_ports']) > 20 else ""))

        # Add to recon_data
        recon_data["port_scan"] = naabu_results

        # Save incrementally
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2, default=str)
            fix_file_ownership(output_file)
            print(f"\n[✓] Results saved to {output_file}")

        return recon_data

    except subprocess.TimeoutExpired:
        print("[!] Scan timed out after 30 minutes")
        return recon_data
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        return recon_data
    finally:
        # Cleanup temp files
        try:
            if scan_temp_dir.exists():
                for f in scan_temp_dir.iterdir():
                    f.unlink()
                scan_temp_dir.rmdir()
        except Exception:
            pass


# =============================================================================
# Standalone Entry Point
# =============================================================================

def enrich_recon_file(recon_file: Path) -> dict:
    """
    Enrich an existing recon JSON file with Naabu scan results.

    Args:
        recon_file: Path to existing recon JSON file

    Returns:
        Enriched recon data
    """
    # Load settings for standalone usage
    from recon.project_settings import get_settings
    settings = get_settings()

    print(f"\n[*] Loading recon file: {recon_file}")

    with open(recon_file, 'r') as f:
        recon_data = json.load(f)

    enriched = run_port_scan(recon_data, output_file=recon_file, settings=settings)

    return enriched

