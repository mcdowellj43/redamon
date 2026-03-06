"""
RedAmon - Port Scanner Module (NMAP-based)

Fast, comprehensive port scanning using nmap via MCP server.
Provides deep service detection, OS fingerprinting, and NSE scripting.

Features:
- SYN and CONNECT scan modes
- Service version detection
- OS fingerprinting
- NSE vulnerability scripts
- JSON output with structured results
"""

import json
import subprocess
import shlex
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
import sys
import re
import xml.etree.ElementTree as ET

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import IANA service lookup (15,000+ services from official registry)
from helpers.iana_services import get_service_name_friendly as get_service_name

# Settings are passed from main.py to avoid multiple database queries


# =============================================================================
# NMAP Direct Execution Functions
# =============================================================================

def is_nmap_available() -> bool:
    """Check if nmap is installed and accessible."""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0 and "Nmap" in result.stdout
    except Exception:
        return False


def execute_nmap_direct(args: str) -> str:
    """Execute nmap command directly."""
    try:
        cmd_args = shlex.split(args)
        result = subprocess.run(
            ["nmap"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=600
        )

        # Check if nmap failed
        if result.returncode != 0:
            error_msg = f"[ERROR] NMAP failed with exit code {result.returncode}"
            if result.stderr:
                error_msg += f"\nSTDERR: {result.stderr}"
            if result.stdout:
                error_msg += f"\nSTDOUT: {result.stdout}"
            return error_msg

        # Combine stdout and stderr
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]: {result.stderr}"

        return output if output.strip() else "[INFO] No results returned"

    except subprocess.TimeoutExpired:
        return "[ERROR] NMAP scan timed out after 10 minutes"
    except FileNotFoundError:
        return "[ERROR] nmap not found. Ensure it is installed and in PATH."
    except Exception as e:
        return f"[ERROR] Failed to execute nmap: {str(e)}"


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
# NMAP Command Builder
# =============================================================================

def build_nmap_command(targets: List[str], settings: dict) -> str:
    """
    Build the nmap command arguments.

    Args:
        targets: List of targets (IPs/hostnames) to scan
        settings: Settings dictionary from main.py

    Returns:
        Command arguments string for nmap
    """
    # Extract settings with defaults
    NMAP_TOP_PORTS = settings.get('NMAP_TOP_PORTS', '1000')
    NMAP_CUSTOM_PORTS = settings.get('NMAP_CUSTOM_PORTS', '')
    NMAP_SCAN_TYPE = settings.get('NMAP_SCAN_TYPE', 'T')  # TCP connect scan for unprivileged mode
    NMAP_SERVICE_DETECTION = settings.get('NMAP_SERVICE_DETECTION', True)
    NMAP_OS_DETECTION = settings.get('NMAP_OS_DETECTION', False)
    NMAP_AGGRESSIVE = settings.get('NMAP_AGGRESSIVE', False)
    NMAP_SCRIPT_SCAN = settings.get('NMAP_SCRIPT_SCAN', True)
    NMAP_TIMING = settings.get('NMAP_TIMING', '4')  # T4 timing
    NMAP_OUTPUT_XML = settings.get('NMAP_OUTPUT_XML', True)

    # Build command arguments
    args = []

    # Add unprivileged flag to avoid raw socket issues
    args.append("--unprivileged")

    # Scan type
    if NMAP_SCAN_TYPE:
        args.append(f"-s{NMAP_SCAN_TYPE}")

    # Port specification
    if NMAP_CUSTOM_PORTS:
        args.extend(["-p", NMAP_CUSTOM_PORTS])
    else:
        args.append(f"--top-ports={NMAP_TOP_PORTS}")

    # Service detection
    if NMAP_SERVICE_DETECTION:
        args.append("-sV")

    # OS detection
    if NMAP_OS_DETECTION:
        args.append("-O")

    # Aggressive scan (includes -A: OS, version, script, traceroute)
    if NMAP_AGGRESSIVE:
        args.append("-A")
    elif NMAP_SCRIPT_SCAN:
        # Default scripts if not aggressive
        args.append("-sC")

    # Timing template
    args.append(f"-T{NMAP_TIMING}")

    # Output format - always include XML for parsing
    if NMAP_OUTPUT_XML:
        args.extend(["-oX", "-"])  # Output XML to stdout

    # Add targets
    args.extend(targets)

    return " ".join(args)


# =============================================================================
# Result Parsing
# =============================================================================

def parse_nmap_xml_output(xml_output: str) -> Dict:
    """
    Parse nmap XML output into structured format.

    Args:
        xml_output: XML output from nmap -oX command

    Returns:
        Structured dictionary with by_host, by_ip, and summary sections
    """
    by_host = {}
    by_ip = {}
    all_ports = set()

    try:
        # Clean up the XML output to extract just the XML part
        xml_start = xml_output.find('<?xml')
        if xml_start == -1:
            xml_start = xml_output.find('<nmaprun')

        if xml_start == -1:
            # No XML found, return empty results
            return create_empty_results()

        xml_data = xml_output[xml_start:]

        # Parse XML
        root = ET.fromstring(xml_data)

        # Process each host
        for host in root.findall('.//host'):
            # Get host status
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue

            # Get addresses (IP and hostname)
            addresses = host.findall('address')
            ip_address = None
            hostname = None

            for addr in addresses:
                if addr.get('addrtype') == 'ipv4':
                    ip_address = addr.get('addr')
                elif addr.get('addrtype') == 'ipv6':
                    ip_address = addr.get('addr')

            # Get hostnames
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')

            # Use IP if no hostname
            if hostname is None:
                hostname = ip_address

            if ip_address is None:
                continue

            # Get OS information
            os_info = None
            os_elem = host.find('os')
            if os_elem is not None:
                os_match = os_elem.find('.//osmatch')
                if os_match is not None:
                    os_info = {
                        'name': os_match.get('name'),
                        'accuracy': os_match.get('accuracy'),
                        'line': os_match.get('line')
                    }

            # Process ports
            ports_elem = host.find('ports')
            host_ports = []
            port_details = []

            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_num = int(port.get('portid'))
                    protocol = port.get('protocol', 'tcp')

                    state_elem = port.find('state')
                    if state_elem is None or state_elem.get('state') != 'open':
                        continue

                    all_ports.add(port_num)
                    host_ports.append(port_num)

                    # Get service information
                    service_elem = port.find('service')
                    service_name = ""
                    service_product = ""
                    service_version = ""
                    service_extrainfo = ""

                    if service_elem is not None:
                        service_name = service_elem.get('name', '')
                        service_product = service_elem.get('product', '')
                        service_version = service_elem.get('version', '')
                        service_extrainfo = service_elem.get('extrainfo', '')

                    # Fallback to IANA service name if not detected
                    if not service_name:
                        service_name = get_service_name(port_num)

                    port_details.append({
                        "port": port_num,
                        "protocol": protocol,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                        "extrainfo": service_extrainfo,
                        "state": "open"
                    })

            # Store by hostname
            if hostname:
                by_host[hostname] = {
                    "host": hostname,
                    "ip": ip_address,
                    "ports": sorted(host_ports),
                    "port_details": sorted(port_details, key=lambda x: x["port"]),
                    "os_info": os_info,
                    "total_ports": len(host_ports)
                }

            # Store by IP
            if ip_address:
                if ip_address not in by_ip:
                    by_ip[ip_address] = {
                        "ip": ip_address,
                        "hostnames": [],
                        "ports": sorted(host_ports),
                        "os_info": os_info,
                        "total_ports": len(host_ports)
                    }

                if hostname and hostname != ip_address and hostname not in by_ip[ip_address]["hostnames"]:
                    by_ip[ip_address]["hostnames"].append(hostname)

    except ET.ParseError as e:
        print(f"[!] XML parsing error: {e}")
        return create_empty_results()
    except Exception as e:
        print(f"[!] Error parsing nmap output: {e}")
        return create_empty_results()

    all_ports_sorted = sorted(list(all_ports))

    # Build summary
    summary = {
        "hosts_scanned": len(by_host),
        "ips_scanned": len(by_ip),
        "hosts_with_open_ports": len([h for h in by_host.values() if h["ports"]]),
        "total_open_ports": sum(len(h["ports"]) for h in by_host.values()),
        "unique_ports": all_ports_sorted,
        "unique_port_count": len(all_ports_sorted),
    }

    return {
        "by_host": by_host,
        "by_ip": by_ip,
        "all_ports": all_ports_sorted,
        "summary": summary
    }


def create_empty_results() -> Dict:
    """Create empty results structure."""
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
        }
    }


# =============================================================================
# Main Scan Function
# =============================================================================

def run_port_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Run NMAP port scan on targets from recon data.

    Args:
        recon_data: Dictionary containing DNS/subdomain data
        output_file: Path to save enriched results (optional)
        settings: Settings dictionary from main.py

    Returns:
        Enriched recon_data with "port_scan" section added
    """
    print("\n" + "="*60)
    print("NMAP PORT SCANNER")
    print("="*60)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    # Extract settings with defaults
    NMAP_TOP_PORTS = settings.get('NMAP_TOP_PORTS', '1000')
    NMAP_CUSTOM_PORTS = settings.get('NMAP_CUSTOM_PORTS', '')
    NMAP_SCAN_TYPE = settings.get('NMAP_SCAN_TYPE', 'T')
    NMAP_SERVICE_DETECTION = settings.get('NMAP_SERVICE_DETECTION', True)
    NMAP_OS_DETECTION = settings.get('NMAP_OS_DETECTION', False)
    NMAP_AGGRESSIVE = settings.get('NMAP_AGGRESSIVE', False)
    NMAP_TIMING = settings.get('NMAP_TIMING', '4')

    # Check NMAP availability
    if not is_nmap_available():
        error_msg = "[ERROR] NMAP is not installed or not accessible. Cannot perform port scanning."
        print(error_msg)
        raise RuntimeError(error_msg)

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

    # Build and execute command
    cmd_args = build_nmap_command(all_targets, settings)

    print(f"\n[*] Starting NMAP scan...")
    print(f"    [*] Scan type: {NMAP_SCAN_TYPE}")
    print(f"    [*] Ports: {NMAP_CUSTOM_PORTS if NMAP_CUSTOM_PORTS else f'top {NMAP_TOP_PORTS}'}")
    print(f"    [*] Timing: T{NMAP_TIMING}")
    print(f"    [*] Service detection: {NMAP_SERVICE_DETECTION}")
    print(f"    [*] OS detection: {NMAP_OS_DETECTION}")
    print(f"    [*] Aggressive mode: {NMAP_AGGRESSIVE}")

    start_time = datetime.now()

    # Execute scan directly
    nmap_output = execute_nmap_direct(cmd_args)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Check for errors
    if nmap_output.startswith("[ERROR]"):
        print(f"\n{nmap_output}")
        raise RuntimeError(nmap_output)

    # Parse results
    print(f"\n[*] Parsing results...")
    results = parse_nmap_xml_output(nmap_output)

    # Build final structure
    nmap_results = {
        "scan_metadata": {
            "scan_timestamp": start_time.isoformat(),
            "scan_duration_seconds": round(duration, 2),
            "scanner": "nmap",
            "scan_type": NMAP_SCAN_TYPE,
            "ports_config": NMAP_CUSTOM_PORTS if NMAP_CUSTOM_PORTS else f"top-{NMAP_TOP_PORTS}",
            "service_detection": NMAP_SERVICE_DETECTION,
            "os_detection": NMAP_OS_DETECTION,
            "aggressive_mode": NMAP_AGGRESSIVE,
            "timing": f"T{NMAP_TIMING}",
            "total_targets": len(all_targets),
            "execution_method": "direct"
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
        print(f"\n[✓] Results saved to {output_file}")

    return recon_data


# =============================================================================
# Standalone Entry Point
# =============================================================================

def enrich_recon_file(recon_file: Path) -> dict:
    """
    Enrich an existing recon JSON file with NMAP scan results.

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