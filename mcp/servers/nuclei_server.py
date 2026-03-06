"""
Nuclei MCP Server - Vulnerability Scanner

Exposes nuclei vulnerability scanner as MCP tools for agentic penetration testing.
Uses dynamic CLI wrapper approach for maximum flexibility.

Tools:
    - execute_nuclei: Execute nuclei with any CLI arguments
"""

from fastmcp import FastMCP
import subprocess
import shlex
import os

# Server configuration
SERVER_NAME = "nuclei"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("NUCLEI_PORT", "8002"))

mcp = FastMCP(SERVER_NAME)


@mcp.tool()
def execute_nuclei(args: str) -> str:
    """
    Execute nuclei vulnerability scanner with any valid CLI arguments.

    Nuclei is a fast and customizable vulnerability scanner based on simple
    YAML-based templates. It can detect CVEs, misconfigurations, exposed panels,
    and more using its extensive template library.

    Args:
        args: Command-line arguments for nuclei (without the 'nuclei' command itself)

    Returns:
        Command output (stdout + stderr combined)

    Examples:
        Basic vulnerability scan:
        - "-u http://10.0.0.5 -severity critical,high -jsonl"

        Scan for specific CVE:
        - "-u http://10.0.0.5 -id CVE-2021-41773 -jsonl"

        Scan with tags:
        - "-u http://10.0.0.5 -tags cve,rce,lfi -jsonl"

        Scan multiple URLs from file:
        - "-l urls.txt -severity critical,high -jsonl"

        Use custom template:
        - "-u http://10.0.0.5 -t /opt/nuclei-templates/custom.yaml"

        Scan with all templates:
        - "-u http://10.0.0.5 -jsonl"

        Technology detection:
        - "-u http://10.0.0.5 -tags tech -jsonl"

        Scan for exposed panels:
        - "-u http://10.0.0.5 -tags panel -jsonl"

        Rate limited scan:
        - "-u http://10.0.0.5 -rate-limit 10 -jsonl"
    """
    try:
        cmd_args = shlex.split(args)

        # Add progress indicators and reduce timeout for better responsiveness
        if "-silent" not in cmd_args:
            cmd_args.append("-silent")
        if "-nc" not in cmd_args:  # No color for clean output
            cmd_args.append("-nc")

        # Use shorter timeout to prevent client disconnection
        result = subprocess.run(
            ["nuclei"] + cmd_args,
            capture_output=True,
            text=True,
            timeout=120  # Reduced from 600 to 120 seconds
        )

        output = result.stdout.strip()
        error_output = ""

        if result.stderr:
            # Filter out progress/info messages but keep actual errors
            stderr_lines = [
                line for line in result.stderr.split('\n')
                if line and not any(x in line.lower() for x in [
                    '[inf]', '[wrn]', 'templates loaded', 'nuclei engine',
                    'config directory', 'cache directory', 'pdcp directory'
                ])
            ]
            if stderr_lines:
                error_output = f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        # Provide meaningful response based on results
        if result.returncode != 0:
            return f"[ERROR] Nuclei execution failed (exit code: {result.returncode}){error_output}"

        if output:
            return output + error_output
        else:
            return "[INFO] Scan completed - No vulnerabilities found" + error_output

    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out after 120 seconds. Try using specific templates or reducing target scope with -t <template> or -severity critical,high"
    except FileNotFoundError:
        return "[ERROR] nuclei not found. Ensure it is installed and in PATH."
    except Exception as e:
        return f"[ERROR] Unexpected error: {str(e)}"



if __name__ == "__main__":
    import sys

    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")
