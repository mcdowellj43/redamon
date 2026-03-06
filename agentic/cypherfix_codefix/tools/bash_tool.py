"""Bash tool: subprocess execution with safety."""

import asyncio
import os
import re

BLOCKED_PATTERNS = [
    r'rm\s+(-rf?\s+)?/',
    r'mkfs\.',
    r'dd\s+if=',
    r'>\s*/dev/',
]


async def github_bash(state, command: str, timeout: int = 120000) -> str:
    """Run a shell command in the cloned repo directory."""
    timeout_seconds = min(timeout / 1000, 600)

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            return f"Error: Command blocked for safety reasons: {command}"

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(state.repo_path),
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return f"Error: Command timed out after {timeout_seconds}s: {command}"

        output = stdout.decode('utf-8', errors='replace')
        exit_code = proc.returncode

        result = output
        if exit_code != 0:
            result += f"\n\n[Exit code: {exit_code}]"

        return result

    except Exception as e:
        return f"Error executing command: {type(e).__name__}: {str(e)}"
