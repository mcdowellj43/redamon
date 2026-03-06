"""Execute tool node — runs the selected tool with progress streaming support."""

import os
import re
import logging

import httpx

from state import AgentState
from orchestrator_helpers.json_utils import json_dumps_safe
from orchestrator_helpers.config import get_identifiers
from tools import set_tenant_context, set_phase_context

logger = logging.getLogger(__name__)


async def execute_tool_node(
    state: AgentState,
    config,
    *,
    tool_executor,
    streaming_callbacks,
    session_manager_base,
) -> dict:
    """
    Execute the selected tool.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        tool_executor: PhaseAwareToolExecutor instance.
        streaming_callbacks: Dict of session_id -> streaming callback objects.
        session_manager_base: Base URL for the kali-sandbox session manager.
    """
    user_id, project_id, session_id = get_identifiers(state, config)

    step_data = state.get("_current_step") or {}
    tool_name = step_data.get("tool_name")
    tool_args = step_data.get("tool_args") or {}
    phase = state.get("current_phase", "informational")
    iteration = state.get("current_iteration", 0)

    # Detailed logging - tool execution start
    logger.info(f"\n{'='*60}")
    logger.info(f"EXECUTE TOOL - Iteration {iteration} - Phase: {phase}")
    logger.info(f"{'='*60}")
    logger.info(f"TOOL_NAME: {tool_name}")
    logger.info(f"TOOL_ARGS:")
    if tool_args:
        for key, value in tool_args.items():
            val_str = str(value)
            if len(val_str) > 200:
                val_str = val_str[:10000]
            logger.info(f"  {key}: {val_str}")
    else:
        logger.info("  (no arguments)")

    # Handle missing tool name
    if not tool_name:
        logger.error(f"[{user_id}/{project_id}/{session_id}] No tool name in step_data")
        step_data["tool_output"] = "Error: No tool specified"
        step_data["success"] = False
        step_data["error_message"] = "No tool name provided"
        logger.info(f"TOOL_OUTPUT: Error - No tool specified")
        logger.info(f"{'='*60}\n")
        return {
            "_current_step": step_data,
            "_tool_result": {"success": False, "error": "No tool name provided"},
        }

    # Set context
    set_tenant_context(user_id, project_id)
    set_phase_context(phase)

    extra_updates = {}

    # Check if this is a long-running command that needs progress streaming
    is_long_running_msf = (
        tool_name == "metasploit_console" and
        any(cmd in (tool_args.get("command", "") or "").lower() for cmd in ["run", "exploit"])
    )
    is_long_running_hydra = (tool_name == "execute_hydra")

    # Execute the tool (with progress streaming for long-running commands)
    streaming_cb = streaming_callbacks.get(session_id)
    if is_long_running_msf and streaming_cb:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Using execute_with_progress for long-running MSF command")
        result = await tool_executor.execute_with_progress(
            tool_name,
            tool_args,
            phase,
            progress_callback=streaming_cb.on_tool_output_chunk
        )
    elif is_long_running_hydra and streaming_cb:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Using execute_with_progress for Hydra brute force")
        result = await tool_executor.execute_with_progress(
            tool_name,
            tool_args,
            phase,
            progress_callback=streaming_cb.on_tool_output_chunk,
            progress_url=os.environ.get('MCP_HYDRA_PROGRESS_URL', 'http://kali-sandbox:8014/progress')
        )
    else:
        result = await tool_executor.execute(tool_name, tool_args, phase)

    # Update step with output (handle None result)
    if result:
        step_data["tool_output"] = result.get("output") or ""
        step_data["success"] = result.get("success", False)
        step_data["error_message"] = result.get("error")
    else:
        step_data["tool_output"] = ""
        step_data["success"] = False
        step_data["error_message"] = "Tool execution returned no result"

    # Detailed logging - tool output
    tool_output = step_data.get("tool_output", "")
    success = step_data.get("success", False)
    error_msg = step_data.get("error_message")

    logger.info(f"SUCCESS: {success}")
    if error_msg:
        logger.info(f"ERROR: {error_msg}")

    logger.info(f"TOOL_OUTPUT ({len(tool_output)} chars):")
    if tool_output:
        output_preview = tool_output[:100000]
        for line in output_preview.split('\n'):
            logger.info(f"  | {line}")
        if len(tool_output) > 100000:
            logger.info(f"  | ... ({len(tool_output) - 100000} more chars)")
    else:
        logger.info("  (empty output)")
    logger.info(f"{'='*60}\n")

    # Detect new Metasploit sessions and register chat mapping
    if tool_name == "metasploit_console" and tool_output:
        for match in re.finditer(r'session\s+(\d+)\s+opened', tool_output, re.IGNORECASE):
            msf_session_id = int(match.group(1))
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/session-chat-map",
                        json={"msf_session_id": msf_session_id, "chat_session_id": session_id}
                    )
            except Exception:
                pass  # Best effort, don't break execution

    # Register non-MSF listeners (netcat, socat) created via kali_shell
    if tool_name == "kali_shell" and tool_args:
        cmd = tool_args.get("command", "")
        if re.search(r'(nc|ncat)\s+.*-l', cmd) or 'socat' in cmd:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/non-msf-sessions",
                        json={"type": "listener", "tool": "netcat", "command": cmd,
                               "chat_session_id": session_id}
                    )
            except Exception:
                pass

    updates = {
        "_current_step": step_data,
        "_tool_result": result or {"success": False, "error": "No result"},
    }
    updates.update(extra_updates)
    return updates
