"""Streaming event emission and file detection helpers."""

import os
import re
import logging

logger = logging.getLogger(__name__)


def detect_generated_file(step: dict) -> dict | None:
    """Detect if a tool execution created a downloadable file in /tmp/.

    Checks both tool_args (for explicit -o /tmp/... flags) and
    tool_output (for file listing output confirming creation).

    Returns:
        dict with file metadata or None if no file detected.
    """
    tool_args = step.get("tool_args", {})
    output = (step.get("tool_output") or "") + (step.get("output_analysis") or "")
    command = ""

    if isinstance(tool_args, dict):
        command = tool_args.get("command", "") or tool_args.get("code", "")
    elif isinstance(tool_args, str):
        command = tool_args

    # Pattern 1: msfvenom -o /tmp/filename
    m = re.search(r'-o\s+(/tmp/[^\s;"\']+)', command)
    if m:
        filepath = m.group(1)
        filename = os.path.basename(filepath)
        # Verify file mentioned in output (success indicator)
        if filename in output and "[ERROR]" not in output[:200]:
            return {
                "filepath": filepath,
                "filename": filename,
                "source": "msfvenom",
                "description": f"Generated payload: {filename}",
            }

    # Pattern 2: cp ... /tmp/filename (from fileformat module copy)
    m = re.search(r'cp\s+\S+\s+(/tmp/[^\s;"\']+)', command)
    if m:
        filepath = m.group(1)
        filename = os.path.basename(filepath)
        if filename in output and "[ERROR]" not in output[:200]:
            return {
                "filepath": filepath,
                "filename": filename,
                "source": "fileformat",
                "description": f"Generated document: {filename}",
            }

    # Pattern 3: Output mentions a file was saved to /tmp/
    m = re.search(r'[Ss]aved\s+(?:as\s+|to\s+)?(/tmp/[^\s"\']+)', output)
    if m:
        filepath = m.group(1)
        filename = os.path.basename(filepath)
        return {
            "filepath": filepath,
            "filename": filename,
            "source": "tool_output",
            "description": f"Generated file: {filename}",
        }

    return None


async def emit_streaming_events(state: dict, callback) -> None:
    """Emit appropriate streaming events based on state changes."""
    try:
        # Phase update (includes attack_path_type for dynamic routing display)
        if "current_phase" in state:
            await callback.on_phase_update(
                state.get("current_phase", "informational"),
                state.get("current_iteration", 0),
                state.get("attack_path_type", "cve_exploit")
            )

        # Todo list update
        if "todo_list" in state and state.get("todo_list"):
            await callback.on_todo_update(state["todo_list"])

        # Approval request - use state marker to prevent duplicate emissions
        if state.get("awaiting_user_approval") and state.get("phase_transition_pending"):
            pending = state["phase_transition_pending"]
            # Create unique key for this specific transition
            approval_key = f"{pending.get('from_phase', '')}_{pending.get('to_phase', '')}"
            if state.get("_emitted_approval_key") != approval_key:
                await callback.on_approval_request(pending)
                state["_emitted_approval_key"] = approval_key

        # Question request - use state marker to prevent duplicate emissions
        if state.get("awaiting_user_question") and state.get("pending_question"):
            pending = state["pending_question"]
            # Create unique key for this specific question
            question_key = f"{pending.get('phase', '')}_{hash(pending.get('question', '')[:100])}"
            if state.get("_emitted_question_key") != question_key:
                await callback.on_question_request(pending)
                state["_emitted_question_key"] = question_key

        # 1. Emit tool_complete for PREVIOUS completed step (if any)
        #    This MUST come before thinking, so the frontend sees:
        #    tool_complete → thinking → tool_start (correct timeline order)
        if "_completed_step" in state and state["_completed_step"]:
            cstep = state["_completed_step"]
            if cstep.get("success") is not None and cstep.get("output_analysis") and not cstep.get("_emitted_complete"):
                await callback.on_tool_complete(
                    cstep.get("tool_name", "unknown"),
                    cstep["success"],
                    cstep.get("output_analysis", "")[:10000],
                    actionable_findings=cstep.get("actionable_findings", []),
                    recommended_next_steps=cstep.get("recommended_next_steps", []),
                )
                cstep["_emitted_complete"] = True

                # Also emit execution_step summary for the completed step
                await callback.on_execution_step({
                    "iteration": cstep.get("iteration", 0),
                    "phase": state.get("current_phase", "informational"),
                    "thought": cstep.get("thought", ""),
                    "tool_name": cstep.get("tool_name"),
                    "success": cstep.get("success", False),
                    "output_summary": cstep.get("output_analysis", "")[:10000],
                    "actionable_findings": cstep.get("actionable_findings", []),
                    "recommended_next_steps": cstep.get("recommended_next_steps", []),
                })

                # Detect file creation in tool output and notify frontend
                if cstep.get("tool_name") in ("kali_shell", "execute_code", "metasploit_console"):
                    file_info = detect_generated_file(cstep)
                    if file_info:
                        await callback.on_file_ready(file_info)

        # 2. Emit thinking (from _decision stored by _think_node)
        if "_decision" in state and state["_decision"]:
            decision = state["_decision"]
            if decision.get("thought") and not decision.get("_emitted_thinking"):
                try:
                    await callback.on_thinking(
                        state.get("current_iteration", 0),
                        state.get("current_phase", "informational"),
                        decision.get("thought", ""),
                        decision.get("reasoning", "")
                    )
                    decision["_emitted_thinking"] = True
                except Exception as e:
                    logger.error(f"Error emitting thinking event: {e}")

        # 3. Emit tool_start and output chunks for CURRENT step (new tool)
        if "_current_step" in state and state["_current_step"]:
            step = state["_current_step"]
            # Emit tool start
            if step.get("tool_name") and not step.get("_emitted_start"):
                await callback.on_tool_start(
                    step["tool_name"],
                    step.get("tool_args", {})
                )
                step["_emitted_start"] = True

            # Emit tool output chunk (raw tool output)
            if step.get("tool_output") and not step.get("_emitted_output"):
                await callback.on_tool_output_chunk(
                    step.get("tool_name", "unknown"),
                    step["tool_output"],
                    is_final=True
                )
                step["_emitted_output"] = True

            # NOTE: tool_complete for current step will be emitted via _completed_step
            # in the NEXT think iteration

        # Task complete - only emit AFTER generate_response_node has finished
        if state.get("task_complete") and state.get("_report_generated"):
            await callback.on_task_complete(
                state.get("completion_reason", "Task completed successfully"),
                state.get("current_phase", "informational"),
                state.get("current_iteration", 0)
            )

    except Exception as e:
        logger.error(f"Error emitting streaming events: {e}")
        # Don't fail the whole operation if streaming fails
        pass
