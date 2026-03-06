"""WebSocket handler for the CodeFix agent."""

import asyncio
import json
import logging
import uuid
from fastapi import WebSocket, WebSocketDisconnect

from .orchestrator import CodeFixOrchestrator
from .state import CodeFixState

logger = logging.getLogger(__name__)


class CodeFixStreamingCallback:
    """Streams CodeFix events to frontend via WebSocket."""

    def __init__(self, websocket: WebSocket):
        self.ws = websocket

    async def on_phase(self, phase: str, description: str):
        await self._send("codefix_phase", {"phase": phase, "description": description})

    async def on_thinking(self, thought: str):
        await self._send("thinking", {"thought": thought})

    async def on_thinking_chunk(self, chunk: str):
        await self._send("thinking_chunk", {"chunk": chunk})

    async def on_tool_start(self, tool_name: str, tool_args: dict):
        display_args = {
            k: v[:200] if isinstance(v, str) and len(v) > 200 else v
            for k, v in tool_args.items()
        }
        await self._send("tool_start", {"tool_name": tool_name, "tool_args": display_args})

    async def on_tool_complete(self, tool_name: str, success: bool, output_summary: str):
        await self._send("tool_complete", {
            "tool_name": tool_name, "success": success,
            "output_summary": output_summary[:500],
        })

    async def on_diff_block(self, block):
        await self._send("diff_block", block.model_dump())

    async def on_block_status(self, block_id: str, status: str):
        await self._send("block_status", {"block_id": block_id, "status": status})

    async def on_fix_plan(self, plan: dict):
        await self._send("fix_plan", plan)

    async def on_pr_created(self, pr_data: dict):
        await self._send("pr_created", pr_data)

    async def on_complete(self, remediation_id: str, status: str, pr_url: str = None):
        await self._send("codefix_complete", {
            "remediation_id": remediation_id, "status": status, "pr_url": pr_url,
        })

    async def on_error(self, message: str, recoverable: bool = True):
        await self._send("error", {"message": message, "recoverable": recoverable})

    async def _send(self, msg_type: str, payload: dict):
        try:
            await self.ws.send_json({"type": msg_type, "payload": payload})
        except Exception:
            pass


async def handle_codefix_websocket(websocket: WebSocket):
    """Main WebSocket handler for CodeFix agent connections."""
    await websocket.accept()
    callback = CodeFixStreamingCallback(websocket)

    state: CodeFixState | None = None
    orchestrator: CodeFixOrchestrator | None = None
    codefix_task: asyncio.Task | None = None

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type", "")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            elif msg_type == "init":
                payload = msg.get("payload", msg)
                state = CodeFixState()
                state.user_id = payload.get("user_id", "")
                state.project_id = payload.get("project_id", "")
                state.session_id = payload.get("session_id", str(uuid.uuid4()))
                state.streaming_callback = callback
                await websocket.send_json({
                    "type": "connected", "session_id": state.session_id,
                })

            elif msg_type == "start_fix":
                if not state:
                    await callback.on_error("Not initialized. Send init first.", recoverable=True)
                    continue

                payload = msg.get("payload", msg)
                remediation_id = payload.get("remediation_id", "")
                state.remediation_id = remediation_id

                orchestrator = CodeFixOrchestrator(state=state, callback=callback)

                async def run_codefix():
                    try:
                        await orchestrator.run(remediation_id)
                    except Exception as e:
                        logger.exception("CodeFix failed")
                        await callback.on_error(str(e), recoverable=False)

                codefix_task = asyncio.create_task(run_codefix())

            elif msg_type == "block_decision":
                payload = msg.get("payload", msg)
                if orchestrator and orchestrator.approval_future and not orchestrator.approval_future.done():
                    orchestrator.approval_future.set_result(payload)

            elif msg_type == "guidance":
                payload = msg.get("payload", msg)
                if orchestrator:
                    orchestrator.add_guidance(payload.get("message", ""))

            elif msg_type == "stop":
                if codefix_task and not codefix_task.done():
                    codefix_task.cancel()
                    try:
                        await codefix_task
                    except (asyncio.CancelledError, Exception):
                        pass
                if orchestrator:
                    await orchestrator.cleanup()
                    orchestrator = None
                await websocket.send_json({"type": "stopped"})

    except WebSocketDisconnect:
        logger.info("CodeFix WebSocket disconnected")
    except Exception as e:
        logger.exception(f"CodeFix WebSocket error: {e}")
    finally:
        if codefix_task and not codefix_task.done():
            codefix_task.cancel()
        if orchestrator:
            await orchestrator.cleanup()
