"""
Chat Persistence Module

Persists agent chat messages to the webapp's PostgreSQL database
via the REST API. Uses httpx (already in requirements.txt).

All calls are fire-and-forget with error handling — persistence
failures must NEVER crash the agent.
"""

import os
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")


async def save_chat_message(
    session_id: str,
    msg_type: str,
    data: dict,
    project_id: Optional[str] = None,
    user_id: Optional[str] = None,
):
    """Save a single chat message to the conversation via session ID."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            body: dict = {"type": msg_type, "data": data}
            if project_id:
                body["projectId"] = project_id
            if user_id:
                body["userId"] = user_id
            resp = await client.post(
                f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}/messages",
                json=body,
            )
            if resp.status_code not in (200, 201):
                logger.warning(
                    f"Chat persistence failed ({resp.status_code}): {resp.text[:200]}"
                )
    except Exception as e:
        logger.warning(f"Chat persistence error: {e}")


async def update_conversation(
    session_id: str,
    updates: dict,
):
    """Update conversation metadata (agentRunning, phase, etc.) by session ID."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.patch(
                f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}",
                json=updates,
            )
            if resp.status_code not in (200, 201):
                logger.warning(
                    f"Conversation update failed ({resp.status_code}): {resp.text[:200]}"
                )
    except Exception as e:
        logger.warning(f"Conversation update error: {e}")
