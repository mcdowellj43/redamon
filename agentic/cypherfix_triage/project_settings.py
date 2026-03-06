"""Load CypherFix settings from the webapp API."""

import httpx
import logging
import os

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")


async def load_cypherfix_settings(project_id: str) -> dict:
    """Fetch cypherfix settings from webapp API."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{WEBAPP_API_URL}/api/projects/{project_id}")
            resp.raise_for_status()
            project = resp.json()
            return {
                "github_token": project.get("cypherfixGithubToken", ""),
                "default_repo": project.get("cypherfixDefaultRepo", ""),
                "default_branch": project.get("cypherfixDefaultBranch", "main"),
                "branch_prefix": project.get("cypherfixBranchPrefix", "cypherfix/"),
                "require_approval": project.get("cypherfixRequireApproval", True),
                "llm_model": project.get("cypherfixLlmModel", "") or project.get("agentOpenaiModel", ""),
                "openai_api_key": project.get("agentOpenaiApiKey", ""),
            }
    except Exception as e:
        logger.error(f"Failed to load cypherfix settings: {e}")
        return {}
