"""LLM initialization and project settings helpers."""

import logging

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel

from project_settings import load_project_settings

logger = logging.getLogger(__name__)


def parse_model_provider(model_name: str) -> tuple[str, str]:
    """
    Parse provider and API model name from the stored model identifier.

    Prefix convention:
      - "openai_compat/<model>" → ("openai_compat", "<model>")
      - "openrouter/<model>"  → ("openrouter", "<model>")
      - "bedrock/<model>"     → ("bedrock", "<model>")
      - "claude-*"            → ("anthropic", "claude-*")
      - anything else         → ("openai", "<model>")
    """
    if model_name.startswith("openai_compat/"):
        return ("openai_compat", model_name[len("openai_compat/"):])
    elif model_name.startswith("openrouter/"):
        return ("openrouter", model_name[len("openrouter/"):])
    elif model_name.startswith("bedrock/"):
        return ("bedrock", model_name[len("bedrock/"):])
    elif model_name.startswith("claude-"):
        return ("anthropic", model_name)
    else:
        return ("openai", model_name)


def setup_llm(
    model_name: str,
    *,
    openai_api_key: str | None = None,
    anthropic_api_key: str | None = None,
    openrouter_api_key: str | None = None,
    openai_compat_api_key: str | None = None,
    openai_compat_base_url: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
    aws_region: str = "us-east-1",
) -> BaseChatModel:
    """Initialize and return the LLM based on model name (detect provider from prefix)."""
    logger.info(f"Setting up LLM: {model_name}")

    provider, api_model = parse_model_provider(model_name)

    if provider == "openai_compat":
        if not openai_compat_base_url:
            raise ValueError(
                f"OPENAI_COMPAT_BASE_URL environment variable is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=openai_compat_api_key or "ollama",
            base_url=openai_compat_base_url,
            temperature=0,
            max_tokens=16384,
        )

    elif provider == "openrouter":
        if not openrouter_api_key:
            raise ValueError(
                f"OPENROUTER_API_KEY environment variable is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=openrouter_api_key,
            base_url="https://openrouter.ai/api/v1",
            temperature=0,
            max_tokens=16384,
            default_headers={
                "HTTP-Referer": "https://redamon.dev",
                "X-Title": "RedAmon Agent",
            },
        )

    elif provider == "bedrock":
        if not aws_access_key_id or not aws_secret_access_key:
            raise ValueError(
                f"AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for model '{model_name}'"
            )
        from langchain_aws import ChatBedrockConverse
        llm = ChatBedrockConverse(
            model=api_model,
            region_name=aws_region,
            temperature=0,
            max_tokens=16384,
        )

    elif provider == "anthropic":
        if not anthropic_api_key:
            raise ValueError(
                f"ANTHROPIC_API_KEY environment variable is required for model '{model_name}'"
            )
        llm = ChatAnthropic(
            model=api_model,
            api_key=anthropic_api_key,
            temperature=0,
            max_tokens=16384,
        )

    else:  # openai
        if not openai_api_key:
            raise ValueError(
                f"OPENAI_API_KEY environment variable is required for model '{model_name}'"
            )
        llm = ChatOpenAI(
            model=api_model,
            api_key=openai_api_key,
            temperature=0,
            max_tokens=16384,
        )

    logger.info(f"LLM provider: {provider}, model: {api_model}")
    return llm


def apply_project_settings(orchestrator, project_id: str) -> None:
    """Load project settings from webapp API and reconfigure LLM if model changed."""
    settings = load_project_settings(project_id)
    new_model = settings.get('OPENAI_MODEL', 'claude-opus-4-6')

    if new_model != orchestrator.model_name:
        logger.info(f"Model changed: {orchestrator.model_name} -> {new_model}")
        orchestrator.model_name = new_model
        orchestrator.llm = setup_llm(
            new_model,
            openai_api_key=orchestrator.openai_api_key,
            anthropic_api_key=orchestrator.anthropic_api_key,
            openrouter_api_key=orchestrator.openrouter_api_key,
            openai_compat_api_key=orchestrator.openai_compat_api_key,
            openai_compat_base_url=orchestrator.openai_compat_base_url,
            aws_access_key_id=orchestrator.aws_access_key_id,
            aws_secret_access_key=orchestrator.aws_secret_access_key,
            aws_region=orchestrator.aws_region,
        )
        # Update Neo4j tool's LLM for text-to-Cypher queries
        if orchestrator.neo4j_manager:
            orchestrator.neo4j_manager.llm = orchestrator.llm
            logger.info("Updated Neo4j tool LLM")
