"""
Model provider discovery for RedAmon Agent.

Fetches available models from configured AI providers (OpenAI, Anthropic,
OpenAI-compatible endpoints, OpenRouter, AWS Bedrock) and returns them in a
unified format for the frontend.
Results are cached in memory for 1 hour.
"""

import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
_cache: dict[str, Any] = {}
_cache_ts: float = 0.0
CACHE_TTL = 3600  # 1 hour


def _is_cache_valid() -> bool:
    return bool(_cache) and (time.time() - _cache_ts) < CACHE_TTL


def invalidate_cache() -> None:
    global _cache, _cache_ts
    _cache = {}
    _cache_ts = 0.0


# ---------------------------------------------------------------------------
# Unified model schema
# ---------------------------------------------------------------------------
def _model(id: str, name: str, context_length: int | None = None,
           description: str = "") -> dict:
    return {
        "id": id,
        "name": name,
        "context_length": context_length,
        "description": description,
    }


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------
async def fetch_openai_models() -> list[dict]:
    """Fetch chat models from the OpenAI API."""
    api_key = os.getenv("OPENAI_API_KEY", "")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp.raise_for_status()

    data = resp.json().get("data", [])

    # Keep only chat-capable models (gpt-*, o1-*, o3-*)
    chat_prefixes = ("gpt-", "o1-", "o3-", "o4-")
    # Exclude known non-chat suffixes
    exclude_suffixes = ("-instruct", "-realtime", "-transcribe", "-tts", "-search",
                        "-audio", "-mini-tts")
    exclude_substrings = ("dall-e", "whisper", "embedding", "moderation", "davinci",
                          "babbage", "curie")

    models = []
    for m in data:
        mid = m.get("id", "")
        if not any(mid.startswith(p) for p in chat_prefixes):
            continue
        if any(mid.endswith(s) for s in exclude_suffixes):
            continue
        if any(sub in mid for sub in exclude_substrings):
            continue
        models.append(_model(
            id=mid,
            name=mid,
            description="OpenAI",
        ))

    # Sort: newest/largest first (reverse alphabetical is a rough proxy)
    models.sort(key=lambda m: m["id"], reverse=True)
    return models


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------
async def fetch_anthropic_models() -> list[dict]:
    """Fetch models from the Anthropic API."""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            params={"limit": 100},
        )
        resp.raise_for_status()

    data = resp.json().get("data", [])
    models = []
    for m in data:
        mid = m.get("id", "")
        display_name = m.get("display_name", mid)
        models.append(_model(
            id=mid,
            name=display_name,
            description="Anthropic",
        ))

    return models


# ---------------------------------------------------------------------------
# OpenAI-Compatible
# ---------------------------------------------------------------------------
async def fetch_openai_compat_models() -> list[dict]:
    """Fetch models from a user-configured OpenAI-compatible API endpoint."""
    base_url = os.getenv("OPENAI_COMPAT_BASE_URL", "").rstrip("/")
    api_key = os.getenv("OPENAI_COMPAT_API_KEY", "") or "ollama"

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp.raise_for_status()
    data = resp.json().get("data", [])

    models = []
    for m in data:
        mid = m.get("id", "")
        if not mid:
            continue
        models.append(_model(
            id=f"openai_compat/{mid}",
            name=mid,
            description="OpenAI-Compatible",
        ))

    models.sort(key=lambda m: m["id"])
    return models


# ---------------------------------------------------------------------------
# OpenRouter
# ---------------------------------------------------------------------------
async def fetch_openrouter_models() -> list[dict]:
    """Fetch models from the OpenRouter API."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get("https://openrouter.ai/api/v1/models")
        resp.raise_for_status()

    data = resp.json().get("data", [])

    models = []
    for m in data:
        mid = m.get("id", "")
        name = m.get("name", mid)
        ctx = m.get("context_length")

        # Only include models that accept text input and produce text output
        arch = m.get("architecture", {})
        input_mods = arch.get("input_modalities", [])
        output_mods = arch.get("output_modalities", [])
        if "text" not in input_mods or "text" not in output_mods:
            continue

        # Build pricing description
        pricing = m.get("pricing", {})
        prompt_cost = pricing.get("prompt", "0")
        completion_cost = pricing.get("completion", "0")
        try:
            p_cost = float(prompt_cost) * 1_000_000
            c_cost = float(completion_cost) * 1_000_000
            price_desc = f"${p_cost:.2f}/${c_cost:.2f} per 1M tokens"
        except (ValueError, TypeError):
            price_desc = ""

        models.append(_model(
            id=f"openrouter/{mid}",
            name=name,
            context_length=ctx,
            description=price_desc,
        ))

    return models


# ---------------------------------------------------------------------------
# AWS Bedrock
# ---------------------------------------------------------------------------
async def fetch_bedrock_models() -> list[dict]:
    """Fetch foundation models from AWS Bedrock."""
    import asyncio

    def _list_models() -> list[dict]:
        import boto3
        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        client = boto3.client("bedrock", region_name=region)
        response = client.list_foundation_models(
            byOutputModality="TEXT",
            byInferenceType="ON_DEMAND",
        )
        summaries = response.get("modelSummaries", [])

        results = []
        for m in summaries:
            mid = m.get("modelId", "")
            name = m.get("modelName", mid)
            provider = m.get("providerName", "")
            input_mods = m.get("inputModalities", [])
            output_mods = m.get("outputModalities", [])
            inference_types = m.get("inferenceTypesSupported", [])
            lifecycle = m.get("modelLifecycle", {}).get("status", "")
            streaming = m.get("responseStreamingSupported", False)

            # Only include active, on-demand, text-in/text-out, streaming models
            if "ON_DEMAND" not in inference_types:
                continue
            if "TEXT" not in input_mods or "TEXT" not in output_mods:
                continue
            if lifecycle != "ACTIVE":
                continue
            if not streaming:
                continue

            results.append(_model(
                id=f"bedrock/{mid}",
                name=f"{name} ({provider})",
                description=f"AWS Bedrock — {provider}",
            ))

        return results

    # Run boto3 call in a thread to avoid blocking the event loop
    return await asyncio.to_thread(_list_models)


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------
async def fetch_all_models() -> dict[str, list[dict]]:
    """
    Fetch models from all configured providers in parallel.

    Returns a dict keyed by provider display name, each containing a list
    of model dicts with {id, name, context_length, description}.
    Uses an in-memory cache (1 hour TTL).
    """
    global _cache, _cache_ts

    if _is_cache_valid():
        return _cache

    import asyncio

    tasks: dict[str, Any] = {}

    if os.getenv("OPENAI_API_KEY"):
        tasks["OpenAI (Direct)"] = fetch_openai_models()
    if os.getenv("OPENAI_COMPAT_BASE_URL"):
        tasks["OpenAI-Compatible"] = fetch_openai_compat_models()
    if os.getenv("ANTHROPIC_API_KEY"):
        tasks["Anthropic (Direct)"] = fetch_anthropic_models()
    if os.getenv("OPENROUTER_API_KEY"):
        tasks["OpenRouter"] = fetch_openrouter_models()
    if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
        tasks["AWS Bedrock"] = fetch_bedrock_models()

    if not tasks:
        return {}

    results: dict[str, list[dict]] = {}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)

    for provider, result in zip(tasks.keys(), gathered):
        if isinstance(result, Exception):
            logger.warning(f"Failed to fetch models from {provider}: {result}")
            results[provider] = []
        else:
            results[provider] = result

    _cache = results
    _cache_ts = time.time()

    total = sum(len(v) for v in results.values())
    logger.info(f"Fetched {total} models from {len(results)} providers (cached for {CACHE_TTL}s)")

    return results
