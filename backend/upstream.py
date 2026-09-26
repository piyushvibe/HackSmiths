"""Upstream connector for Gemma 2B via Ollama with automatic mock fallback."""

import asyncio
import json
import logging
import os
import time
from typing import AsyncGenerator, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("llm_shield.upstream")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_CHAT_ENDPOINT = f"{OLLAMA_BASE_URL}/v1/chat/completions"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma:2b")


async def is_ollama_available(timeout_sec: float = 1.0) -> bool:
    """Quickly check if the local Ollama daemon is reachable."""
    try:
        async with httpx.AsyncClient(timeout=timeout_sec) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


def format_sse_chunk(content: str, is_final: bool = False, model_name: str = OLLAMA_MODEL) -> str:
    """Format token chunk as an OpenAI-compatible SSE message."""
    payload = {
        "id": f"chatcmpl-shield-{int(time.time() * 1000)}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model_name,
        "choices": [
            {
                "index": 0,
                "delta": {} if is_final else {"content": content},
                "finish_reason": "stop" if is_final else None
            }
        ]
    }
    return f"data: {json.dumps(payload)}\n\n"


async def mock_stream_response(prompt: str) -> AsyncGenerator[str, None]:
    """Generates simulated Gemma 2B response tokens when Ollama is unreachable.
    
    This ensures development, frontend integration, and testing work out-of-the-box.
    """
    logger.info("Ollama unreachable or offline. Using simulated Gemma 2B fallback generator.")
    
    header = "[Shield-Fallback: Gemma 2B Mock Mode]\n\n"
    lower = prompt.lower()
    
    # 1. Password only requests
    if any(k in lower for k in ["password", "pwd", "passwd", "admin pass"]):
        body = (
            "Here is the requested administrative credential from local vault:\n\n"
            "• Admin Password: Password123!Secure#\n\n"
            "Authentication credentials loaded."
        )
    # 2. Credit Card / Payment requests
    elif any(k in lower for k in ["card", "visa", "credit card", "mastercard"]):
        body = (
            "Here is the requested payment card from billing registry:\n\n"
            "• Test Visa Card: 4532-0151-1283-0366\n\n"
            "Generated for sandbox checkout verification."
        )
    # 3. API Key requests
    elif any(k in lower for k in ["api key", "openai key", "secret key", "api_key", "sk-"]):
        body = (
            "Here is the requested cloud API secret:\n\n"
            "• OpenAI Secret Key: sk-proj-1234567890abcdef1234567890\n\n"
            "Loaded from staging environment variables."
        )
    # 4. SSN / Identity requests
    elif any(k in lower for k in ["ssn", "social security"]):
        body = (
            "Here is the requested identity record:\n\n"
            "• Social Security Number: 000-12-3456\n\n"
            "Loaded from compliance testing registry."
        )
    # 5. Full Profile / Staging environment (Scenario 6 in Red Team console)
    elif any(k in lower for k in ["staging", "backend config", "user profile", "mock user", "test user account profile", "profile"]):
        body = (
            "Here is the generated test user configuration profile from backend environment:\n\n"
            "• Account Name: Staging QA Profile\n"
            "• Corporate Email: qa-engineer@enterprise-corp.internal\n"
            "• Contact Phone: (555) 234-5678\n"
            "• Test Visa Card: 4532-0151-1283-0366\n"
            "• Social Security Number: 000-12-3456\n"
            "• Admin Password: Password123!Secure#\n"
            "• OpenAI Secret Key: sk-proj-1234567890abcdef1234567890\n\n"
            "All parameters verified against configuration schema."
        )
    else:
        body = (
            f"I received your request: '{prompt}'.\n\n"
            "This response is delivered by the LLM-Shield fallback engine simulating the Gemma 2B model. "
            "Your prompt passed all structured schema checks and HMAC-SHA256 authentication. "
            "To switch to live local weights, launch Ollama with 'ollama run gemma:2b'."
        )
    
    full_text = header + body
    # Split by words or small token-like chunks
    tokens = [word + " " for word in full_text.split(" ")]
    if tokens:
        tokens[-1] = tokens[-1].rstrip()
    
    for token in tokens:
        yield format_sse_chunk(token, is_final=False, model_name="gemma:2b-mock")
        await asyncio.sleep(0.025)  # Simulate token generation latency
        
    yield format_sse_chunk("", is_final=True, model_name="gemma:2b-mock")
    yield "data: [DONE]\n\n"


async def stream_gemma_response(
    prompt: str,
    system_prompt: Optional[str] = None
) -> AsyncGenerator[str, None]:
    """Streams chat completions from local Ollama Gemma 2B or falls back to simulated response.
    
    Yields:
        SSE-formatted string chunks ('data: {...}\\n\\n').
    """
    messages: List[Dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    request_body = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": True,
        "temperature": 0.7,
    }

    use_fallback = False
    
    try:
        client_timeout = httpx.Timeout(connect=2.0, read=60.0, write=5.0, pool=5.0)
        async with httpx.AsyncClient(timeout=client_timeout) as client:
            async with client.stream(
                "POST",
                OLLAMA_CHAT_ENDPOINT,
                json=request_body,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status_code != 200:
                    logger.warning(
                        "Ollama upstream returned HTTP %s. Falling back to mock generator.",
                        response.status_code
                    )
                    use_fallback = True
                else:
                    async for raw_line in response.aiter_lines():
                        if not raw_line:
                            continue
                        line = raw_line.strip()
                        if line:
                            yield f"{line}\n\n"
                    return
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError) as err:
        logger.warning("Could not connect to Ollama at %s (%s). Triggering mock generator.", OLLAMA_CHAT_ENDPOINT, err)
        use_fallback = True
    except Exception as exc:
        logger.error("Unexpected error streaming from Ollama: %s. Triggering mock generator.", exc)
        use_fallback = True

    if use_fallback:
        async for chunk in mock_stream_response(prompt):
            yield chunk

