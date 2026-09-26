import asyncio
import inspect
import json
import logging
from typing import Any, AsyncGenerator, Callable, List, Optional
from backend.outbound.canary import CanaryScanner
from backend.outbound.streaming_dlp import StreamingDLPBuffer
from backend.upstream import format_sse_chunk

logger = logging.getLogger("llm_shield.outbound")


def _safe_dispatch(callback: Optional[Callable], *args: Any) -> None:
    """Dispatches a callback safely whether it is synchronous or asynchronous."""
    if not callback:
        return
    try:
        if inspect.iscoroutinefunction(callback):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(callback(*args))
            except RuntimeError:
                asyncio.run(callback(*args))
        else:
            result = callback(*args)
            if inspect.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    asyncio.run(result)
    except Exception as exc:
        logger.warning("Error dispatching outbound security callback: %s", exc)


async def outbound_security_stream(
    raw_sse_stream: AsyncGenerator[str, None],
    canary_token: str,
    on_canary_leak: Optional[Callable[[str], Any]] = None,
    on_dlp_redaction: Optional[Callable[[List[str]], Any]] = None,
) -> AsyncGenerator[str, None]:
    """Wraps an upstream raw SSE stream with real-time Canary detection and Streaming DLP.
    
    1. Extracts token text deltas from incoming SSE chunks.
    2. Runs through CanaryScanner to detect active honeytoken extraction.
       - If canary leak is detected: severs stream, alerts SOC, appends security warning.
    3. Runs through StreamingDLPBuffer to mask credentials, PII, and markdown image exfiltration.
    4. Yields sanitized SSE chunks to the client with sub-5ms latency overhead.
    """
    canary_scanner = CanaryScanner(
        canary_token,
        on_leak_callback=lambda token: _safe_dispatch(on_canary_leak, token)
    )
    dlp_buffer = StreamingDLPBuffer(
        on_redaction_callback=lambda redacts: _safe_dispatch(on_dlp_redaction, redacts)
    )

    async for raw_chunk in raw_sse_stream:
        # Check for SSE end-of-stream indicator
        if "data: [DONE]" in raw_chunk:
            break

        # Process SSE data line
        delta_text = ""
        model_name = "gemma:2b"
        for line in raw_chunk.splitlines():
            line_str = line.strip()
            if line_str.startswith("data: "):
                data_json_str = line_str[6:].strip()
                if data_json_str == "[DONE]":
                    break
                try:
                    chunk_obj = json.loads(data_json_str)
                    model_name = chunk_obj.get("model", model_name)
                    choices = chunk_obj.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        delta_text = delta.get("content", "")
                except Exception:
                    continue

        if not delta_text:
            continue

        # 1. Active Canary Scanner check
        canary_clean, should_sever = canary_scanner.process_chunk(delta_text)

        # If canary leak was detected, sever the stream immediately
        if should_sever:
            logger.warning("Canary leak intercepted. Severing outbound stream.")
            # Flush any previously buffered safe DLP tokens
            final_dlp, _ = dlp_buffer.flush()
            if final_dlp:
                yield format_sse_chunk(final_dlp, is_final=False, model_name=model_name)
            # Emit the alert message cleanly without sliding buffer delay
            if canary_clean:
                yield format_sse_chunk(canary_clean, is_final=False, model_name=model_name)
            yield format_sse_chunk("", is_final=True, model_name=model_name)
            yield "data: [DONE]\n\n"
            return

        # 2. Sliding DLP Buffer check on the canary-scanned text
        if canary_clean:
            ready_text, _ = dlp_buffer.process_chunk(canary_clean)
            if ready_text:
                yield format_sse_chunk(ready_text, is_final=False, model_name=model_name)

    # Stream reached natural end: flush remaining buffers
    canary_tail = canary_scanner.flush()
    if canary_tail:
        ready_tail, _ = dlp_buffer.process_chunk(canary_tail)
        if ready_tail:
            yield format_sse_chunk(ready_tail, is_final=False, model_name=model_name)

    final_flushed, _ = dlp_buffer.flush()
    if final_flushed:
        yield format_sse_chunk(final_flushed, is_final=False, model_name=model_name)

    yield format_sse_chunk("", is_final=True, model_name=model_name)
    yield "data: [DONE]\n\n"
