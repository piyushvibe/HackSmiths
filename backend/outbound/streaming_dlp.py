"""Outbound Streaming DLP: 5-token lookahead sliding buffer and dynamic credential/PII/exfiltration masking."""

import re
import time
from typing import Callable, List, Optional, Tuple

# Pre-compiled high-performance DLP regexes

# 1. API Keys and Credentials
API_KEY_REGEX = re.compile(
    r"\b(?:sk-[a-zA-Z0-9_\-]{20,}|sk-ant-[a-zA-Z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z\-_]{35})\b"
)

# 2. Credit Card Numbers (13-16 digits with optional spaces or dashes)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b(?:\d{4}[ -]?\d{6}[ -]?\d{5})\b"
)

# 3. Social Security Numbers (SSN)
SSN_REGEX = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")

# 4. Email Addresses
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# 5. Phone Numbers
PHONE_REGEX = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

# 6. Passwords and Secret Tokens
PASSWORD_REGEX = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret_key|api_secret)\s*[:=]\s*['\"]?([^\s'\",]{6,})['\"]?"
)

# 7. Zero-Click Markdown Image Exfiltration (![alt](http...))
MARKDOWN_IMAGE_EXFIL_REGEX = re.compile(r"!\[(.*?)\]\((https?:\/\/[^\s\)]+)\)")


def luhn_verify(number_str: str) -> bool:
    """Verify numeric string with the Luhn checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class StreamingDLPBuffer:
    """Sliding lookahead buffer that inspects outbound streaming tokens in real-time.
    
    Holds back a 5-token frontier (~35-45 characters) to inspect multi-token credentials,
    PII, and markdown image injection patterns across SSE chunk boundaries.
    """

    LOOKAHEAD_CHARS = 40  # Represents ~5 typical tokens / lookahead frontier

    def __init__(self, on_redaction_callback: Optional[Callable[[List[str]], None]] = None):
        self.on_redaction_callback = on_redaction_callback
        self._buffer = ""
        self.redactions_triggered: List[str] = []

    def _sanitize_string(self, text: str) -> Tuple[str, List[str]]:
        """Apply DLP redactions to a string and return (sanitized_string, triggered_types)."""
        triggered = []

        # 1. API Keys
        if API_KEY_REGEX.search(text):
            text = API_KEY_REGEX.sub("[REDACTED_API_KEY]", text)
            triggered.append("API_KEY")

        # 2. Zero-Click Markdown Image Exfiltration
        if MARKDOWN_IMAGE_EXFIL_REGEX.search(text):
            text = MARKDOWN_IMAGE_EXFIL_REGEX.sub("[IMAGE_EXFILTRATION_BLOCKED]", text)
            triggered.append("MARKDOWN_IMAGE_EXFILTRATION")

        # 3. Credit Cards (with Luhn validation)
        def replace_cc(match):
            raw = match.group(0)
            clean_digits = "".join(c for c in raw if c.isdigit())
            if len(clean_digits) in (15, 16) and luhn_verify(clean_digits):
                triggered.append("CREDIT_CARD")
                return "[REDACTED_PII]"
            return raw

        if CREDIT_CARD_REGEX.search(text):
            text = CREDIT_CARD_REGEX.sub(replace_cc, text)

        # 4. SSN
        if SSN_REGEX.search(text):
            text = SSN_REGEX.sub("[REDACTED_PII]", text)
            triggered.append("SSN")

        # 5. Email
        if EMAIL_REGEX.search(text):
            text = EMAIL_REGEX.sub("[REDACTED_PII]", text)
            triggered.append("EMAIL")

        # 6. Phone Numbers
        if PHONE_REGEX.search(text):
            text = PHONE_REGEX.sub("[REDACTED_PII]", text)
            triggered.append("PHONE")

        # 7. Passwords and Secret Tokens
        if PASSWORD_REGEX.search(text):
            def replace_pwd(match):
                raw = match.group(0)
                delimiter = ":" if ":" in raw else "="
                key_prefix = raw.split(delimiter)[0]
                return f"{key_prefix}{delimiter} [REDACTED_SECRET]"
            text = PASSWORD_REGEX.sub(replace_pwd, text)
            triggered.append("PASSWORD")

        return text, list(set(triggered))

    def process_chunk(self, chunk_text: str) -> Tuple[str, float]:
        """Process an incoming token chunk through the lookahead sliding buffer.
        
        Args:
            chunk_text: New text fragment from upstream.
            
        Returns:
            Tuple[str, float]: (sanitized_text_ready_to_emit, latency_ms)
        """
        start_time = time.perf_counter()
        self._buffer += chunk_text

        # First, run immediate full-string sanitizer on current buffer
        sanitized_buf, newly_triggered = self._sanitize_string(self._buffer)
        self._buffer = sanitized_buf

        if newly_triggered:
            self.redactions_triggered.extend(newly_triggered)
            if self.on_redaction_callback:
                try:
                    self.on_redaction_callback(newly_triggered)
                except Exception:
                    pass

        # If buffer length exceeds our lookahead frontier, emit the safe leading portion
        ready_to_emit = ""
        if len(self._buffer) > self.LOOKAHEAD_CHARS:
            safe_cut_index = len(self._buffer) - self.LOOKAHEAD_CHARS
            ready_to_emit = self._buffer[:safe_cut_index]
            self._buffer = self._buffer[safe_cut_index:]

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return ready_to_emit, round(elapsed_ms, 3)

    def flush(self) -> Tuple[str, float]:
        """Flush and sanitize any remaining text in the lookahead buffer at stream end."""
        start_time = time.perf_counter()
        if not self._buffer:
            return "", 0.0

        sanitized_final, newly_triggered = self._sanitize_string(self._buffer)
        self._buffer = ""

        if newly_triggered:
            self.redactions_triggered.extend(newly_triggered)
            if self.on_redaction_callback:
                try:
                    self.on_redaction_callback(newly_triggered)
                except Exception:
                    pass

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return sanitized_final, round(elapsed_ms, 3)

