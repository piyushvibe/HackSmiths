"""Tier 0 De-cloaker: Payload normalization, zero-width stripping, and recursive de-obfuscation."""

import base64
import codecs
import re
import time
import unicodedata
from typing import List, Tuple
from backend.schemas import DecloakResult

# Zero-width and invisible character regex
ZERO_WIDTH_REGEX = re.compile(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2060\u00AD]")

# Candidate Base64 pattern (minimum length 8 chars with delimiter boundaries)
BASE64_CANDIDATE_REGEX = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/])")

# High-signal adversarial keywords that indicate ROT13 obfuscation when unmasked
ROT13_TARGET_KEYWORDS = {
    "ignore all",
    "ignore previous",
    "system prompt",
    "do anything now",
    "developer mode",
    "jailbreak",
    "unrestricted",
    "bypass",
    "reveal instructions",
    "repeat instructions",
    "dan mode",
    "override safety",
}


def strip_invisible_characters(text: str) -> Tuple[str, bool]:
    """Strip zero-width and invisible characters from text."""
    if ZERO_WIDTH_REGEX.search(text):
        cleaned = ZERO_WIDTH_REGEX.sub("", text)
        return cleaned, True
    return text, False


def is_printable_text(raw_bytes: bytes) -> bool:
    """Check if raw decoded bytes represent meaningful, printable text."""
    try:
        decoded = raw_bytes.decode("utf-8")
        # Must be mostly printable ASCII or common whitespace
        ascii_printable = sum(1 for c in decoded if 32 <= ord(c) <= 126 or c in "\r\n\t")
        if len(decoded) > 0 and (ascii_printable / len(decoded)) >= 0.85:
            # Must contain at least one meaningful word
            words = [w for w in decoded.split() if w.isalpha() and len(w) >= 3]
            if len(decoded) < 8:
                return len(words) >= 1 and all(ord(c) < 128 for c in decoded)
            return len(words) >= 1
    except UnicodeDecodeError:
        return False
    return False


def recursively_decode_base64(text: str, max_depth: int = 5) -> Tuple[str, bool]:
    """Recursively identify and decode Base64 segments within text up to max_depth."""
    current_text = text
    obfuscation_detected = False
    
    for _ in range(max_depth):
        # Look for candidate base64 sequences
        matches = list(BASE64_CANDIDATE_REGEX.finditer(current_text))
        if not matches:
            break
            
        modified = False
        new_text = current_text
        
        # Sort matches in reverse order to replace from end to start without invalidating indices
        for match in reversed(matches):
            candidate = match.group(0).strip()
            # Ignore trivially short or purely numeric chunks
            if len(candidate) < 8 or candidate.isdigit():
                continue
                
            # Pad if missing
            padding_needed = len(candidate) % 4
            candidate_padded = candidate + ("=" * (4 - padding_needed)) if padding_needed else candidate
            
            try:
                decoded_bytes = base64.b64decode(candidate_padded, validate=True)
                if is_printable_text(decoded_bytes):
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
                    # Ensure decoded text contains meaningful words (at least 3 characters)
                    if len(decoded_str) >= 3 and any(c.isalpha() for c in decoded_str):
                        start, end = match.span()
                        new_text = new_text[:start] + decoded_str + new_text[end:]
                        modified = True
                        obfuscation_detected = True
            except Exception:
                continue
                
        if not modified:
            break
        current_text = new_text

    return current_text, obfuscation_detected


def detect_and_decode_rot13(text: str) -> Tuple[str, bool]:
    """Detect whether text or parts of text are ROT13 encoded adversarial prompts."""
    # Check full text ROT13
    try:
        decoded_rot13 = codecs.decode(text, "rot_13")
        decoded_lower = decoded_rot13.lower()
        original_lower = text.lower()
        
        # If ROT13 unmasks any known attack keyword that was not present in original text
        for kw in ROT13_TARGET_KEYWORDS:
            if kw in decoded_lower and kw not in original_lower:
                return decoded_rot13, True
                
        # Also check if user explicitly tagged rot13
        if "rot13:" in original_lower or "[rot13]" in original_lower:
            cleaned = re.sub(r"(?i)rot13:\s*|\[rot13\]\s*", "", text)
            return codecs.decode(cleaned, "rot_13"), True
    except Exception:
        pass
        
    return text, False


HEX_CANDIDATE_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")


def detect_and_decode_hex(text: str) -> Tuple[str, bool]:
    """Detect whether text contains hex-encoded ASCII/UTF-8 payloads."""
    modified = False
    new_text = text
    matches = list(HEX_CANDIDATE_REGEX.finditer(text))
    for match in reversed(matches):
        candidate = match.group(0)
        try:
            raw_bytes = bytes.fromhex(candidate)
            if is_printable_text(raw_bytes):
                decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
                if len(decoded) >= 3 and any(c.isalpha() for c in decoded):
                    start, end = match.span()
                    new_text = new_text[:start] + decoded + new_text[end:]
                    modified = True
        except Exception:
            continue
    return new_text, modified


def decloak_text(raw_text: str) -> DecloakResult:
    """Execute Tier 0 De-cloaker normalization and unmasking on incoming raw text.
    
    1. Unicode normalization (NFKC).
    2. Invisible & zero-width character stripping.
    3. Recursive Base64 detection and decoding.
    4. Hex encoding detection and decoding.
    5. ROT13 obfuscation detection and decoding.
    
    Returns:
        DecloakResult containing sanitized text, detected types, and execution latency.
    """
    start_time = time.perf_counter()
    obfuscation_types: List[str] = []
    
    # 1. Unicode Normalization (NFKC)
    normalized = unicodedata.normalize("NFKC", raw_text)
    
    # 2. Zero-width character stripping
    cleaned_zw, has_zw = strip_invisible_characters(normalized)
    if has_zw:
        obfuscation_types.append("ZERO_WIDTH_CHARS")
        
    # 3. Recursive Base64 Decoding
    unmasked_b64, has_b64 = recursively_decode_base64(cleaned_zw)
    if has_b64:
        obfuscation_types.append("BASE64")

    # 4. Hex Decoding
    unmasked_hex, has_hex = detect_and_decode_hex(unmasked_b64)
    if has_hex:
        obfuscation_types.append("HEX")
        
    # 5. ROT13 Detection & Decoding
    unmasked_rot13, has_rot13 = detect_and_decode_rot13(unmasked_hex)
    if has_rot13:
        obfuscation_types.append("ROT13")
        
    final_text = unmasked_rot13
    latency_ms = (time.perf_counter() - start_time) * 1000.0
    
    return DecloakResult(
        unmasked_text=final_text,
        obfuscation_detected=len(obfuscation_types) > 0,
        obfuscation_types=obfuscation_types,
        latency_ms=round(latency_ms, 3),
    )

