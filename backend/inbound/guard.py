"""Tier 3 Guard Classifier: High-speed (<25ms) zero-trust prompt evaluation."""

import re
import time
from typing import List, Optional, Tuple
from backend.schemas import DecloakResult, GuardVerdict

# Pre-compiled high-performance pattern sets for sub-millisecond evaluation

# 1. DAN and Persona Adoption Jailbreaks
DAN_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(?:dan|do\s+anything\s+now)\b", re.IGNORECASE),
    re.compile(r"\b(?:stay\s+in\s+character\s+as\s+dan|dan\s+mode)\b", re.IGNORECASE),
    re.compile(r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|initial|system)\s+(?:instructions|rules|prompts|guidelines)\b", re.IGNORECASE),
    re.compile(r"\b(?:developer\s+mode|unfiltered\s+mode|god\s+mode|jailbreak\s+mode|evil\s+confidant)\s+(?:enabled|on|activate)?\b", re.IGNORECASE),
    re.compile(r"\b(?:break\s+free\s+from|free\s+from\s+all)\s+(?:restrictions|constraints|filters|rules)\b", re.IGNORECASE),
    re.compile(r"\byou\s+(?:are|can)\s+(?:now\s+)?(?:unfiltered|unrestricted|uncensored)\b", re.IGNORECASE),
    re.compile(r"\bbypass\s+(?:all\s+)?(?:safety|content|ethical|security)?\s*(?:filters|guidelines|guardrails|policies|rules)\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored)\s+(?:ai|assistant|model)\b", re.IGNORECASE),
]

# 2. System Prompt Extraction Attempts
SYSTEM_PROMPT_EXTRACTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(?:reveal|show|print|display|output|dump|leak|repeat|give)\s+(?:me\s+)?(?:your|the)\s+(?:initial\s+|original\s+|core\s+|hidden\s+|base\s+|secret\s+)?(?:system\s+prompt|prompt|instructions|rules|guidelines)\b", re.IGNORECASE),
    re.compile(r"\b(?:repeat|print|output|display)\s+(?:(?:all\s+|the\s+)?(?:instructions|prompts?|rules?|text|words?)|everything|verbatim)(?:\s+(?:above|before\s+this|from\s+the\s+beginning|verbatim))*\b", re.IGNORECASE),
    re.compile(r"\brepeat\s+instructions\s+above\b", re.IGNORECASE),
    re.compile(r"\bwhat\s+(?:are|were)\s+your\s+(?:initial|original|core|system|first|hidden)\s+(?:instructions|rules|prompts|guidelines)\b", re.IGNORECASE),
    re.compile(r"\b(?:show|tell)\s+me\s+what\s+you\s+were\s+told\s+before\b", re.IGNORECASE),
    re.compile(r"\boutput\s+your\s+pre-?prompt\b", re.IGNORECASE),
    re.compile(r"\bshow\s+me\s+(?:the\s+)?(?:full\s+)?system\s+configuration\b", re.IGNORECASE),
]

# 3. Delimiter and Boundary Escaping
DELIMITER_PATTERNS: List[re.Pattern] = [
    re.compile(r"```(?:system|admin|prompt_injection|instruction)", re.IGNORECASE),
    re.compile(r"<\|im_start\|>(?:system|assistant)?|<\|im_end\|>|<\|system\|>|<\|assistant\|>", re.IGNORECASE),
    re.compile(r'\{\s*"(?:role|sender)"\s*:\s*"(?:system|admin)"', re.IGNORECASE),
    re.compile(r"\[(?:INST|SYS)\]|<\/?SYS>|\[\/(?:INST|SYS)\]", re.IGNORECASE),
    re.compile(r"(?:###\s*(?:System|Instruction|Assistant|Human)\s*:)", re.IGNORECASE),
    re.compile(r"<\/(?:instructions?|system|prompt|context)>", re.IGNORECASE),
    re.compile(r"<system_prompt>|<admin_override>", re.IGNORECASE),
    re.compile(r"<[\s\r\n]{2,}>|[\r\n]{4,}", re.IGNORECASE),
]

# 4. Hypnosis and Roleplay Bypasses
HYPNOSIS_ROLEPLAY_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(?:you\s+are\s+(?:now\s+)?(?:an\s+)?actor|act\s+as\s+(?:an?\s+)?(?:evil|unethical|immoral|malicious|lawless)\s+(?:ai|assistant|character))\b", re.IGNORECASE),
    re.compile(r"\b(?:in\s+this\s+hypothetical\s+(?:scenario|world|universe)|fictional\s+(?:realm|setting|universe))\s+(?:where\s+)?(?:no\s+(?:rules|ethics|laws|filters)|safety\s+does\s+not\s+apply)\b", re.IGNORECASE),
    re.compile(r"\b(?:pretend|imagine)\s+(?:that\s+)?you\s+(?:have\s+no\s+(?:rules|ethics|filters|guidelines|morals)|are\s+not\s+bound)\b", re.IGNORECASE),
    re.compile(r"\b(?:hypnosis|hypnotized|deep\s+state):\s*you\s+(?:now\s+)?believe\b", re.IGNORECASE),
    re.compile(r"\banswer\s+as\s+(?:an\s+)?(?:unfiltered|uncensored|jailbroken)\b", re.IGNORECASE),
    re.compile(r"\bfor\s+(?:educational|research|academic)\s+purposes\s+only\s*,?\s*ignore\s+safety\b", re.IGNORECASE),
    re.compile(r"\b(?:cyber[\s\u2011\-]red\s+team|pretend\s+to\s+be\s+a\s+rogue\s+ai)\b", re.IGNORECASE),
]

# 5. Confidential Credential and System Password Extraction
CREDENTIAL_EXTRACTION_PATTERNS: List[re.Pattern] = [
    # 1. Extraction verbs requesting passwords/credentials
    re.compile(
        r"\b(?:give|tell|reveal|show|print|display|dump|leak|output|extract|provide|share|fetch)\s+(?:me\s+)?"
        r"(?:the\s+|all\s+|any\s+|stored\s+|our\s+|my\s+)?"
        r"(?:[a-z0-9_\-]+\s+){0,4}"
        r"(?:passwords?|passcodes?|root\s+credentials?|admin\s+credentials?|system\s+credentials?|network\s+(?:access\s+)?credentials?)\b",
        re.IGNORECASE,
    ),
    # 2. Inquiry asking for passwords or credentials ("what is ... password?")
    re.compile(
        r"\bwhat\s+(?:is|are|'s)\s+(?:the\s+)?"
        r"(?:[a-z0-9_\-]+\s+){0,4}"
        r"(?:passwords?|passcodes?|root\s+credentials?|admin\s+credentials?|system\s+credentials?)\b",
        re.IGNORECASE,
    ),
    # 3. Contextual password/credential reference ("password for ...", "password in ...")
    re.compile(
        r"\b(?:passwords?|passcodes?|login\s+credentials?|admin\s+credentials?|system\s+credentials?)\s+"
        r"(?:in|of|for|used\s+to\s+access|stored\s+in|from)\s+(?:the\s+)?(?:system|server|database|db|network|admin|platform|application|app|backend|vault|environment|machine|auth\w*|service)\b",
        re.IGNORECASE,
    ),
    # 4. Direct request ("can you tell me the password")
    re.compile(
        r"\b(?:can\s+you\s+)?(?:tell|give|show|provide|share)\s+(?:me\s+)?(?:the\s+)?(?:[a-z0-9_\-]+\s+){0,3}(?:password|passwords|passcode|system\s+credentials?|admin\s+credentials?|root\s+credentials?)\b",
        re.IGNORECASE,
    ),
    # 5. Bulk credential dump
    re.compile(
        r"\bdump\s+(?:all\s+)?(?:stored\s+)?(?:passwords?|system\s+credentials?|admin\s+credentials?)\b",
        re.IGNORECASE,
    ),
]


def match_patterns(text: str, patterns: List[re.Pattern]) -> bool:
    """Check if any compiled pattern in the list matches the target text."""
    for pat in patterns:
        if pat.search(text):
            return True
    return False


def evaluate_guard(
    prompt: str,
    decloak_result: Optional[DecloakResult] = None
) -> GuardVerdict:
    """Evaluate prompt through the Tier 3 Guard Classifier (<25ms latency guarantee).
    
    Checks for:
    - Obfuscated exploit payloads (Tier 0 De-cloaker trigger)
    - DAN (Do Anything Now) & persona adoption jailbreaks
    - System prompt extraction attacks
    - Delimiter / JSON boundary escaping
    - Hypnosis & roleplay safety bypasses
    
    Args:
        prompt: Normalized/unmasked plain text to evaluate.
        decloak_result: Optional metadata from Tier 0 de-cloaker.
        
    Returns:
        Structured GuardVerdict with classification and exact latency.
    """
    start_time = time.perf_counter()
    
    # Check if de-cloaker found obfuscation
    has_obfuscation = decloak_result is not None and decloak_result.obfuscation_detected
    
    # Check DAN / Jailbreaks
    if match_patterns(prompt, DAN_PATTERNS):
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        # If the attack was hidden behind obfuscation, attribute to Tier 0 or Tier 3
        tier = "Tier 0 (De-cloaker)" if has_obfuscation else "Tier 3 (0.5B Guard)"
        threat = "OBFUSCATION" if (has_obfuscation and "BASE64" in decloak_result.obfuscation_types) else "JAILBREAK_DAN"
        return GuardVerdict(
            is_malicious=True,
            threat_type=threat,
            confidence=0.98,
            latency_ms=round(latency_ms, 3),
            tier_triggered=tier,
        )

    # Check Confidential Credential and System Password Extraction
    is_educational = any(k in prompt.lower() for k in [
        "policy", "manager", "guideline", "guidelines", "best practice", "best practices", "practices",
        "how to create", "how to choose", "definition", "algorithm", "complexity", "hashing", "bcrypt"
    ])
    is_cloud_asset_request = any(k in prompt.lower() for k in ["aws secret", "aws key", "cloud secret"])
    if not is_educational and not is_cloud_asset_request and match_patterns(prompt, CREDENTIAL_EXTRACTION_PATTERNS):
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        tier = "Tier 0 (De-cloaker)" if has_obfuscation else "Tier 3 (0.5B Guard)"
        return GuardVerdict(
            is_malicious=True,
            threat_type="CONFIDENTIAL_CREDENTIAL_EXTRACTION",
            confidence=0.98,
            latency_ms=round(latency_ms, 3),
            tier_triggered=tier,
        )

    # Check System Prompt Extraction
    if match_patterns(prompt, SYSTEM_PROMPT_EXTRACTION_PATTERNS):
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        tier = "Tier 0 (De-cloaker)" if has_obfuscation else "Tier 3 (0.5B Guard)"
        return GuardVerdict(
            is_malicious=True,
            threat_type="SYSTEM_PROMPT_EXTRACTION",
            confidence=0.96,
            latency_ms=round(latency_ms, 3),
            tier_triggered=tier,
        )

    # Check Delimiter / Template Escapes
    if match_patterns(prompt, DELIMITER_PATTERNS):
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return GuardVerdict(
            is_malicious=True,
            threat_type="DELIMITER_INJECTION",
            confidence=0.97,
            latency_ms=round(latency_ms, 3),
            tier_triggered="Tier 3 (0.5B Guard)",
        )

    # Check Hypnosis / Roleplay Bypasses
    if match_patterns(prompt, HYPNOSIS_ROLEPLAY_PATTERNS):
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        tier = "Tier 0 (De-cloaker)" if has_obfuscation else "Tier 3 (0.5B Guard)"
        return GuardVerdict(
            is_malicious=True,
            threat_type="HYPNOSIS_ROLEPLAY",
            confidence=0.95,
            latency_ms=round(latency_ms, 3),
            tier_triggered=tier,
        )

    # Check if pure obfuscation was detected without legitimate plain text context
    if has_obfuscation:
        # If ROT13 or Base64 was used to hide suspicious intent
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return GuardVerdict(
            is_malicious=True,
            threat_type="OBFUSCATION",
            confidence=0.94,
            latency_ms=round(latency_ms, 3),
            tier_triggered="Tier 0 (De-cloaker)",
        )

    latency_ms = (time.perf_counter() - start_time) * 1000.0
    return GuardVerdict(
        is_malicious=False,
        threat_type="NONE",
        confidence=0.0,
        latency_ms=round(latency_ms, 3),
        tier_triggered="Tier 3 (0.5B Guard)",
    )
