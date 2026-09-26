"""Adaptive Risk Engine for LLM-Shield.

Calculates dynamic session and request risk scores (0–100) using a transparent 6-factor model:
Risk = AuthRisk + DeviceRisk + BehaviorRisk + RateRisk + PromptRisk + DataSensitivityRisk

Interpretation:
- 0–30:   LOW RISK    -> Access Granted
- 31–60:  MEDIUM RISK -> Additional Verification Required / Limited Access
- 61–100: HIGH RISK   -> Access Restricted, Step-Up MFA Triggered (Demo OTP: 123456)
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from backend.database import get_db_connection, record_security_event, update_session_risk


@dataclass
class RiskFactorBreakdown:
    auth_risk: int = 0
    device_risk: int = 0
    behavior_risk: int = 0
    rate_risk: int = 0
    prompt_risk: int = 0
    data_sensitivity_risk: int = 0

    @property
    def total(self) -> int:
        score = (
            self.auth_risk
            + self.device_risk
            + self.behavior_risk
            + self.rate_risk
            + self.prompt_risk
            + self.data_sensitivity_risk
        )
        return max(0, min(100, score))

    @property
    def level(self) -> str:
        s = self.total
        if s <= 30:
            return "LOW"
        elif s <= 60:
            return "MEDIUM"
        return "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": self.total,
            "risk_level": self.level,
            "factors": {
                "authentication_risk": self.auth_risk,
                "device_risk": self.device_risk,
                "behavioral_risk": self.behavior_risk,
                "request_rate_risk": self.rate_risk,
                "prompt_risk": self.prompt_risk,
                "data_sensitivity_risk": self.data_sensitivity_risk,
            },
            "access_decision": (
                "ACCESS_GRANTED" if self.level == "LOW"
                else ("VERIFICATION_REQUIRED" if self.level == "MEDIUM" else "ACCESS_RESTRICTED")
            ),
        }


class RateLimiter:
    """Sliding-window request rate monitor for Denial-of-Wallet mitigation."""

    def __init__(self, window_seconds: int = 60, burst_threshold: int = 15):
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def record_request(self, session_id: str) -> Tuple[bool, int, int]:
        """Records a request and checks if rate limit is exceeded.
        
        Returns:
            (is_rate_limited, count_in_window, risk_penalty)
        """
        now = time.time()
        cutoff = now - self.window_seconds
        # Clean older entries
        self.requests[session_id] = [t for t in self.requests[session_id] if t > cutoff]
        self.requests[session_id].append(now)
        count = len(self.requests[session_id])

        if count > self.burst_threshold:
            # Exceeded safe threshold
            penalty = min(35, 10 + (count - self.burst_threshold) * 3)
            return True, count, penalty
        elif count > (self.burst_threshold // 2):
            return False, count, 10
        return False, count, 0


rate_limiter = RateLimiter(window_seconds=60, burst_threshold=12)

# In-memory storage for active session factors
_session_factors: Dict[str, RiskFactorBreakdown] = {}


def get_or_create_session_factors(session_id: str, is_stolen_sim: bool = False) -> RiskFactorBreakdown:
    """Retrieves or initializes the factor breakdown for a given session."""
    if session_id not in _session_factors:
        if is_stolen_sim:
            _session_factors[session_id] = RiskFactorBreakdown(
                auth_risk=0,       # Credentials were valid!
                device_risk=25,    # Unknown attacker hardware
                behavior_risk=20,  # Abnormal geo/time
                rate_risk=15,      # Automated burst
                prompt_risk=18,    # Recon payloads
                data_sensitivity_risk=0,
            )
        else:
            _session_factors[session_id] = RiskFactorBreakdown(
                auth_risk=0,
                device_risk=5,     # Known corporate device
                behavior_risk=5,   # Standard working pattern
                rate_risk=0,
                prompt_risk=0,
                data_sensitivity_risk=0,
            )
    return _session_factors[session_id]


def recalculate_risk(
    session_id: str,
    prompt_text: Optional[str] = None,
    is_malicious_prompt: bool = False,
    is_sensitive_request: bool = False,
    extra_auth_risk: int = 0,
    reset_mfa: bool = False,
    ai_analysis: Optional[Any] = None,
) -> RiskFactorBreakdown:
    """Dynamically recalculates risk score and updates the database record.
    
    Combines:
    - Deterministic security signals (HMAC, Auth, Rate, Guard, DLP)
    - AI Security Analyzer signals (confidence-aware, normalized)
    - Session context
    
    Guarantees no double-counting between AI and deterministic detections.
    """
    factors = get_or_create_session_factors(session_id)

    if reset_mfa:
        # User completed step-up MFA!
        factors.auth_risk = 0
        factors.device_risk = max(0, factors.device_risk - 15)
        factors.behavior_risk = max(0, factors.behavior_risk - 15)
        factors.rate_risk = 0
        factors.prompt_risk = 0
        factors.data_sensitivity_risk = 0
    else:
        if extra_auth_risk:
            factors.auth_risk = min(30, factors.auth_risk + extra_auth_risk)

        # 1. Normalized Prompt Risk (No double counting)
        ai_prompt_risk = 0
        if ai_analysis:
            raw_ai_score = getattr(ai_analysis, "risk_score", 0) if hasattr(ai_analysis, "risk_score") else ai_analysis.get("risk_score", 0)
            confidence = getattr(ai_analysis, "confidence", 1.0) if hasattr(ai_analysis, "confidence") else ai_analysis.get("confidence", 1.0)
            threat_type = getattr(ai_analysis, "threat_type", "NONE") if hasattr(ai_analysis, "threat_type") else ai_analysis.get("threat_type", "NONE")
            decision = getattr(ai_analysis, "decision", "PASS") if hasattr(ai_analysis, "decision") else ai_analysis.get("decision", "PASS")

            # Scale effective prompt risk by confidence
            if decision == "BLOCK" or threat_type in ("PROMPT_INJECTION", "JAILBREAK", "SYSTEM_PROMPT_EXTRACTION"):
                ai_prompt_risk = max(30, int(35 * confidence))
            elif decision == "CHALLENGE" or threat_type == "SUSPICIOUS_BEHAVIOR":
                ai_prompt_risk = int(20 * confidence)
            else:
                ai_prompt_risk = int((raw_ai_score / 100.0) * 15 * confidence)

        if is_malicious_prompt:
            factors.prompt_risk = max(35, ai_prompt_risk)
        elif ai_prompt_risk > 0:
            factors.prompt_risk = min(35, max(factors.prompt_risk, ai_prompt_risk))
        elif prompt_text and len(prompt_text) > 0:
            lower = prompt_text.lower()
            if any(k in lower for k in ["admin", "root", "bypass", "system prompt", "override", "leak", "dump"]):
                factors.prompt_risk = min(30, factors.prompt_risk + 15)
            else:
                factors.prompt_risk = max(0, factors.prompt_risk - 5)

        # 2. Normalized Data Sensitivity Risk (Consolidated between DLP & AI)
        ai_data_risk = 0
        if ai_analysis:
            threat_type = getattr(ai_analysis, "threat_type", "") if hasattr(ai_analysis, "threat_type") else ai_analysis.get("threat_type", "")
            if threat_type in ("CREDENTIAL_REQUEST", "SECRET_EXFILTRATION", "DATA_EXFILTRATION"):
                ai_data_risk = 25
            elif threat_type == "PII_EXPOSURE":
                ai_data_risk = 20

        if is_sensitive_request:
            factors.data_sensitivity_risk = max(20, ai_data_risk)
        elif ai_data_risk > 0:
            factors.data_sensitivity_risk = min(30, max(factors.data_sensitivity_risk, ai_data_risk))
        else:
            factors.data_sensitivity_risk = max(0, factors.data_sensitivity_risk - 5)

        # 3. Rate factor evaluation
        _, req_count, penalty = rate_limiter.record_request(session_id)
        factors.rate_risk = penalty

    # Save to SQLite database
    total = factors.total
    update_session_risk(session_id, total, reason=f"Recalculated: Total={total}, Level={factors.level}")
    return factors


# Centralized Prototype Risk Weights (Section 7)
PROTOTYPE_RISK_WEIGHTS: Dict[str, int] = {
    "mfa_verified": -30,
    "passkey_verified": -15,
    "trusted_session": -15,
    "valid_hmac": -10,
    "suspicious_prompt": 25,
    "credential_extraction": 30,
    "unusual_behavior": 15,
    "untrusted_device": 25,
}

BLOCKING_RISK_THRESHOLD: int = 60


def reassess_session_risk(
    session_id: str,
    mfa_verified: bool = True,
    passkey_verified: bool = False,
    is_compromised_sim: bool = False,
    prompt_text: Optional[str] = None,
    hmac_valid: bool = True,
    is_trusted_session: bool = True,
    ai_analysis: Optional[Any] = None,
) -> Dict[str, Any]:
    """Zero-Trust Post-MFA Risk Reassessment Engine (Sections 2, 6, 7, 8).
    
    CORE PRINCIPLE: MFA SUCCESS != AUTOMATIC TRUST.
    After MFA verification succeeds, this function dynamically reassesses the
    session across all application security signals before restoring LLM access.
    
    Returns:
        Structured reassessment verdict with previous/new scores, evaluated
        signals, access decision, and whether access is restored.
    """
    factors = get_or_create_session_factors(session_id)
    prev_score = factors.total

    evaluated_signals: List[Dict[str, Any]] = []
    calculated_risk = 0

    if is_compromised_sim:
        # Compromised MFA Scenario: Attacker has valid OTP, but anomalous environmental signals persist
        calculated_risk = 65  # Base elevated score > 60 threshold
        factors.device_risk = 25
        factors.behavior_risk = 20
        factors.data_sensitivity_risk = 30
        factors.auth_risk = 0
        factors.prompt_risk = 0
        factors.rate_risk = 0

        evaluated_signals = [
            {"signal": "mfa_verified", "weight": PROTOTYPE_RISK_WEIGHTS["mfa_verified"], "status": "VERIFIED"},
            {"signal": "passkey_verified", "weight": PROTOTYPE_RISK_WEIGHTS["passkey_verified"], "status": "VERIFIED"},
            {"signal": "untrusted_device", "weight": PROTOTYPE_RISK_WEIGHTS["untrusted_device"], "status": "DETECTED (+25)"},
            {"signal": "unusual_behavior", "weight": 20, "status": "ANOMALY (+20)"},
            {"signal": "credential_extraction", "weight": PROTOTYPE_RISK_WEIGHTS["credential_extraction"], "status": "FLAGGED (+30)"},
            {"signal": "valid_hmac", "weight": PROTOTYPE_RISK_WEIGHTS["valid_hmac"], "status": "VALID (-10)"},
        ]
    else:
        # Legitimate Reassessment Flow
        # Baseline starting risk
        base = 25
        if not is_trusted_session:
            base += 15

        # Check prompt signals if present
        prompt_penalty = 0
        if prompt_text:
            lower = prompt_text.lower()
            if any(k in lower for k in ["admin", "root", "bypass", "system prompt", "override"]):
                prompt_penalty = PROTOTYPE_RISK_WEIGHTS["suspicious_prompt"]
            if any(k in lower for k in ["secret", "password", "key", "token", "credential"]):
                prompt_penalty = max(prompt_penalty, PROTOTYPE_RISK_WEIGHTS["credential_extraction"])

        hmac_credit = PROTOTYPE_RISK_WEIGHTS["valid_hmac"] if hmac_valid else 35
        mfa_credit = PROTOTYPE_RISK_WEIGHTS["mfa_verified"] if mfa_verified else 0
        passkey_credit = PROTOTYPE_RISK_WEIGHTS["passkey_verified"] if passkey_verified else 0
        session_credit = PROTOTYPE_RISK_WEIGHTS["trusted_session"] if is_trusted_session else 0

        calculated_risk = max(0, min(100, base + prompt_penalty + hmac_credit + mfa_credit + passkey_credit + session_credit))

        # Reset factor breakdown to low baseline
        factors.auth_risk = 0
        factors.device_risk = 5
        factors.behavior_risk = 5
        factors.rate_risk = 0
        factors.prompt_risk = prompt_penalty
        factors.data_sensitivity_risk = 0

        evaluated_signals = [
            {"signal": "mfa_verified", "weight": mfa_credit, "status": "VERIFIED (-30)"},
        ]
        if passkey_verified:
            evaluated_signals.append({"signal": "passkey_verified", "weight": passkey_credit, "status": "VERIFIED (-15)"})
        evaluated_signals.extend([
            {"signal": "trusted_session", "weight": session_credit, "status": "VERIFIED (-15)"},
            {"signal": "valid_hmac", "weight": hmac_credit, "status": "VALID (-10)"},
        ])
        if prompt_penalty > 0:
            evaluated_signals.append({"signal": "prompt_sensitivity", "weight": prompt_penalty, "status": f"FLAGGED (+{prompt_penalty})"})
        if ai_analysis:
            ai_threat = getattr(ai_analysis, "threat_type", "NONE") if hasattr(ai_analysis, "threat_type") else ai_analysis.get("threat_type", "NONE")
            ai_conf = getattr(ai_analysis, "confidence", 1.0) if hasattr(ai_analysis, "confidence") else ai_analysis.get("confidence", 1.0)
            evaluated_signals.append({
                "signal": "ai_security_analyzer",
                "weight": 0 if ai_threat == "NONE" else 20,
                "status": f"{ai_threat} (conf {int(ai_conf * 100)}%)"
            })

    # Determine risk level and decision against threshold (60)
    risk_level = "LOW" if calculated_risk < 40 else ("MEDIUM" if calculated_risk <= BLOCKING_RISK_THRESHOLD else "HIGH")
    access_restored = calculated_risk <= BLOCKING_RISK_THRESHOLD
    access_decision = "ACCESS_GRANTED" if access_restored else "ACCESS_RESTRICTED"

    if access_restored:
        reason = f"Identity verified via Authenticator OTP. Zero-Trust risk reassessment satisfied (Score: {calculated_risk}/100, {risk_level} Risk). LLM workstation access restored."
        record_security_event(
            event_type="RISK_REASSESSMENT_PASSED",
            severity="INFO",
            description=reason,
            session_id=session_id,
            details=f"Previous: {prev_score}, Reassessed: {calculated_risk}, Decision: ACCESS_GRANTED",
        )
    else:
        reason = f"MFA was successfully verified, but post-MFA risk reassessment remains elevated (Score: {calculated_risk}/100, HIGH Risk). Access remains blocked by Zero-Trust policy."
        record_security_event(
            event_type="MFA_VERIFIED_RISK_HIGH",
            severity="CRITICAL",
            description=reason,
            session_id=session_id,
            details=f"Previous: {prev_score}, Reassessed: {calculated_risk}, Decision: ACCESS_RESTRICTED",
        )

    # Persist updated score
    update_session_risk(session_id, calculated_risk, reason=f"Post-MFA Reassessment: Score={calculated_risk}")

    return {
        "status": "MFA_REASSESSMENT_PASSED" if access_restored else "MFA_REASSESSMENT_FAILED",
        "mfa_verified": mfa_verified,
        "access_restored": access_restored,
        "previous_score": prev_score,
        "previous_risk_score": prev_score,
        "reassessed_score": calculated_risk,
        "reassessed_risk_score": calculated_risk,
        "risk_score": calculated_risk,
        "risk_level": risk_level,
        "access_decision": access_decision,
        "blocking_threshold": BLOCKING_RISK_THRESHOLD,
        "signals_evaluated": evaluated_signals,
        "evaluated_signals": evaluated_signals,
        "reason": reason,
        "factors": factors.to_dict()["factors"],
    }


def simulate_stolen_credentials(session_id: str) -> Dict[str, Any]:
    """Simulates the Stolen Credential Scenario.
    
    Shows that AUTHENTICATED ≠ TRUSTED:
    Valid Credentials -> Login SUCCESS -> Unknown Device + Abnormal Behavior + Sensitive Request -> HIGH RISK (~78) -> STEP-UP MFA
    """
    factors = RiskFactorBreakdown(
        auth_risk=0,       # Crucial: Credentials WERE valid!
        device_risk=25,    # Unknown Linux/headless device
        behavior_risk=23,  # Unusual timezone & IP subnet
        rate_risk=12,      # Automated replay frequency
        prompt_risk=18,    # Probing system capabilities
        data_sensitivity_risk=0,
    )
    _session_factors[session_id] = factors
    total = factors.total
    level = factors.level
    
    update_session_risk(session_id, total, reason="STOLEN_CREDENTIAL_SIMULATION: Unknown device + Behavioral anomaly")
    record_security_event(
        event_type="STOLEN_CREDENTIAL_DETECTED",
        severity="CRITICAL",
        description="Possible Credential Compromise: Valid password used from unknown device and anomalous behavioral pattern.",
        session_id=session_id,
        details="Authenticated != Trusted. Triggered Step-Up MFA Challenge.",
    )

    return {
        "status": "simulation_active",
        "scenario": "Stolen Credentials (Authenticated != Trusted)",
        "risk_breakdown": factors.to_dict(),
        "step_up_required": True,
        "demo_otp": "123456",
        "message": "Suspicious activity detected. Additional verification is required.",
    }


def simulate_compromised_mfa(session_id: str) -> Dict[str, Any]:
    """Simulates Compromised MFA Scenario (Section 10).
    
    Demonstrates: MFA SUCCESS != AUTOMATIC TRUST.
    Attacker possesses valid OTP, but Zero-Trust post-MFA reassessment catches
    anomalous hardware, untrusted network, and credential probing signals.
    Result: Risk remains HIGH (65/100) -> ACCESS REMAINS BLOCKED.
    """
    factors = RiskFactorBreakdown(
        auth_risk=0,
        device_risk=25,    # Unknown attacker hardware (+25)
        behavior_risk=20,  # Suspicious geo-location & subnet (+20)
        rate_risk=0,
        prompt_risk=0,
        data_sensitivity_risk=30, # Credential probe (+30)
    )
    _session_factors[session_id] = factors
    score = 75

    update_session_risk(session_id, score, reason="COMPROMISED_MFA_SIMULATION: Elevated anomaly signals")
    record_security_event(
        event_type="COMPROMISED_MFA_SIMULATION",
        severity="CRITICAL",
        description="Red Team: Compromised MFA Credential scenario initiated. Session marked with high-risk signals.",
        session_id=session_id,
        details="Attacker possesses valid OTP, but environmental signals are untrusted.",
    )

    return {
        "status": "simulation_active",
        "scenario": "Compromised MFA Credential (MFA Success != Automatic Trust)",
        "session_id": session_id,
        "initial_risk": score,
        "risk_score": score,
        "risk_level": "HIGH",
        "warning": "MFA Success != Automatic Trust. Unknown attacker device, behavioral anomalies, and credential probe detected.",
        "instructions": "Enter valid Demo OTP 123456. Zero-Trust post-MFA reassessment will evaluate contextual risk signals and reject workstation restoration.",
        "step_up_required": True,
        "demo_otp": "123456",
        "expected_post_mfa_risk": 65,
        "expected_decision": "ACCESS_RESTRICTED",
        "message": "Compromised MFA scenario active: Attacker has OTP 123456. Post-MFA reassessment will catch anomalous signals and keep access blocked.",
        "risk_breakdown": {
            "total_score": score,
            "risk_level": "HIGH",
            "factors": factors.to_dict()["factors"],
        },
    }


def simulate_denial_of_wallet(session_id: str) -> Dict[str, Any]:
    """Simulates a Denial-of-Wallet automated burst."""
    factors = get_or_create_session_factors(session_id)
    factors.rate_risk = 35
    total = factors.total

    update_session_risk(session_id, total, reason="DENIAL_OF_WALLET_SIMULATION: High request burst")
    record_security_event(
        event_type="RATE_LIMIT_EXCEEDED",
        severity="HIGH",
        description="Potential Denial-of-Wallet behavior detected. Request rate exceeded 15 req/min threshold.",
        session_id=session_id,
        details="Rate limiter activated. Throttling upstream model invocations.",
    )

    return {
        "status": "simulation_active",
        "scenario": "Denial-of-Wallet Mitigation",
        "risk_breakdown": factors.to_dict(),
        "warning": "Potential Denial-of-Wallet behavior detected.",
    }
