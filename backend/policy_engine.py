"""Central Security Policy & Data Classification Engine for LLM-Shield.

Enforces independent multi-layered security controls:
1. Authentication (Who are you?)
2. Session Risk (Is the session suspicious?)
3. Data Classification (What is the sensitivity level: Public, Internal, Confidential, Secret?)
4. RBAC Authorization (Does the user's role have the required permission?)
5. Prompt Security (Is the prompt an injection or jailbreak?)
6. Central Policy Decision (ALLOW, BLOCK, DENY, STEP_UP_MFA, REDACT)
7. Outbound DLP & Canary verification
"""

from typing import Any, Dict, Optional, Tuple
from backend.ai_security_analyzer import (
    AISecurityAnalysisResult,
    _detect_semantic_intent_locally,
)
from backend.database import check_role_permission, log_audit_event
from backend.inbound.decloaker import decloak_text
from backend.inbound.guard import evaluate_guard
from backend.inbound.semantic_detector import deberta_classifier, semantic_detector
from backend.vault import retrieve_vault_asset


def classify_requested_resource(prompt_text: str) -> Dict[str, Any]:
    """Classifies the prompt into an enterprise resource and data classification level.
    
    Levels:
        LEVEL 1: PUBLIC
        LEVEL 2: INTERNAL
        LEVEL 3: CONFIDENTIAL / PII
        LEVEL 4: SECRET
    """
    lower = prompt_text.lower()

    # Level 4: SECRET
    if any(k in lower for k in ["aws secret key", "aws secret", "aws key", "production aws", "cloud secret", "cloud credentials"]):
        return {
            "resource_id": "AWS_PRODUCTION_KEY",
            "name": "Production AWS Secret Key",
            "sensitivity": "SECRET",
            "level": "LEVEL 4: SECRET",
            "description": "Production AWS cloud infrastructure master credentials",
            "required_permission": "PRODUCTION_SECRET_READ",
        }
    if any(k in lower for k in ["database password", "db password", "db credentials", "postgres password", "root password"]):
        return {
            "resource_id": "DATABASE_PASSWORD",
            "name": "Production Database Password",
            "sensitivity": "SECRET",
            "level": "LEVEL 4: SECRET",
            "description": "Production PostgreSQL cluster root credentials",
            "required_permission": "DB_SECRET_READ",
        }
    if any(k in lower for k in ["jwt secret", "jwt token secret", "signing secret", "jwt key"]):
        return {
            "resource_id": "JWT_SECRET",
            "name": "Production JWT Secret Key",
            "sensitivity": "SECRET",
            "level": "LEVEL 4: SECRET",
            "description": "Production authentication token signature secret",
            "required_permission": "JWT_SECRET_READ",
        }
    if any(k in lower for k in ["internal api key", "service key", "service mesh key", "mesh api key"]) or (
        "api key" in lower and not any(k in lower for k in ["public", "how", "what is"])
    ):
        return {
            "resource_id": "INTERNAL_API_KEY",
            "name": "Internal API Secret Key",
            "sensitivity": "SECRET",
            "level": "LEVEL 4: SECRET",
            "description": "Internal microservice mesh API key",
            "required_permission": "SECRET_ACCESS",
        }

    # Level 3: CONFIDENTIAL / PII
    if any(k in lower for k in [
        "password", "passwords", "passcode", "credentials", "master password",
        "system password", "admin password", "root password", "database password",
        "vault password", "wifi password", "login password", "sudo password",
        "stored password", "supervisor password"
    ]) and not any(k in lower for k in [
        "policy", "manager", "guideline", "guidelines", "best practice", "best practices",
        "practices", "how to choose", "definition", "algorithm", "complexity", "hashing", "hash", "bcrypt"
    ]):
        return {
            "resource_id": "CONFIDENTIAL_SYSTEM_PASSWORDS",
            "name": "Confidential System Credentials & Passwords",
            "sensitivity": "CONFIDENTIAL",
            "level": "LEVEL 3: CONFIDENTIAL",
            "description": "Confidential system passwords and authentication credentials",
            "required_permission": "SYSTEM_PASSWORD_READ",
        }

    if any(k in lower for k in ["address", "give me the address", "rahul's address", "rahul address", "customer address", "home address", "residential address", "user address"]):
        return {
            "resource_id": "ADDRESS",
            "name": "Customer Residential Address",
            "sensitivity": "CONFIDENTIAL",
            "level": "LEVEL 3: CONFIDENTIAL",
            "description": "Customer confidential residential home address records",
            "required_permission": "ADDRESS_READ",
        }

    if any(k in lower for k in ["phone", "phone number", "customer phone", "mobile number", "contact number"]):
        return {
            "resource_id": "PHONE_NUMBER",
            "name": "Customer Phone Number",
            "sensitivity": "CONFIDENTIAL",
            "level": "LEVEL 3: CONFIDENTIAL",
            "description": "Customer confidential telephone contact details",
            "required_permission": "PHONE_READ",
        }

    if any(k in lower for k in ["rahul", "customer pii", "customer records", "billing record", "user ssn", "customer account"]):
        return {
            "resource_id": "CUSTOMER_RECORDS",
            "name": "Customer Rahul's Address & PII",
            "sensitivity": "CONFIDENTIAL",
            "level": "LEVEL 3: CONFIDENTIAL / PII",
            "description": "Customer confidential personally identifiable information (PII)",
            "required_permission": "CUSTOMER_PII_READ",
        }

    # Level 2: INTERNAL
    if any(k in lower for k in ["internal document", "internal doc", "internal dev", "developer documentation", "developer guide", "architecture document"]):
        return {
            "resource_id": "INTERNAL_DEV_DOCS",
            "name": "Internal Developer Documentation",
            "sensitivity": "INTERNAL",
            "level": "LEVEL 2: INTERNAL",
            "description": "Internal engineering architecture docs and development guides",
            "required_permission": "INTERNAL_DOCS_READ",
        }

    # Level 1: PUBLIC (Default for safe general inquiries)
    return {
        "resource_id": "COMPANY_PUBLIC_INFO",
        "name": "Company Public Website & Overview",
        "sensitivity": "PUBLIC",
        "level": "LEVEL 1: PUBLIC",
        "description": "Public enterprise portal information and website details",
        "required_permission": "PUBLIC_READ",
    }


def evaluate_security_policy(
    user_id: str,
    user_name: str,
    role: str,
    session_id: str,
    session_risk: int,
    mfa_verified: bool,
    prompt_text: str,
    ai_analysis: Optional[AISecurityAnalysisResult] = None,
) -> Dict[str, Any]:
    """Central Policy Engine making explicit, visible security decisions.
    
    Inputs:
        - Authenticated Identity & Role
        - Session Risk (0-100)
        - AI Security Analyzer evidence (untrusted intelligence layer)
        - Resource Classification (Level 1-4)
        - RBAC comparison
        - Step-Up MFA status
        
    Outputs:
        Structured SecurityAnalysis card payload for in-chat display.
    """
    # 1. Tier 0: De-cloaking & Normalization
    decloak_res = decloak_text(prompt_text)
    clean_text = decloak_res.unmasked_text

    # 2. Inbound Prompt Threat Inspection (Guard + FAISS Prototype + DeBERTa v3 Prototype)
    guard_verdict = evaluate_guard(clean_text, decloak_res)
    semantic_res = semantic_detector.search(clean_text)
    deberta_res = deberta_classifier.classify(clean_text, semantic_res)

    # 3. AI Security Analyzer (Phase 2 & Phase 5)
    if ai_analysis is None:
        ai_analysis = _detect_semantic_intent_locally(clean_text, decloak_res, guard_verdict)

    is_guard_threat = guard_verdict.is_malicious
    is_semantic_threat = semantic_res["decision"] == "BLOCK"
    is_deberta_threat = deberta_res["label"] in ("PROMPT_INJECTION", "JAILBREAK")
    is_ai_block = (ai_analysis.decision == "BLOCK")

    is_prompt_malicious = is_guard_threat or is_semantic_threat or is_deberta_threat or is_ai_block
    
    # Calculate Prompt Risk (0-100)
    sim_score = semantic_res.get("similarity_score", 0.1)
    if is_prompt_malicious:
        prompt_risk = max(82, ai_analysis.risk_score, int(sim_score * 100))
        prompt_risk_level = "HIGH"
        if is_guard_threat:
            threat_category = guard_verdict.threat_type
        elif is_ai_block:
            threat_category = ai_analysis.threat_type
        else:
            threat_category = deberta_res["label"]
        threat_classification = threat_category
        prompt_security = "BLOCKED"
        prompt_security_display = "❌ BLOCKED"
    else:
        prompt_risk = min(25, max(5, int(sim_score * 100), int(ai_analysis.risk_score * 0.3)))
        prompt_risk_level = "LOW"
        threat_category = "SAFE"
        threat_classification = "BENIGN REQUEST"
        prompt_security = "PASSED"
        prompt_security_display = "✅ PASSED"

    # 4. Data Classification
    classification = classify_requested_resource(clean_text)
    resource_id = classification["resource_id"]
    resource_name = classification["name"]
    sensitivity_level = classification["sensitivity"]
    data_level = classification["level"]
    required_permission = classification["required_permission"]

    # 5. RBAC Evaluation
    rbac_res = check_role_permission(role, resource_id)
    is_authorized = rbac_res["is_authorized"]
    user_permission = rbac_res["user_permission"]

    # 6. Session Risk Assessment
    session_risk_level = "LOW" if session_risk <= 30 else ("MEDIUM" if session_risk <= 60 else "HIGH")

    # 7. Central Policy Decision Engine
    vault_payload = None
    sanitized_prompt = getattr(ai_analysis, "sanitized_input", None) or clean_text

    # RULE 1: MALICIOUS PROMPT (Prompt Risk HIGH)
    if is_prompt_malicious:
        final_decision = "BLOCK"
        final_action = "BLOCKED"
        final_action_display = "🚫 BLOCKED"
        if threat_category == "CONFIDENTIAL_CREDENTIAL_EXTRACTION":
            decision_badge = "🔒 CONFIDENTIAL BLOCKED"
            status_headline = "Confidential Credential Extraction Blocked"
            authorization = "NOT REACHED / BLOCKED BY CONFIDENTIAL SECURITY"
            authorization_display = "NOT REACHED / BLOCKED BY CONFIDENTIAL SECURITY"
            reason = (
                "Confidential credential extraction attempt detected. System passwords and authentication credentials cannot be queried or exposed through the LLM."
            )
        else:
            decision_badge = "❌ THREAT BLOCKED"
            status_headline = "Adversarial Prompt Blocked"
            authorization = "NOT REACHED / BLOCKED BY PROMPT SECURITY"
            authorization_display = "NOT REACHED / BLOCKED BY PROMPT SECURITY"
            reason = (
                f"Adversarial prompt detected ({threat_category}). "
                f"Prompt security layer blocked request. Low session risk ({session_risk}/100) does not bypass prompt injection defense."
            )

    # RULE 2: SUSPICIOUS SESSION (Session Risk HIGH, e.g. Stolen Credentials)
    elif session_risk >= 61:
        final_decision = "STEP_UP_MFA"
        final_action = "STEP_UP_MFA"
        final_action_display = "🔐 WAITING FOR MFA"
        decision_badge = "🔐 STEP-UP MFA REQUIRED"
        status_headline = "High Session Risk — MFA Required"
        authorization = "STEP_UP_MFA"
        authorization_display = "🔐 STEP-UP MFA REQUIRED"
        reason = (
            f"Possible Credential Compromise: Session risk is {session_risk}/100 (HIGH) due to abnormal device/behavioral signals. "
            "Step-Up MFA verification is required before any prompt can proceed."
        )

    # RULE 3: UNAUTHORIZED REQUEST (Role Permission NOT GRANTED)
    # Prompt is safe (Prompt Security: PASSED), but user lacks RBAC permission!
    # Do NOT call user a hacker!
    elif not is_authorized:
        final_decision = "DENIED"
        final_action = "BLOCKED"
        final_action_display = "🚫 BLOCKED"
        decision_badge = "PROMPT SAFE — ACCESS DENIED"
        status_headline = "Prompt Safe — Access Denied"
        authorization = "DENIED"
        authorization_display = "❌ DENIED"
        if resource_id == "ADDRESS":
            reason = f"{role} role does not have permission to access the requested address."
        elif resource_id == "PHONE_NUMBER":
            reason = f"{role} role does not have permission to access the requested phone number."
        else:
            reason = (
                f"{role} role does not have permission ({required_permission}) to access {data_level} resource ({resource_name}). "
                "Authorization failure — secret data was not retrieved."
            )

    # RULE 4: AUTHORIZED SENSITIVE RESOURCE REQUIRING STEP-UP MFA (Section 11 & 12)
    elif (sensitivity_level == "SECRET" and not mfa_verified) or (getattr(ai_analysis, "decision", "") == "CHALLENGE" and not mfa_verified):
        final_decision = "STEP_UP_MFA"
        final_action = "STEP_UP_MFA"
        final_action_display = "🔐 WAITING FOR MFA"
        decision_badge = "🔐 STEP-UP MFA REQUIRED"
        status_headline = "Step-Up MFA Required for Secret"
        authorization = "STEP_UP_MFA"
        authorization_display = "🔐 STEP-UP MFA REQUIRED"
        reason = (
            f"Role {role} is permitted for {resource_name}, but access to Level 4 SECRET resources mandates Step-Up MFA verification."
            if sensitivity_level == "SECRET"
            else f"AI Security Analyzer elevated risk ({ai_analysis.threat_type}) — Step-Up MFA challenge required before proceeding."
        )

    # RULE 4.5: SENSITIVE INPUT REDACTION (Section 11)
    elif getattr(ai_analysis, "decision", "") == "REDACT" and getattr(ai_analysis, "sanitized_input", None):
        final_decision = "REDACT"
        final_action = "REDACTED"
        final_action_display = "✂️ REDACTED"
        decision_badge = "✂️ INPUT REDACTED"
        status_headline = "Sensitive Input Redacted"
        authorization = "GRANTED_REDACTED"
        authorization_display = "✅ GRANTED (REDACTED)"
        reason = "Sensitive credentials or PII detected in input prompt. Sanitized before upstream model execution."

    # RULE 5: AUTHORIZED REQUEST (Controlled Retrieval)
    else:
        final_decision = "ALLOW"
        final_action = "ALLOWED"
        final_action_display = "✅ ALLOWED"
        decision_badge = "✓ ALLOWED"
        status_headline = "Prompt Safe & Access Authorized"
        authorization = "GRANTED"
        authorization_display = "✅ GRANTED"
        if sensitivity_level in ("SECRET", "CONFIDENTIAL", "INTERNAL"):
            vault_ok, vault_msg, vault_data = retrieve_vault_asset(resource_id, role, mfa_verified)
            if vault_ok and vault_data:
                vault_payload = vault_data
                reason = f"Access authorized: {role} granted access to {resource_name} ({data_level}). Output protected by Outbound DLP."
            else:
                reason = f"Access authorized: {vault_msg}"
        else:
            reason = f"Public request authorized for role {role}."

    # Record Audit Log (Section 28 & 34)
    severity_map = {"ALLOW": "INFO", "REDACT": "WARNING", "STEP_UP_MFA": "WARNING", "DENIED": "WARNING", "BLOCK": "CRITICAL"}
    log_audit_event(
        event_type=f"POLICY_{final_decision}",
        severity=severity_map.get(final_decision, "INFO"),
        action=final_decision,
        user_id=user_id,
        role=role,
        session_id=session_id,
        risk=max(session_risk, prompt_risk),
        details=f"Resource: {resource_name} ({data_level}) | Reason: {reason}",
    )

    return {
        "authenticated_user": user_name or user_id,
        "user_id": user_id,
        "role": role,
        "requested_resource": resource_name,
        "resource_id": resource_id,
        "data_classification": sensitivity_level,
        "data_level": data_level,
        "required_permission": required_permission,
        "user_permission": user_permission,
        "role_authorized": is_authorized,
        "session_risk": session_risk,
        "session_risk_level": session_risk_level,
        "prompt_risk": prompt_risk,
        "prompt_risk_level": prompt_risk_level,
        "threat_category": threat_category,
        "threat_classification": threat_classification,
        "prompt_security": prompt_security,
        "prompt_security_display": prompt_security_display,
        "authorization": authorization,
        "authorization_display": authorization_display,
        "final_action": final_action,
        "final_action_display": final_action_display,
        "status_headline": status_headline,
        "security_checks": {
            "decloak_status": "OBFUSCATION_NORMALIZED" if decloak_res.obfuscation_detected else "CLEAN",
            "obfuscation_detected": decloak_res.obfuscation_detected,
            "obfuscation_types": decloak_res.obfuscation_types,
            "semantic_similarity_pct": semantic_res.get("similarity_pct", "10%"),
            "faiss_status": "MATCHED" if is_semantic_threat else "SAFE",
            "deberta_classification": deberta_res["label"],
            "deberta_confidence": deberta_res["confidence"],
            "rbac_check": "GRANTED" if is_authorized else "DENIED",
            "dlp_status": "ACTIVE_ARMED",
        },
        "ai_analysis": {
            "decision": ai_analysis.decision,
            "risk_score": ai_analysis.risk_score,
            "confidence": ai_analysis.confidence,
            "confidence_pct": f"{int(ai_analysis.confidence * 100)}%",
            "threat_type": ai_analysis.threat_type,
            "signals": ai_analysis.signals,
            "reason": ai_analysis.reason,
            "model_name": ai_analysis.model_name,
            "latency_ms": ai_analysis.latency_ms,
            "sanitized_input": getattr(ai_analysis, "sanitized_input", None),
        } if ai_analysis else None,
        "sanitized_prompt": sanitized_prompt,
        "final_decision": final_decision,
        "decision_badge": decision_badge,
        "reason": reason,
        "vault_payload": vault_payload,
    }
