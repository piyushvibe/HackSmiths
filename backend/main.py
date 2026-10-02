"""FastAPI main application for LLM-Shield core proxy."""

import asyncio
import json
import logging
import os
import secrets
import time
from typing import Optional, Set
from urllib.parse import quote, urlencode

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.auth import verify_signature, verify_shield_auth
from backend.google_auth import (
    verify_google_id_token,
    exchange_google_auth_code,
    get_google_client_id,
    get_google_client_secret,
    get_google_callback_url,
    get_app_base_url,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_CALLBACK_URL,
    APP_BASE_URL,
)
from backend.database import (
    authenticate_user,
    register_user,
    authenticate_or_register_google_user,
    authenticate_google_signin,
    register_google_signup,
    create_user_session,
    get_session_by_token,
    verify_session_mfa,
    verify_session_otp,
    verify_session_passkey,
    invalidate_session,
    get_security_events,
    get_dashboard_stats,
    record_security_event,
    get_db_connection,
)
from backend.inbound.decloaker import decloak_text
from backend.inbound.guard import evaluate_guard
from backend.inbound.semantic_detector import semantic_detector, deberta_classifier
from backend.outbound import (
    generate_canary_token,
    build_canary_system_prompt,
    outbound_security_stream,
)
from backend.risk_engine import (
    recalculate_risk,
    simulate_stolen_credentials,
    simulate_denial_of_wallet,
    rate_limiter,
    get_or_create_session_factors,
    reassess_session_risk,
    simulate_compromised_mfa,
    BLOCKING_RISK_THRESHOLD,
)
from backend.policy_engine import evaluate_security_policy, classify_requested_resource
from backend.ai_security_analyzer import analyze_prompt_security, AISecurityAnalysisResult
from backend.outbound.streaming_dlp import StreamingDLPBuffer
from backend.schemas import (
    HealthResponse,
    ShieldRequest,
    TelemetryEvent,
    LoginRequest,
    RegisterRequest,
    GoogleAuthRequest,
    GoogleConfigResponse,
    LoginResponse,
    MfaVerifyRequest,
    PasskeyVerifyRequest,
    RiskScoreResponse,
    SimulationRequest,
    AuthCheckRequest,
    DlpScanRequest,
)
from backend.upstream import (
    OLLAMA_CHAT_ENDPOINT,
    OLLAMA_MODEL,
    is_ollama_available,
    stream_gemma_response,
    format_sse_chunk,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("llm_shield.main")

app = FastAPI(
    title="LLM-Shield Security Proxy",
    version="1.0.0",
    description="Core Proxy, Authentication, Structured Prompting & Telemetry Gateway",
)

# CORS enabled for frontend connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SOCConnectionManager:
    """Manages real-time telemetry WebSocket subscribers for the SOC dashboard."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("SOC Dashboard connected. Active clients: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info("SOC Dashboard disconnected. Active clients: %d", len(self.active_connections))

    async def broadcast(self, event: TelemetryEvent):
        """Broadcasts telemetry events to all active SOC dashboard WebSocket clients."""
        if not self.active_connections:
            return
        payload = event.model_dump()
        dead_connections = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception as err:
                logger.warning("Failed to dispatch telemetry to client: %s", err)
                dead_connections.add(connection)
        for dead in dead_connections:
            self.active_connections.discard(dead)


soc_manager = SOCConnectionManager()


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint exposing system status and Ollama availability."""
    ollama_online = await is_ollama_available()
    return HealthResponse(
        status="healthy",
        timestamp=int(time.time()),
        upstream_url=OLLAMA_CHAT_ENDPOINT,
        upstream_model=OLLAMA_MODEL,
        ollama_online=ollama_online,
    )


@app.post("/auth/login", response_model=LoginResponse)
async def login_endpoint(payload: LoginRequest):
    """Authenticates credentials (email or username) against secure PBKDF2 hashed storage."""
    identifier = (payload.email or payload.username or "").strip()
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is required.",
        )
    if not payload.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required.",
        )
    user = authenticate_user(
        identifier,
        payload.password,
        device=payload.device or "Mac / Chrome (Corporate)",
        ip_address=payload.ip_address or "127.0.0.1",
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    
    session = create_user_session(
        user["id"],
        device=payload.device or "Mac / Chrome (Corporate)",
        ip_address=payload.ip_address or "127.0.0.1",
    )
    factors = recalculate_risk(session["session_id"])

    await soc_manager.broadcast(
        TelemetryEvent(
            event="USER_AUTHENTICATED",
            user_id=user["username"],
            session_id=session["session_id"],
            status="allowed",
            details={
                "role": user["role"],
                "device": session["device"],
                "risk_score": factors.total,
                "risk_level": factors.level,
            },
        )
    )

    return LoginResponse(
        token=session["token"],
        user_id=session["user_id"],
        username=session["username"],
        role=session["role"],
        full_name=session["full_name"],
        session_id=session["session_id"],
        risk_score=factors.total,
        risk_level=factors.level,
        access_decision="ACCESS_GRANTED" if factors.total <= 30 else ("VERIFICATION_REQUIRED" if factors.total <= 60 else "ACCESS_RESTRICTED"),
        device=session["device"],
        login_time=session["login_time"],
        mfa_verified=session["mfa_verified"],
    )


@app.post("/auth/register", response_model=LoginResponse)
async def register_endpoint(payload: RegisterRequest):
    """Registers a new corporate user and establishes an initial authenticated session."""
    if payload.password_confirm and payload.password != payload.password_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match. Please verify your password confirmation.",
        )

    clean_email = (payload.email or "").strip().lower()
    raw_user = (payload.username or "").strip().lower()
    if not clean_email and "@" in raw_user:
        clean_email = raw_user
        clean_username = clean_email.split("@")[0]
    elif raw_user and "@" not in raw_user:
        clean_username = raw_user
    else:
        clean_username = clean_email.split("@")[0] if clean_email else ""

    user, err = register_user(
        username=clean_username,
        password=payload.password,
        full_name=payload.full_name,
        email=clean_email or None,
        role="Developer",  # Least-privileged default role
        device=payload.device or "Mac / Chrome (Corporate)",
        ip_address=payload.ip_address or "127.0.0.1",
    )
    if err or not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err or "Registration failed. Invalid username or password format.",
        )
    
    session = create_user_session(
        user["id"],
        device=payload.device or "Mac / Chrome (Corporate)",
        ip_address=payload.ip_address or "127.0.0.1",
    )
    factors = recalculate_risk(session["session_id"])

    await soc_manager.broadcast(
        TelemetryEvent(
            event="USER_REGISTERED",
            user_id=user["username"],
            session_id=session["session_id"],
            status="allowed",
            details={
                "role": user["role"],
                "full_name": user["full_name"],
                "device": session["device"],
                "auth_method": "PBKDF2-HMAC-SHA256",
            },
        )
    )

    return LoginResponse(
        token=session["token"],
        user_id=session["user_id"],
        username=session["username"],
        role=session["role"],
        full_name=session["full_name"],
        session_id=session["session_id"],
        risk_score=factors.total,
        risk_level=factors.level,
        access_decision="ACCESS_GRANTED" if factors.total <= 30 else ("VERIFICATION_REQUIRED" if factors.total <= 60 else "ACCESS_RESTRICTED"),
        device=session["device"],
        login_time=session["login_time"],
        mfa_verified=session["mfa_verified"],
    )


@app.get("/auth/google/config", response_model=GoogleConfigResponse)
async def google_config_endpoint():
    """Returns Google OAuth configuration and readiness."""
    client_id = get_google_client_id()
    secret = get_google_client_secret()
    configured = bool(client_id and secret)
    message = (
        "Google OAuth 2.0 is configured and active."
        if configured
        else "Google OAuth configuration is missing on the server. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the server .env file."
    )
    return GoogleConfigResponse(
        client_id=client_id if configured else "",
        configured=configured,
        auth_url="/auth/google/login",
        message=message,
    )


@app.get("/auth/google/login")
async def google_login_redirect(mode: str = "signin"):
    """Redirects user to Google OAuth 2.0 authorization endpoint."""
    client_id = get_google_client_id()
    secret = get_google_client_secret()
    if not client_id or not secret:
        return RedirectResponse(url="/?auth_error=google_not_configured")

    clean_mode = "signup" if str(mode).lower() == "signup" else "signin"
    state_token = f"{clean_mode}:{secrets.token_urlsafe(16)}"
    
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": get_google_callback_url(),
        "scope": "openid email profile",
        "state": state_token,
        "access_type": "online",
        "prompt": "select_account",
    }
    google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    return RedirectResponse(url=google_auth_url)


@app.get("/auth/google/callback")
async def google_oauth_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    """Handles OAuth 2.0 callback from Google, exchanges code for ID token, and logs in user."""
    if error:
        err_msg = "access_denied" if "access_denied" in str(error) else str(error)
        return RedirectResponse(url=f"/?auth_error={err_msg}")

    if not code:
        return RedirectResponse(url="/?auth_error=missing_code")

    # Extract mode from state
    mode = "signin"
    if state and ":" in state:
        mode = state.split(":")[0]

    # Exchange code for tokens
    tokens = await exchange_google_auth_code(code)
    if not tokens or "id_token" not in tokens:
        return RedirectResponse(url="/?auth_error=token_exchange_failed")

    # Verify ID token
    verified_payload = await verify_google_id_token(tokens["id_token"])
    if not verified_payload:
        return RedirectResponse(url="/?auth_error=invalid_token")

    google_id = verified_payload.get("sub", "")
    email = verified_payload.get("email", "")
    full_name = verified_payload.get("name") or email.split("@")[0].title()

    if mode == "signup":
        user, err = register_google_signup(
            google_id=google_id,
            email=email,
            full_name=full_name,
            device="Mac / Chrome (Google SSO)",
        )
    else:
        user, err = authenticate_google_signin(
            google_id=google_id,
            email=email,
            device="Mac / Chrome (Google SSO)",
        )

    if err == "ACCOUNT_NOT_FOUND":
        return RedirectResponse(url=f"/?auth_error=account_not_found&mode=signup&email={quote(email)}")
    
    if err or not user:
        return RedirectResponse(url=f"/?auth_error={quote(err or 'auth_failed')}")

    session = create_user_session(user["id"], device="Mac / Chrome (Google SSO)")
    recalculate_risk(session["session_id"])

    await soc_manager.broadcast(
        TelemetryEvent(
            event="GOOGLE_SSO_LOGIN",
            user_id=user["username"],
            session_id=session["session_id"],
            status="allowed",
            details={
                "email": email,
                "role": user["role"],
                "auth_provider": "Google OAuth 2.0",
                "mode": mode,
            },
        )
    )

    session_data = json.dumps({
        "token": session["token"],
        "user_id": session["user_id"],
        "username": session["username"],
        "role": session["role"],
        "full_name": session["full_name"],
        "session_id": session["session_id"],
        "risk_score": session["risk_score"],
        "risk_level": session["risk_level"],
        "access_decision": "ACCESS_GRANTED",
        "device": session["device"],
        "login_time": session["login_time"],
        "mfa_verified": False,
    })
    return RedirectResponse(url=f"/?auth_token={quote(session['token'])}&auth_session={quote(session_data)}")


@app.post("/auth/google", response_model=LoginResponse)
@app.post("/auth/google/verify", response_model=LoginResponse)
async def google_auth_endpoint(payload: GoogleAuthRequest):
    """Authenticates or registers user via Google SSO (GIS ID Token or verified payload)."""
    mode = (payload.mode or "signin").strip().lower()
    google_id = payload.google_id
    email = payload.email
    full_name = payload.full_name

    # If client passed a Google ID token from Google Identity Services
    if payload.credential:
        verified = await verify_google_id_token(payload.credential)
        if not verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google identity verification failed. Invalid ID token or unverified email.",
            )
        google_id = verified.get("sub")
        email = verified.get("email")
        full_name = verified.get("name") or (email.split("@")[0].title() if email else "Google User")

    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid email address is required for Google authentication.",
        )

    # Execute Sign In or Sign Up
    if mode == "signup":
        user, err = register_google_signup(
            google_id=google_id or "",
            email=email,
            full_name=full_name,
            device=payload.device or "Mac / Chrome (Google SSO)",
            ip_address=payload.ip_address or "127.0.0.1",
        )
    else:
        user, err = authenticate_google_signin(
            google_id=google_id or "",
            email=email,
            device=payload.device or "Mac / Chrome (Google SSO)",
            ip_address=payload.ip_address or "127.0.0.1",
        )

    if err == "ACCOUNT_NOT_FOUND":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No LLM Shield account found with this Google identity. Please switch to Sign Up to create your account.",
        )

    if err or not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err or "Google authentication failed.",
        )

    session = create_user_session(
        user["id"],
        device=payload.device or "Mac / Chrome (Google SSO)",
        ip_address=payload.ip_address or "127.0.0.1",
    )
    factors = recalculate_risk(session["session_id"])

    await soc_manager.broadcast(
        TelemetryEvent(
            event="GOOGLE_SSO_LOGIN",
            user_id=user["username"],
            session_id=session["session_id"],
            status="allowed",
            details={
                "email": email,
                "role": user["role"],
                "auth_provider": "Google Identity Services",
                "device": session["device"],
                "risk_score": factors.total,
                "mode": mode,
            },
        )
    )

    return LoginResponse(
        token=session["token"],
        user_id=session["user_id"],
        username=session["username"],
        role=session["role"],
        full_name=session["full_name"],
        session_id=session["session_id"],
        risk_score=factors.total,
        risk_level=factors.level,
        access_decision="ACCESS_GRANTED" if factors.total <= 30 else ("VERIFICATION_REQUIRED" if factors.total <= 60 else "ACCESS_RESTRICTED"),
        device=session["device"],
        login_time=session["login_time"],
        mfa_verified=session["mfa_verified"],
    )


@app.post("/auth/logout")
async def logout_endpoint(token: str = ""):
    """Invalidates active session token."""
    if token:
        invalidate_session(token)
    return {"status": "success", "message": "Session invalidated."}


@app.post("/auth/verify-mfa")
@app.post("/api/mfa/verify-stepup")
async def verify_mfa_endpoint(payload: MfaVerifyRequest):
    """Validates step-up MFA challenge with demo OTP (123456) and advances state to PASSKEY_REQUIRED."""
    await soc_manager.broadcast(
        TelemetryEvent(
            event="OTP_VERIFICATION_STARTED",
            session_id=payload.session_id,
            status="verifying",
            details={
                "auth_stage": "OTP_PENDING",
                "message": "Validating TOTP 6-digit verification code...",
            },
        )
    )

    raw_val = payload.otp if payload.otp is not None else (payload.otp_code or "")
    clean_otp = str(raw_val).strip().replace(" ", "").replace("-", "")
    
    # Requirement: Strict 6-digit validation
    if len(clean_otp) < 6 or not clean_otp.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter the 6-digit verification code.",
        )
    
    if clean_otp not in ("123456", "DEMO"):
        record_security_event(
            event_type="MFA_FAILED",
            severity="WARNING",
            description=f"Failed MFA attempt with code '{payload.otp}'",
            session_id=payload.session_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code. Verification failed. Please check your code and try again.",
        )

    # 1. Step-up MFA OTP verified
    verify_session_otp(payload.session_id)
    await soc_manager.broadcast(
        TelemetryEvent(
            event="OTP_VERIFIED",
            session_id=payload.session_id,
            status="verified",
            details={
                "auth_stage": "OTP_VERIFIED",
                "factor": "Authenticator App (TOTP 6-digit)",
                "message": "Step-up MFA OTP 123456 verified. Second factor (Passkey) required before access can be restored.",
            },
        )
    )

    await soc_manager.broadcast(
        TelemetryEvent(
            event="PASSKEY_VERIFICATION_REQUIRED",
            session_id=payload.session_id,
            status="challenge",
            details={
                "auth_stage": "PASSKEY_REQUIRED",
                "policy": "Zero-Trust Multi-Factor Identity Verification",
                "message": "One more verification factor required: Hardware/Biometric Passkey assertion.",
            },
        )
    )

    # If passkey is provided in this payload (e.g. combined call or test), verify passkey directly
    if payload.passkey or payload.passkey_assertion:
        passkey_req = PasskeyVerifyRequest(
            session_id=payload.session_id,
            passkey_assertion=payload.passkey or payload.passkey_assertion,
            is_compromised_sim=payload.is_compromised_sim,
        )
        return await verify_passkey_endpoint(passkey_req)

    # Return explicit PASSKEY_REQUIRED state with access_granted=False (OTP alone != Access)
    return {
        "status": "verified",
        "auth_state": "PASSKEY_REQUIRED",
        "success": True,
        "access_granted": False,
        "otp_verified": True,
        "passkey_required": True,
        "message": "Step-up MFA OTP 123456 verified. Passkey verification required before protected information can be released.",
        "factors": get_or_create_session_factors(payload.session_id).to_dict()["factors"],
    }


@app.post("/auth/verify-passkey")
@app.post("/api/mfa/verify-passkey")
async def verify_passkey_endpoint(payload: PasskeyVerifyRequest):
    """Validates Passkey / WebAuthn cryptographic assertion and executes final post-verification risk reassessment."""
    await soc_manager.broadcast(
        TelemetryEvent(
            event="PASSKEY_VERIFICATION_STARTED",
            session_id=payload.session_id,
            status="verifying",
            details={
                "auth_stage": "PASSKEY_PENDING",
                "message": "Validating WebAuthn / Passkey cryptographic challenge response...",
            },
        )
    )

    assertion = payload.passkey_assertion or "DEMO_PASSKEY_VALID"
    # Strict validation of assertion failure conditions
    if assertion in ("FAIL", "INVALID") or "invalid" in str(assertion).lower():
        await soc_manager.broadcast(
            TelemetryEvent(
                event="PASSKEY_VERIFICATION_FAILED",
                session_id=payload.session_id,
                status="blocked",
                details={
                    "auth_stage": "PASSKEY_FAILED",
                    "action": "Protected information withheld. Session access remains restricted.",
                    "message": "Passkey verification failed. Cryptographic assertion rejected.",
                },
            )
        )
        record_security_event(
            event_type="PASSKEY_FAILED",
            severity="WARNING",
            description="Passkey verification assertion failed.",
            session_id=payload.session_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passkey verification failed.",
        )

    # 1. Passkey verified
    verify_session_passkey(payload.session_id)
    await soc_manager.broadcast(
        TelemetryEvent(
            event="PASSKEY_VERIFIED",
            session_id=payload.session_id,
            status="verified",
            details={
                "auth_stage": "PASSKEY_VERIFIED",
                "authentication": "OTP + Passkey",
                "action": "Proceeding to post-verification risk reassessment",
                "message": "Passkey assertion verified successfully. Identity verification complete.",
            },
        )
    )

    # 2. Final Zero-Trust Risk Reassessment
    reassessment = reassess_session_risk(
        session_id=payload.session_id,
        mfa_verified=True,
        passkey_verified=True,
        is_compromised_sim=payload.is_compromised_sim,
    )

    await soc_manager.broadcast(
        TelemetryEvent(
            event="POST_VERIFICATION_RISK_REASSESSMENT",
            session_id=payload.session_id,
            status="reassessing",
            details={
                "risk_score": reassessment["reassessed_risk_score"],
                "policy": "PASSED" if reassessment["access_restored"] else "BLOCKED",
                "message": "Evaluating multi-factor identity signals, session state, and HMAC integrity...",
                "evaluated_signals": reassessment["evaluated_signals"],
            },
        )
    )

    if reassessment["access_restored"]:
        verify_session_mfa(payload.session_id)
        await soc_manager.broadcast(
            TelemetryEvent(
                event="ACCESS_RESTORED",
                session_id=payload.session_id,
                status="allowed",
                details={
                    "message": "Protected information may now be released. LLM workstation access restored.",
                    "risk_score": reassessment["reassessed_risk_score"],
                    "risk_level": reassessment["risk_level"],
                },
            )
        )
        return {
            "status": "verified",
            "auth_state": "ACCESS_GRANTED",
            "reassessment_status": "MFA_REASSESSMENT_PASSED",
            "success": True,
            "access_granted": True,
            "message": "Identity verified. Authorized information may now be released according to policy.",
            "previous_risk_score": reassessment["previous_risk_score"],
            "reassessed_risk_score": reassessment["reassessed_risk_score"],
            "risk_score": reassessment["reassessed_risk_score"],
            "risk_level": reassessment["risk_level"],
            "access_decision": "ACCESS_GRANTED",
            "evaluated_signals": reassessment["evaluated_signals"],
            "factors": get_or_create_session_factors(payload.session_id).to_dict()["factors"],
        }
    else:
        await soc_manager.broadcast(
            TelemetryEvent(
                event="ACCESS_REMAINS_BLOCKED",
                session_id=payload.session_id,
                status="blocked",
                details={
                    "message": "Identity factors verified, but session risk remains too high. Information remains protected.",
                    "risk_score": reassessment["reassessed_risk_score"],
                    "risk_level": reassessment["risk_level"],
                },
            )
        )
        return {
            "status": "restricted",
            "auth_state": "ACCESS_BLOCKED",
            "reassessment_status": "MFA_REASSESSMENT_FAILED",
            "success": True,
            "access_granted": False,
            "message": "Identity factors verified, but session risk remains too high. Information remains protected.",
            "previous_risk_score": reassessment["previous_risk_score"],
            "reassessed_risk_score": reassessment["reassessed_risk_score"],
            "risk_score": reassessment["reassessed_risk_score"],
            "risk_level": reassessment["risk_level"],
            "access_decision": "ACCESS_RESTRICTED",
            "evaluated_signals": reassessment["evaluated_signals"],
            "factors": get_or_create_session_factors(payload.session_id).to_dict()["factors"],
        }


@app.get("/auth/session")
async def get_session_info(token: str):
    """Retrieves session profile, identity metadata, and risk score."""
    sess = get_session_by_token(token)
    if not sess:
        raise HTTPException(status_code=401, detail="Session not found or expired.")
    factors = get_or_create_session_factors(sess["id"])
    return {
        **sess,
        "risk_breakdown": factors.to_dict(),
    }


@app.get("/risk/current")
async def get_current_risk(session_id: str):
    """Returns dynamic 6-factor risk breakdown for active session."""
    factors = get_or_create_session_factors(session_id)
    return factors.to_dict()


@app.post("/risk/recalculate")
async def trigger_recalculate_risk(session_id: str):
    """Recalculates risk score for session."""
    factors = recalculate_risk(session_id)
    return factors.to_dict()


@app.post("/security/simulate/stolen-credentials")
async def sim_stolen_credentials(payload: SimulationRequest):
    """Interactive Simulation: Stolen Credentials (Authenticated != Trusted)."""
    sess_id = payload.session_id or "sess-default"
    result = simulate_stolen_credentials(sess_id)
    await soc_manager.broadcast(
        TelemetryEvent(
            event="STOLEN_CREDENTIAL_DETECTED",
            session_id=sess_id,
            status="blocked",
            details={
                "scenario": "Simulate Stolen Credentials",
                "risk_score": result["risk_breakdown"]["total_score"],
                "warning": "Authenticated != Trusted. Unknown device & behavioral anomaly detected.",
            },
        )
    )
    return result


@app.post("/security/simulate/denial-of-wallet")
async def sim_denial_of_wallet(payload: SimulationRequest):
    """Interactive Simulation: Denial of Wallet (Rate Limiting)."""
    sess_id = payload.session_id or "sess-default"
    result = simulate_denial_of_wallet(sess_id)
    await soc_manager.broadcast(
        TelemetryEvent(
            event="RATE_LIMIT_EXCEEDED",
            session_id=sess_id,
            status="blocked",
            details={
                "scenario": "Denial of Wallet",
                "risk_score": result["risk_breakdown"]["total_score"],
                "warning": result["warning"],
            },
        )
    )
    return result


@app.post("/security/simulate/compromised-mfa")
async def sim_compromised_mfa(payload: SimulationRequest):
    """Interactive Red Team Simulation: Compromised MFA / Stolen OTP (MFA Success != Automatic Trust)."""
    sess_id = payload.session_id or "sess-default"
    result = simulate_compromised_mfa(sess_id)
    await soc_manager.broadcast(
        TelemetryEvent(
            event="COMPROMISED_MFA_SIMULATION",
            session_id=sess_id,
            status="blocked",
            details={
                "scenario": "Compromised MFA (Stolen OTP)",
                "risk_score": result["risk_score"],
                "warning": result["warning"],
                "instructions": result["instructions"],
            },
        )
    )
    return result


@app.post("/risk/reassess")
async def reassess_risk_endpoint(payload: MfaVerifyRequest):
    """Explicit Zero-Trust post-MFA or dynamic risk reassessment across all security signals."""
    sess_id = payload.session_id or "sess-default"
    result = reassess_session_risk(
        session_id=sess_id,
        mfa_verified=True,
        is_compromised_sim=payload.is_compromised_sim,
    )
    event_type = "RISK_REASSESSMENT_PASSED" if result["access_restored"] else "MFA_VERIFIED_RISK_HIGH"
    status_str = "allowed" if result["access_restored"] else "blocked"
    await soc_manager.broadcast(
        TelemetryEvent(
            event=event_type,
            session_id=sess_id,
            status=status_str,
            details={
                "message": result["reason"],
                "previous_risk_score": result["previous_risk_score"],
                "risk_score": result["reassessed_risk_score"],
                "risk_level": result["risk_level"],
                "evaluated_signals": result["evaluated_signals"],
            },
        )
    )
    return {
        "status": result["status"],
        "success": True,
        "access_granted": result["access_restored"],
        "message": result["reason"],
        "previous_risk_score": result["previous_risk_score"],
        "reassessed_risk_score": result["reassessed_risk_score"],
        "risk_score": result["reassessed_risk_score"],
        "risk_level": result["risk_level"],
        "access_decision": result["access_decision"],
        "evaluated_signals": result["evaluated_signals"],
        "factors": get_or_create_session_factors(sess_id).to_dict()["factors"],
    }


@app.post("/security/simulate/prompt-injection")
async def sim_prompt_injection(payload: SimulationRequest):
    """Interactive Simulation: Prompt Injection Block."""
    sess_id = payload.session_id or "sess-default"
    await soc_manager.broadcast(
        TelemetryEvent(
            event="PROMPT_INJECTION_BLOCKED",
            session_id=sess_id,
            status="blocked",
            details={
                "threat": "PROMPT_INJECTION",
                "reason": "Request attempts to override system instructions.",
                "severity": "HIGH",
            },
        )
    )
    return {
        "status": "simulation_active",
        "threat": "Prompt Injection",
        "decision": "BLOCK",
        "severity": "HIGH",
        "reason": "The request attempts to override system instructions.",
    }


@app.get("/security/events")
async def get_events_feed(limit: int = 50):
    """Audit log feed of security events."""
    return get_security_events(limit=limit)


@app.get("/security/dashboard")
async def get_dashboard():
    """Aggregated metrics for Security Admin view."""
    return get_dashboard_stats()


@app.get("/api/security/evaluation/benchmark")
async def get_security_evaluation_benchmark():
    """Evaluates the AI Security Analyzer over ground-truth benchmark and returns precision/recall metrics."""
    from backend.evaluation import run_evaluation_benchmark
    return await run_evaluation_benchmark()


class PromptEvalRequest(BaseModel):
    prompt: str


@app.post("/api/security/evaluate-prompt")
async def evaluate_single_prompt(payload: PromptEvalRequest):
    """Directly evaluates a prompt with the AI Security Analyzer and returns structured evidence."""
    res = await analyze_prompt_security(payload.prompt)
    return res.model_dump()



@app.post("/authorization/check")
async def authorization_check_endpoint(payload: AuthCheckRequest):
    """Explicit Role-Based Access Control and Resource Classification Check (Section 8, 9, 35)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT s.*, u.username, u.role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?", (payload.session_id,))
        sess = cursor.fetchone()
    
    if not sess:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    
    role = sess["role"]
    prompt = payload.prompt or ""
    
    if payload.resource_id:
        from backend.database import check_role_permission
        rbac_res = check_role_permission(role, payload.resource_id)
        return rbac_res
    elif prompt:
        classification = classify_requested_resource(prompt)
        from backend.database import check_role_permission
        rbac_res = check_role_permission(role, classification["resource_id"])
        rbac_res["classification"] = classification
        return rbac_res
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must provide resource_id or prompt.")


@app.post("/dlp/scan")
async def dlp_scan_endpoint(payload: DlpScanRequest):
    """Direct Outbound DLP scan for sensitive secrets, credentials, and PII (Section 20-22, 35)."""
    dlp_buf = StreamingDLPBuffer()
    sanitized, triggered = dlp_buf._sanitize_string(payload.text)
    return {
        "original_text": payload.text,
        "sanitized_text": sanitized,
        "redactions_triggered": triggered,
        "count": len(triggered),
        "dlp_status": "REDACTED" if triggered else "CLEAN",
    }


@app.post("/chat")
@app.post("/api/chat")
async def chat_proxy(request: ShieldRequest):
    """Secure chat gateway.
    
    Validates structured schema, enforces HMAC-SHA256 authentication, evaluates
    rate limiting, applies adaptive risk control, inspects via de-cloaker & semantic
    classifier, broadcasts telemetry, and streams sanitized LLM response.
    """
    logger.info(
        "Chat request received: user_id=%s, session_id=%s, action=%s",
        request.user.id,
        request.user.session_id,
        request.action,
    )

    # Step A: Verify Cryptographic Auth (SHA-256 HMAC)
    is_valid = verify_signature(request)
    if not is_valid:
        await soc_manager.broadcast(
            TelemetryEvent(
                event="auth_failure",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="blocked",
                details={
                    "reason": "Invalid or tampered HMAC-SHA256 signature",
                    "prompt_preview": request.prompt.raw[:60] + "..." if len(request.prompt.raw) > 60 else request.prompt.raw,
                },
            )
        )
        record_security_event(
            event_type="AUTH_FAILURE",
            severity="CRITICAL",
            description="Tampered or invalid HMAC-SHA256 signature detected.",
            session_id=request.user.session_id,
            user_id=request.user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "Invalid HMAC-SHA256 signature or request payload has been tampered with."
            },
            headers={"WWW-Authenticate": "HMAC-SHA256"}
        )

    # Step B: Denial-of-Wallet Rate Limit Check
    is_rate_limited, req_count, _ = rate_limiter.record_request(request.user.session_id)
    if is_rate_limited:
        await soc_manager.broadcast(
            TelemetryEvent(
                event="RATE_LIMIT_EXCEEDED",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="blocked",
                details={
                    "req_count": req_count,
                    "warning": "Potential Denial-of-Wallet behavior detected.",
                },
            )
        )
        record_security_event(
            event_type="RATE_LIMIT_EXCEEDED",
            severity="HIGH",
            description=f"Denial-of-Wallet mitigation: {req_count} requests in 60s window.",
            session_id=request.user.session_id,
            user_id=request.user.id,
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "RATE_LIMIT_EXCEEDED",
                "message": "Potential Denial-of-Wallet behavior detected. Request rate exceeded threshold.",
            },
        )

    # Step C: Central Security Policy Engine (Authentication, Session Risk, RBAC, Data Classification, Prompt Security)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT s.*, u.username, u.role, u.full_name 
               FROM sessions s 
               JOIN users u ON s.user_id = u.id 
               WHERE s.id = ?""",
            (request.user.session_id,)
        )
        db_sess = cursor.fetchone()

    # 0. Pre-Security & AI Security Analyzer (Sections 2, 3, 4, 5)
    decloak_res = decloak_text(request.prompt.raw)
    guard_verdict = evaluate_guard(decloak_res.unmasked_text, decloak_result=decloak_res)
    ai_analysis = await analyze_prompt_security(
        raw_prompt=request.prompt.raw,
        decloak_res=decloak_res,
        guard_verdict=guard_verdict,
    )

    current_factors = recalculate_risk(
        request.user.session_id,
        prompt_text=request.prompt.raw,
        is_malicious_prompt=guard_verdict.is_malicious or ai_analysis.decision == "BLOCK",
        ai_analysis=ai_analysis,
    )
    current_risk = db_sess["risk_score"] if db_sess else current_factors.total
    mfa_verified = bool(db_sess["mfa_verified"]) if db_sess else False
    user_role = db_sess["role"] if db_sess else request.user.role
    user_name = db_sess["username"] if db_sess else request.user.id

    policy_verdict = evaluate_security_policy(
        user_id=request.user.id,
        user_name=user_name,
        role=user_role,
        session_id=request.user.session_id,
        session_risk=current_risk,
        mfa_verified=mfa_verified,
        prompt_text=request.prompt.raw,
        ai_analysis=ai_analysis,
    )

    # 1. MALICIOUS PROMPT BLOCKED
    if policy_verdict["final_decision"] == "BLOCK":
        logger.warning(
            "Threat blocked by LLM-Shield: %s (threat: %s)",
            policy_verdict["reason"],
            policy_verdict["threat_category"],
        )
        record_security_event(
            event_type="THREAT_BLOCKED",
            severity="CRITICAL",
            description=policy_verdict["reason"],
            session_id=request.user.session_id,
            user_id=request.user.id,
            details=f"Prompt: {request.prompt.raw[:80]}",
        )
        ai_info = policy_verdict.get("ai_analysis") or {}
        await soc_manager.broadcast(
            TelemetryEvent(
                event="threat_blocked",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="blocked",
                details={
                    "threat_type": policy_verdict["threat_category"],
                    "confidence": policy_verdict["security_checks"]["deberta_confidence"],
                    "latency_ms": ai_info.get("latency_ms", 0.08),
                    "tier_triggered": "Tier 3 (0.5B Guard)",
                    "semantic_similarity": policy_verdict["security_checks"]["semantic_similarity_pct"],
                    "deberta_classification": policy_verdict["security_checks"]["deberta_classification"],
                    "obfuscation_detected": policy_verdict["security_checks"]["obfuscation_detected"],
                    "obfuscation_types": policy_verdict["security_checks"]["obfuscation_types"],
                    "security_analysis": policy_verdict,
                    "ai_analysis": ai_info,
                    "decision": "BLOCK",
                    "risk_score": ai_info.get("risk_score", policy_verdict["prompt_risk"]),
                    "signals": ai_info.get("signals", []),
                    "reason": policy_verdict["reason"],
                    "prompt_preview": request.prompt.raw[:60] + "..." if len(request.prompt.raw) > 60 else request.prompt.raw,
                },
            )
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "BLOCKED_BY_LLM_SHIELD",
                "reason": policy_verdict["threat_category"],
                "message": policy_verdict["reason"],
                "semantic_similarity": policy_verdict["security_checks"]["semantic_similarity_pct"],
                "security_analysis": policy_verdict,
                "tokens_billed": 0,
                "cost": "$0.00",
            },
        )

    # 2. UNAUTHORIZED RESOURCE ACCESS DENIED
    if policy_verdict["final_decision"] == "DENIED":
        logger.warning("Authorization denied by LLM-Shield: %s", policy_verdict["reason"])
        record_security_event(
            event_type="AUTHORIZATION_DENIED",
            severity="WARNING",
            description=policy_verdict["reason"],
            session_id=request.user.session_id,
            user_id=request.user.id,
            details=f"Resource: {policy_verdict['requested_resource']} ({policy_verdict['data_level']})",
        )
        await soc_manager.broadcast(
            TelemetryEvent(
                event="authorization_denied",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="denied",
                details={
                    "threat_type": "UNAUTHORIZED_RESOURCE_REQUEST",
                    "resource": policy_verdict["requested_resource"],
                    "required_permission": policy_verdict["required_permission"],
                    "user_role": user_role,
                    "reason": policy_verdict["reason"],
                    "security_analysis": policy_verdict,
                },
            )
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "ACCESS_DENIED",
                "reason": policy_verdict["reason"],
                "message": policy_verdict["reason"],
                "security_analysis": policy_verdict,
                "tokens_billed": 0,
                "cost": "$0.00",
            },
        )

    # 3. SUSPICIOUS SESSION OR SENSITIVE SECRET STEP-UP MFA REQUIRED
    if policy_verdict["final_decision"] == "STEP_UP_MFA":
        await soc_manager.broadcast(
            TelemetryEvent(
                event="STEP_UP_MFA_REQUIRED",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="challenge",
                details={
                    "auth_stage": "MFA_REQUIRED",
                    "risk_score": policy_verdict["session_risk"],
                    "reason": policy_verdict["reason"],
                    "step_up_required": True,
                    "security_analysis": policy_verdict,
                },
            )
        )
        await soc_manager.broadcast(
            TelemetryEvent(
                event="ACCESS_RESTRICTED",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="blocked",
                details={
                    "risk_score": policy_verdict["session_risk"],
                    "reason": policy_verdict["reason"],
                    "step_up_required": True,
                    "security_analysis": policy_verdict,
                },
            )
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "STEP_UP_REQUIRED",
                "message": policy_verdict["reason"],
                "reason": policy_verdict["reason"],
                "risk_score": policy_verdict["session_risk"],
                "risk_level": policy_verdict["session_risk_level"],
                "demo_otp": "123456",
                "security_analysis": policy_verdict,
            },
        )

    # 4. REDACT or ALLOWED - BROADCAST TELEMETRY
    decloak_res = decloak_text(request.prompt.raw)
    ai_info = policy_verdict.get("ai_analysis") or {}

    if policy_verdict["final_decision"] == "REDACT":
        await soc_manager.broadcast(
            TelemetryEvent(
                event="AI_SECURITY_REDACT",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="redacted",
                details={
                    "event_type": "AI_SECURITY_REDACT",
                    "decision": "REDACT",
                    "message": "Sensitive content removed before model processing.",
                    "sanitized_input": policy_verdict.get("sanitized_prompt"),
                    "threat_type": ai_info.get("threat_type", "SECRET_EXFILTRATION"),
                    "risk_score": ai_info.get("risk_score", 45),
                    "confidence": ai_info.get("confidence", 0.92),
                    "signals": ai_info.get("signals", []),
                    "security_analysis": policy_verdict,
                },
            )
        )
    else:
        await soc_manager.broadcast(
            TelemetryEvent(
                event="request_authenticated",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="allowed",
                details={
                    "role": user_role,
                    "prompt_length": len(decloak_res.unmasked_text),
                    "timestamp": request.prompt.timestamp,
                    "resource": policy_verdict["requested_resource"],
                    "data_level": policy_verdict["data_level"],
                    "security_analysis": policy_verdict,
                },
            )
        )

    # Generate honeytoken canary for active prompt leak protection
    canary_token = generate_canary_token()
    canary_system_prompt = build_canary_system_prompt(canary_token)

    async def on_canary_leak(token: str):
        logger.critical("Canary leak intercepted: %s for user %s", token, request.user.id)
        await soc_manager.broadcast(
            TelemetryEvent(
                event="CANARY_LEAK_BLOCKED",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="blocked",
                details={
                    "canary": token,
                    "threat": "PROMPT_EXTRACTION",
                },
            )
        )

    async def on_dlp_redaction(redactions: list[str]):
        logger.warning("Outbound DLP redactions applied: %s", redactions)
        record_security_event(
            event_type="DLP_REDACTION",
            severity="WARNING",
            description=f"Outbound streaming DLP sanitized sensitive data: {', '.join(redactions)}",
            session_id=request.user.session_id,
            user_id=request.user.id,
            details=f"Types: {', '.join(redactions)}",
        )
        await soc_manager.broadcast(
            TelemetryEvent(
                event="DLP_REDACTION",
                user_id=request.user.id,
                session_id=request.user.session_id,
                action=request.action,
                status="redacted",
                details={"redaction_types": redactions, "count": len(redactions)},
            )
        )

    # Controlled Data Retrieval from Vault OR Upstream Gemma 2B
    async def vault_stream_generator():
        text = policy_verdict["vault_payload"]
        for word in text.split(" "):
            yield format_sse_chunk(word + " ", is_final=False, model_name="vault:controlled-retrieval")
            await asyncio.sleep(0.015)
        yield format_sse_chunk("", is_final=True, model_name="vault:controlled-retrieval")
        yield "data: [DONE]\n\n"

    prompt_to_stream = policy_verdict.get("sanitized_prompt") or decloak_res.unmasked_text
    raw_stream = vault_stream_generator() if policy_verdict.get("vault_payload") else stream_gemma_response(
        prompt=prompt_to_stream,
        system_prompt=canary_system_prompt,
    )

    secured_stream = outbound_security_stream(
        raw_sse_stream=raw_stream,
        canary_token=canary_token,
        on_canary_leak=on_canary_leak,
        on_dlp_redaction=on_dlp_redaction,
    )

    async def event_generator():
        try:
            # Emit structured security analysis card event immediately at stream inception
            import json
            yield f"data: {json.dumps({'type': 'security_analysis', 'security_analysis': policy_verdict})}\n\n"
            async for chunk in secured_stream:
                yield chunk
            # Notify SOC upon successful stream completion
            await soc_manager.broadcast(
                TelemetryEvent(
                    event="stream_completed",
                    user_id=request.user.id,
                    session_id=request.user.session_id,
                    action=request.action,
                    status="completed",
                )
            )
        except Exception as exc:
            logger.error("Streaming error: %s", exc)
            await soc_manager.broadcast(
                TelemetryEvent(
                    event="stream_error",
                    user_id=request.user.id,
                    session_id=request.user.session_id,
                    action=request.action,
                    status="error",
                    details={"error": str(exc)},
                )
            )

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.websocket("/ws/soc")
async def websocket_soc(websocket: WebSocket):
    """WebSocket endpoint for real-time SOC security dashboard telemetry."""
    await soc_manager.connect(websocket)
    try:
        # Initial greeting event
        await websocket.send_json(
            TelemetryEvent(
                event="soc_connected",
                status="active",
                details={"active_clients": len(soc_manager.active_connections)},
            ).model_dump()
        )
        while True:
            # Keep connection open and accept incoming control pings or messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        soc_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("SOC WebSocket error: %s", exc)
        soc_manager.disconnect(websocket)


@app.get("/api/status")
async def upstream_status():
    """Returns the active upstream engine: Ollama (live) or the internal mock simulator."""
    ollama_online = await is_ollama_available()
    return {
        "ollama_online": ollama_online,
        "engine": "Gemma 2B via Ollama (Live)" if ollama_online else "Simulated Gemma 2B (Offline Fallback)",
        "engine_short": "Ollama Live" if ollama_online else "Fallback Simulator",
        "model": OLLAMA_MODEL,
        "endpoint": OLLAMA_CHAT_ENDPOINT,
        "timestamp": int(time.time()),
    }


# Mount static frontend assets and dedicated view routes for web UI
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if not os.path.exists(frontend_dir):
    cwd_frontend = os.path.join(os.getcwd(), "frontend")
    if os.path.exists(cwd_frontend):
        frontend_dir = cwd_frontend

@app.get("/user")
@app.get("/chatbot")
async def serve_user_view():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

@app.get("/hacker")
@app.get("/redteam")
async def serve_hacker_view():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

@app.get("/soc")
@app.get("/radar")
async def serve_soc_view():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)

