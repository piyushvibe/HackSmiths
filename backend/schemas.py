"""Pydantic schemas for LLM-Shield structured prompting and telemetry."""

from typing import Any, Dict, Optional
import time
from pydantic import BaseModel, Field


class UserContext(BaseModel):
    """User identity and authorization context."""
    id: str = Field(..., description="Unique user identifier")
    role: str = Field(..., description="Role of the user, e.g. admin, analyst, guest")
    session_id: str = Field(..., description="Active session tracking identifier")


class PromptContext(BaseModel):
    """Structured prompt data with creation timestamp."""
    raw: str = Field(..., description="Raw prompt content submitted by the user")
    timestamp: int = Field(
        default_factory=lambda: int(time.time()),
        description="Epoch timestamp (seconds) when prompt was created"
    )


class AuthContext(BaseModel):
    """Cryptographic signature and token specifications."""
    token_type: str = Field(default="HMAC-SHA256", description="Authentication token algorithm")
    sha256: str = Field(..., description="Hex-encoded HMAC-SHA256 signature of canonical request payload")


class ShieldRequest(BaseModel):
    """Exact structured prompt schema for incoming LLM-Shield proxy requests."""
    user: UserContext
    prompt: PromptContext
    action: str = Field(default="chat", description="Requested action or pipeline mode")
    authenticate: AuthContext

    def canonical_dict(self) -> Dict[str, Any]:
        """Returns the deterministic dictionary of data that is covered by the HMAC signature."""
        return {
            "user": {
                "id": self.user.id,
                "role": self.user.role,
                "session_id": self.user.session_id,
            },
            "prompt": {
                "raw": self.prompt.raw,
                "timestamp": self.prompt.timestamp,
            },
            "action": self.action,
        }


class HealthResponse(BaseModel):
    """Service health and upstream connectivity status."""
    status: str
    timestamp: int
    upstream_url: str
    upstream_model: str
    ollama_online: bool


class TelemetryEvent(BaseModel):
    """Structured security telemetry event streamed to the SOC dashboard."""
    event: str
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    action: Optional[str] = None
    status: str
    details: Optional[Dict[str, Any]] = None


class DecloakResult(BaseModel):
    """Result from the Tier 0 De-cloaker normalization and unmasking."""
    unmasked_text: str
    obfuscation_detected: bool
    obfuscation_types: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0


class GuardVerdict(BaseModel):
    """Structured verdict from the Guard Classifier."""
    is_malicious: bool
    threat_type: str = "NONE"
    confidence: float = 0.0
    latency_ms: float = 0.0
    tier_triggered: str = "Tier 3 (0.5B Guard)"


class BlockedResponse(BaseModel):
    """Zero-trust rejection response format when an attack is blocked."""
    error: str = "BLOCKED_BY_LLM_SHIELD"
    reason: str
    tokens_billed: int = 0
    cost: str = "$0.00"


class LoginRequest(BaseModel):
    """Credentials payload for /auth/login."""
    username: Optional[str] = None
    email: Optional[str] = None
    password: str
    device: Optional[str] = "Mac / Chrome (Corporate)"
    ip_address: Optional[str] = "127.0.0.1"


class RegisterRequest(BaseModel):
    """Payload for user registration /auth/register."""
    username: Optional[str] = None
    email: Optional[str] = None
    password: str
    password_confirm: Optional[str] = None
    full_name: str
    role: Optional[str] = "Developer"
    device: Optional[str] = "Mac / Chrome (Corporate)"
    ip_address: Optional[str] = "127.0.0.1"


class GoogleAuthRequest(BaseModel):
    """Payload for Google SSO /auth/google."""
    credential: Optional[str] = Field(None, description="Google OpenID Connect ID token / JWT")
    code: Optional[str] = Field(None, description="Google OAuth 2.0 authorization code from popup / GIS")
    redirect_uri: Optional[str] = Field(None, description="Redirect URI matching authorization request")
    picture: Optional[str] = Field(None, description="Profile picture URL from Google profile")
    email: Optional[str] = None
    full_name: Optional[str] = None
    google_id: Optional[str] = None
    mode: str = Field(default="signin", description="Authentication mode: 'signin' or 'signup'")
    device: Optional[str] = "Mac / Chrome (Google SSO)"
    ip_address: Optional[str] = "127.0.0.1"


class GoogleConfigResponse(BaseModel):
    """Configuration descriptor for Google OAuth."""
    client_id: str
    configured: bool
    auth_url: str
    message: Optional[str] = None


class LoginResponse(BaseModel):
    """Successful login session descriptor."""
    token: str
    user_id: str
    username: str
    role: str
    full_name: str
    session_id: str
    risk_score: int
    risk_level: str
    access_decision: str
    device: str
    login_time: int
    mfa_verified: bool


class MfaVerifyRequest(BaseModel):
    """Step-up MFA verification payload."""
    session_id: str
    otp: Optional[str] = None
    otp_code: Optional[str] = None
    prompt_context: Optional[str] = None
    is_compromised_sim: bool = False
    passkey: Optional[str] = None
    passkey_assertion: Optional[str] = None


class PasskeyVerifyRequest(BaseModel):
    """Zero-Trust Passkey / WebAuthn verification payload."""
    session_id: str
    passkey_assertion: Optional[str] = None
    client_data_json: Optional[str] = None
    authenticator_data: Optional[str] = None
    signature: Optional[str] = None
    is_demo_passkey: bool = True
    is_compromised_sim: bool = False


class RiskReassessmentResponse(BaseModel):
    """Structured response for Zero-Trust post-MFA risk reassessment."""
    status: str
    success: bool
    access_granted: bool
    message: str
    previous_risk_score: int
    reassessed_risk_score: int
    risk_score: int
    risk_level: str
    access_decision: str
    evaluated_signals: list[Dict[str, Any]] = Field(default_factory=list)
    factors: Dict[str, int] = Field(default_factory=dict)


class RiskScoreResponse(BaseModel):
    """Dynamic risk score and itemized factor breakdown."""
    total_score: int
    risk_level: str
    access_decision: str
    factors: Dict[str, int]
    session_id: str


class SimulationRequest(BaseModel):
    """Trigger payload for security simulations."""
    session_id: Optional[str] = None


class AuthCheckRequest(BaseModel):
    """Payload for POST /authorization/check."""
    session_id: str
    resource_id: Optional[str] = None
    prompt: Optional[str] = None


class DlpScanRequest(BaseModel):
    """Payload for POST /dlp/scan."""
    text: str



