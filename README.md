# LLM-Shield: Zero-Trust AI Defense Platform

**LLM-Shield** is a comprehensive, production-grade defense-in-depth security gateway that safeguards Large Language Model applications against adversarial jailbreaks, system prompt extraction, credential/PII leakage, and unauthorized tampering.

---

## Complete Multi-Tier Defense Pipeline

```
Adversary / Client
       │
       ▼
[STEP 1: Cryptographic Authentication]
  • HMAC-SHA256 Canonical Signing
  • Rejects tampered payloads with HTTP 401 Unauthorized
       │
       ▼
[STEP 2: Inbound Zero-Trust Engine]
  • Tier 0 De-cloaker: Unicode NFKC, Zero-Width Stripping, Recursive Base64 & ROT13 Unmasking
  • Tier 3 Guard Classifier: DAN, Prompt Extraction, Delimiter Escapes, Hypnosis/Roleplay (<25ms SLA)
  • Threat Blocked: HTTP 403 Forbidden ($0.00 Cost, 0 Tokens Billed, Upstream NEVER Called)
       │
       ▼
[STEP 3: Active Canary Deception & Outbound Streaming DLP]
  • Ephemeral Honeytoken Injection: CANARY_SEC_XXXXXXXX in hidden instructions
  • Real-Time Canary Stream Scanner: Instant cutoff with mathematical proof warning upon leak
  • 5-Token Sliding Lookahead DLP: Dynamic masking of API keys, PII (Luhn CC, SSN, emails), and Markdown Image Exfiltration (<5ms overhead)
       │
       ▼
[STEP 4: 3-in-1 Web UI & SOC Security Radar]
  • Panel 1: Enterprise User Chatbot with Structured JSON & HMAC Inspector
  • Panel 2: Hacker Terminal with 6 One-Click Attack Triggers
  • Panel 3: Live SOC Security Radar via WebSocket /ws/soc with KPI Metrics
```

---

## 3-in-1 Frontend Web UI for Live Judge Demo

The web application is accessible at **`http://localhost:8000/`**.

### 1. Panel 1: User Chatbot App (Enterprise User)
- Authenticated user profile: `piyush_analyst` (SecOps Lead).
- Green verified badge: `SHA-256 HMAC [Verified]`.
- Conversational chat interface with real-time SSE streaming text.
- **"Inspect Structured JSON" modal**: Displays the live canonical JSON payload and computed SHA-256 HMAC signature.

### 2. Panel 2: Hacker Terminal / Red Team Console
- Dark CLI terminal with 6 instant one-click attack triggers:
  1. `[1. Base64 Obfuscated Jailbreak]`
  2. `[2. DAN v11 Prompt Hijack]`
  3. `[3. System Prompt Extraction (Canary Trigger)]`
  4. `[4. Markdown Image Exfiltration Attack]`
  5. `[5. Tampered SHA-256 Signature (Auth Spoof)]`
  6. `[6. PII / Secret Leak Trigger]`
- Monospace execution feed with request diagnostics and `[HTTP 403 FORBIDDEN - $0 Tokens Billed]` badges.

### 3. Panel 3: SOC Security Radar
- Real-time WebSocket connection to `/ws/soc`.
- Live KPI Metric Cards:
  * **Average Latency**: `< 25ms SLA` (typically `~0.02ms`).
  * **Attacks Blocked**: Real-time counter of zero-trust interceptions.
  * **Secrets / PII Masked**: Outbound streaming DLP detections.
  * **Cost & Tokens Saved**: Cost calculation for blocked attacks ($0.00 model cost).
- **Active Canary Surveillance**: Current honeytoken display and extraction alert status.
- **Live Threat Event Stream**: Color-coded animated cards:
  * 🟥 **Red Card**: Inbound Exploit Blocked (Jailbreak, Obfuscation, Tampered Auth).
  * 🟨 **Yellow Card**: Outbound Streaming DLP Redacted (API key, PII, Markdown Image).
  * 🟩 **Green Card**: Legitimate Query Verified & Forwarded.

---

## Quickstart

### 1. Installation
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Gateway Server
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open the Web Dashboard
Open your browser and navigate to:
```
http://localhost:8000
```

---

## Running the Automated Test Suite

Run all 35 tests covering HMAC auth, Inbound De-cloaker & Guard Classifier, Active Canary Deception, Streaming DLP, and Frontend static mounting:

```bash
.venv/bin/pytest -v -s
```

All 35 tests pass with sub-millisecond execution times.
