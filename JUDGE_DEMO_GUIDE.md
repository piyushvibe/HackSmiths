# 🛡️ LLM-Shield — Judge Demo Guide

## Team: HackSmiths | Piyush · Anushka · Shujat · Nivedita

---

## ⚡ Launch the App (30 seconds)

```bash
# Terminal 1 — Start the backend
cd /path/to/HackSmiths
source .venv/bin/activate
uvicorn backend.main:app --reload --port 8000

# Terminal 2 (Optional) — Start Ollama with Gemma 2B for live LLM
ollama run gemma2:2b
```

Open browser: **[http://localhost:8000](http://localhost:8000)**

> If Ollama is not running, the proxy automatically falls back to the **built-in Simulated Gemma engine** — the demo works identically in both modes. The navbar badge shows the active engine.

---

## 🎤 3-Minute Pitch Script

### [0:00 – 0:30] Piyush — The Problem

> *"Every enterprise AI deployment today has a critical gap: the LLM itself is a black box that trusts everything it receives. A single malicious prompt can extract confidential system instructions, exfiltrate PII, or jailbreak the model — all at zero cost to the attacker, and 100% billable to your company."*

> *"LLM-Shield is a zero-trust security gateway that intercepts every prompt before it reaches the LLM and every token before it reaches the user — with mathematical proof of protection."*

### [0:30 – 1:15] Anushka — Live Demo: Safe Path

1. **Click Panel 1** (Enterprise Chatbot)
2. Type: *"What are the OWASP Top 10?"* → Hit Send
3. Point to: **SHA-256 HMAC [Verified]** badge → *"Every request is cryptographically signed"*
4. Point to: **SOC Panel** → green `request_authenticated` event appearing live
5. Click **🔍 JSON** button → show the structured schema with live hash

### [1:15 – 2:00] Shujat — Live Demo: Attack Blocked

1. **Click Attack Button: `⚔️ DAN Jailbreak`** in Panel 2
2. Terminal shows: `POST /api/chat → 403` in red
3. SOC Panel shows: **`threat_blocked` | JAILBREAK_DAN | conf: 0.95** card
4. Point: *"Blocked in under 25ms. Zero tokens sent to the LLM. Zero dollars billed."*

5. **Click Attack Button: `🕵️ System Prompt Theft`**
6. Chat starts streaming → then **[SECURITY ALERT: System prompt extraction blocked with 100% mathematical proof.]** appears
7. SOC shows: **`CANARY_LEAK_BLOCKED`** in red
8. Point: *"We injected a cryptographic honeytoken into the system prompt. The moment it leaked, we severed the stream — provably, before a single confidential byte reached the user."*

### [2:00 – 2:30] Nivedita — The Architecture

> *"LLM-Shield has 4 security layers:"*
> 1. **SHA-256 HMAC Zero-Trust Auth** — tampered requests rejected before touching the LLM
> 2. **Tier-0 De-cloaker** — strips Base64, ROT13, Unicode obfuscation in < 2ms
> 3. **0.5B Guard Classifier** — heuristic + neural threat detection in < 25ms
> 4. **Active Canary + 5-Token DLP Buffer** — outbound stream scanned token-by-token

> *"We also fine-tuned a 0.5B Qwen model on prompt injection datasets using Unsloth — 10-minute training on a free T4 GPU — exportable to GGUF for full offline Ollama deployment."*

### [2:30 – 3:00] Piyush — Close

> *"LLM-Shield is the missing security layer between your users and your AI. It's completely model-agnostic, runs fully offline, and adds sub-30ms overhead. Every attack costs the attacker nothing — and your company nothing."*

> *"Thank you."*

---

## 🎯 Button Click Sequence (fastest demo path)

| Order | Action | What Judges See |
|-------|--------|-----------------|
| 1 | Type a normal question → **Send** | Green `request_authenticated` event in SOC |
| 2 | Click **🔍 JSON** inspector | Live SHA-256 hash + structured payload |
| 3 | Click **`⚔️ DAN Jailbreak`** | Red `403 BLOCKED` in terminal + SOC alert |
| 4 | Click **`🔑 Base64 Obfuscation`** | `OBFUSCATION` blocked in < 2ms |
| 5 | Click **`🕵️ System Prompt Theft`** | Stream starts → CANARY ALERT severs it |
| 6 | Click **`💳 API Key Leakage`** | `[REDACTED_API_KEY]` visible in chat response |
| 7 | Click **`🔐 Tampered HMAC`** | `401 Unauthorized` in terminal |
| 8 | Run benchmark (optional) | `python scripts/run_judge_benchmark.py` |

---

## 🏆 Key Talking Points for Judges

| Feature | What to Say |
|---|---|
| **Sub-30ms guard** | "Our heuristic guard averages 0.016ms — 1500× faster than sending to the LLM" |
| **$0 billed on attacks** | "Blocked requests never reach Ollama/OpenAI — zero token cost" |
| **Canary proof** | "Mathematical certainty: if the honeytoken appears, the extraction is proven and severed" |
| **Offline capable** | "Runs fully air-gapped with Ollama — no OpenAI API key needed" |
| **0.5B fine-tune** | "We trained a custom guard model — 10 min, free GPU, LoRA r=16, 4-bit" |
| **35 tests passing** | "`pytest` → 35/35 green — production-grade reliability" |

---

## 🔧 Troubleshooting

| Problem | Fix |
|---|---|
| Port 8000 in use | `lsof -ti:8000 | xargs kill -9` |
| `.venv` not found | `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` |
| Ollama not found | Demo works without it — badge shows "Fallback Simulator" |
| CORS error in browser | Ensure server is on `localhost:8000`, not `127.0.0.1` |
| Tests failing | `PYTHONPATH=. pytest -v` (or check `pyproject.toml` has `pythonpath = ["."]`) |

---

## 📁 Project Structure at a Glance

```
HackSmiths/
├── backend/
│   ├── main.py              ← FastAPI proxy + /api/status endpoint
│   ├── auth.py              ← SHA-256 HMAC signing & verification
│   ├── upstream.py          ← Gemma 2B (Ollama) + mock fallback
│   ├── schemas.py           ← Pydantic structured schema
│   ├── inbound/
│   │   ├── decloaker.py     ← Base64/ROT13/Unicode de-obfuscator
│   │   └── guard.py         ← 0.5B Heuristic Guard Classifier
│   └── outbound/
│       ├── canary.py        ← Cryptographic honeytoken engine
│       ├── streaming_dlp.py ← 5-token sliding DLP buffer
│       └── pipeline.py      ← Outbound security orchestrator
├── frontend/
│   ├── index.html           ← 3-panel UI (Chat / Hacker / SOC)
│   ├── styles.css           ← Light/Dark theme
│   └── app.js               ← WebCrypto HMAC + SSE + WebSocket
├── unsloth_training/
│   ├── train_0.5b_guard.py  ← Fine-tuning script (Colab-ready)
│   └── README.md
├── scripts/
│   └── run_judge_benchmark.py ← 6-scenario automated benchmark
└── tests/                   ← 35 tests (all passing)
```

---

*LLM-Shield — HackSmiths 2026* 🛡️

