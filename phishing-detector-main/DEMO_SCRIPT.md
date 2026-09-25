# Demo Script — AI Phishing Shield (5–6 min)

**Duration total: ~5 min 30 s** | Audience: judges / evaluators | Tone: confident, paced, minimal jargon.

---

## Setup (do BEFORE judges arrive — 2 min)

1. Start the app: `python3 -m streamlit run app.py` (from `phishing-detector-main/`).
2. Open `http://localhost:8501` in the browser, zoom to ~100%, full-screen.
3. Refresh once so the login screen is clean.
4. Keep these handy on a sticky note:
   - **Login:** `admin` / `CyberForgeAdmin2026!`
   - **Test phishing URL:** `http://paypal.com-security-verify.net/login`
   - **Test phishing email:** one of the built-in samples (use the button).
   - **Test domain for geo:** `www.paypal.com` or the attacker domain above.

---

## Timeline

### 0:00–0:30 — Intro & Login
- "Good morning everyone. I'm going to show you **AI Phishing Shield** — a unified platform that detects phishing **emails, URLs, and social-engineering messages**, and then **forensically traces the attacker**."
- Log in as admin (click **🔑 LOCAL ADMIN**, type `admin` / `CyberForgeAdmin2026!`, hit LOGIN).
- Point at the dashboard: live counters (total scans, threats detected, safe emails), the session scan history on the left.

### 0:30–1:30 — Tab 1: Email Analysis (main selling point)
- Go to **📧 Email Analysis**.
- Click a **🚨 Phishing** sample button to auto-fill the text box. Paste a fresh phishing email if you want to look more "live".
- Press **ANALYZE EMAIL**.
- Narrate what appears:
  1. **Heuristic findings** (urgency, credential wording, link analysis).
  2. **ML verdict** — note the model: TF-IDF + Multinomial Naive Bayes, and that we even support 5-tier classes (safe/suspicious/impersonated/phishing/fraud).
  3. **Risk score + recommendations**.
- "It's not a black box — you see *why* it's flagged, not just that it is."

### 1:30–2:15 — Tab 2: Email Header Forensics (impressive)
- Within Email Analysis use the **Email Header Forensics** section (paste a header-rich sample, or upload the provided `.eml`).
- Show the parsed **SPF / DKIM / DMARC** verdicts and the spoof-flag (`From` vs `Return-Path` mismatch).
- "Even if content looks safe, we validate the *identity* of the sender — authentication-layer checks."

### 2:15–2:50 — Tab 3: URL Analysis
- Switch to **🔗 URL Analysis**.
- Paste `http://paypal.com-security-verify.net/login`, run analysis.
- Show: lookalike-domain detection, length/redirect heuristics, reputation check, ML verdict + risk score.
- "Notice it catches the lookalike domain — typo-squatting detection."

### 2:50–3:20 — Tab 4: Social Engineering
- Switch to **🕵️ Social Engineering**.
- Paste a short manipulative message (e.g., "Your OTP is expiring, call 1800… immediately").
- Show the technique classification (urgency / impersonation / bait) and the confidence.
- "Separates pure message-level manipulation from technical phishing."

### 3:20–4:10 — Tab 5: GeoLocation & Forensics + IP Intelligence
- Switch to **🔬 GeoLocation & Forensics**.
- Run the geo lookup on the attack domain. Show **attacker IP / ISP / ASN / geo-map position** and cross-check with AbuseIPDB reputation.
- Switch to **🛰️ IP Intelligence** — different IP sample, show duplicate/suspicious `Received` headers.
- "This is the *forensic closure* step — we don't just block, we trace."

### 4:10–4:40 — Tab 6: Origin, Graph & Case Management
- Switch to **🕸️ Origin & Cases**.
- Show the **threat graph** (connections between sources), saved **cases**, and mention **compliance logging**.
- "Every finding is stored as a case — audit-ready and shareable."

### 4:40–5:10 — Tab 7: Auth & Tracking + Integrations
- Switch to **🔑 Auth & Tracking**.
- Show the **webhook/API endpoint** and live **tracker** (Tap-IN / pixel tracking).
- Briefly scroll to the **API/webhook** block — real-time ingestion from other tools.
- "Teams can push threat intel into the platform via webhook, not just the UI."

### 5:10–5:30 — Wrap-up
- Jump back to the dashboard counters — note threats detected incremented during the live demo.
- "To summarize: **analysis → forensics → case management → sharing**, all in one screen. Thank you — happy to take questions."
- End.

---

## Tips
- If the internet (WHOIS/geo API) is slow, the app degrades gracefully — pre-run the geo lookup once before judges arrive.
- Pre-load the **threat graph** and **cases** so they render instantly.
- Practice the sample clicks so every tab fires in one click.
- Keep a printed or phone copy of the phishing URL/email as a fallback if samples don't auto-fill.