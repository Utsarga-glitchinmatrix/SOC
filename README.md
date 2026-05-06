# Phishing Email Analyzer 🛡️

A defensive security tool that detects phishing and social engineering attacks in emails using AI-powered analysis combined with rule-based static checks.

---

## What It Does

Runs a two-stage analysis pipeline on any email:

1. **Static checks** — instant rule-based detection (domain mismatches, suspicious keywords, bad URLs)
2. **AI analysis** — deep contextual analysis via OpenRouter AI (social engineering, impersonation, tactics, risk scoring)

Outputs a color-coded terminal report with a verdict, risk score, threat indicators, and an actionable recommendation.

---

## Requirements

- Python 3.10 or higher
- An OpenRouter API key (free) — get one at [openrouter.ai/keys](https://openrouter.ai/keys)

---

## Installation

**Step 1 — Clone or download the project:**
```
your project folder/
    utd.py
    README.md
```

**Step 2 — Create and activate a virtual environment:**
```bash
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows
source .venv/bin/activate          # Mac/Linux
```

**Step 3 — Install dependencies:**
```bash
pip install openai
```

**Step 4 — Add your API key:**

Open `utd.py` and find line 227:
```python
OPENROUTER_API_KEY = "your-key-here"
```
Replace `your-key-here` with your actual OpenRouter API key.

---

## Usage

**Interactive mode** (prompts you field by field):
```bash
python utd.py
```

**Analyze a raw .eml file:**
```bash
python utd.py --eml suspicious.eml
```

**Analyze a plain text email file:**
```bash
python utd.py --file email.txt
```

**Save full JSON report to disk:**
```bash
python utd.py --json-out report.json
```

---

## Input Fields

| Field | Required | Description |
|-------|----------|-------------|
| From | Yes | Sender email address |
| Subject | Yes | Email subject line |
| Reply-To | No | Reply-To address if different |
| Return-Path | No | Bounce address |
| X-Mailer | No | Sending service (e.g. SendGrid) |
| Email Body | Yes | Full email body (type END to finish) |
| Links | No | Extra URLs found in the email |

---

## Output

The tool prints a color-coded report in the terminal:

```
════════════════════════════════════════════════════════════════
  🚨 PHISHING DETECTED
  Risk Score: 87/100  ·  Multiple high-severity indicators found
════════════════════════════════════════════════════════════════

  SUMMARY
  This email exhibits classic phishing characteristics...

  RULE-BASED FLAGS
  ✖ [HIGH  ] REPLY_TO_MISMATCH: From domain ≠ Reply-To domain
  ⚠ [MEDIUM] SUSPICIOUS_KEYWORDS: verify your account, urgent

  THREAT INDICATORS
  ✖ [HIGH  ] Sender impersonates PayPal but domain is paypa1.ru
  ⚠ [MEDIUM] Urgency language designed to bypass critical thinking

  METADATA ASSESSMENT
  Domain Analysis:    Typosquatted domain detected
  Urgency Level:      High
  Link Assessment:    HTTP link pointing to IP address
  Sender Auth:        SPF likely failing — domain mismatch

  TACTICS & TECHNIQUES
  Tactics:     Brand Impersonation, Urgency Pressure
  Techniques:  Spearphishing Link, Credential Harvesting

  RECOMMENDATION
  Do not click any links. Report to your IT/security team immediately.
```

### Verdict levels:

| Verdict | Risk Score | Meaning |
|---------|-----------|---------|
| 🚨 PHISHING DETECTED | 70–100 | High confidence phishing |
| ⚠ SUSPICIOUS EMAIL | 40–69 | Review carefully before acting |
| ✔ LIKELY LEGITIMATE | 0–39 | Appears safe |

---

## What It Detects

**Rule-based (instant):**
- Reply-To / From domain mismatch
- Free email provider senders (Gmail, Yahoo, etc.)
- Suspicious keywords (urgent, verify, suspended, prize, etc.)
- Raw IP addresses in URLs
- Unencrypted HTTP links
- Excessive subdomain depth

**AI-powered (deep):**
- Brand impersonation and typosquatting
- Social engineering language patterns
- Lookalike/homoglyph domains
- Credential harvesting indicators
- MITRE ATT&CK technique tagging
- Sender authentication inference (SPF/DKIM)
- Overall risk scoring with detailed reasoning

---

## Project Structure

```
security_engineer/
├── utd.py          # Main analyzer script
├── README.md       # This file
└── .venv/          # Virtual environment (auto-created)
```

---

## Security Notice

⚠️ **Never share your API key publicly.** Keep it only inside `utd.py` and never commit it to GitHub or share it in chats. If exposed, revoke it immediately at [openrouter.ai/keys](https://openrouter.ai/keys) and create a new one.

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `401 Missing Authentication` | API key is wrong or revoked — get a new one |
| `404 No endpoints found` | Model name changed — update model in `utd.py` |
| `python not found` | Install Python from python.org, check "Add to PATH" |
| `pip not found` | Use `python -m pip install openai` instead |
| `JSONDecodeError` | AI returned malformed response — run again |

---

## License

This tool is for **defensive security purposes only**. Do not use it to facilitate any malicious activity.
