#!/usr/bin/env python3
"""
Phishing Email Analyzer
A defensive security tool that uses OpenRouter API to detect phishing indicators in emails.
Usage:
    pip install openai
    python phishing_analyzer.py
    python phishing_analyzer.py --file email.txt
    python phishing_analyzer.py --eml email.eml
"""

import re
import json
import argparse
import email
import sys
from email import policy
from urllib.parse import urlparse
from pathlib import Path


# ── ANSI colors ──────────────────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
def dim(s):    return f"{C.DIM}{s}{C.RESET}"


# ── Static pre-analysis helpers ──────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "verify your account", "confirm your identity", "unusual activity",
    "suspended", "urgent", "immediate action", "click here", "act now",
    "limited time", "your account has been", "security alert",
    "update your payment", "prize", "winner", "congratulations",
    "free gift", "wire transfer", "western union", "gift card",
    "password expired", "login attempt", "unauthorized access",
]

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
}

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+', re.IGNORECASE
)

IP_IN_URL = re.compile(
    r'https?://\d{1,3}(\.\d{1,3}){3}'
)


def extract_urls(text: str) -> list[str]:
    return list(set(URL_PATTERN.findall(text or "")))


def extract_domain(email_addr: str) -> str | None:
    match = re.search(r'@([\w.\-]+)', email_addr or "")
    return match.group(1).lower() if match else None


def static_indicators(data: dict) -> list[dict]:
    """Fast rule-based checks before sending to Claude."""
    findings = []
    body    = (data.get("body") or "").lower()
    subject = (data.get("subject") or "").lower()
    sender  = data.get("from") or ""
    replyto = data.get("reply_to") or ""
    urls    = data.get("links") or []

    # Sender domain checks
    sender_domain  = extract_domain(sender)
    replyto_domain = extract_domain(replyto)

    if sender_domain and replyto_domain and sender_domain != replyto_domain:
        findings.append({
            "rule": "REPLY_TO_MISMATCH",
            "severity": "HIGH",
            "detail": f"From domain '{sender_domain}' ≠ Reply-To domain '{replyto_domain}'"
        })

    if sender_domain and sender_domain in FREE_EMAIL_PROVIDERS:
        findings.append({
            "rule": "FREE_PROVIDER_SENDER",
            "severity": "MEDIUM",
            "detail": f"Sent from free email provider: {sender_domain}"
        })

    # Suspicious keywords
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body or kw in subject]
    if hits:
        findings.append({
            "rule": "SUSPICIOUS_KEYWORDS",
            "severity": "MEDIUM",
            "detail": f"Matched keywords: {', '.join(hits[:5])}"
        })

    # URL analysis
    for url in urls:
        parsed = urlparse(url)
        if IP_IN_URL.match(url):
            findings.append({
                "rule": "IP_ADDRESS_URL",
                "severity": "HIGH",
                "detail": f"URL uses raw IP address: {url}"
            })
        if parsed.scheme == "http":
            findings.append({
                "rule": "UNENCRYPTED_URL",
                "severity": "MEDIUM",
                "detail": f"Unencrypted HTTP link: {url}"
            })
        hostname = parsed.hostname or ""
        if hostname.count(".") > 3:
            findings.append({
                "rule": "EXCESSIVE_SUBDOMAINS",
                "severity": "MEDIUM",
                "detail": f"Suspicious subdomain depth: {hostname}"
            })

    # URL count anomaly
    body_urls = extract_urls(data.get("body") or "")
    if len(body_urls) > 8:
        findings.append({
            "rule": "HIGH_URL_COUNT",
            "severity": "LOW",
            "detail": f"{len(body_urls)} URLs found in body"
        })

    return findings


def parse_eml_file(path: str) -> dict:
    """Parse a raw .eml file into structured fields."""
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            body_parts.append(str(msg.get_payload()))

    body = "\n".join(body_parts)
    urls = extract_urls(body)

    return {
        "from":        msg.get("From", ""),
        "subject":     msg.get("Subject", ""),
        "reply_to":    msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "mailer":      msg.get("X-Mailer", ""),
        "body":        body,
        "links":       urls,
    }


# ── Claude analysis ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior cybersecurity analyst specializing in phishing email detection and threat intelligence. You perform deep, methodical analysis of emails for malicious indicators. You are precise, direct, and never alarmist without evidence."""

def build_prompt(data: dict, static_findings: list[dict]) -> str:
    static_block = ""
    if static_findings:
        lines = [f"  - [{f['severity']}] {f['rule']}: {f['detail']}" for f in static_findings]
        static_block = "PRE-ANALYSIS FLAGS (rule-based):\n" + "\n".join(lines) + "\n\n"

    return f"""Analyze this email for phishing and social engineering. Return ONLY valid JSON, no markdown fences.

{static_block}EMAIL HEADERS & METADATA:
From:         {data.get('from') or 'Not provided'}
Subject:      {data.get('subject') or 'Not provided'}
Reply-To:     {data.get('reply_to') or 'Not provided'}
Return-Path:  {data.get('return_path') or 'Not provided'}
X-Mailer:     {data.get('mailer') or 'Not provided'}

EMAIL BODY:
{data.get('body') or 'Not provided'}

LINKS EXTRACTED:
{chr(10).join(data.get('links') or []) or 'None'}

Analyze for: domain spoofing, urgency/fear/scarcity tactics, credential harvesting, brand impersonation, lookalike/typosquatted domains, suspicious link patterns, mismatched sender info, social engineering language, grammar anomalies, and suspicious infrastructure.

Return ONLY this JSON:
{{
  "verdict": "phishing" | "suspicious" | "safe",
  "risk_score": <integer 0-100>,
  "verdict_reason": "<one concise sentence>",
  "summary": "<2-3 sentence analytical summary>",
  "indicators": [
    {{"severity": "HIGH" | "MEDIUM" | "LOW" | "INFO", "text": "<specific finding>"}}
  ],
  "tactics": ["<social engineering tactic labels>"],
  "techniques": ["<MITRE ATT&CK or general technique labels>"],
  "domain_analysis": "<assessment of sender domain legitimacy>",
  "urgency_level": "None" | "Low" | "Medium" | "High",
  "link_assessment": "<summary of link risk>",
  "sender_auth_assessment": "<SPF/DKIM inference from available data>",
  "recommendation": "<clear actionable recommendation for the recipient>"
}}"""


OPENROUTER_API_KEY = ""  # ← paste new key here

def analyze_with_gemini(data, static_findings):
    from openai import OpenAI
    client = OpenAI(
        api_key=OPENROUTER_API_KEY,
        base_url="https://openrouter.ai/api/v1"
    )
    prompt = build_prompt(data, static_findings)
    response = client.chat.completions.create(
        model="mistralai/mistral-7b-instruct:free",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
    )
    raw = response.choices[0].message.content.strip()
    raw = re.sub(r"^```(?:json)?", "", raw).rstrip("`").strip()
    return json.loads(raw)


# ── Output rendering ─────────────────────────────────────────────────────────

SEV_COLOR = {"HIGH": red, "MEDIUM": yellow, "LOW": green, "INFO": dim}
SEV_ICON  = {"HIGH": "✖", "MEDIUM": "⚠", "LOW": "✔", "INFO": "·"}

VERDICT_STYLE = {
    "phishing":   (red,    "🚨 PHISHING DETECTED"),
    "suspicious": (yellow, "⚠  SUSPICIOUS EMAIL"),
    "safe":       (green,  "✔  LIKELY LEGITIMATE"),
}


def render_report(result: dict, static_findings: list[dict]) -> None:
    score   = result.get("risk_score", 0)
    verdict = result.get("verdict", "unknown").lower()

    color_fn, label = VERDICT_STYLE.get(verdict, (dim, "UNKNOWN"))

    width = 64
    print()
    print(color_fn("═" * width))
    print(color_fn(f"  {label}"))
    print(color_fn(f"  Risk Score: {score}/100  ·  {result.get('verdict_reason', '')}"))
    print(color_fn("═" * width))

    # Summary
    print()
    print(bold("  SUMMARY"))
    for line in (result.get("summary") or "").split(". "):
        if line.strip():
            print(f"  {line.strip()}.")
    print()

    # Static pre-checks
    if static_findings:
        print(bold("  RULE-BASED FLAGS"))
        for f in static_findings:
            icon = SEV_ICON.get(f["severity"], "·")
            col  = SEV_COLOR.get(f["severity"], dim)
            print(f"  {col(icon)} [{f['severity']:6}] {f['rule']}: {f['detail']}")
        print()

    # Claude indicators
    indicators = result.get("indicators") or []
    if indicators:
        print(bold("  THREAT INDICATORS"))
        for ind in indicators:
            sev  = ind.get("severity", "INFO").upper()
            icon = SEV_ICON.get(sev, "·")
            col  = SEV_COLOR.get(sev, dim)
            print(f"  {col(icon)} [{sev:6}] {ind.get('text', '')}")
        print()

    # Metadata table
    print(bold("  METADATA ASSESSMENT"))
    rows = [
        ("Domain Analysis",  result.get("domain_analysis", "N/A")),
        ("Urgency Level",    result.get("urgency_level", "N/A")),
        ("Link Assessment",  result.get("link_assessment", "N/A")),
        ("Sender Auth",      result.get("sender_auth_assessment", "N/A")),
    ]
    for key, val in rows:
        print(f"  {dim(key+':'):<26} {val}")
    print()

    # Tactics & Techniques
    tactics    = result.get("tactics") or []
    techniques = result.get("techniques") or []
    if tactics or techniques:
        print(bold("  TACTICS & TECHNIQUES"))
        if tactics:
            print(f"  {dim('Tactics:'):<16} {red(', '.join(tactics))}")
        if techniques:
            print(f"  {dim('Techniques:'):<16} {yellow(', '.join(techniques))}")
        print()

    # Recommendation
    rec = result.get("recommendation")
    if rec:
        print(bold("  RECOMMENDATION"))
        print(f"  {cyan(rec)}")
        print()

    print(dim("─" * width))
    print()


# ── Interactive input ────────────────────────────────────────────────────────

def prompt_input(label: str, required: bool = False, multiline: bool = False) -> str:
    print(f"{dim('  ▸')} {bold(label)}" + (" (required)" if required else " (press Enter to skip)"))
    if multiline:
        print(dim("    Paste content, then type END on a new line and press Enter:"))
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == "END":
                break
            lines.append(line)
        return "\n".join(lines).strip()
    else:
        val = input("    > ").strip()
        return val


def interactive_mode() -> dict:
    print()
    print(bold(cyan("  ╔══════════════════════════════════════╗")))
    print(bold(cyan("  ║   PHISHING EMAIL ANALYZER v1.0       ║")))
    print(bold(cyan("  ║   Defensive Security Tool             ║")))
    print(bold(cyan("  ╚══════════════════════════════════════╝")))
    print()
    print(dim("  Fill in the email fields below. Links are auto-extracted from the body."))
    print()

    data = {}
    data["from"]        = prompt_input("From (sender address)", required=True)
    data["subject"]     = prompt_input("Subject", required=True)
    data["reply_to"]    = prompt_input("Reply-To")
    data["return_path"] = prompt_input("Return-Path")
    data["mailer"]      = prompt_input("X-Mailer / Sending Service")
    data["body"]        = prompt_input("Email Body", required=True, multiline=True)

    extra_links = prompt_input("Additional Links (comma-separated, or leave blank)")
    auto_links  = extract_urls(data["body"])
    manual_links = [l.strip() for l in extra_links.split(",") if l.strip()]
    data["links"] = list(set(auto_links + manual_links))

    if data["links"]:
        print(f"\n  {dim('Auto-extracted')} {len(auto_links)} URL(s) from body.")

    return data


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyzer — powered by Claude AI"
    )
    parser.add_argument("--eml",  help="Path to a .eml file to analyze")
    parser.add_argument("--file", help="Path to a plain-text email file")
    parser.add_argument("--json-out", help="Save full JSON result to this file")
    args = parser.parse_args()

    # Load data
    if args.eml:
        print(f"\n{dim('  Parsing')} {args.eml} ...")
        data = parse_eml_file(args.eml)
    elif args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        data = {
            "from": "", "subject": "", "reply_to": "",
            "return_path": "", "mailer": "",
            "body": text,
            "links": extract_urls(text),
        }
    else:
        data = interactive_mode()

    # Static pre-analysis
    print(f"\n{dim('  Running static checks...')}")
    static_findings = static_indicators(data)

    # OpenRouter analysis
    print(dim("  Sending to OpenRouter for deep analysis..."))
    try:
        result = analyze_with_gemini(data, static_findings)
    except json.JSONDecodeError as e:
        print(red(f"\n  [ERROR] Failed to parse OpenRouter response as JSON: {e}"))
        sys.exit(1)
    except Exception as e:
        print(red(f"\n  [ERROR] OpenRouter API error: {e}"))
        sys.exit(1)

    # Render
    render_report(result, static_findings)

    # Optionally save JSON
    if args.json_out:
        full = {"input": data, "static_findings": static_findings, "claude_analysis": result}
        Path(args.json_out).write_text(json.dumps(full, indent=2))
        print(dim(f"  Full JSON saved to: {args.json_out}"))
        print()


if __name__ == "__main__":
    main()