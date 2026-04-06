# detector.py
import re
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class Finding:
    type: str
    value: str

# ---- Regex patterns (India + generic) ----
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

PHONE_RE = re.compile(r'\b(?:\+91[- ]?)?[6-9]\d{9}\b')  # Indian mobile

PAN_RE = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')       # PAN format

AADHAAR_RE = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')   # 12-digit (simple)

# Visa/Master/Amex/Discover; we will Luhn-check after match
CARD_RE = re.compile(r'\b(?:\d[ -]?){13,19}\b')

IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
)

# Keywords that imply sensitive content (basic dictionary)
SENSITIVE_KEYWORDS = [
    "password", "passcode", "otp", "secret key", "private key",
    "api_key", "token", "bearer", "authorization", "confidential",
    "account number", "ifsc", "upi", "cvv"
]

def luhn_ok(num: str) -> bool:
    digits = [int(ch) for ch in re.sub(r'[^0-9]', '', num)]
    if len(digits) < 13:  # too short to be a card
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def dedupe(seq: List[str]) -> List[str]:
    seen = set(); out = []
    for s in seq:
        s2 = s.strip()
        if s2 not in seen:
            seen.add(s2); out.append(s2)
    return out

def find_all(pattern: re.Pattern, text: str) -> List[str]:
    return [m.group(0) for m in pattern.finditer(text)]

def detect_sensitive_data(text: str) -> Tuple[List[Finding], str]:
    findings: List[Finding] = []

    emails = dedupe(find_all(EMAIL_RE, text))
    phones = dedupe(find_all(PHONE_RE, text))
    pans = dedupe(find_all(PAN_RE, text))
    aads = dedupe(find_all(AADHAAR_RE, text))
    ips = dedupe(find_all(IP_RE, text))

    # Cards: regex first, then Luhn filter
    raw_cards = dedupe(find_all(CARD_RE, text))
    cards = [c for c in raw_cards if luhn_ok(c)]

    # Keywords (context)
    kw_hits = []
    lower = text.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in lower:
            kw_hits.append(kw)

    for e in emails: findings.append(Finding("Email", e))
    for p in phones: findings.append(Finding("Phone", p))
    for pan in pans: findings.append(Finding("PAN", pan))
    for ad in aads: findings.append(Finding("Aadhaar (12-digit)", ad))
    for c in cards: findings.append(Finding("Credit/Debit Card", c))
    for ip in ips: findings.append(Finding("IP Address", ip))
    for kw in dedupe(kw_hits): findings.append(Finding("Sensitive Keyword", kw))

    # Simple decision logic
    high_types = {"Credit/Debit Card", "Aadhaar (12-digit)", "PAN"}
    med_types = {"Email", "Phone", "IP Address"}

    decision = "ALLOW"
    if any(f.type in high_types for f in findings):
        decision = "BLOCK"
    elif any(f.type in med_types for f in findings) or kw_hits:
        decision = "WARN"

    return [f.__dict__ for f in findings], decision
