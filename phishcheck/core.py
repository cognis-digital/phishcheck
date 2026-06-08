"""Core phishing-signal scoring engine (stdlib only, no network).

The engine is deterministic and explainable: every point of risk is tied to a
named signal with a human-readable reason. Two surfaces are scored:

  * URLs  -> score_url(): lookalike/IDN/obfuscation/intent heuristics
  * Emails-> score_email(): header-auth (SPF/DKIM/DMARC), display-name spoof,
            from/return-path mismatch, urgent intent, plus embedded-URL scoring
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.utils import parseaddr, getaddresses
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, unquote

# Risk band thresholds (cumulative weighted score -> verdict).
RISK_THRESHOLDS = {"suspicious": 30, "high": 60}

# Brands commonly impersonated; used for lookalike/typosquat detection.
_BRANDS = (
    "paypal", "apple", "microsoft", "office365", "outlook", "google",
    "gmail", "amazon", "netflix", "facebook", "instagram", "chase",
    "wellsfargo", "bankofamerica", "citibank", "docusign", "dropbox",
    "linkedin", "coinbase", "binance", "fedex", "ups", "dhl", "usps",
    "icloud", "adobe", "steam", "whatsapp",
)

# Free / disposable / shortener hosts that warrant extra scrutiny.
_SHORTENERS = (
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
)

# TLDs disproportionately used in abuse campaigns.
_RISKY_TLDS = (
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work",
    "country", "kim", "click", "link", "review", "loan", "rest",
)

# Urgency / credential-harvest intent language.
_INTENT_PATTERNS = (
    (re.compile(r"\bverify (your )?(account|identity|password)\b", re.I),
     "credential-verification lure"),
    (re.compile(r"\b(suspend|lock|disabl|deactivat)\w*\b", re.I),
     "account-suspension threat"),
    (re.compile(r"\b(urgent|immediate(ly)?|right now|act now|within \d+ hours?)\b", re.I),
     "artificial urgency"),
    (re.compile(r"\b(confirm|update|re-?enter)\w* (your )?(payment|billing|card|password|login)\b", re.I),
     "credential/billing harvest"),
    (re.compile(r"\b(gift card|wire transfer|bitcoin|crypto|invoice attached)\b", re.I),
     "payment-redirect / BEC lure"),
    (re.compile(r"\b(won|winner|prize|lottery|claim your)\b", re.I),
     "prize/lottery bait"),
)

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PUNYCODE_RE = re.compile(r"(^|\.)xn--", re.I)


@dataclass
class Verdict:
    """A scored result: verdict band + the signals that produced it."""
    target: str
    score: int
    verdict: str  # clean | suspicious | high
    signals: List[Tuple[str, int, str]] = field(default_factory=list)

    def add(self, name: str, weight: int, reason: str) -> None:
        self.signals.append((name, weight, reason))
        self.score += weight

    def finalize(self) -> "Verdict":
        if self.score >= RISK_THRESHOLDS["high"]:
            self.verdict = "high"
        elif self.score >= RISK_THRESHOLDS["suspicious"]:
            self.verdict = "suspicious"
        else:
            self.verdict = "clean"
        return self

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "score": self.score,
            "verdict": self.verdict,
            "signals": [
                {"signal": n, "weight": w, "reason": r}
                for (n, w, r) in self.signals
            ],
        }


# Back-compat aliases requested by spec.
UrlFinding = Verdict
EmailFinding = Verdict


def _levenshtein(a: str, b: str) -> int:
    """Classic edit distance; small inputs, fine for brand comparison."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = cur
    return prev[-1]


def _registrable(host: str) -> str:
    """Best-effort registrable label (stdlib only, no PSL)."""
    parts = host.split(".")
    return parts[-2] if len(parts) >= 2 else host


def _brand_lookalike(host: str) -> Optional[Tuple[str, str]]:
    """Detect typosquats / brand-in-subdomain. Returns (brand, reason)."""
    host = host.lower()
    labels = host.split(".")
    reg = _registrable(host)
    for brand in _BRANDS:
        if brand == reg:
            return None  # exact registrable match is the real brand domain
        # Brand appears as a non-registrable label (e.g. paypal.evil.com
        # or login-paypal.secure-update.com).
        for lab in labels[:-2] if len(labels) > 2 else []:
            if brand in lab and lab != brand:
                return brand, f"brand '{brand}' used in subdomain/label '{lab}'"
        # Near-miss typosquat on the registrable label (paypa1, paypaI, etc).
        d = _levenshtein(reg, brand)
        if 0 < d <= max(1, len(brand) // 6) and abs(len(reg) - len(brand)) <= 2:
            return brand, f"registrable label '{reg}' is edit-distance {d} from '{brand}'"
        # Brand glued to extra words in the registrable label.
        if brand in reg and reg != brand and len(reg) - len(brand) <= 12:
            return brand, f"brand '{brand}' embedded in registrable label '{reg}'"
    return None


def score_url(url: str) -> Verdict:
    """Score a single URL for phishing signals. Deterministic, explainable."""
    v = Verdict(target=url, score=0, verdict="clean")
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw  # tolerate bare hostnames
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if not host:
        v.add("unparsable", 20, "URL has no parseable host")
        return v.finalize()

    # Scheme.
    if parts.scheme == "http":
        v.add("no-tls", 10, "uses http:// (no transport encryption)")

    # Userinfo trick: https://paypal.com@evil.com
    if parts.username or "@" in (parts.netloc.split("/")[0]):
        v.add("userinfo-host", 25,
              "credentials/'@' in authority can mask the true host")

    # Raw IP host.
    if _IPV4_RE.match(host):
        v.add("ip-host", 25, "host is a bare IP address, not a domain")

    # Punycode / IDN homograph.
    if _PUNYCODE_RE.search(host):
        v.add("punycode", 25, "punycode (xn--) host risks homograph spoofing")

    # Excessive subdomain depth.
    depth = host.count(".")
    if depth >= 4:
        v.add("deep-subdomain", 15, f"{depth}-level host obscures real domain")

    # Risky TLD.
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _RISKY_TLDS:
        v.add("risky-tld", 15, f".{tld} TLD is high-abuse")

    # Shortener.
    if host in _SHORTENERS:
        v.add("shortener", 15, f"link shortener '{host}' hides destination")

    # Brand lookalike.
    look = _brand_lookalike(host)
    if look:
        brand, reason = look
        v.add("brand-lookalike", 30, reason)

    # Hyphen/digit-heavy host (e.g. secure-login-update-account).
    reg = _registrable(host)
    if host.count("-") >= 3:
        v.add("hyphen-spam", 10, "many hyphens in host (campaign pattern)")
    if sum(c.isdigit() for c in reg) >= 4:
        v.add("digit-host", 8, "digit-heavy registrable label")

    # Suspicious path/query intent + obfuscation.
    decoded = unquote(parts.path + "?" + parts.query)
    if "%" in (parts.path + parts.query):
        v.add("encoded-path", 8, "percent-encoded path/query may hide payload")
    for pat, label in _INTENT_PATTERNS:
        if pat.search(decoded):
            v.add("intent-keyword", 10, f"path/query suggests {label}")
            break
    if re.search(r"\.(exe|scr|js|vbs|hta|zip)$", parts.path, re.I):
        v.add("risky-file", 15, "links directly to an executable/archive")

    return v.finalize()


def _auth_results(msg) -> dict:
    """Parse Authentication-Results / *-Authentication-Results headers."""
    out = {"spf": None, "dkim": None, "dmarc": None}
    blobs = []
    for h in ("Authentication-Results", "ARC-Authentication-Results",
              "Received-SPF"):
        blobs.extend(msg.get_all(h, []))
    text = " ".join(blobs).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", text)
        if m:
            out[mech] = m.group(1)
    # Received-SPF often just starts with the result word.
    if out["spf"] is None:
        for blob in msg.get_all("Received-SPF", []):
            m = re.match(r"\s*(\w+)", blob)
            if m:
                out["spf"] = m.group(1).lower()
                break
    return out


_URL_IN_BODY = re.compile(r"https?://[^\s<>\"')]+", re.I)


def _body_text(msg) -> str:
    if msg.is_multipart():
        chunks = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        chunks.append(payload.decode(
                            part.get_content_charset() or "utf-8",
                            "replace"))
                except Exception:
                    continue
        return "\n".join(chunks)
    payload = msg.get_payload(decode=True)
    if payload:
        try:
            return payload.decode(msg.get_content_charset() or "utf-8", "replace")
        except Exception:
            return msg.get_payload()
    return msg.get_payload() or ""


def score_email(raw_email: str) -> Verdict:
    """Score a raw RFC-822 email for phishing signals (headers + body + URLs)."""
    msg = message_from_string(raw_email)
    from_hdr = msg.get("From", "")
    disp, from_addr = parseaddr(from_hdr)
    v = Verdict(target=from_addr or from_hdr or "<no From>", score=0,
                verdict="clean")

    from_dom = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    # --- Header authentication (SPF/DKIM/DMARC) ---
    auth = _auth_results(msg)
    for mech in ("spf", "dkim", "dmarc"):
        res = auth[mech]
        if res in ("fail", "softfail", "none"):
            wt = 25 if mech == "dmarc" else 15
            v.add(f"{mech}-{res}", wt, f"{mech.upper()} result is '{res}'")
        elif res is None:
            v.add(f"{mech}-missing", 5, f"no {mech.upper()} result present")

    # --- Return-Path / From domain mismatch ---
    _, rp_addr = parseaddr(msg.get("Return-Path", ""))
    rp_dom = rp_addr.split("@")[-1].lower() if "@" in rp_addr else ""
    if from_dom and rp_dom and rp_dom != from_dom:
        v.add("returnpath-mismatch", 15,
              f"Return-Path domain '{rp_dom}' != From domain '{from_dom}'")

    # --- Reply-To divergence ---
    for _, rt_addr in getaddresses(msg.get_all("Reply-To", [])):
        rt_dom = rt_addr.split("@")[-1].lower() if "@" in rt_addr else ""
        if rt_dom and from_dom and rt_dom != from_dom:
            v.add("replyto-divergence", 12,
                  f"Reply-To domain '{rt_dom}' != From domain '{from_dom}'")
            break

    # --- Display-name spoof: name claims a brand the domain doesn't match ---
    disp_l = disp.lower()
    for brand in _BRANDS:
        if brand in disp_l and brand not in from_dom and _registrable(from_dom) != brand:
            v.add("displayname-spoof", 20,
                  f"display name cites '{brand}' but From domain is '{from_dom}'")
            break
    # Display name that itself looks like an email address (classic spoof).
    if "@" in disp and parseaddr("x <" + disp + ">")[1] != from_addr:
        v.add("displayname-address", 12,
              "display name contains a different email address")

    # --- Intent language in subject + body ---
    subject = msg.get("Subject", "")
    body = _body_text(msg)
    hay = subject + "\n" + body
    seen = set()
    for pat, label in _INTENT_PATTERNS:
        if pat.search(hay) and label not in seen:
            seen.add(label)
            v.add("intent-language", 8, label)
    if len(seen) >= 2:
        v.add("intent-stacking", 8, "multiple manipulation cues co-occur")

    # --- Embedded URLs: score each, fold worst into the email verdict ---
    urls = list(dict.fromkeys(_URL_IN_BODY.findall(body)))[:25]
    worst = 0
    for u in urls:
        uv = score_url(u)
        if uv.score > worst:
            worst = uv.score
        if uv.verdict != "clean":
            v.add("embedded-url", min(uv.score, 30),
                  f"link {u} scored {uv.score} ({uv.verdict})")
    # HTML anchor mismatch: visible text shows one domain, href another.
    for vis_dom, href in re.findall(
            r'href=["\']https?://([^/"\'?]+)[^>]*>\s*https?://([^<\s/]+)',
            body, re.I):
        if vis_dom.lower() != href.lower():
            v.add("anchor-mismatch", 18,
                  f"link text shows '{href}' but href is '{vis_dom}'")
            break

    return v.finalize()
