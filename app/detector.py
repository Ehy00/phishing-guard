from __future__ import annotations

import math
import re
from email.utils import parseaddr
from typing import Iterable, List, Tuple

import tldextract

from .models import EmailAnalysisRequest, EmailAnalysisResponse, Finding, RiskLevel
from .services.url_reputation import lookup_urls

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s<>"']+|[a-z0-9\-\_]+\.[a-z]{2,}(?:/[^\s<>"']*)?)"""
)
URGENT_PHRASES = {
    "act now",
    "asap",
    "bank verification needed",
    "urgent",
    "immediately",
    "limited time",
    "suspend",
    "verify your account",
    "password expires",
    "account locked",
    "payment required",
}
SENSITIVE_KEYWORDS = {
    "password",
    "passcode",
    "credit card",
    "debit card",
    "social security",
    "ssn",
    "account number",
    "pin",
    "verification code",
    "bank routing",
    "tax id",
}
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".js",
    ".vbs",
    ".cmd",
    ".com",
    ".pif",
    ".jar",
    ".cpl",
    ".ps1",
}


def analyze_email(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    """Run heuristic analysis against a suspected phishing email."""
    urls = _collect_urls(payload)

    findings: List[Finding] = []
    findings.extend(_detect_urgency(payload))
    findings.extend(_detect_sensitive_requests(payload))
    findings.extend(_detect_sender_anomalies(payload, urls))
    findings.extend(_detect_suspicious_links(payload, urls))
    findings.extend(_detect_attachment_risk(payload))
    findings.extend(_detect_language_anomalies(payload))

    score, risk = _score_findings(findings)

    url_insights = []
    if urls:
        url_insights = lookup_urls(urls)

    recommendations = _build_recommendations(risk, findings, bool(urls))

    return EmailAnalysisResponse(
        overall_risk=risk,
        score=score,
        findings=findings,
        url_insights=url_insights,
        recommendations=recommendations,
    )


def _collect_urls(payload: EmailAnalysisRequest) -> List[str]:
    urls = list(dict.fromkeys(payload.urls or []))
    matches = URL_REGEX.findall(payload.body or "")
    for match in matches:
        url = match[0] if isinstance(match, tuple) else match
        if url.lower().startswith("www."):
            url = f"https://{url}"
        if url not in urls:
            urls.append(url)
    return urls


def _detect_urgency(payload: EmailAnalysisRequest) -> List[Finding]:
    text = f"{payload.subject}\n{payload.body}".lower()
    evidence = [
        phrase for phrase in URGENT_PHRASES if phrase in text and len(phrase) > 3
    ]

    excessive_caps = sum(1 for word in payload.body.split() if word.isupper() and len(word) > 3)
    exclamation_runs = len(re.findall(r"!{2,}", payload.body))

    details = []
    if evidence:
        details.append(f"Urgency phrases detected: {', '.join(sorted(evidence))}")
    if excessive_caps >= 3:
        details.append("Multiple all-caps words detected.")
    if exclamation_runs:
        details.append("Repeated exclamation marks found.")

    if not details:
        return []

    severity = RiskLevel.medium if len(details) == 1 else RiskLevel.high
    return [
        Finding(
            category="Urgency Tactics",
            description="Signals of artificial urgency present in subject/body.",
            severity=severity,
            evidence=details,
        )
    ]


def _detect_sender_anomalies(
    payload: EmailAnalysisRequest, urls: Iterable[str]
) -> List[Finding]:
    findings: List[Finding] = []

    sender_email = _normalize_email(payload.sender)
    reply_to_email = _normalize_email(payload.reply_to)

    sender_domain = _domain_from_email(sender_email) if sender_email else None
    reply_to_domain = _domain_from_email(reply_to_email) if reply_to_email else None

    evidence = []
    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        evidence.append(
            f"Sender domain `{sender_domain}` differs from reply-to `{reply_to_domain}`."
        )

    # Compare sender domain against URL domains
    url_domains = {_domain_from_url(u) for u in urls if _domain_from_url(u)}
    if sender_domain and url_domains and sender_domain not in url_domains:
        sample = ", ".join(sorted(url_domains)[:3])
        evidence.append(
            f"Links point to domains ({sample}) that do not match sender domain `{sender_domain}`."
        )

    if evidence:
        findings.append(
            Finding(
                category="Sender Domain Mismatch",
                description="Sender information conflicts with link or reply-to domains.",
                severity=RiskLevel.high if len(evidence) > 1 else RiskLevel.medium,
                evidence=evidence,
            )
        )

    return findings


def _detect_sensitive_requests(payload: EmailAnalysisRequest) -> List[Finding]:
    text = payload.body.lower()
    hits = [kw for kw in SENSITIVE_KEYWORDS if kw in text]
    if not hits:
        return []

    context_snippets = _extract_context(payload.body, hits)

    return [
        Finding(
            category="Sensitive Data Request",
            description="Email references requests for sensitive or credential information.",
            severity=RiskLevel.high,
            evidence=context_snippets or hits,
        )
    ]


def _detect_suspicious_links(
    payload: EmailAnalysisRequest, urls: Iterable[str]
) -> List[Finding]:
    urls = list(urls)
    if not urls:
        return []

    evidence = []
    severity = RiskLevel.medium
    for url in urls:
        domain = _domain_from_url(url)
        if not domain:
            continue

        if _looks_like_ip(domain):
            severity = RiskLevel.high
            evidence.append(f"URL `{url}` uses raw IP address.")
        elif _has_typosquatting_pattern(domain):
            severity = RiskLevel.high
            evidence.append(f"Domain `{domain}` appears typosquatted.")

        if url.lower().startswith("http://"):
            evidence.append(f"URL `{url}` is not served over HTTPS.")

    if len(urls) > 5:
        evidence.append(f"Email contains a high number of links ({len(urls)}).")

    if not evidence:
        return []

    return [
        Finding(
            category="Suspicious Links",
            description="Potentially malicious URLs detected in message body.",
            severity=severity,
            evidence=evidence,
        )
    ]


def _detect_attachment_risk(payload: EmailAnalysisRequest) -> List[Finding]:
    if not payload.attachments:
        return []

    flagged = [
        name
        for name in payload.attachments
        if any(name.lower().endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS)
    ]
    if not flagged:
        return []

    return [
        Finding(
            category="Suspicious Attachments",
            description="Attachments carry extensions commonly used in malware.",
            severity=RiskLevel.high,
            evidence=flagged,
        )
    ]


def _detect_language_anomalies(payload: EmailAnalysisRequest) -> List[Finding]:
    text = payload.body
    words = re.findall(r"[A-Za-z']+", text)
    if len(words) < 20:
        return []

    misspell_indicator = _estimate_spelling_issues(words)
    punctuation_runs = len(re.findall(r"[?!.]{3,}", text))
    inconsistent_spacing = len(re.findall(r"\s{3,}", text))

    evidence = []
    if misspell_indicator > 0.2:
        evidence.append("High ratio of uncommon words detected.")
    if punctuation_runs:
        evidence.append("Repeated punctuation suggests informal tone.")
    if inconsistent_spacing:
        evidence.append("Irregular spacing/padding detected within the body.")

    if not evidence:
        return []

    severity = RiskLevel.low if len(evidence) == 1 else RiskLevel.medium
    return [
        Finding(
            category="Grammar & Style",
            description="Writing quality indicators suggest potential social engineering.",
            severity=severity,
            evidence=evidence,
        )
    ]


def _estimate_spelling_issues(words: List[str]) -> float:
    """
    Estimate spelling or diction problems by measuring how many tokens look unusual.
    Uses a simple heuristic: words with rare character bigrams or repeated consonants.
    """
    if not words:
        return 0.0

    def looks_unusual(token: str) -> bool:
        token = token.lower()
        if len(token) <= 3:
            return False
        if token in COMMON_ENGLISH_WORDS:
            return False
        if re.search(r"[0-9]", token):
            return True
        if re.search(r"(.)\\1\\1", token):
            return True
        rare_bigrams = sum(1 for bigram in zip(token, token[1:]) if bigram not in COMMON_BIGRAMS)
        return rare_bigrams >= max(2, math.ceil(len(token) / 3))

    unusual_count = sum(1 for word in words if looks_unusual(word))
    return unusual_count / len(words)


def _extract_context(body: str, keywords: Iterable[str], window: int = 40) -> List[str]:
    snippets = []
    lowered = body.lower()
    for keyword in keywords:
        start = lowered.find(keyword)
        if start == -1:
            continue
        snippet = body[max(0, start - window) : start + len(keyword) + window]
        snippets.append(snippet.strip())
    return snippets


def _domain_from_email(email_address: str | None) -> str | None:
    if not email_address or "@" not in email_address:
        return None
    return email_address.split("@")[-1].lower().strip()


def _domain_from_url(url: str | None) -> str | None:
    if not url:
        return None
    extracted = tldextract.extract(url)
    if not extracted.domain:
        return None
    parts = [extracted.domain, extracted.suffix] if extracted.suffix else [extracted.domain]
    return ".".join(parts).lower()


def _looks_like_ip(domain: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain))


def _has_typosquatting_pattern(domain: str) -> bool:
    suspicious_patterns = ["paypal-secure", "micros0ft", "app1e", "verificati0n"]
    for pattern in suspicious_patterns:
        if pattern in domain:
            return True
    repeated_chars = re.search(r"(.)\\1{2,}", domain.replace(".", ""))
    return bool(repeated_chars)


def _normalize_email(email_address: str | None) -> str | None:
    if not email_address:
        return None
    parsed = parseaddr(email_address)[1]
    return parsed.lower() if parsed else None


def _score_findings(findings: Iterable[Finding]) -> Tuple[float, RiskLevel]:
    weights = {
        RiskLevel.low: 10,
        RiskLevel.medium: 20,
        RiskLevel.high: 35,
    }
    score = sum(weights[finding.severity] for finding in findings)
    score = min(100, score)
    if score >= 60:
        risk = RiskLevel.high
    elif score >= 30:
        risk = RiskLevel.medium
    else:
        risk = RiskLevel.low
    return score, risk


def _build_recommendations(
    risk: RiskLevel, findings: List[Finding], has_urls: bool
) -> List[str]:
    recommendations = []
    if risk is RiskLevel.high:
        recommendations.append(
            "Do not interact with the email. Report it to your security team."
        )
    if any(f.category == "Sensitive Data Request" for f in findings):
        recommendations.append(
            "Never share credentials or personal information via email links."
        )
    if has_urls:
        recommendations.append(
            "Hover over links to inspect destinations before clicking."
        )
    if any(f.category == "Sender Domain Mismatch" for f in findings):
        recommendations.append(
            "Verify the sender through a known, trusted communication channel."
        )
    if not recommendations:
        recommendations.append("Email appears lower risk but remain vigilant.")
    return recommendations


# Basic frequency dictionaries for heuristics
COMMON_ENGLISH_WORDS = {
    "the",
    "be",
    "to",
    "of",
    "and",
    "a",
    "in",
    "that",
    "have",
    "i",
    "it",
    "for",
    "not",
    "on",
    "with",
    "he",
    "as",
    "you",
    "do",
    "at",
    "this",
    "but",
    "his",
    "by",
    "from",
    "they",
    "we",
    "say",
    "her",
    "she",
    "or",
    "an",
    "will",
    "my",
    "one",
    "all",
    "would",
    "there",
    "their",
}

COMMON_BIGRAMS = {
    ("t", "h"),
    ("h", "e"),
    ("a", "n"),
    ("e", "r"),
    ("r", "e"),
    ("i", "n"),
    ("o", "n"),
    ("n", "d"),
    ("e", "n"),
    ("t", "o"),
    ("e", "s"),
    ("o", "f"),
}
