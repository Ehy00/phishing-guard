from __future__ import annotations

import os
from typing import List, Optional

import httpx
import tldextract

from ..models import URLInsight

URLSCAN_ENDPOINT = "https://urlscan.io/api/v1/search/"


def lookup_urls(urls: List[str]) -> List[URLInsight]:
    """
    Inspect URLs using urlscan.io if an API key is configured.
    Falls back to placeholder insights otherwise.
    """
    insights: List[URLInsight] = []
    if not urls:
        return insights

    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return [
            URLInsight(
                url=url,
                status="unavailable",
                details="No URLSCAN_API_KEY configured; skipped live reputation lookup.",
            )
            for url in urls
        ]

    headers = {"API-Key": api_key}
    with httpx.Client(timeout=10.0) as client:
        for url in urls:
            domain = _domain_from_url(url)
            if not domain:
                insights.append(
                    URLInsight(
                        url=url,
                        status="unknown",
                        details="Unable to extract domain for reputation check.",
                    )
                )
                continue
            params = {"q": f"domain:{domain}"}
            try:
                response = client.get(URLSCAN_ENDPOINT, params=params, headers=headers)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                insights.append(
                    URLInsight(
                        url=url,
                        status="error",
                        details=f"urlscan lookup failed: {exc}",
                    )
                )
                continue

            insight = _parse_urlscan_response(url, response.json())
            insights.append(insight)

    return insights


def _parse_urlscan_response(url: str, payload: dict) -> URLInsight:
    total = payload.get("total", 0)
    if total == 0:
        return URLInsight(
            url=url,
            reputation="no-data",
            status="clean",
            details="No prior scans found for this domain.",
        )

    results = payload.get("results", [])
    latest = results[0] if results else {}
    verdicts = latest.get("verdicts", {})
    overall = verdicts.get("overall", {})

    malicious = overall.get("malicious")
    score = overall.get("score")
    categories = overall.get("categories") or []

    status = "malicious" if malicious else "review"
    rep = "block" if malicious else "suspicious"

    findings = []
    if categories:
        findings.append(f"Categories: {', '.join(categories)}")
    if score is not None:
        findings.append(f"Verdict score: {score}")

    return URLInsight(
        url=url,
        reputation=rep,
        status=status,
        details=f"Observed in {total} urlscan submission(s).",
        findings=findings,
    )


def _domain_from_url(url: str) -> Optional[str]:
    extracted = tldextract.extract(url)
    if not extracted.domain:
        return None
    parts = [extracted.domain, extracted.suffix] if extracted.suffix else [extracted.domain]
    return ".".join(parts).lower()
