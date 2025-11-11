from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Finding(BaseModel):
    category: str
    description: str
    severity: RiskLevel
    evidence: List[str] = Field(default_factory=list)


class URLInsight(BaseModel):
    url: HttpUrl | str
    reputation: Optional[str] = None
    status: Optional[str] = None
    details: Optional[str] = None
    findings: List[str] = Field(default_factory=list)


class EmailAnalysisRequest(BaseModel):
    subject: str = Field(..., description="Email subject line.")
    body: str = Field(..., description="Full email body as plain text.")
    sender: Optional[str] = Field(
        default=None, description="Complete sender email address."
    )
    sender_name: Optional[str] = Field(
        default=None, description="Sender display name if available."
    )
    reply_to: Optional[str] = Field(
        default=None, description="Reply-To address if different from sender."
    )
    urls: List[str] = Field(
        default_factory=list, description="List of URLs extracted from the email."
    )
    attachments: List[str] = Field(
        default_factory=list, description="List of attachment filenames."
    )
    headers: Optional[str] = Field(
        default=None, description="Raw email headers if available."
    )


class EmailAnalysisResponse(BaseModel):
    overall_risk: RiskLevel
    score: float = Field(..., ge=0, le=100)
    findings: List[Finding]
    url_insights: List[URLInsight] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
