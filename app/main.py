from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .detector import analyze_email
from .models import EmailAnalysisRequest, EmailAnalysisResponse

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="Phishing Detection Lab",
    description=(
        "Experimental phishing detection playground leveraging heuristics, "
        "URL reputation services, and open phishing datasets."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request) -> HTMLResponse:
    """Serve the interactive phishing analysis dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health", tags=["System"])
async def health() -> dict:
    """Simple health probe for orchestrations."""
    return {"status": "ok"}


@app.post("/api/analyze", response_model=EmailAnalysisResponse, tags=["Analysis"])
async def analyze_endpoint(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    """
    Accept email metadata and perform phishing analysis.
    Designed for experimentation with samples sourced from public datasets
    (Nazario, APWG, Kaggle) or private spam folders.
    """
    return analyze_email(payload)
