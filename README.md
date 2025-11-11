# Phishing Detection Lab

An interactive phishing analysis playground built with Python (FastAPI) and a lightweight HTML/CSS interface. Drop in real-world phishing emails from your spam folder or public corpora (Nazario, APWG, Kaggle) to visualize urgency cues, sender mismatches, sensitive data requests, suspicious links/attachments, and writing anomalies. Optional URL reputation lookups via the urlscan.io API enrich the verdict.

## Key Features

- **Heuristic engine** that flags urgency tactics, domain mismatches, sensitive data requests, suspicious links/attachments, and grammar/style anomalies.
- **URL reputation enrichment** via urlscan.io (configure the `URLSCAN_API_KEY` environment variable to enable live lookups).
- **Dataset-friendly workflow** so you can experiment with curated corpora (Nazario phishing corpus, APWG eCrime Exchange, Kaggle phishing email datasets) or paste emails captured from personal spam folders.
- **Beautiful single-page UI** for rapid analyst feedback; easily repurpose the API for browser extensions or SOC automations.
- **Extensible Python core** ready for classic ML models or LLM-based summarizers when you want to go beyond heuristics.

## Tech Stack

- **Python** for the core detection logic and FastAPI service layer.
- **HTML/CSS + vanilla JavaScript** for the interactive web interface.
- **Optional JavaScript** (in a separate project) if you decide to ship a browser extension.
- **Optional ML/LLM components** can be layered later without reworking the interface.

## Getting Started

### Prerequisites

- Python 3.10+
- (Optional) urlscan.io API key for URL reputation lookups.

### Installation

```bash
cd /workspace  # adjust if you cloned elsewhere
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the Web App

```bash
# (optional) enable URL reputation checks
export URLSCAN_API_KEY=your_urlscan_api_key

# start the FastAPI server
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000> in your browser. Use the form to paste an email subject/body, sender details, URLs, and attachment names. The results panel returns a risk rating, weighted score, category findings, URL reputation insights, and remediation advice.

### API Usage (automation / testing)

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
        "subject": "Urgent: Verify payroll",
        "body": "Your account will be suspended...",
        "sender": "hr-support@payroll-updates.co",
        "reply_to": "helpdesk@payroll-updates.co",
        "urls": ["https://acme-payroll-security.com/login"]
      }'
```

### Experimenting with Public Datasets

1. **Download corpora** such as the Nazario phishing corpus, APWG feeds, or Kaggle phishing email datasets.
2. **Normalize samples** into JSON using fields expected by `EmailAnalysisRequest` (subject, body, sender, reply_to, urls, attachments).
3. **Batch process** records by calling `/api/analyze` from a script, or wire the logic from `app/detector.py` into your data pipeline to score emails offline.
4. **Extend scoring** by training ML models (e.g., scikit-learn, transformers) and combining their predictions with the heuristic findings already returned by the API.

### Next Steps & Ideas

- Add persistence (SQLite, PostgreSQL) to track historical analyses.
- Build a browser extension (JavaScript) that injects this API into webmail pages.
- Integrate with SOC tooling or Slack/Teams bots for alerting.
- Layer an LLM summarizer to generate analyst-ready threat briefs.

## Project Status

- ✅ Core heuristic engine and web UI
- ✅ URL reputation integration (urlscan.io)
- 🚧 ML/LLM enhancements ready to plug in
- 🚧 Browser extension & mobile client opportunities

Stay vigilant and keep iterating! For questions or contributions, open an issue or submit a PR.
