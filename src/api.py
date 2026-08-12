"""
HTTP interface for the triage engine.

The engine knows nothing about the web — this module is a thin
wrapper that maps HTTP requests onto the same functions the CLI
calls. Keeping that boundary means the triage logic stays testable
without a running server.
"""

import json
import time
from collections import defaultdict, deque
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from src import casenote, config, extract, intel, score

app = FastAPI(
    title="Alert Triage Engine",
    description=(
        "Automates the mechanical part of SOC alert triage: extracts "
        "indicators from an alert, enriches them against threat "
        "intelligence sources, and returns a recommendation with the "
        "evidence behind it. The engine recommends; a human decides."
    ),
    version="1.0.0",
)

# The UI is served from the same origin, so CORS is not needed for
# normal use. It is permitted here only so the API can be tried from
# a separate frontend during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------

# In-memory per-client request log. Resets on restart, which is fine
# for a single-instance deployment — the goal is stopping one visitor
# from exhausting a day's API quota, not enforcing a billing tier.
_request_log: dict[str, deque] = defaultdict(deque)


def _rate_limited(client_ip: str) -> bool:
    now = time.time()
    log = _request_log[client_ip]

    while log and now - log[0] > config.RATE_LIMIT_WINDOW_SECONDS:
        log.popleft()

    if len(log) >= config.RATE_LIMIT_REQUESTS:
        return True

    log.append(now)
    return False


# ---------------------------------------------------------------
# Request and response models
# ---------------------------------------------------------------

class TriageRequest(BaseModel):
    """
    An alert to triage.

    Accepts either a structured alert object or a block of raw text —
    a syslog line, an email body, a pasted log excerpt. Real alerts
    arrive in both shapes, and indicators hide in free text as often
    as they sit in dedicated fields.
    """

    alert: Optional[dict[str, Any]] = Field(
        default=None,
        description="Structured alert object",
    )
    raw_text: Optional[str] = Field(
        default=None,
        max_length=50000,
        description="Unstructured alert text",
    )

    @field_validator("raw_text")
    @classmethod
    def _not_only_whitespace(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            return None
        return v

    def resolved_alert(self) -> dict[str, Any]:
        """Normalise either input form into a single alert dict."""
        if self.alert:
            return self.alert
        return {"description": self.raw_text or ""}


class HealthResponse(BaseModel):
    status: str
    configured_sources: dict[str, bool]
    active_source_count: int


# ---------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    """
    Report which intel sources have credentials configured.

    Checked before triage so the UI can show which sources are live.
    Without it, a missing key produces a silent 401 on every lookup
    and results look thin for no visible reason.
    """
    sources = config.configured_sources()
    return HealthResponse(
        status="ok",
        configured_sources=sources,
        active_source_count=sum(sources.values()),
    )


@app.get("/api/samples", tags=["system"])
async def list_samples() -> dict[str, Any]:
    """List the bundled sample alerts, so the UI can offer examples."""
    samples = []

    if config.SAMPLES_DIR.exists():
        for path in sorted(config.SAMPLES_DIR.glob("*.json")):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                samples.append({
                    "filename": path.name,
                    "name": data.get("rule_name", path.stem),
                    "alert": data,
                })
            except (OSError, ValueError):
                continue

    return {"samples": samples}


@app.post("/api/triage", tags=["triage"])
async def triage(request: TriageRequest, req: Request) -> dict[str, Any]:
    """
    Triage an alert.

    Extracts indicators, enriches each against every configured source
    concurrently, scores the combined evidence, and returns a
    recommendation with a ticket-ready case note.

    Returns 422 when neither an alert nor raw text is supplied, 429
    when the per-client rate limit is reached, and 200 with an empty
    result when an alert simply contains no indicators — the last is
    a valid outcome, not an error.
    """
    if not request.alert and not request.raw_text:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'alert' (an object) or 'raw_text' (a string).",
        )

    client_ip = req.client.host if req.client else "unknown"
    if _rate_limited(client_ip):
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit reached ({config.RATE_LIMIT_REQUESTS} triages per "
                f"hour). This demo runs on free-tier threat intelligence quotas "
                f"— clone the repo and run it locally with your own API keys "
                f"for unlimited use."
            ),
        )

    alert = request.resolved_alert()
    iocs = extract.extract_from_alert(alert)

    if not iocs:
        return {
            "verdict": "close",
            "verdict_description": config.VERDICT_DESCRIPTIONS["close"],
            "score": 0,
            "indicators": [],
            "indicator_count": 0,
            "enriched_count": 0,
            "context_only_count": 0,
            "degraded_sources": [],
            "confidence": "normal",
            "driving_indicator": None,
            "case_note": (
                "No indicators of compromise were found in this alert. "
                "Nothing could be enriched, so this assessment reflects the "
                "absence of extractable observables rather than a positive "
                "finding of safety."
            ),
            "case_note_markdown": "",
        }

    enriched = await intel.enrich_all(iocs)
    result = score.score_alert(enriched)

    result["case_note"] = casenote.build_note(result, alert)
    result["case_note_markdown"] = casenote.build_note_markdown(result, alert)

    return result


# ---------------------------------------------------------------
# Static UI
# ---------------------------------------------------------------

# Mounted last so API routes take precedence over the static files.
if config.STATIC_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=config.STATIC_DIR),
        name="static",
    )

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        index_file = config.STATIC_DIR / "index.html"
        if not index_file.exists():
            raise HTTPException(status_code=404, detail="UI not built")
        return FileResponse(index_file)