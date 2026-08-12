"""
Central configuration for the alert triage engine.

All tunable values live here so triage policy can be adjusted
without touching engine logic. API credentials are read from the
environment, never hardcoded.
"""

import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv

# Read .env into the environment. In deployment there is no .env file —
# the platform sets these directly — and this call simply does nothing.
load_dotenv()

# ---------------------------------------------------------------
# Paths
# ---------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
SAMPLES_DIR = DATA_DIR / "samples"
STATIC_DIR = PROJECT_ROOT / "static"

# Cache location is overridable because hosted environments often mount
# the project directory read-only. Falling back to a temp path keeps
# the engine working there; the cache is disposable by design.
CACHE_DIR = Path(os.getenv("CACHE_DIR", str(DATA_DIR / "cache")))

try:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    CACHE_DIR = Path(tempfile.gettempdir()) / "alert-triage-cache"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------
# API credentials
# ---------------------------------------------------------------

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# abuse.ch moved ThreatFox behind authentication. The key is still
# free but is now required — get one from auth.abuse.ch.
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")


def configured_sources() -> dict[str, bool]:
    """
    Which intel sources have credentials available.

    Checked at startup so the UI can show which sources are active
    rather than every lookup failing silently with a 401.
    """
    return {
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "greynoise": bool(GREYNOISE_API_KEY),
        "otx": bool(OTX_API_KEY),
        "threatfox": bool(ABUSECH_API_KEY),
    }


# ---------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------

VT_BASE_URL = "https://www.virustotal.com/api/v3"
GREYNOISE_BASE_URL = "https://api.greynoise.io/v3/community"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

REQUEST_TIMEOUT_SECONDS = 15

# VirusTotal's free tier allows 4 requests per minute. Rather than
# sleeping between calls, concurrent VT requests are capped and
# results are cached aggressively — the same indicator recurs across
# many alerts, so most lookups in normal use are cache hits.
VT_MAX_CONCURRENT = 2
CACHE_MAX_AGE_HOURS = 24

# Cap on IOCs enriched per alert. A malformed alert or a pasted log
# dump could contain hundreds; without a cap, one request would burn
# an entire daily quota.
MAX_IOCS_PER_ALERT = 25

# A public deployment exposes the engine's API quota to anyone who
# finds the URL. A per-client cap stops one visitor exhausting a
# day's lookups in a single burst.
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "20"))
RATE_LIMIT_WINDOW_SECONDS = 3600

# ---------------------------------------------------------------
# Scoring policy
# ---------------------------------------------------------------

# VirusTotal aggregates ~70 engines, which disagree constantly. One
# or two detections is usually a false positive; five or more is
# meaningful consensus.
VT_MALICIOUS_THRESHOLD = 5
VT_SUSPICIOUS_THRESHOLD = 2

# GreyNoise classifications meaning "this scans the whole internet,
# it is not targeting us". These downgrade an indicator rather than
# clearing it — a mass scanner can still deliver a payload.
GREYNOISE_BENIGN_CLASSIFICATIONS = {"benign"}
GREYNOISE_NOISE_CLASSIFICATIONS = {"benign", "unknown"}

# Number of OTX pulses (published threat reports) referencing an
# indicator before it is treated as campaign-associated.
OTX_PULSE_THRESHOLD = 1

# ThreatFox confidence level, 0-100, above which a malware family
# association is treated as reliable.
THREATFOX_CONFIDENCE_THRESHOLD = 50

# ---------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------

# The engine recommends; a human decides. There is deliberately no
# auto-close — an analyst must be able to disagree in seconds, which
# is why every verdict carries its supporting evidence.
VERDICTS = ["escalate", "investigate", "monitor", "close"]

VERDICT_DESCRIPTIONS = {
    "escalate": "Strong evidence of malicious activity — hand to L2 now",
    "investigate": "Mixed or partial signals — needs analyst judgement",
    "monitor": "Weak signals — log and watch, no immediate action",
    "close": "No supporting evidence — likely benign or background noise",
}

# Score ranges mapping to verdicts. Thresholds are a policy choice,
# not a fact, and should be tuned to a team's actual capacity — a
# queue of escalations nobody can work through is worse than none.
VERDICT_THRESHOLDS = {
    "escalate": 70,
    "investigate": 40,
    "monitor": 15,
}