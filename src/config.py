"""
Central configuration for the alert triage engine.

All tunable values live here so triage policy can be adjusted
without touching engine logic. API credentials are read from the
environment, never hardcoded.
"""

import os
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
CACHE_DIR = DATA_DIR / "cache"
SAMPLES_DIR = DATA_DIR / "samples"
STATIC_DIR = PROJECT_ROOT / "static"

# ---------------------------------------------------------------
# API credentials
# ---------------------------------------------------------------

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# ThreatFox needs no credentials, so the engine still returns
# something useful when nothing is configured.
THREATFOX_REQUIRES_KEY = False


def configured_sources() -> dict[str, bool]:
    """
    Which intel sources have credentials available.

    Checked at startup so the UI can show which sources are active
    rather than failing silently on every lookup.
    """
    return {
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "greynoise": bool(GREYNOISE_API_KEY),
        "otx": bool(OTX_API_KEY),
        "threatfox": True,
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
# sleeping between calls, results are cached aggressively — the same
# indicator appears across many alerts.
CACHE_MAX_AGE_HOURS = 24

# Cap on IOCs enriched per alert. A malformed alert or a pasted log
# dump could contain hundreds; without a cap one request would burn
# an entire daily quota.
MAX_IOCS_PER_ALERT = 25

# ---------------------------------------------------------------
# Scoring policy
# ---------------------------------------------------------------

# VirusTotal aggregates ~70 engines, which disagree constantly.
# One or two detections is usually a false positive; five or more
# is meaningful consensus.
VT_MALICIOUS_THRESHOLD = 5
VT_SUSPICIOUS_THRESHOLD = 2

# GreyNoise classifications that mean "this scans the whole internet,
# it isn't targeting us". These downgrade an indicator rather than
# clearing it — a scanner can still deliver a payload.
GREYNOISE_BENIGN_CLASSIFICATIONS = {"benign"}
GREYNOISE_NOISE_CLASSIFICATIONS = {"benign", "unknown"}

# Number of OTX pulses (published threat reports) referencing an
# indicator before it is treated as campaign-associated.
OTX_PULSE_THRESHOLD = 1

# ---------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------

# The engine recommends; a human decides. There is deliberately no
# "auto-close" — an analyst must be able to disagree in seconds,
# which is why every verdict carries its supporting evidence.
VERDICTS = ["escalate", "investigate", "monitor", "close"]

VERDICT_DESCRIPTIONS = {
    "escalate": "Strong evidence of malicious activity — hand to L2 now",
    "investigate": "Mixed or partial signals — needs analyst judgement",
    "monitor": "Weak signals — log and watch, no immediate action",
    "close": "No supporting evidence — likely benign or background noise",
}

# Score ranges mapping to verdicts. Thresholds are a policy choice,
# not a fact, and should be tuned to a team's actual capacity.
VERDICT_THRESHOLDS = {
    "escalate": 70,
    "investigate": 40,
    "monitor": 15,
}