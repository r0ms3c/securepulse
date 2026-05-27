import os


# ── What is this file? ───────────────────────────────────────────────────────
# A central place for all configuration values that Lambdas need at runtime.
# Instead of calling os.environ.get("QUEUE_URL") scattered across every file,
# every Lambda imports from here.
#
# Benefits:
# - One place to change a variable name if needed
# - Raises clear errors if a required variable is missing
# - Easy to mock in unit tests
# ────────────────────────────────────────────────────────────────────────────

def get_required(key: str) -> str:
    """
    Read a required environment variable.
    Raises a clear error if it's missing — better than a cryptic
    KeyError buried deep in Lambda logs.
    """
    value = os.environ.get(key)
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{key}' is not set. "
            f"Check the Lambda environment configuration in CDK."
        )
    return value


def get_optional(key: str, default: str = "") -> str:
    """
    Read an optional environment variable.
    Returns the default value if not set.
    """
    return os.environ.get(key, default)


# ── Resource Names ───────────────────────────────────────────────────────────
# These are injected by CDK at deploy time (see ingestion_stack.py shared_env)
# Every Lambda in the ingestion layer has access to these.

def queue_url() -> str:
    """URL of the SQS queue where fetchers send raw items."""
    return get_required("QUEUE_URL")


def raw_bucket() -> str:
    """Name of the S3 bucket for raw feed storage and audit trail."""
    return get_required("RAW_BUCKET")


def table_name() -> str:
    """Name of the DynamoDB table."""
    return get_required("TABLE_NAME")


# ── NVD API Configuration ────────────────────────────────────────────────────
# NVD = National Vulnerability Database (NIST)
# API docs: https://nvd.nist.gov/developers/vulnerabilities

# How many hours back to look for new CVEs on each run.
# Since the fetcher runs every 60 minutes, 2 hours gives a safe overlap
# to avoid missing CVEs during any brief API downtime.
NVD_LOOKBACK_HOURS = int(get_optional("NVD_LOOKBACK_HOURS", "2"))

# NVD rate limits: 5 requests/second without API key, 50/second with key.
# We sleep between requests to stay within limits.
NVD_RATE_LIMIT_DELAY = float(get_optional("NVD_RATE_LIMIT_DELAY", "0.6"))

# Max results per NVD API page (their maximum is 2000)
NVD_PAGE_SIZE = int(get_optional("NVD_PAGE_SIZE", "2000"))