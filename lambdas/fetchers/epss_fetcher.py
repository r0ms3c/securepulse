import csv
import gzip
import json
import logging
import io
import boto3
import urllib.request
from datetime import datetime, timezone

from shared.config import queue_url, raw_bucket, table_name
from shared.models import RawFeedItem

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── AWS Clients ──────────────────────────────────────────────────────────────
sqs = boto3.client("sqs")
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

# ── EPSS Feed URL ────────────────────────────────────────────────────────────
# FIRST.org publishes a new EPSS CSV every day.
# The file is gzip-compressed — we decompress it in memory.
# Format: cve,epss,percentile
# Example: CVE-2021-44228,0.97534,0.99921
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# ── EPSS Index Keys ──────────────────────────────────────────────────────────
# We store EPSS scores in DynamoDB so the scorer Lambda can look up
# any CVE's score without calling the EPSS API on every item.
# Key format: "EPSS#<CVE-ID>" with SK "META"
EPSS_META_PK = "EPSS_META"
EPSS_META_SK = "META"


def fetch_epss_feed() -> list[dict]:
    """
    Download and parse the EPSS CSV feed.

    The file is gzip-compressed CSV with a comment header line:
      #model_version:v2024.01.30,score_date:2026-06-09T00:00:00+0000
      cve,epss,percentile
      CVE-2021-44228,0.97534,0.99921
      CVE-2022-1388,0.97501,0.99918
      ...

    Returns a list of dicts with keys: cve_id, epss_score, percentile
    """
    logger.info(f"Downloading EPSS feed from {EPSS_URL}")

    req = urllib.request.Request(
        EPSS_URL,
        headers={"User-Agent": "SecurePulse/1.0 (security-intel-platform)"}
    )

    with urllib.request.urlopen(req, timeout=60) as response:
        # Read compressed bytes and decompress in memory
        # No need to write to disk — Lambda has 512MB of /tmp space
        # but we don't need it here
        compressed_data = response.read()

    # Decompress gzip in memory
    with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
        content = gz.read().decode("utf-8")

    # ── Parse CSV ────────────────────────────────────────────────────────────
    # The first line is a comment starting with # containing metadata.
    # We skip it and parse the rest as standard CSV.
    lines = content.splitlines()
    model_version = "unknown"
    score_date = "unknown"
    data_lines = []

    for line in lines:
        if line.startswith("#"):
            # Extract model version and score date from comment
            # Format: #model_version:v2024.01.30,score_date:2026-06-09T00:00:00+0000
            parts = line.lstrip("#").split(",")
            for part in parts:
                if "model_version" in part:
                    model_version = part.split(":")[1]
                elif "score_date" in part:
                    score_date = part.split(":", 1)[1]
        else:
            data_lines.append(line)

    logger.info(f"EPSS model version: {model_version}, score date: {score_date}")

    # Parse CSV rows
    reader = csv.DictReader(data_lines)
    scores = []
    for row in reader:
        try:
            scores.append({
                "cve_id": row["cve"],
                "epss_score": float(row["epss"]),
                "percentile": float(row["percentile"]),
            })
        except (KeyError, ValueError) as e:
            logger.warning(f"Skipping malformed EPSS row {row}: {e}")

    logger.info(f"Parsed {len(scores)} EPSS scores")
    return scores, model_version, score_date


def get_last_processed_date() -> str:
    """
    Get the score date we processed on the last run.

    EPSS updates once per day — if we already processed today's scores
    there's no need to reprocess. We store the last processed date
    in DynamoDB and compare on each run.

    Returns the last processed date string, or empty string if first run.
    """
    table = dynamodb.Table(table_name())
    try:
        response = table.get_item(
            Key={"PK": EPSS_META_PK, "SK": EPSS_META_SK}
        )
        return response.get("Item", {}).get("last_score_date", "")
    except Exception as e:
        logger.warning(f"Could not retrieve EPSS meta: {e}")
        return ""


def update_epss_meta(score_date: str, model_version: str, total_scores: int) -> None:
    """
    Update the EPSS metadata record in DynamoDB.
    Tracks the last processed date so we skip reruns on the same day.
    """
    table = dynamodb.Table(table_name())
    table.put_item(
        Item={
            "PK": EPSS_META_PK,
            "SK": EPSS_META_SK,
            "last_score_date": score_date,
            "model_version": model_version,
            "total_scores": total_scores,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    logger.info(f"Updated EPSS meta in DynamoDB: score_date={score_date}")


def store_epss_scores_in_dynamodb(scores: list[dict]) -> None:
    """
    Store EPSS scores in DynamoDB for fast lookup by the scorer Lambda.

    Why store all scores?
    The scorer Lambda processes CVEs one at a time from SQS.
    For each CVE it needs to look up the EPSS score quickly.
    Storing all scores in DynamoDB means O(1) lookup per CVE
    instead of downloading the entire CSV on every scoring operation.

    We use DynamoDB batch_writer for efficient bulk writes.
    batch_writer automatically handles batching in groups of 25
    (DynamoDB's batch write limit) and retries any unprocessed items.

    Key format: PK="EPSS#CVE-2021-44228", SK="META"
    """
    table = dynamodb.Table(table_name())
    written = 0

    # batch_writer is a context manager that buffers writes and
    # flushes in batches of 25 — much faster than individual put_item calls
    with table.batch_writer() as batch:
        for score in scores:
            batch.put_item(
                Item={
                    "PK": f"EPSS#{score['cve_id']}",
                    "SK": "META",
                    "cve_id": score["cve_id"],
                    "epss_score": str(score["epss_score"]),  # DynamoDB requires Decimal for floats
                    "percentile": str(score["percentile"]),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            written += 1

    logger.info(f"Stored {written} EPSS scores in DynamoDB")


def get_high_epss_items(scores: list[dict], threshold: float = 0.7) -> list[RawFeedItem]:
    """
    Convert high-risk EPSS entries into RawFeedItems for SQS processing.

    We don't send ALL 200,000+ CVEs to SQS — only those with an EPSS
    score above the threshold (default 0.7 = 70% exploitation probability).

    Why 0.7?
    - Scores above 0.7 represent the top ~2% of all CVEs
    - These are CVEs with very high real-world exploitation likelihood
    - They deserve immediate attention even if CVSS score is moderate
    - Lower threshold = more noise; higher = might miss important CVEs

    This is configurable via the NVD_LOOKBACK_HOURS pattern if needed.
    """
    high_risk = [s for s in scores if s["epss_score"] >= threshold]
    logger.info(
        f"High EPSS items (>={threshold}): {len(high_risk)} "
        f"out of {len(scores)} total"
    )

    items = []
    for score in high_risk:
        cve_id = score["cve_id"]
        epss_pct = score["epss_score"] * 100  # Convert to percentage for readability

        items.append(RawFeedItem(
            source="EPSS",
            source_id=cve_id,
            title=f"[High EPSS] {cve_id} — {epss_pct:.1f}% exploitation probability",
            description=(
                f"{cve_id} has an EPSS score of {score['epss_score']:.4f} "
                f"({epss_pct:.1f}% probability of exploitation in the next 30 days). "
                f"EPSS percentile: {score['percentile']:.4f} "
                f"(higher than {score['percentile']*100:.1f}% of all CVEs)."
            ),
            published_at=datetime.now(timezone.utc).date().isoformat(),
            source_url=f"https://www.first.org/epss/graph?id={cve_id}",
            epss_score=score["epss_score"],
            epss_percentile=score["percentile"],
        ))

    return items


def send_to_sqs(items: list[RawFeedItem]) -> int:
    """Send high-risk EPSS items to SQS in batches of 10."""
    url = queue_url()
    sent_count = 0

    for i in range(0, len(items), 10):
        batch = items[i:i + 10]
        entries = [
            {
                "Id": str(idx),
                "MessageBody": json.dumps(item.to_dict()),
            }
            for idx, item in enumerate(batch)
        ]

        response = sqs.send_message_batch(
            QueueUrl=url,
            Entries=entries,
        )

        failed = response.get("Failed", [])
        if failed:
            logger.error(f"SQS batch had {len(failed)} failures: {failed}")

        sent_count += len(response.get("Successful", []))

    return sent_count


def save_raw_to_s3(compressed_data: bytes, fetch_time: str) -> str:
    """Save the raw compressed EPSS feed to S3 for audit trail."""
    bucket = raw_bucket()
    key = f"epss/raw/{fetch_time[:10]}/epss_scores.csv.gz"

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=compressed_data,
        ContentType="application/gzip",
    )

    logger.info(f"Saved raw EPSS feed to s3://{bucket}/{key}")
    return key


def handler(event, context):
    """
    Lambda entry point — called by EventBridge every 60 minutes.

    Flow:
    1. Check if we already processed today's EPSS scores
    2. If yes — skip (EPSS only updates once per day)
    3. If no  — download and parse the EPSS CSV
    4. Store all scores in DynamoDB for scorer Lambda lookups
    5. Send high-risk items (EPSS >= 0.7) to SQS
    6. Update EPSS metadata record
    7. Return summary
    """
    logger.info("EPSS fetcher Lambda started")
    fetch_time = datetime.now(timezone.utc).isoformat()
    today = fetch_time[:10]

    # ── Check if already processed today ────────────────────────────────────
    # EPSS updates once per day. If we already have today's scores,
    # skip the download entirely — saves bandwidth and DynamoDB writes.
    last_date = get_last_processed_date()
    if last_date and today in last_date:
        logger.info(f"EPSS scores already processed for {today}. Skipping.")
        return {
            "status": "skipped",
            "reason": "Already processed today's EPSS scores",
            "last_processed_date": last_date,
        }

    # ── Download and parse ───────────────────────────────────────────────────
    scores, model_version, score_date = fetch_epss_feed()

    # ── Save raw to S3 ───────────────────────────────────────────────────────
    # Re-download compressed for S3 storage
    # (we already decompressed in memory above — this is just for audit)
    req = urllib.request.Request(
        EPSS_URL,
        headers={"User-Agent": "SecurePulse/1.0"}
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        compressed_data = response.read()
    s3_key = save_raw_to_s3(compressed_data, fetch_time)

    # ── Store all scores in DynamoDB ─────────────────────────────────────────
    # This takes a few minutes for 200k+ entries — Lambda timeout is 3 min.
    # We increase the timeout for this Lambda in the next step.
    store_epss_scores_in_dynamodb(scores)

    # ── Send high-risk items to SQS ──────────────────────────────────────────
    high_risk_items = get_high_epss_items(scores)
    sent_count = send_to_sqs(high_risk_items)

    # ── Update metadata ──────────────────────────────────────────────────────
    update_epss_meta(score_date, model_version, len(scores))

    summary = {
        "status": "success",
        "model_version": model_version,
        "score_date": score_date,
        "total_scores": len(scores),
        "high_risk_items": len(high_risk_items),
        "items_sent_to_sqs": sent_count,
        "raw_s3_key": s3_key,
        "fetch_time": fetch_time,
    }

    logger.info(f"EPSS fetcher complete: {summary}")
    return summary