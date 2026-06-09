import json
import logging
import boto3
import urllib.request
from datetime import datetime, timezone

import sys
import os

# ── Shared modules ───────────────────────────────────────────────────────────
# Lambda runs from the lambdas/ root so shared/ is directly importable.
from shared.config import queue_url, raw_bucket, table_name
from shared.models import RawFeedItem

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── AWS Clients ──────────────────────────────────────────────────────────────
sqs = boto3.client("sqs")
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

# ── CISA KEV Feed URL ────────────────────────────────────────────────────────
# This is a public JSON file CISA updates whenever a new CVE is added.
# No authentication required, no pagination — just a single download.
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ── DynamoDB KEV Index Key ───────────────────────────────────────────────────
# We store the full KEV catalog in DynamoDB so the scorer Lambda can
# quickly check "is this CVE on the KEV list?" without calling CISA's API.
# Key format: "KEV_INDEX" — a single item that holds the full set of CVE IDs.
KEV_INDEX_PK = "KEV_INDEX"
KEV_INDEX_SK = "META"


def fetch_kev_feed() -> dict:
    """
    Download the CISA KEV JSON feed.

    The feed is a single JSON file containing all known exploited
    vulnerabilities. As of 2026 it contains ~1200+ entries.

    Returns the parsed JSON as a Python dict.
    """
    logger.info(f"Downloading CISA KEV feed from {CISA_KEV_URL}")

    req = urllib.request.Request(
        CISA_KEV_URL,
        headers={"User-Agent": "SecurePulse/1.0 (security-intel-platform)"}
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8"))

    total = len(data.get("vulnerabilities", []))
    logger.info(f"Downloaded KEV feed: {total} total entries")
    return data


def get_existing_kev_ids() -> set:
    """
    Retrieve the set of CVE IDs we already know are on the KEV list.

    We store this in DynamoDB so we can detect NEW additions on each run.
    On the very first run this returns an empty set.

    Why track this?
    We only want to send NEW KEV entries to SQS for processing.
    If we sent all 1200+ entries every hour, we'd flood the queue
    with duplicates and waste LLM API calls re-processing old items.
    """
    table = dynamodb.Table(table_name())

    try:
        response = table.get_item(
            Key={"PK": KEV_INDEX_PK, "SK": KEV_INDEX_SK}
        )
        item = response.get("Item", {})
        # Return the stored set of CVE IDs, or empty set if first run
        return set(item.get("cve_ids", []))
    except Exception as e:
        logger.warning(f"Could not retrieve existing KEV index: {e}. Treating all as new.")
        return set()


def update_kev_index(all_cve_ids: list[str]) -> None:
    """
    Update the KEV index in DynamoDB with the full current CVE ID list.

    Called after each successful fetch to keep the index current.
    Next run will compare against this updated list to find new entries.
    """
    table = dynamodb.Table(table_name())

    table.put_item(
        Item={
            "PK": KEV_INDEX_PK,
            "SK": KEV_INDEX_SK,
            "cve_ids": all_cve_ids,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_count": len(all_cve_ids),
        }
    )
    logger.info(f"Updated KEV index in DynamoDB: {len(all_cve_ids)} total entries")


def parse_kev_entry(entry: dict) -> RawFeedItem:
    """
    Convert a single CISA KEV entry into our normalized RawFeedItem.

    A KEV entry looks like this in the raw JSON:
    {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 contains...",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known"
    }

    The dueDate is the federal deadline for patching — highly relevant
    for any organization that follows CISA guidance.
    """
    cve_id = entry.get("cveID", "UNKNOWN")
    vendor = entry.get("vendorProject", "")
    product = entry.get("product", "")
    vuln_name = entry.get("vulnerabilityName", cve_id)
    due_date = entry.get("dueDate")
    ransomware_use = entry.get("knownRansomwareCampaignUse", "Unknown")

    # ── Build a rich description ─────────────────────────────────────────────
    # KEV entries have a short description plus a required action.
    # We combine them into a single description for our pipeline.
    short_desc = entry.get("shortDescription", "")
    required_action = entry.get("requiredAction", "")
    ransomware_note = (
        " Known to be used in ransomware campaigns."
        if ransomware_use == "Known" else ""
    )

    description = f"{short_desc} Required action: {required_action}{ransomware_note}"

    return RawFeedItem(
        source="CISA_KEV",
        source_id=cve_id,
        title=f"[KEV] {vuln_name}",  # [KEV] prefix makes it visually distinct in the digest

        description=description,

        # KEV entries have a dateAdded field — when CISA added it to the list.
        # We use this as published_at so freshness scoring works correctly.
        published_at=entry.get("dateAdded", datetime.now(timezone.utc).date().isoformat()),

        source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",

        # ── KEV-specific fields ──────────────────────────────────────────────
        # is_kev=True is the critical flag — the scorer uses this to
        # give a major boost to the exploitability score.
        is_kev=True,
        kev_due_date=due_date,

        # Affected product from KEV (less detailed than NVD CPE strings
        # but still useful for filtering)
        affected_products=[f"{vendor} {product}".strip()],
    )


def save_raw_to_s3(data: dict, fetch_time: str) -> str:
    """
    Save the raw KEV feed to S3 for audit trail.
    Stored under cisa_kev/raw/<date>/<timestamp>.json
    """
    bucket = raw_bucket()
    key = f"cisa_kev/raw/{fetch_time[:10]}/{fetch_time}.json"

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data, indent=2),
        ContentType="application/json",
    )

    logger.info(f"Saved raw KEV feed to s3://{bucket}/{key}")
    return key


def send_to_sqs(items: list[RawFeedItem]) -> int:
    """
    Send new KEV entries to SQS in batches of 10.
    Identical pattern to the NVD fetcher.
    """
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


def handler(event, context):
    """
    Lambda entry point — called by EventBridge every 60 minutes.

    Flow:
    1. Download the full CISA KEV JSON feed
    2. Load existing KEV CVE IDs from DynamoDB
    3. Find NEW entries (not seen on previous runs)
    4. Parse new entries into RawFeedItems
    5. Save raw feed to S3
    6. Update KEV index in DynamoDB
    7. Send new entries to SQS
    8. Return summary
    """
    logger.info("CISA KEV fetcher Lambda started")
    fetch_time = datetime.now(timezone.utc).isoformat()

    # ── Download the feed ────────────────────────────────────────────────────
    kev_data = fetch_kev_feed()
    vulnerabilities = kev_data.get("vulnerabilities", [])
    catalog_version = kev_data.get("catalogVersion", "unknown")

    logger.info(f"KEV catalog version: {catalog_version}, total entries: {len(vulnerabilities)}")

    # ── Find new entries ─────────────────────────────────────────────────────
    # Compare current feed against what we saw last run.
    # Only process CVEs we haven't seen before.
    existing_ids = get_existing_kev_ids()
    all_current_ids = [e.get("cveID") for e in vulnerabilities]

    new_entries = [
        entry for entry in vulnerabilities
        if entry.get("cveID") not in existing_ids
    ]

    logger.info(
        f"KEV comparison: {len(existing_ids)} previously known, "
        f"{len(vulnerabilities)} current, "
        f"{len(new_entries)} new entries"
    )

    # ── Save raw feed to S3 ──────────────────────────────────────────────────
    s3_key = save_raw_to_s3(kev_data, fetch_time)

    # ── Update KEV index in DynamoDB ─────────────────────────────────────────
    # Always update even if no new entries — keeps the index fresh
    # and updates the updated_at timestamp.
    update_kev_index(all_current_ids)

    # ── Parse and send new entries ───────────────────────────────────────────
    sent_count = 0
    if new_entries:
        items = []
        for entry in new_entries:
            try:
                items.append(parse_kev_entry(entry))
            except Exception as e:
                logger.error(f"Failed to parse KEV entry {entry.get('cveID')}: {e}")

        sent_count = send_to_sqs(items)
        logger.info(f"Sent {sent_count} new KEV entries to SQS")
    else:
        logger.info("No new KEV entries since last run")

    # ── Summary ──────────────────────────────────────────────────────────────
    summary = {
        "status": "success",
        "catalog_version": catalog_version,
        "total_kev_entries": len(vulnerabilities),
        "new_entries_found": len(new_entries),
        "items_sent_to_sqs": sent_count,
        "raw_s3_key": s3_key,
        "fetch_time": fetch_time,
    }

    logger.info(f"CISA KEV fetcher complete: {summary}")
    return summary