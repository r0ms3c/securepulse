from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# ── What is this file? ───────────────────────────────────────────────────────
# Defines the data structures (models) used across all Lambdas.
# Using dataclasses means we get type hints, default values, and
# clean __repr__ for free — without needing a heavy ORM or Pydantic.
#
# Every raw item fetched from any source gets normalized into a
# RawFeedItem before being sent to SQS. This means the processing
# Lambda doesn't need to know whether an item came from NVD, CISA,
# or a blog post — it always receives the same structure.
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class CvssScore:
    """
    Represents a CVSS (Common Vulnerability Scoring System) score.
    CVSS is the industry standard for rating vulnerability severity.

    v3_score: Float from 0.0 to 10.0
      0.0-3.9  = Low
      4.0-6.9  = Medium
      7.0-8.9  = High
      9.0-10.0 = Critical

    v3_vector: The full CVSS vector string, e.g.:
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      This encodes attack vector, complexity, privileges required, etc.
    """
    v3_score: Optional[float] = None
    v3_vector: Optional[str] = None
    v2_score: Optional[float] = None  # Older CVEs may only have v2


@dataclass
class RawFeedItem:
    """
    A normalized item from any feed source before scoring and enrichment.

    Every fetcher Lambda (NVD, CISA KEV, EPSS, RSS blogs) converts its
    raw API response into this structure before pushing to SQS.

    This is the "contract" between the ingestion layer and processing layer.
    The scorer Lambda always receives RawFeedItems regardless of source.
    """

    # ── Identity ─────────────────────────────────────────────────────────────
    source: str          # e.g. "NVD", "CISA_KEV", "MSRC", "MANDIANT_BLOG"
    source_id: str       # e.g. "CVE-2025-12345", blog post URL
    title: str           # Human-readable title

    # ── Content ──────────────────────────────────────────────────────────────
    description: str              # Raw description from the source
    published_at: str             # ISO 8601 datetime string
    source_url: Optional[str] = None  # Link back to original source

    # ── Vulnerability-specific fields (NVD items) ────────────────────────────
    cvss: Optional[CvssScore] = None
    cwe_ids: list[str] = field(default_factory=list)    # e.g. ["CWE-79", "CWE-89"]
    affected_products: list[str] = field(default_factory=list)  # CPE strings

    # ── CISA KEV fields ──────────────────────────────────────────────────────
    is_kev: bool = False           # True if on CISA Known Exploited list
    kev_due_date: Optional[str] = None  # Federal patch deadline if KEV

    # ── EPSS fields ──────────────────────────────────────────────────────────
    epss_score: Optional[float] = None    # 0.0-1.0 probability of exploitation
    epss_percentile: Optional[float] = None  # How it ranks vs all CVEs

    # ── Metadata ─────────────────────────────────────────────────────────────
    ingested_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    raw_s3_key: Optional[str] = None  # S3 key where raw response is stored

    def to_dict(self) -> dict:
        """
        Convert to a plain dictionary for JSON serialization.
        Used when sending to SQS (which only accepts strings/dicts).
        """
        return {
            "source": self.source,
            "source_id": self.source_id,
            "title": self.title,
            "description": self.description,
            "published_at": self.published_at,
            "source_url": self.source_url,
            "cvss": {
                "v3_score": self.cvss.v3_score,
                "v3_vector": self.cvss.v3_vector,
                "v2_score": self.cvss.v2_score,
            } if self.cvss else None,
            "cwe_ids": self.cwe_ids,
            "affected_products": self.affected_products,
            "is_kev": self.is_kev,
            "kev_due_date": self.kev_due_date,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "ingested_at": self.ingested_at,
            "raw_s3_key": self.raw_s3_key,
        }