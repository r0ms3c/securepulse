# SecurePulse

AI-powered security intelligence platform that ingests CVEs, vendor advisories,
and threat intel feeds, scores them by severity and exploitability using LLMs,
and delivers a prioritized daily briefing via email, Slack, and a web dashboard.

> "Wake up to a security briefing that's already been triaged.
>  Read only what matters. Miss nothing critical."

---

## The Problem

Security engineers start every day drowning in noise — CVE databases, vendor
advisories, threat intel blogs, CISA alerts. By the time you've manually triaged
what matters, you've lost 1-2 hours. And you've probably still missed something.

## The Solution

SecurePulse runs continuously in the background, ingesting from multiple sources,
scoring each item across five risk dimensions using an LLM, and delivering a
prioritized briefing every morning. It acts as your first-pass security analyst —
one that never sleeps and never skips a source.

---

## Architecture

```
EventBridge (cron)
        │
        ▼
Fetcher Lambdas (NVD, CISA KEV, EPSS, RSS)
        │
        ▼
SQS Queue
        │
        ▼
Scorer + LLM Enricher Lambdas
        │
        ▼
DynamoDB + S3
        │
        ▼
Email (SES) + Slack + Web Dashboard
```


Built entirely on AWS Serverless — Lambda, DynamoDB, SQS, EventBridge,
SES, S3, CloudFront. Infrastructure as Code with AWS CDK (Python).

---

## Scoring Framework

Each item is scored across five dimensions:

| Dimension | Weight | Signal |
|-----------|--------|--------|
| Exploitability | 30% | EPSS score, CISA KEV status |
| Severity | 25% | CVSS base score, CWE type |
| Freshness | 15% | Publication date, patch availability |
| Breadth | 15% | Affected products, vendor market share |
| Intel Value | 15% | IOCs, TTPs, mitigations present |

Priority tiers: **CRITICAL** (8.0-10.0) → **HIGH** (6.0-7.9) →
**MEDIUM** (4.0-5.9) → **LOW** (1.0-3.9)

---

## Feed Sources

**Phase 1 (active):** NVD/CVE, CISA KEV, EPSS
**Phase 2:** Microsoft MSRC, AWS Security, Google Project Zero, vendor RSS
**Phase 3:** Mandiant, CrowdStrike, Unit 42, Krebs on Security
**Phase 4:** Commercial threat intel APIs (Recorded Future, AlienVault OTX)

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation — NVD + CISA KEV + EPSS → email digest | 🔨 In Progress |
| 2 | Enrichment — vendor advisories + Slack delivery | ⏳ Planned |
| 3 | Dashboard — React web UI with search and filters | ⏳ Planned |
| 4 | Advanced Intel — threat blogs + IOC extraction | ⏳ Planned |
| 5 | Productization — multi-tenancy + billing | ⏳ Planned |
| 6 | OpenClaw — conversational AI agent layer | ⏳ Planned |
| 7 | Portfolio — showcase, blog post, demo video | ⏳ Planned |

---

## Cost

Approximately **$10-25/month** for a solo user on AWS (eu-west-1).
LLM API calls are the dominant cost — using AWS Bedrock reduces this significantly.

---

## Tech Stack

- **Infrastructure**: AWS CDK (Python), CloudFormation
- **Compute**: AWS Lambda (Python 3.12)
- **Queue**: AWS SQS with Dead Letter Queue
- **Database**: AWS DynamoDB (on-demand)
- **Storage**: AWS S3
- **Email**: AWS SES
- **Scheduling**: AWS EventBridge
- **AI/LLM**: Provider-agnostic gateway (Claude, GPT-4, AWS Bedrock)
- **Dashboard**: React + Vite + Tailwind (Phase 3)

---

## Setup

Full setup instructions coming in Issue #13 once Phase 1 is complete.
Prerequisites: Python 3.12+, Node.js 22+, AWS CLI v2, AWS CDK CLI.

---

## License

MIT

