from aws_cdk import (
    Stack,
    Duration,        # Used to express time values (seconds, minutes, hours)
    RemovalPolicy,
    aws_sqs as sqs,                        # Simple Queue Service
    aws_lambda as lambda_,                 # Lambda (underscore avoids conflict with Python's built-in `lambda`)
    aws_lambda_event_sources as lambda_es, # Connects SQS queue to Lambda as a trigger
    aws_events as events,                  # EventBridge — scheduling and event routing
    aws_events_targets as targets,         # Defines what EventBridge triggers (e.g. a Lambda)
    aws_iam as iam,                        # IAM roles and policies
)
from constructs import Construct
from .storage_stack import StorageStack


# ── What does the Ingestion Stack do? ───────────────────────────────────────
# This stack is responsible for the first layer of the pipeline:
# FETCH raw security data from external sources and queue it for processing.
#
# Flow:
#   EventBridge (cron) → triggers Fetcher Lambdas every 60 minutes
#   Fetcher Lambdas    → fetch from NVD, CISA KEV, EPSS APIs
#   Fetcher Lambdas    → push raw items to SQS queue
#   SQS queue          → feeds into the Processing stack (next issue)
#
# Why is SQS in the middle?
# Feeds can burst — Patch Tuesday drops 80+ CVEs at once.
# SQS absorbs the burst so processing Lambdas work at a controlled pace.
# If processing fails, SQS retries automatically.
# If it keeps failing, the item goes to the Dead Letter Queue (DLQ)
# so nothing is silently lost.
class IngestionStack(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        storage: StorageStack,  # We pass StorageStack in so we can grant permissions to the table/bucket
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── Dead Letter Queue (DLQ) ──────────────────────────────────────────
        # The DLQ is a safety net.
        # If a message fails processing 3 times (maxReceiveCount below),
        # SQS moves it here instead of discarding it.
        # You can inspect the DLQ in the AWS console to debug failures
        # without losing the original data.
        self.dlq = sqs.Queue(
            self,
            "RawFeedsDLQ",
            queue_name="securepulse-raw-feeds-dlq",

            # ── Retention Period ─────────────────────────────────────────────
            # How long to keep failed messages in the DLQ before deleting them.
            # 14 days gives you enough time to notice and investigate failures.
            retention_period=Duration.days(14),

            # ── Encryption ───────────────────────────────────────────────────
            # SQS_MANAGED: AWS encrypts messages at rest automatically.
            encryption=sqs.QueueEncryption.SQS_MANAGED,
        )

        # ── Main SQS Queue ───────────────────────────────────────────────────
        # This is the central buffer between fetching and processing.
        # Fetcher Lambdas write here; the Scorer Lambda reads from here.
        #
        # We expose self.queue so the ProcessingStack can read from it
        # and so we can grant fetcher Lambdas write permissions.
        self.queue = sqs.Queue(
            self,
            "RawFeedsQueue",
            queue_name="securepulse-raw-feeds",

            # ── Visibility Timeout ───────────────────────────────────────────
            # When a Lambda picks up a message, SQS hides it from other
            # consumers for this duration. If the Lambda finishes successfully,
            # it deletes the message. If it crashes or times out, the message
            # becomes visible again after this timeout and gets retried.
            # Set this to at least 6x your Lambda timeout.
            # Our processing Lambda will run for max 5 minutes → 30 min here.
            visibility_timeout=Duration.minutes(30),

            # ── Message Retention ────────────────────────────────────────────
            # How long to keep unprocessed messages before discarding them.
            # 4 days is plenty — if items sit unprocessed for 4 days,
            # something is seriously wrong and you want to know about it.
            retention_period=Duration.days(4),

            # ── Dead Letter Queue Configuration ─────────────────────────────
            # After 3 failed attempts, move the message to the DLQ.
            # This prevents a single bad message from blocking the queue forever.
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,  # Retry 3 times before giving up
                queue=self.dlq,
            ),

            encryption=sqs.QueueEncryption.SQS_MANAGED,
        )

        # ── Shared Lambda Environment Variables ─────────────────────────────
        # These variables are injected into every fetcher Lambda at runtime.
        # Lambdas read them with os.environ.get("QUEUE_URL") etc.
        # This way we never hardcode AWS resource names in Lambda code —
        # the infrastructure tells the Lambda where things are.
        shared_env = {
            "QUEUE_URL": self.queue.queue_url,
            "RAW_BUCKET": storage.raw_bucket.bucket_name,
            "TABLE_NAME": storage.table.table_name,
        }

        # ── NVD Fetcher Lambda ───────────────────────────────────────────────
        # Fetches CVEs from the NVD (National Vulnerability Database) API.
        # Runs every 60 minutes triggered by EventBridge.
        # We'll write the actual Python code in Issue #3.
        self.nvd_fetcher = lambda_.Function(
            self,
            "NvdFetcher",
            function_name="securepulse-nvd-fetcher",

            # ── Runtime ──────────────────────────────────────────────────────
            # Python 3.12 — latest stable Python on Lambda.
            runtime=lambda_.Runtime.PYTHON_3_12,

            # ── Code Location ────────────────────────────────────────────────
            # Points to the folder containing the Lambda code.
            # CDK will zip this folder and upload it to S3 for deployment.
            code=lambda_.Code.from_asset("../lambdas"),

            # ── Handler ──────────────────────────────────────────────────────
            # Format: "filename.function_name"
            # Lambda will call nvd_fetcher.handler() when invoked.
            handler="fetchers.nvd_fetcher.handler",

            # ── Timeout ──────────────────────────────────────────────────────
            # Max time this Lambda can run before AWS kills it.
            # NVD API can be slow with pagination — 5 minutes is safe.
            timeout=Duration.minutes(5),

            # ── Memory ───────────────────────────────────────────────────────
            # 256MB is plenty for a fetch-and-queue operation.
            # More memory also means more CPU on Lambda.
            memory_size=256,

            environment=shared_env,
        )

        # ── CISA KEV Fetcher Lambda ──────────────────────────────────────────
        # Fetches the CISA Known Exploited Vulnerabilities list.
        # Simple JSON download — faster and lighter than NVD.
        self.cisa_fetcher = lambda_.Function(
            self,
            "CisaKevFetcher",
            function_name="securepulse-cisa-kev-fetcher",
            runtime=lambda_.Runtime.PYTHON_3_12,
            code=lambda_.Code.from_asset("../lambdas"),
            handler="cisa_kev_fetcher.handler",
            timeout=Duration.minutes(3),
            memory_size=128,
            environment=shared_env,
        )

        # ── EPSS Fetcher Lambda ──────────────────────────────────────────────
        # Fetches the daily EPSS CSV from FIRST.org.
        # EPSS = Exploit Prediction Scoring System.
        # Gives each CVE a probability score of being exploited in 30 days.
        self.epss_fetcher = lambda_.Function(
            self,
            "EpssFetcher",
            function_name="securepulse-epss-fetcher",
            runtime=lambda_.Runtime.PYTHON_3_12,
            code=lambda_.Code.from_asset("../lambdas"),
            handler="epss_fetcher.handler",
            timeout=Duration.minutes(3),
            memory_size=128,
            environment=shared_env,
        )

        # ── IAM Permissions ──────────────────────────────────────────────────
        # Least privilege: each Lambda gets only what it needs.
        # grant_send_messages() → Lambda can write to SQS but not read
        # grant_put() → Lambda can write to S3 but not delete or read others
        # grant_write_data() → Lambda can write to DynamoDB but not read
        #
        # CDK generates the exact IAM policy statements automatically.
        # You don't need to write JSON policies manually.
        for fetcher in [self.nvd_fetcher, self.cisa_fetcher, self.epss_fetcher]:
            self.queue.grant_send_messages(fetcher)         # SQS write
            storage.raw_bucket.grant_put(fetcher)           # S3 write
            storage.table.grant_write_data(fetcher)         # DynamoDB write

        # ── EventBridge Scheduler ────────────────────────────────────────────
        # EventBridge is AWS's event bus and scheduler.
        # We create a rule that fires on a cron schedule and
        # triggers all three fetcher Lambdas simultaneously.
        #
        # This is the heartbeat of the entire pipeline.
        # Every 60 minutes → fetch → queue → process → deliver.
        fetch_schedule = events.Rule(
            self,
            "FetchSchedule",
            rule_name="securepulse-fetch-schedule",

            # ── Cron Expression ──────────────────────────────────────────────
            # schedule_expression("rate(60 minutes)") = run every 60 minutes.
            # Alternatively use cron() for specific times:
            # events.Schedule.cron(minute="0", hour="*") = top of every hour
            schedule=events.Schedule.rate(Duration.minutes(60)),

            description="Triggers all SecurePulse fetcher Lambdas every 60 minutes",
        )

        # Add all three fetchers as targets of this schedule.
        # When the rule fires, all three Lambdas are invoked in parallel.
        fetch_schedule.add_target(targets.LambdaFunction(self.nvd_fetcher))
        fetch_schedule.add_target(targets.LambdaFunction(self.cisa_fetcher))
        fetch_schedule.add_target(targets.LambdaFunction(self.epss_fetcher))