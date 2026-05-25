from aws_cdk import (
    Stack,          # Base class for all CDK stacks
    RemovalPolicy,  # Controls what happens to resources when you delete the stack
    aws_dynamodb as dynamodb,  # DynamoDB constructs
    aws_s3 as s3,              # S3 constructs
)
from constructs import Construct


# ── What is a Stack? ─────────────────────────────────────────────────────────
# A Stack is a unit of deployment in CDK/CloudFormation.
# Think of it as a "group of related AWS resources" that get
# created, updated, and deleted together.
#
# We're separating our infrastructure into multiple stacks:
#   - StorageStack    → DynamoDB + S3 (this file)
#   - IngestionStack  → Lambda + SQS + EventBridge (Phase 1, next)
#   - ProcessingStack → Scorer + LLM Lambdas
#   - DeliveryStack   → SES + Slack + API Gateway
#
# Why separate stacks? If you only change the email template,
# you only redeploy DeliveryStack — not everything.
# It's faster, safer, and easier to reason about.
class StorageStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        # ── Always call super().__init__() first ─────────────────────────────
        # This registers the stack with the CDK app and sets up
        # internal CDK machinery. Never skip this line.
        super().__init__(scope, construct_id, **kwargs)

        # ── DynamoDB Table ───────────────────────────────────────────────────
        # DynamoDB is a NoSQL key-value database.
        # Every item (CVE, advisory, blog post) we ingest gets stored here
        # with its scores, summary, and metadata.
        #
        # We expose `self.table` so other stacks can reference it.
        # For example, the IngestionStack will need to know the table name
        # to give its Lambdas write permissions.
        self.table = dynamodb.Table(
            self,
            "SecurePulseItems",       # CDK logical ID (internal reference)
            table_name="SecurePulseItems",  # The actual name in AWS

            # ── Primary Key ──────────────────────────────────────────────────
            # DynamoDB uses a composite primary key: PK + SK together
            # must be unique across all items.
            #
            # PK (Partition Key): groups related items together.
            #   Format: "ITEM#NVD#CVE-2025-12345"
            #   This means: item from NVD source, CVE ID 2025-12345
            #
            # SK (Sort Key): orders items within the same partition.
            #   "META"              → the main scored item record
            #   "ENRICHMENT#<time>" → LLM enrichment results over time
            #
            # This design lets you fetch a CVE and all its enrichment
            # history in a single DynamoDB query.
            partition_key=dynamodb.Attribute(
                name="PK",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="SK",
                type=dynamodb.AttributeType.STRING
            ),

            # ── Billing Mode ─────────────────────────────────────────────────
            # PAY_PER_REQUEST means you pay per read/write operation.
            # There's no minimum charge — if the system is idle, cost is $0.
            # Perfect for a solo project that isn't running 24/7 yet.
            # (Alternative is PROVISIONED, where you pre-allocate capacity
            # and pay even when idle — not what we want here.)
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,

            # ── Encryption ───────────────────────────────────────────────────
            # AWS_MANAGED means AWS manages the encryption keys for you.
            # All data is encrypted at rest automatically.
            # This is the right choice for a security-focused project.
            encryption=dynamodb.TableEncryption.AWS_MANAGED,

            # ── Removal Policy ───────────────────────────────────────────────
            # RETAIN means: if you run `cdk destroy`, keep the DynamoDB table.
            # This protects your data from accidental deletion.
            # You would need to manually delete the table in the AWS console.
            # (Alternative is DESTROY — dangerous for production data.)
            removal_policy=RemovalPolicy.RETAIN,
        )

        # ── Global Secondary Index (GSI1) ────────────────────────────────────
        # The main table lets you look up items by PK+SK (by source and ID).
        # But the daily email digest needs a different query:
        #   "Give me all items from TODAY, sorted by composite score"
        #
        # A GSI is like creating a second "view" of the same table with
        # a different key structure. It doesn't duplicate your data expensively
        # — DynamoDB manages it automatically.
        #
        # GSI1PK = "DATE#2025-05-25" (the date)
        # GSI1SK = "SCORE#9.2"       (the composite score)
        #
        # With this index you can ask:
        #   "Give me all items where GSI1PK = 'DATE#2025-05-25'
        #    ordered by GSI1SK descending"
        # ...and get today's items from highest to lowest priority instantly.
        self.table.add_global_secondary_index(
            index_name="GSI1",
            partition_key=dynamodb.Attribute(
                name="GSI1PK",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="GSI1SK",
                type=dynamodb.AttributeType.STRING
            ),
            # ALL means the index includes all item attributes.
            # This lets you read the full item from the index without
            # a second lookup to the main table — faster and cheaper.
            projection_type=dynamodb.ProjectionType.ALL,
        )

        # ── S3 Bucket ────────────────────────────────────────────────────────
        # S3 stores raw feed data and LLM responses as an audit trail.
        # DynamoDB has a 400KB item size limit — large blog posts or
        # full NVD responses go to S3, with a pointer stored in DynamoDB.
        #
        # We expose `self.raw_bucket` so other stacks can reference it,
        # just like self.table above.
        self.raw_bucket = s3.Bucket(
            self,
            "RawFeedsBucket",
            # We include self.account in the name because S3 bucket names
            # must be globally unique across ALL AWS accounts worldwide.
            # Adding your account ID guarantees uniqueness.
            bucket_name=f"securepulse-raw-feeds-{self.account}",

            # ── Encryption ───────────────────────────────────────────────────
            # S3_MANAGED: AWS encrypts all objects automatically.
            # No extra cost, no configuration needed — always on.
            encryption=s3.BucketEncryption.S3_MANAGED,

            # ── Block Public Access ───────────────────────────────────────────
            # BLOCK_ALL ensures this bucket can NEVER be made public,
            # even accidentally. Raw security feed data should never
            # be publicly accessible.
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,

            # ── Versioning ───────────────────────────────────────────────────
            # Versioning keeps a history of every object version.
            # If a feed overwrites yesterday's raw data, you can still
            # retrieve the previous version. Essential for an audit trail.
            versioned=True,

            # Same as DynamoDB — keep the bucket even if stack is deleted.
            removal_policy=RemovalPolicy.RETAIN,
        )