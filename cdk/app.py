import aws_cdk as cdk
import os
from stacks.storage_stack import StorageStack
from stacks.ingestion_stack import IngestionStack

app = cdk.App()

# ── Environment ──────────────────────────────────────────────────────────────
# Read account and region from environment variables set by AWS CLI profile.
env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=os.environ.get("CDK_DEFAULT_REGION", "eu-west-1"),
)

# ── Storage Stack ─────────────────────────────────────────────────────────────
# Always deploy storage first — everything else depends on it.
storage = StorageStack(app, "SecurePulseStorageStack", env=env)

# ── Ingestion Stack ───────────────────────────────────────────────────────────
# Pass storage as a dependency so ingestion Lambdas can be granted
# permissions to write to the DynamoDB table and S3 bucket.
ingestion = IngestionStack(
    app,
    "SecurePulseIngestionStack",
    storage=storage,
    env=env,
)

app.synth()