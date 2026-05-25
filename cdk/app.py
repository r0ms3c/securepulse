import aws_cdk as cdk
import os
from stacks.storage_stack import StorageStack

# ── App Entry Point ─────────────────────────────────────────────────────────
# This is the root of your CDK application.
# Think of it like the "main()" of your infrastructure.
# Every stack you create gets registered here and deployed together.
app = cdk.App()

# ── Environment Configuration ────────────────────────────────────────────────
# We read the AWS account and region from environment variables instead of
# hardcoding them. This means the same code can deploy to different
# environments (dev, staging, prod) just by changing env vars.
#
# CDK_DEFAULT_ACCOUNT and CDK_DEFAULT_REGION are automatically set by the
# AWS CLI when you run: export AWS_PROFILE=securepulse
# So you don't need to set them manually — they come from your AWS profile.
env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=os.environ.get("CDK_DEFAULT_REGION", "eu-west-1"),
)

# ── Storage Stack ────────────────────────────────────────────────────────────
# This creates the DynamoDB table and S3 bucket.
# We pass `env` so CDK knows which AWS account and region to deploy to.
StorageStack(app, "SecurePulseStorageStack", env=env)

# ── Synthesize ───────────────────────────────────────────────────────────────
# This tells CDK to generate the CloudFormation templates.
# Always the last line in app.py.
app.synth()