# -----------------------------------------------------------------------------
# SSM Documents Deployment
#
# Deploys standardized SSM documents to multiple regions for operational use.
# -----------------------------------------------------------------------------

import pulumi
import pulumi_aws as aws
from typing import List

from ssm_component import SsmDocs

# Read configuration from Pulumi.yaml
config = pulumi.Config()
enabled_regions = config.get_object("enabled_regions", [])
account_ids = config.get_object("accountIds", [])

# Create a provider for each enabled region
regional_providers = {}
for region in enabled_regions:
    regional_providers[region] = aws.Provider(
        f"aws-{region}",
        region=region,
    )

# Create SSM documents in each enabled region
ssm_docs_by_region = {}
for region in enabled_regions:
    provider = regional_providers[region]

    # Create the SSM documents in this region
    ssm_docs_by_region[region] = SsmDocs(
        f"ssm-docs-{region}",
        args={
            "accountIds": account_ids,
            "region": region,
        },
        opts=pulumi.ResourceOptions(provider=provider),
    )

# Export the document names by region
for region, docs in ssm_docs_by_region.items():
    pulumi.export(f"ssm_docs_{region}", pulumi.Output.all(docs.document_names))
