# -----------------------------------------------------------------------------
# SSM Documents Component
#
# Pulumi component resource that creates and manages AWS Systems Manager
# documents across multiple regions and accounts using standardized templates.
# -----------------------------------------------------------------------------

import json
import pulumi
import pulumi_aws as aws
from pulumi import ResourceOptions
from typing import Any, Dict, List, Optional, TypedDict

from validator import SsmDocumentValidator
from document_templates import SsmDocumentTemplates


class SsmDocsArgs(TypedDict, total=False):
    """
    Arguments for the SsmDocs component.

    Attributes:
        accountIds: List of AWS account IDs to share documents with
        region: AWS region to deploy documents to
        namePrefix: Prefix to add to document names
    """

    accountIds: List[str]
    region: str
    namePrefix: str


class SsmDocs(pulumi.ComponentResource):
    """
    Pulumi component for managing AWS SSM documents.

    This component creates and manages a collection of standardized SSM documents
    for common operational tasks. Documents are deployed to specified regions,
    shared with specified accounts, and use consistent naming conventions.

    Attributes:
        document_names: List of created document names
        document_count: Number of documents created
    """

    def __init__(
        self,
        name: str,
        args: Optional[SsmDocsArgs] = None,
        opts: Optional[ResourceOptions] = None,
    ):
        """
        Initialize the SSM Documents component.

        Args:
            name: Name for this instance of the component
            args: Configuration arguments for the component
            opts: Pulumi resource options
        """
        super().__init__("cloudops:components:SsmDocs", name, {}, opts)
        args = args or {}

        # Setup account IDs and region
        if args.get("accountIds"):
            account_ids = pulumi.Output.from_input(args["accountIds"])
        else:
            account_ids = aws.get_caller_identity_output().account_id.apply(
                lambda id: [id]
            )

        region = args.get("region", aws.config.region)
        provider = aws.Provider(
            f"{name}-prov", region=region, opts=ResourceOptions(parent=self)
        )

        # Initialize region code for document naming
        region_code = self._get_region_code(region)
        name_prefix = args.get("namePrefix", "")
        shared_csv = account_ids.apply(lambda ids: ",".join(ids))

        # Common resource options and tags
        common_opts = ResourceOptions(parent=self, provider=provider)
        common_tags = {
            "maintainer": "Elang",
            "department": "Cloud Ops",
            "deployedVia": "Pulumi",
            "region": region,
        }

        # Initialize validator
        validator = SsmDocumentValidator()

        # Create documents
        document_names = self._create_documents(
            name,
            name_prefix,
            region_code,
            shared_csv,
            common_opts,
            common_tags,
            validator,
        )

        # Register component outputs
        self.document_names = document_names
        self.document_count = len(document_names)

        self.register_outputs(
            {
                "document_count": self.document_count,
                "document_names": self.document_names,
            }
        )

    def _get_region_code(self, region_name: str) -> str:
        """
        Create a standardized code for each AWS region.

        Args:
            region_name: The full AWS region name (e.g., us-east-1)

        Returns:
            str: A shortened region code (e.g., use1)
        """
        region_codes = {
            "us-east-1": "use1",  # N. Virginia
            "us-east-2": "use2",  # Ohio
            "us-west-1": "usw1",  # N. California
            "us-west-2": "usw2",  # Oregon
            "ca-central-1": "cac1",  # Canada
            "us-gov-east-1": "usge1",  # GovCloud East
            "us-gov-west-1": "usgw1",  # GovCloud West
            "sa-east-1": "sae1",  # São Paulo
            "eu-north-1": "eun1",  # Stockholm
            "eu-west-1": "euw1",  # Ireland
            "eu-west-2": "euw2",  # London
            "eu-west-3": "euw3",  # Paris
            "eu-central-1": "euc1",  # Frankfurt
            "eu-south-1": "eus1",  # Milan
            "me-south-1": "mes1",  # Bahrain
            "af-south-1": "afs1",  # Cape Town
            "ap-east-1": "ape1",  # Hong Kong
            "ap-south-1": "aps1",  # Mumbai
            "ap-northeast-1": "apne1",  # Tokyo
            "ap-northeast-2": "apne2",  # Seoul
            "ap-northeast-3": "apne3",  # Osaka
            "ap-southeast-1": "apse1",  # Singapore
            "ap-southeast-2": "apse2",  # Sydney
            "ap-southeast-3": "apse3",  # Jakarta
            "cn-north-1": "cnn1",  # Beijing
            "cn-northwest-1": "cnnw1",  # Ningxia
        }

        if region_name in region_codes:
            return region_codes[region_name]

        # Fallback for new regions not in our map
        parts = region_name.split("-")
        if len(parts) >= 3:
            return parts[0][0] + parts[1][0] + parts[2]
        return region_name

    def _make_ssm_doc(
        self,
        logical_id: str,
        doc_name: str,
        payload: Dict[str, Any],
        region_code: str,
        name_prefix: str,
        shared_csv,
        common_tags,
        common_opts,
        validator,
    ):
        """
        Create and validate an individual SSM document.

        Args:
            logical_id: Pulumi resource identifier
            doc_name: Base name for the document
            payload: Document content
            region_code: Region code to append to the document name
            name_prefix: Prefix to add to document name
            shared_csv: CSV string of account IDs to share with
            common_tags: Tags to apply to the document
            common_opts: Pulumi resource options
            validator: SSM document validator instance

        Returns:
            aws.ssm.Document: The created document resource
        """
        # Use region code for document naming
        prefixed_name = (
            f"{name_prefix}{doc_name}-{region_code}"
            if name_prefix
            else f"{doc_name}-{region_code}"
        )

        try:
            # Validate document
            validator.validate_document(payload, prefixed_name)

            # Create resource
            return aws.ssm.Document(
                logical_id,
                name=prefixed_name,
                document_type="Command",
                document_format="JSON",
                target_type="/AWS::EC2::Instance",
                tags=common_tags,
                content=json.dumps(payload, indent=2),
                permissions=shared_csv.apply(
                    lambda csv: {"type": "Share", "account_ids": csv}
                ),
                opts=common_opts,
            )
        except Exception as e:
            pulumi.log.error(f"Error creating SSM document '{prefixed_name}': {str(e)}")
            raise

    def _create_documents(
        self,
        name,
        name_prefix,
        region_code,
        shared_csv,
        common_opts,
        common_tags,
        validator,
    ):
        """
        Create all standard SSM documents from templates.

        Args:
            name: Base resource name
            name_prefix: Prefix for document names
            region_code: Region code to append to document names
            shared_csv: CSV string of account IDs to share with
            common_opts: Common Pulumi resource options
            common_tags: Common resource tags
            validator: SSM document validator instance

        Returns:
            List[str]: Names of the created documents
        """
        # Map of document logical names to their template methods and final names
        document_templates = [
            ("NewRelic-Agent-Install", SsmDocumentTemplates.new_relic_agent_install),
            ("NewRelic-Agent-Upgrade", SsmDocumentTemplates.new_relic_agent_upgrade),
            (
                "NewRelic-Agent-Uninstall",
                SsmDocumentTemplates.new_relic_agent_uninstall,
            ),
            (
                "Create-Local-User-Windows",
                SsmDocumentTemplates.create_local_user_windows,
            ),
            (
                "Reset-Local-User-Passwords-Windows",
                SsmDocumentTemplates.reset_local_user_passwords_windows,
            ),
            (
                "Check-Local-User-Expiration-Windows",
                SsmDocumentTemplates.check_user_expiration_windows,
            ),
            ("Create-Local-User-Linux", SsmDocumentTemplates.create_local_user_linux),
            ("Delete-Local-Users-Linux", SsmDocumentTemplates.delete_local_users_linux),
            (
                "Create-Passwordless-User-Linux",
                SsmDocumentTemplates.create_passwordless_user_linux,
            ),
            ("Upgrade-Packages-Linux", SsmDocumentTemplates.upgrade_packages_linux),
            ("Disk-Cleanup-Windows", SsmDocumentTemplates.windows_disk_cleanup),
            (
                "Check-Local-User-Expiration-Linux",
                SsmDocumentTemplates.check_user_expiration_linux,
            ),
        ]

        # Create all documents
        document_resources = {}
        for i, (doc_name, template_method) in enumerate(document_templates):
            logical_id = f"{name}-doc{i+1:02d}"
            document_resources[doc_name] = self._make_ssm_doc(
                logical_id,
                doc_name,
                template_method(),
                region_code,
                name_prefix,
                shared_csv,
                common_tags,
                common_opts,
                validator,
            )

        # Return list of document names
        return [doc_name for doc_name, _ in document_templates]
