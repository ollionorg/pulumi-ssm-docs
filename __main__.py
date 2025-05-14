import pulumi
import boto3
from ssm_docs import SsmDocs

# Get configuration
config = pulumi.Config()
current_stack = pulumi.get_stack()


def get_region_code(region_name):
    """Create a unique, readable code for each AWS region."""
    region_codes = {
        # North America
        "us-east-1": "use1",  # N. Virginia
        "us-east-2": "use2",  # Ohio
        "us-west-1": "usw1",  # N. California
        "us-west-2": "usw2",  # Oregon
        "ca-central-1": "cac1",  # Canada
        "us-gov-east-1": "usge1",  # GovCloud East
        "us-gov-west-1": "usgw1",  # GovCloud West
        # South America
        "sa-east-1": "sae1",  # São Paulo
        # Europe
        "eu-north-1": "eun1",  # Stockholm
        "eu-west-1": "euw1",  # Ireland
        "eu-west-2": "euw2",  # London
        "eu-west-3": "euw3",  # Paris
        "eu-central-1": "euc1",  # Frankfurt
        "eu-south-1": "eus1",  # Milan
        # Middle East
        "me-south-1": "mes1",  # Bahrain
        # Africa
        "af-south-1": "afs1",  # Cape Town
        # Asia Pacific
        "ap-east-1": "ape1",  # Hong Kong
        "ap-south-1": "aps1",  # Mumbai
        "ap-northeast-1": "apne1",  # Tokyo
        "ap-northeast-2": "apne2",  # Seoul
        "ap-northeast-3": "apne3",  # Osaka
        "ap-southeast-1": "apse1",  # Singapore
        "ap-southeast-2": "apse2",  # Sydney
        "ap-southeast-3": "apse3",  # Jakarta
        # China
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


def get_available_aws_regions():
    """
    Fetch all available AWS regions dynamically.
    Returns a dictionary of {region_name: region_code}
    """
    try:
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(AllRegions=True)

        # Create region dictionary with proper region codes
        regions = {}
        for region in response["Regions"]:
            region_name = region["RegionName"]
            # Generate region code
            region_code = get_region_code(region_name)
            regions[region_name] = region_code

        return regions
    except Exception as e:
        pulumi.log.warn(
            f"Unable to fetch AWS regions dynamically: {str(e)}. Falling back to static list."
        )
        # Return a static fallback list in case of errors
        return {
            "us-east-1": "use1",
            "us-east-2": "use2",
            "us-west-1": "usw1",
            "us-west-2": "usw2",
            "eu-central-1": "euc1",
            "eu-west-1": "euw1",
            "eu-west-2": "euw2",
            "eu-west-3": "euw3",
            "ap-southeast-1": "apse1",
            "ap-southeast-2": "apse2",
            "ap-northeast-1": "apne1",
            "ap-south-1": "aps1",
        }


# Get all available AWS regions dynamically
all_regions = get_available_aws_regions()

# Read regions to enable from config with error handling
try:
    enabled_regions_list = config.get_object("enabled_regions")
    # Ensure it's a list
    if enabled_regions_list and not isinstance(enabled_regions_list, list):
        pulumi.log.warn("enabled_regions config is not defined, using default regions")
        enabled_regions_list = None
except Exception as e:
    pulumi.log.warn(f"Error reading enabled_regions config: {str(e)}")
    enabled_regions_list = None

# Set default regions if needed
if not enabled_regions_list:
    # Default regions to enable if not specified
    default_regions = ["ap-southeast-1"]
    pulumi.log.info(f"Using default regions: {default_regions}")
    regions_to_deploy = {
        region: code
        for region, code in all_regions.items()
        if region in default_regions
    }
else:
    # Filter to only the enabled regions
    regions_to_deploy = {
        region: code
        for region, code in all_regions.items()
        if region in enabled_regions_list
    }
if not regions_to_deploy:
    pulumi.log.warn(
        "No valid regions to deploy to after filtering. Check your enabled_regions configuration."
    )
    pulumi.log.info("Falling back to default region: ap-southeast-1")
    regions_to_deploy = {"ap-southeast-1": all_regions.get("ap-southeast-1", "apse1")}
    pulumi.log.info(
        f"Deploying to configured regions: {list(regions_to_deploy.keys())}"
    )

# Complete mapping of AWS regions to friendly names following proper English naming conventions
region_friendly_names = {
    # North America
    "us-east-1": "us-north-virginia",  # US East (N. Virginia)
    "us-east-2": "us-ohio",  # US East (Ohio)
    "us-west-1": "us-north-california",  # US West (N. California)
    "us-west-2": "us-oregon",  # US West (Oregon)
    "ca-central-1": "canada-central",  # Canada (Central)
    "us-gov-east-1": "us-gov-east",  # AWS GovCloud (US-East)
    "us-gov-west-1": "us-gov-west",  # AWS GovCloud (US-West)
    # South America
    "sa-east-1": "south-america-sao-paulo",  # South America (São Paulo)
    # Europe
    "eu-north-1": "europe-stockholm",  # Europe (Stockholm)
    "eu-west-1": "europe-ireland",  # Europe (Ireland)
    "eu-west-2": "europe-london",  # Europe (London)
    "eu-west-3": "europe-paris",  # Europe (Paris)
    "eu-central-1": "europe-frankfurt",  # Europe (Frankfurt)
    "eu-central-2": "europe-zurich",  # Europe (Zurich)
    "eu-south-1": "europe-milan",  # Europe (Milan)
    "eu-south-2": "europe-spain",  # Europe (Spain)
    # Middle East
    "me-south-1": "middle-east-bahrain",  # Middle East (Bahrain)
    "me-central-1": "middle-east-uae",  # Middle East (UAE)
    # Africa
    "af-south-1": "africa-cape-town",  # Africa (Cape Town)
    # Asia Pacific
    "ap-east-1": "asia-hong-kong",  # Asia Pacific (Hong Kong)
    "ap-south-1": "asia-mumbai",  # Asia Pacific (Mumbai)
    "ap-south-2": "asia-hyderabad",  # Asia Pacific (Hyderabad)
    "ap-northeast-1": "asia-tokyo",  # Asia Pacific (Tokyo)
    "ap-northeast-2": "asia-seoul",  # Asia Pacific (Seoul)
    "ap-northeast-3": "asia-osaka",  # Asia Pacific (Osaka)
    "ap-southeast-1": "asia-singapore",  # Asia Pacific (Singapore)
    "ap-southeast-2": "asia-sydney",  # Asia Pacific (Sydney)
    "ap-southeast-3": "asia-jakarta",  # Asia Pacific (Jakarta)
    "ap-southeast-4": "asia-melbourne",  # Asia Pacific (Melbourne)
    # China
    "cn-north-1": "china-beijing",  # China (Beijing)
    "cn-northwest-1": "china-ningxia",  # China (Ningxia)
    # Israel
    "il-central-1": "israel-tel-aviv",  # Israel (Tel Aviv)
}

# Get account IDs directly from Pulumi config with error handling
try:
    account_ids = config.get_object("accountIds")
    if account_ids and not isinstance(account_ids, list):
        pulumi.log.warn(
            "accountIds config for sharing is not defined, using current account only"
        )
        account_ids = None
except Exception as e:
    pulumi.log.warn(f"Error reading accountIds config: {str(e)}")
    account_ids = None

# Deploy to each enabled region
for region, region_code in regions_to_deploy.items():
    # Get a friendly name for the region, fallback to region code if not found
    logical_name = region_friendly_names.get(region, region.replace("-", "_"))

    args = {"region": region}
    if account_ids:
        args["accountIds"] = account_ids

    SsmDocs(f"ssmDocs-{logical_name}", args)
