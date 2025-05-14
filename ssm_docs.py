import json
import sys
import regex

import pulumi
import pulumi_aws as aws
from pulumi import ResourceOptions
from typing import Any, Dict, List, Optional, TypedDict


def validate_ssm_document(payload: dict, doc_name: str):
    """Main validation entry point for SSM documents - no modifications"""
    try:
        errors = []
        warnings = []

        # Core validation functions
        validate_basic_fields(payload, errors, warnings)
        validate_parameters(payload, errors, warnings)

        # Check for onFailure in steps
        validate_on_failure(payload, warnings, default="Abort")

        # Schema-specific validation based on version
        schema_version = payload.get("schemaVersion", "")
        if schema_version == "2.2":
            validate_schema_2_2(payload, errors, warnings)
        elif schema_version in ["0.3", "1.0", "1.2", "2.0"]:
            validate_older_schemas(payload, schema_version, errors)

        # Process validation results
        return process_validation_results(doc_name, errors, warnings)

    except Exception as e:
        if isinstance(e, ValueError) and "failed schema validation" in str(e):
            raise
        error_message = (
            f"Error during validation of SSM document '{doc_name}': {str(e)}"
        )
        pulumi.log.error(error_message)
        raise ValueError(error_message)


def process_validation_results(doc_name, errors, warnings):
    """Process and report validation results"""
    if errors:
        error_message = (
            f"SSM document '{doc_name}' failed schema validation:\n- "
            + "\n- ".join(errors)
        )
        pulumi.log.error(error_message)
        raise ValueError(error_message)

    if warnings:
        warning_message = (
            f"SSM document '{doc_name}' validation warnings:\n- "
            + "\n- ".join(warnings)
        )
        pulumi.log.warn(warning_message)

    pulumi.log.info(f"Schema validation passed for SSM document '{doc_name}'")
    return True


def validate_basic_fields(payload, errors, warnings):
    """Validate basic document fields without modifying payload"""
    # Check schema version
    if "schemaVersion" not in payload:
        errors.append("Missing required field 'schemaVersion'")
    elif payload["schemaVersion"] not in ["0.3", "1.0", "1.2", "2.0", "2.2"]:
        errors.append(
            f"Invalid schemaVersion '{payload['schemaVersion']}'. Must be one of: 0.3, 1.0, 1.2, 2.0, 2.2"
        )

    # Check document type - DON'T MODIFY, JUST WARN
    if "documentType" in payload:
        warnings.append(
            "'documentType' should not be in document content JSON. It should be specified as document_type='Command' in the resource definition"
        )

    # Check for description
    if "description" not in payload:
        warnings.append("Missing 'description' field. Add a description to document")
    elif len(payload["description"]) < 10:
        warnings.append("Document description is too short. Add more detail.")

    # Check for unsupported features
    if "targetType" in payload and payload.get("targetType") not in [
        "/",
        "/AWS::EC2::Instance",
    ]:
        warnings.append(
            f"targetType '{payload['targetType']}' may not be supported in all regions or account types"
        )


def validate_parameters(payload, errors, warnings):
    """Validate parameter definitions"""
    if "parameters" not in payload:
        return

    valid_param_types = [
        "String",
        "StringList",
        "Boolean",
        "Integer",
        "MapList",
        "StringMap",
    ]

    for param_name, param_props in payload["parameters"].items():
        # Check parameter name format
        if not param_name.isalnum() and not all(
            c in "_.:" for c in param_name if not c.isalnum()
        ):
            errors.append(
                f"Parameter name '{param_name}' contains invalid characters. Use alphanumeric and _.:"
            )

        # Check parameter properties structure
        if not isinstance(param_props, dict):
            errors.append(f"Parameter '{param_name}' definition must be an object")
            continue

        # Check parameter type
        validate_parameter_type(
            param_name, param_props, valid_param_types, errors, warnings
        )

        # Check allowedValues if present
        if "allowedValues" in param_props and (
            not isinstance(param_props["allowedValues"], list)
            or len(param_props["allowedValues"]) == 0
        ):
            errors.append(
                f"Parameter '{param_name}' has invalid allowedValues. Must be a non-empty array."
            )

        # Check default value
        validate_parameter_default(param_name, param_props, errors)


def validate_parameter_type(param_name, param_props, valid_types, errors, warnings):
    """Validate parameter type and related properties"""
    # Check type is present and valid
    if "type" not in param_props:
        errors.append(f"Parameter '{param_name}' missing required field 'type'")
    elif param_props["type"] not in valid_types:
        errors.append(
            f"Parameter '{param_name}' has invalid type '{param_props['type']}'. "
            f"Valid types are: {', '.join(valid_types)}"
        )

    # Check for SecureString (known invalid type)
    if param_props.get("type") == "SecureString":
        errors.append(
            f"Parameter '{param_name}' has invalid type 'SecureString'. Use 'String' instead."
        )

    # Check parameter description
    if "description" not in param_props:
        warnings.append(
            f"Best practice: Add a description for parameter '{param_name}'"
        )


def validate_parameter_default(param_name, param_props, errors):
    """Validate parameter default values"""
    if "default" in param_props and "type" in param_props:
        param_type = param_props["type"]
        default_val = param_props["default"]

        if (param_type == "Boolean" and not isinstance(default_val, bool)) or (
            param_type == "Integer" and not isinstance(default_val, int)
        ):
            errors.append(
                f"Parameter '{param_name}' default value doesn't match type {param_type}"
            )


def validate_schema_2_2(payload, errors, warnings):
    """Validate schema version 2.2 specific structure"""
    # Check for mainSteps
    if "mainSteps" not in payload:
        errors.append("Document with schemaVersion 2.2 requires 'mainSteps' field")
        return

    # Check mainSteps is an array
    if not isinstance(payload["mainSteps"], list):
        errors.append("'mainSteps' must be an array")
        return

    # Check mainSteps isn't empty
    if len(payload["mainSteps"]) == 0:
        errors.append("'mainSteps' array cannot be empty")
        return

    # Validate each step
    validate_steps(payload["mainSteps"], errors, warnings)


def validate_steps(steps, errors, warnings):
    """Validate steps in a document"""
    step_names = set()

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            errors.append(f"Step {i+1} must be an object")
            continue

        # Check required fields
        if "action" not in step:
            errors.append(f"Step {i+1} missing required field 'action'")

        # Validate step name
        validate_step_name(step, i, step_names, errors)

        # Validate step onFailure property
        validate_step_failure_handling(step, i, warnings)

        # Validate action-specific details
        if "action" in step and step["action"].startswith("aws:"):
            validate_aws_action(step, i, errors, warnings)


def validate_step_name(step, index, step_names, errors):
    """Validate a step name"""
    step_ref = f"Step {index+1}"

    if "name" not in step:
        errors.append(f"{step_ref} missing required field 'name'")
        return

    name = step["name"]
    step_ref = f"Step '{name}'"

    # Check name format
    if not name.isalnum() and not all(c in "_-" for c in name if not c.isalnum()):
        errors.append(
            f"{step_ref} contains invalid characters. Use alphanumeric, underscore and hyphen"
        )

    # Check for duplicates
    elif name in step_names:
        errors.append(f"Duplicate step name: '{name}'. Step names must be unique.")
    else:
        step_names.add(name)


def validate_step_failure_handling(step, index, warnings):
    """Validate step onFailure configuration"""
    step_name = step.get("name", f"step {index+1}")

    if "onFailure" not in step:
        warnings.append(
            f"Best practice: Specify 'onFailure' behavior for step '{step_name}'"
        )
    elif step["onFailure"] not in ["Abort", "Continue"]:
        # Check if it's a step reference
        if not (step["onFailure"].startswith("step:") and len(step["onFailure"]) > 5):
            warnings.append(
                f"Step '{step_name}' has potentially invalid onFailure value: '{step['onFailure']}'"
            )


def validate_aws_action(step, index, errors, warnings):
    """Validate AWS built-in actions"""
    step_name = step.get("name", f"step {index+1}")
    action = step["action"]

    # Check for required inputs for specific actions
    if action in ["aws:runShellScript", "aws:runPowerShellScript", "aws:runDocument"]:
        # Check timeout setting
        if "timeoutSeconds" not in step:
            warnings.append(
                f"Best practice: Add 'timeoutSeconds' to step '{step_name}' to prevent hanging executions"
            )

        # Check inputs field
        if "inputs" not in step:
            errors.append(
                f"Step '{step_name}' with action '{action}' requires 'inputs' field"
            )
            return

        # Action-specific validations
        if action == "aws:runShellScript":
            validate_shell_script(step, step_name, errors, warnings)
        elif action == "aws:runPowerShellScript":
            validate_powershell_script(step, step_name, errors, warnings)


def validate_shell_script(step, step_name, errors, warnings):
    """Validate shell script steps"""
    if "runCommand" not in step["inputs"]:
        errors.append(
            f"Step '{step_name}' with action 'aws:runShellScript' requires 'runCommand' in inputs"
        )
        return

    commands = step["inputs"]["runCommand"]
    if not isinstance(commands, list) or not commands:
        return

    # Check for shebang
    if not any(cmd.strip().startswith("#!/") for cmd in commands):
        warnings.append(
            f"Best practice: Add shebang (#!/bin/bash) to shell script in step '{step_name}'"
        )

    # Check for error handling
    if not any("set -e" in cmd for cmd in commands):
        warnings.append(
            f"Best practice: Add error handling (set -e) to shell script in step '{step_name}'"
        )

def validate_powershell_script(step, step_name, errors, warnings):
    """Validate PowerShell script steps"""
    if "runCommand" not in step["inputs"]:
        errors.append(
            f"Step '{step_name}' with action 'aws:runPowerShellScript' requires 'runCommand' in inputs"
        )
        return

    commands = step["inputs"]["runCommand"]
    if (
        isinstance(commands, list)
        and commands
        and not any("$ErrorActionPreference" in cmd for cmd in commands)
    ):
        warnings.append(
            f"Best practice: Add error handling ($ErrorActionPreference = 'Stop') to PowerShell script in step '{step_name}'"
        )


def validate_older_schemas(payload, schema_version, errors):
    """Validate older schema versions (0.3, 1.0, 1.2, 2.0)"""
    if schema_version in ["0.3", "1.0"] and "runtimeConfig" not in payload:
        errors.append(
            f"Document with schemaVersion {schema_version} requires 'runtimeConfig' field"
        )

    if schema_version in ["1.2", "2.0"] and "mainSteps" not in payload:
        errors.append(
            f"Document with schemaVersion {schema_version} requires 'mainSteps' field"
        )


def validate_on_failure(payload: Dict[str, Any], warnings, default: str = "Abort"):
    """Check if all steps have onFailure without modifying payload"""
    for i, step in enumerate(payload.get("mainSteps", [])):
        if "onFailure" not in step:
            step_name = step.get("name", f"step {i+1}")
            warnings.append(
                f"Step '{step_name}' missing 'onFailure' property. Recommended to add: 'onFailure': '{default}'"
            )


def make_powershell_download_cmd(url: str, dest: str) -> List[str]:
    return [
        "$ver = $PSVersionTable.PSVersion.Major",
        f"$cmd = \"Invoke-WebRequest '{url}' -OutFile {dest}\"",
        "if ($ver -lt 6) { $cmd += ' -UseBasicParsing' }",
        "Invoke-Expression $cmd",
    ]


def _linux_upgrade_steps() -> List[str]:
    return [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "# Function to check if a command exists",
        'command_exists() { command -v "$1" >/dev/null 2>&1; }',
        "# Handle different package managers with backward compatibility",
        "if command_exists dnf; then",
        "  dnf -y update newrelic-infra fluent-bit || true",
        "elif command_exists yum; then",
        "  yum -y update newrelic-infra fluent-bit || true",
        "elif command_exists apt-get; then",
        "  export DEBIAN_FRONTEND=noninteractive",
        "  apt-get update -y",
        "  apt-get install --only-upgrade -y newrelic-infra fluent-bit || true",
        "elif command_exists zypper; then",
        "  zypper -n update newrelic-infra fluent-bit || true",
        "else",
        "  echo 'No supported package manager found'",
        "fi",
        "# Restart service if it exists",
        "if command_exists systemctl && systemctl list-unit-files | grep -q newrelic-infra; then",
        "  systemctl restart newrelic-infra || true",
        "elif command_exists service; then",
        "  service newrelic-infra restart || true",
        "fi",
        "exit 0",
    ]


class SsmDocsArgs(TypedDict, total=False):
    accountIds: List[str]
    region: str
    namePrefix: str


class SsmDocs(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        args: Optional[SsmDocsArgs] = None,
        opts: Optional[ResourceOptions] = None,
    ):
        super().__init__("components:index:SsmDocs", name, {}, opts)
        args = args or {}

        # Fix for account IDs handling
        if args.get("accountIds"):
            # Use from_input instead of output
            account_ids = pulumi.Output.from_input(args["accountIds"])
        else:
            account_ids = aws.get_caller_identity_output().account_id.apply(
                lambda id: [id]
            )

        region = args.get("region", aws.config.region)
        provider = aws.Provider(
            f"{name}-prov", region=region, opts=ResourceOptions(parent=self)
        )

        # Create a region code for document naming
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

        region_code = get_region_code(region)
        name_prefix = args.get("namePrefix", "")
        shared_csv = account_ids.apply(lambda ids: ",".join(ids))
        common_opts = ResourceOptions(parent=self, provider=provider)
        common_tags = {
            "maintainer": "Elang",
            "department": "Cloud Ops",
            "deployedVia": "Pulumi Cloud",
            "region": region,
        }

        def _make_ssm_doc(logical: str, doc_name: str, payload: Dict[str, Any]):
            # Use region code for document naming
            prefixed_name = (
                f"{name_prefix}{doc_name}-{region_code}"
                if name_prefix
                else f"{doc_name}-{region_code}"
            )

            try:
                validate_ssm_document(payload, prefixed_name)

                return aws.ssm.Document(
                    logical,
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
                pulumi.log.error(
                    f"Error creating SSM document '{prefixed_name}': {str(e)}"
                )
                raise

        # 1. INSTALL NEW RELIC INFRA AGENT
        payload01 = {
            "schemaVersion": "2.2",
            "description": "Install & configure the New Relic Infrastructure Agent",
            "parameters": {
                "apiKey": {"type": "String", "description": "New Relic API key"},
                "accountId": {"type": "String", "description": "New Relic Account ID"},
                "region": {
                    "type": "String",
                    "default": "US",
                    "allowedValues": ["EU", "US"],
                },
                "displayName": {"type": "String", "default": ""},
                "enableLogForwarding": {
                    "type": "String",
                    "default": "false",
                    "allowedValues": ["true", "false"],
                },
                "enableProcessMetrics": {
                    "type": "String",
                    "default": "false",
                    "allowedValues": ["true", "false"],
                },
            },
            "mainSteps": [
                {
                    "name": "InstallAgentLinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            '[[ -n "{{ region }}" ]] && export NEW_RELIC_REGION="{{ region }}"',
                            "# Get token for IMDSv2 but fall back to IMDSv1 if needed",
                            'TOKEN=""',
                            "if command -v curl >/dev/null 2>&1; then",
                            '  TOKEN=$(curl -s -f -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null || echo "")',
                            "fi",
                            "# Install New Relic agent",
                            "curl -Ls https://download.newrelic.com/install/newrelic-cli/scripts/install.sh | bash",
                            "cat > /etc/newrelic-infra.yml <<EOF",
                            "license_key: {{ apiKey }}",
                            "EOF",
                            'if [[ -n "{{ displayName }}" ]]; then',
                            '  echo "display_name: {{ displayName }}" >> /etc/newrelic-infra.yml',
                            "fi",
                            'if [[ "{{ enableLogForwarding }}" == "true" ]]; then',
                            "  printf \"\\nlogs:\\n  forward: true\\n  include: '/var/log/syslog,/var/log/auth.log'\\n\" >> /etc/newrelic-infra.yml",
                            "fi",
                            'if [[ "{{ enableProcessMetrics }}" == "true" ]]; then',
                            '  printf "\\nfeatures:\\n  enable_process_metrics: true\\n" >> /etc/newrelic-infra.yml',
                            "fi",
                            "# Start service with compatibility for different service managers",
                            "if command -v systemctl >/dev/null 2>&1; then",
                            "  systemctl restart newrelic-infra || true",
                            "elif command -v service >/dev/null 2>&1; then",
                            "  service newrelic-infra restart || true",
                            "fi",
                            "exit 0",
                        ],
                    },
                },
                {
                    "name": "InstallAgentWindows",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# Check PowerShell version for compatibility",
                            "$ver = $PSVersionTable.PSVersion.Major",
                            "$tmp = Join-Path $env:TEMP 'nrInstall.ps1'",
                            "$cmd = \"Invoke-WebRequest 'https://download.newrelic.com/install/newrelic-cli/scripts/install.ps1' -OutFile $tmp\"",
                            "# Add compatibility parameter for older PowerShell",
                            "if ($ver -lt 6) { $cmd += ' -UseBasicParsing' }",
                            "Invoke-Expression $cmd",
                            "# Run installer with bypass to work on any system",
                            "& powershell -ExecutionPolicy Bypass -File $tmp",
                            "$Env:NEW_RELIC_API_KEY    = '{{ apiKey }}'",
                            "$Env:NEW_RELIC_ACCOUNT_ID = '{{ accountId }}'",
                            "# Install agent",
                            "& 'C:\\Program Files\\New Relic\\New Relic CLI\\newrelic.exe' install -y",
                            "# Configure agent",
                            "if ('{{ displayName }}') {",
                            "  Add-Content 'C:\\Program Files\\New Relic\\newrelic-infra.yml' 'display_name: {{ displayName }}'",
                            "}",
                            "Add-Content 'C:\\Program Files\\New Relic\\newrelic-infra.yml' 'logs:'",
                            "if ('{{ enableLogForwarding }}' -eq 'true') {",
                            "  Add-Content 'C:\\Program Files\\New Relic\\newrelic-infra.yml' '  forward: true'",
                            "  Add-Content 'C:\\Program Files\\New Relic\\newrelic-infra.yml' \"  include: 'System.evtx,Security.evtx'\"",
                            "} else {",
                            "  Add-Content 'C:\\Program Files\\New Relic\\newrelic-infra.yml' '  forward: false'",
                            "}",
                            "Add-Content 'C:\\Program Files\\New Relic\\newrelic-infra.yml' 'features:'",
                            "Add-Content 'C:\\Program Files\\New Relic\\newrelic-infra.yml' ('  enable_process_metrics: ' + ('{{ enableProcessMetrics }}' -eq 'true').ToString().ToLower())",
                            "# Restart service with error handling",
                            "Try { Restart-Service newrelic-infra -ErrorAction SilentlyContinue } Catch { Write-Output 'Service restart attempted' }",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc01", "NewRelic-Agent-Install", payload01)

        # 2. UPGRADE NEW RELIC INFRA AGENT
        payload02 = {
            "schemaVersion": "2.2",
            "description": "Upgrade New Relic Infrastructure Agent (Linux & Windows)",
            "mainSteps": [
                {
                    "name": "UpgradeLinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": _linux_upgrade_steps(),
                    },
                },
                {
                    "name": "UpgradeWindows",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "$tmp = Join-Path $env:TEMP 'nr.msi'",
                            "$wc = New-Object System.Net.WebClient",
                            "# Download with fallback method for compatibility",
                            "Try {",
                            "  $wc.DownloadFile('https://download.newrelic.com/infrastructure_agent/windows/newrelic-infra.msi', $tmp)",
                            "} Catch {",
                            "  # Fallback to PowerShell 3.0+ method",
                            "  Invoke-WebRequest 'https://download.newrelic.com/infrastructure_agent/windows/newrelic-infra.msi' -OutFile $tmp -UseBasicParsing -ErrorAction SilentlyContinue",
                            "}",
                            "# Install MSI package",
                            "Start-Process msiexec.exe -ArgumentList @('/i',$tmp,'/qn','/norestart') -Wait",
                            "# Restart service",
                            "Try { Restart-Service newrelic-infra -ErrorAction SilentlyContinue } Catch {}",
                            "# Cleanup",
                            "Try { Remove-Item $tmp -ErrorAction SilentlyContinue } Catch {}",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc02", "NewRelic-Agent-Upgrade", payload02)

        # 3. UNINSTALL NEW RELIC INFRA AGENT
        payload03 = {
            "schemaVersion": "2.2",
            "description": "Remove New Relic Infrastructure Agent",
            "mainSteps": [
                {
                    "name": "RemoveLinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "onFailure": "Abort",
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            "# Handle different package managers with backward compatibility",
                            'command_exists() { command -v "$1" >/dev/null 2>&1; }',
                            "if command_exists dnf; then",
                            "  dnf remove -y newrelic-infra || true",
                            "elif command_exists yum; then",
                            "  yum remove -y newrelic-infra || true",
                            "elif command_exists apt-get; then",
                            "  export DEBIAN_FRONTEND=noninteractive",
                            "  apt-get remove --purge -y newrelic-infra || true",
                            "elif command_exists zypper; then",
                            "  zypper -n remove newrelic-infra || true",
                            "fi",
                            "rm -f /etc/newrelic-infra.yml || true",
                            "rm -rf /var/log/newrelic-infra || true",
                            "exit 0",
                        ],
                    },
                },
                {
                    "name": "RemoveWindows",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "onFailure": "Continue",
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# Stop and remove service with compatibility for older PowerShell",
                            "Try { Stop-Service newrelic-infra -ErrorAction SilentlyContinue } Catch {}",
                            "$isModernPS = $PSVersionTable.PSVersion.Major -ge 5",
                            "if ($isModernPS) {",
                            "  # Use newer CIM cmdlets if available",
                            "  Try { $pkg = Get-CimInstance -ClassName Win32_Product | Where-Object { $_.Name -like 'New Relic*Infrastructure*' } } Catch {",
                            "    # Fallback to WMI for compatibility",
                            "    $pkg = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like 'New Relic*Infrastructure*' }",
                            "  }",
                            "} else {",
                            "  # Use WMI directly for older PowerShell",
                            "  $pkg = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like 'New Relic*Infrastructure*' }",
                            "}",
                            "If ($pkg) {",
                            "  Start-Process msiexec.exe -ArgumentList '/x', $pkg.IdentifyingNumber, '/qn' -Wait -NoNewWindow",
                            "}",
                            "# Clean up remaining files with error handling for each path",
                            "foreach ($path in @('C:\\Program Files\\New Relic','C:\\ProgramData\\New Relic','C:\\ProgramData\\New Relic Infra')) {",
                            "  if (Test-Path $path) {",
                            "    Try { Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue } Catch {}",
                            "    Try { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue } Catch {}",
                            "  }",
                            "}",
                            "Exit 0",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc03", "NewRelic-Agent-Uninstall", payload03)

        # 4. UPGRADE GCP & NEW RELIC AGENTS
        payload04 = {
            "schemaVersion": "2.2",
            "description": "Upgrade New Relic & Google guest agents (Linux & Windows)",
            "mainSteps": [
                {
                    "name": "UpgradeNRLinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": _linux_upgrade_steps(),
                    },
                },
                {
                    "name": "UpgradeGoogleLinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            'command_exists() { command -v "$1" >/dev/null 2>&1; }',
                            "pkgs='google-compute-engine google-compute-engine-oslogin google-guest-agent google-osconfig-agent'",
                            "if command_exists dnf; then",
                            "  dnf -y install $pkgs || true",
                            "elif command_exists yum; then",
                            "  yum -y install $pkgs || true",
                            "elif command_exists apt-get; then",
                            "  apt-get update -y && apt-get install -y $pkgs || true",
                            "elif command_exists zypper; then",
                            "  zypper --non-interactive install $pkgs || true",
                            "else",
                            "  echo 'No recognized package manager found'",
                            "fi",
                        ],
                    },
                },
                {
                    "name": "UpgradeNRWindows",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "$tmp = Join-Path $env:TEMP 'nr.msi'",
                            "# Download with backward compatibility approach",
                            "$wc = New-Object System.Net.WebClient",
                            "Try {",
                            "  $wc.DownloadFile('https://download.newrelic.com/infrastructure_agent/windows/newrelic-infra.msi', $tmp)",
                            "} Catch {",
                            "  # Fallback for PowerShell 3+",
                            "  Invoke-WebRequest 'https://download.newrelic.com/infrastructure_agent/windows/newrelic-infra.msi' -OutFile $tmp -UseBasicParsing -ErrorAction SilentlyContinue",
                            "}",
                            "# Install MSI",
                            "Start-Process msiexec.exe -ArgumentList @('/i',$tmp,'/qn') -Wait",
                            "Try { Restart-Service newrelic-infra -ErrorAction SilentlyContinue } Catch {}",
                            "Try { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } Catch {}",
                        ],
                    },
                },
                {
                    "name": "GoogetUpdateWindows",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# Check if googet exists",
                            "Try {",
                            "  if (Test-Path 'C:\\ProgramData\\GooGet\\googet.exe') {",
                            "    & 'C:\\ProgramData\\GooGet\\googet.exe' -noconfirm update",
                            "    & 'C:\\ProgramData\\GooGet\\googet.exe' -noconfirm install google-compute-engine-auto-updater",
                            "  } else {",
                            "    Write-Output 'GooGet not found, skipping'",
                            "  }",
                            "} Catch {",
                            '  Write-Output "Error updating GooGet: $_"',
                            "}",
                        ],
                    },
                },
            ],
        }
        _make_ssm_doc(f"{name}-doc04", "Upgrade-Agent-GCP", payload04)

        # 5. UNINSTALL ZABBIX AGENT
        payload05 = {
            "schemaVersion": "2.2",
            "description": "Remove Zabbix Agent (Linux & Windows)",
            "mainSteps": [
                {
                    "name": "RemoveZabbixLinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            'command_exists() { command -v "$1" >/dev/null 2>&1; }',
                            "# Stop service first with compatibility",
                            "if command_exists systemctl && systemctl list-unit-files | grep -q zabbix-agent; then",
                            "  systemctl stop zabbix-agent || true",
                            "elif command_exists service; then",
                            "  service zabbix-agent stop || true",
                            "fi",
                            "# Uninstall with different package managers",
                            "if command_exists dnf; then",
                            "  dnf remove -y zabbix-agent || true",
                            "elif command_exists yum; then",
                            "  yum remove -y zabbix-agent || true",
                            "elif command_exists apt-get; then",
                            "  export DEBIAN_FRONTEND=noninteractive",
                            "  apt-get remove --purge -y zabbix-agent || true",
                            "elif command_exists zypper; then",
                            "  zypper --non-interactive remove zabbix-agent || true",
                            "fi",
                            "exit 0",
                        ],
                    },
                },
                {
                    "name": "RemoveZabbixWindows",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# Stop service with compatibility for older Windows",
                            "Try {",
                            "  Stop-Service 'Zabbix Agent' -ErrorAction SilentlyContinue",
                            "} Catch {",
                            "  # Fallback for very old Windows",
                            '  Try { & sc.exe stop "Zabbix Agent" } Catch {}',
                            "}",
                            "# Get package info using compatible method",
                            "$isModernPS = $PSVersionTable.PSVersion.Major -ge 5",
                            "if ($isModernPS) {",
                            "  Try { $pkg = Get-CimInstance -ClassName Win32_Product | Where-Object {$_.Name -eq 'Zabbix Agent'} } Catch {",
                            "    # Fallback to WMI for compatibility",
                            "    $pkg = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -eq 'Zabbix Agent'}",
                            "  }",
                            "} else {",
                            "  # Use WMI directly for older PowerShell",
                            "  $pkg = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -eq 'Zabbix Agent'}",
                            "}",
                            "if ($pkg) {",
                            "  Start-Process msiexec.exe -ArgumentList @('/x',$pkg.IdentifyingNumber,'/qn') -Wait",
                            "}",
                            "# Remove directory if it exists",
                            "if (Test-Path 'C:\\Program Files\\Zabbix Agent') {",
                            "  Try { Remove-Item 'C:\\Program Files\\Zabbix Agent' -Recurse -Force -ErrorAction SilentlyContinue } Catch {}",
                            "}",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc05", "Zabbix-Agent-Uninstall", payload05)
        # 6. UNINSTALL TREND MICRO DEEP-SECURITY AGENT
        payload06 = {
            "schemaVersion": "2.2",
            "description": "Remove Trend Micro Deep-Security Agent",
            "parameters": {
                "password": {
                    "type": "String",
                    "default": "",
                    "description": "Self-protect password",
                },
            },
            "mainSteps": [
                {
                    "name": "RemoveTMDALinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            'command_exists() { command -v "$1" >/dev/null 2>&1; }',
                            "# Deactivate agent if dsa_control exists",
                            "if command_exists dsa_control; then",
                            "  dsa_control -r || true",
                            "fi",
                            "# Remove agent with different package managers",
                            "if command_exists dnf; then",
                            "  dnf remove -y ds-agent || true",
                            "elif command_exists yum; then",
                            "  yum remove -y ds-agent || true",
                            "elif command_exists apt-get; then",
                            "  export DEBIAN_FRONTEND=noninteractive",
                            "  apt-get remove --purge -y ds-agent || true",
                            "elif command_exists zypper; then",
                            "  zypper --non-interactive remove ds-agent || true",
                            "fi",
                            "# Clean up remaining files",
                            "rm -rf /opt/ds_agent || true",
                            "exit 0",
                        ],
                    },
                },
                {
                    "name": "DisableSelfProtectWin",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "$ctl='C:\\Program Files\\Trend Micro\\Deep Security Agent\\dsa_control.cmd'",
                            "# Check if control script exists before using",
                            "if (Test-Path $ctl) {",
                            "  try {",
                            "    # Use start-process to handle spaces in path reliably",
                            "    Start-Process -FilePath $ctl -ArgumentList '--selfprotect', '0', '-p', '{{ password }}' -Wait -NoNewWindow",
                            "  } catch {",
                            "    # Fallback if Start-Process fails",
                            "    & $ctl --selfprotect 0 -p '{{ password }}'",
                            "  }",
                            "}",
                        ],
                    },
                },
                {
                    "name": "UninstallTMDAWin",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# Get package info with compatibility",
                            "$isModernPS = $PSVersionTable.PSVersion.Major -ge 5",
                            "if ($isModernPS) {",
                            "  Try { $pkg = Get-CimInstance -ClassName Win32_Product | Where-Object {$_.Name -like 'Trend Micro Deep Security Agent'} } Catch {",
                            "    # Fallback to WMI",
                            "    $pkg = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like 'Trend Micro Deep Security Agent'}",
                            "  }",
                            "} else {",
                            "  # Use WMI for older PowerShell",
                            "  $pkg = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like 'Trend Micro Deep Security Agent'}",
                            "}",
                            "if ($pkg) {",
                            "  # Uninstall package",
                            "  Start-Process msiexec.exe -ArgumentList @('/x',$pkg.IdentifyingNumber,'/quiet') -Wait",
                            "}",
                            "# Clean up remaining files",
                            "if (Test-Path 'C:\\Program Files\\Trend Micro') {",
                            "  Try { Remove-Item 'C:\\Program Files\\Trend Micro' -Recurse -Force -ErrorAction SilentlyContinue } Catch {}",
                            "}",
                        ],
                    },
                },
            ],
        }
        _make_ssm_doc(
            f"{name}-doc06", "TrendMicroDeepSecurity-Agent-Uninstall", payload06
        )

        # 7. CREATE LOCAL USER – WINDOWS
        payload07 = {
            "schemaVersion": "2.2",
            "description": "Create a local Windows user - NOTE: Password is intentionally output in command logs",
            "parameters": {
                "username": {"type": "String"},
                "fullName": {"type": "String", "default": ""},
                "userDescription": {"type": "String", "default": "Local user via SSM"},
                "group": {
                    "type": "String",
                    "default": "Remote Desktop Users",
                    "allowedValues": ["Remote Desktop Users", "Administrators"],
                },
            },
            "mainSteps": [
                {
                    "name": "CreateUser",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# SECURITY NOTE: This script intentionally outputs passwords to SSM logs for operational purposes.",
                            "# Ensure SSM command history access is tightly controlled.",
                            "# Input validation",
                            "if ('{{ username }}' -match '[\"\\\\/:*?<>|]') {",
                            "  Write-Output 'ERROR: Username contains invalid characters'",
                            "  exit 1",
                            "}",
                            "# Generate secure random password with complexity verification",
                            "function New-ComplexPassword {",
                            "  do {",
                            "    $pw = -join ((33..126) | Get-Random -Count 16 | ForEach-Object {[char]$_})",
                            "    # Check password complexity",
                            "    $hasUpper = $pw -cmatch '[A-Z]'",
                            "    $hasLower = $pw -cmatch '[a-z]'",
                            "    $hasDigit = $pw -cmatch '[0-9]'",
                            "    $hasSpec = $pw -match '[^A-Za-z0-9]'",
                            "  } until($hasUpper -and $hasLower -and $hasDigit -and $hasSpec)",
                            "  return $pw",
                            "}",
                            "$pw = New-ComplexPassword",
                            "# Use different approaches based on PowerShell version",
                            "$isModernPS = $PSVersionTable.PSVersion.Major -ge 5",
                            "if ($isModernPS) {",
                            "  $sec = ConvertTo-SecureString $pw -AsPlainText -Force",
                            "  # Check if user already exists with modern cmdlets",
                            "  try {",
                            "    if (Get-LocalUser -Name '{{ username }}' -ErrorAction Stop) {",
                            "      Write-Output 'User {{ username }} already exists. No changes made.'",
                            "      exit 0",
                            "    }",
                            "  } catch {",
                            "    # User doesn't exist, continue with creation",
                            "  }",
                            "  # Create the user with modern cmdlets",
                            "  try {",
                            "    $u = New-LocalUser -Name '{{ username }}' -Password $sec -FullName '{{ fullName }}' -Description '{{ userDescription }}' -ErrorAction Stop",
                            "    Write-Output 'User {{ username }} created successfully.'",
                            "  } catch {",
                            '    Write-Output "ERROR: Failed to create user: $_"',
                            "    exit 1",
                            "  }",
                            "  # Add to group with modern cmdlets",
                            "  try {",
                            "    Add-LocalGroupMember -Group '{{ group }}' -Member '{{ username }}' -ErrorAction Stop",
                            "    Write-Output 'Added {{ username }} to the {{ group }} group.'",
                            "  } catch {",
                            '    Write-Output "WARNING: Failed to add user to group: $_"',
                            "  }",
                            "} else {",
                            "  # Legacy approach for older PowerShell versions",
                            "  # Check if user exists using net user",
                            "  $userExists = net user | Where-Object { $_ -match '{{ username }}' }",
                            "  if ($userExists) {",
                            "    Write-Output 'User {{ username }} already exists. No changes made.'",
                            "    exit 0",
                            "  }",
                            "  # Create user with net user command",
                            "  $createCmd = \"net user '{{ username }}' '$pw' /add /fullname:'{{ fullName }}' /comment:'{{ userDescription }}'\"",
                            "  Invoke-Expression $createCmd",
                            "  if ($LASTEXITCODE -ne 0) {",
                            "    Write-Output 'ERROR: Failed to create user using net user command'",
                            "    exit 1",
                            "  }",
                            "  Write-Output 'User {{ username }} created successfully.'",
                            "  # Add to group using net localgroup",
                            "  $groupCmd = \"net localgroup '{{ group }}' '{{ username }}' /add\"",
                            "  Invoke-Expression $groupCmd",
                            "  if ($LASTEXITCODE -ne 0) {",
                            "    Write-Output 'WARNING: Failed to add user to group using net localgroup command'",
                            "  } else {",
                            "    Write-Output 'Added {{ username }} to the {{ group }} group.'",
                            "  }",
                            "}",
                            "# DELIBERATE PASSWORD OUTPUT - This is intentional per operational requirements",
                            'Write-Output "========== SECURE CREDENTIALS ==========" ',
                            "Write-Output ('Username: {{ username }} | Password: ' + $pw)",
                            'Write-Output "========================================="',
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc07", "Create-Local-User-Windows", payload07)

        # 8. RESET LOCAL-USER PASSWORDS – WINDOWS
        payload08 = {
            "schemaVersion": "2.2",
            "description": "Reset Windows local-user passwords - NOTE: New passwords are intentionally output in command logs",
            "parameters": {
                "userNames": {
                    "type": "String",
                    "description": "Comma-separated list of usernames",
                },
            },
            "mainSteps": [
                {
                    "name": "ResetPasswords",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# SECURITY NOTE: This script intentionally outputs passwords to SSM logs for operational purposes.",
                            "# Ensure SSM command history access is tightly controlled.",
                            "# Split the input into an array",
                            "$users = '{{ userNames }}'.Split(',') | ForEach-Object { $_.Trim() }",
                            "if ($users.Count -eq 0 -or $users[0] -eq '') {",
                            "  Write-Output 'ERROR: No usernames provided.'",
                            "  exit 1",
                            "}",
                            "# Generate secure random password with complexity verification",
                            "function New-ComplexPassword {",
                            "  do {",
                            "    $pw = -join ((33..126) | Get-Random -Count 16 | ForEach-Object {[char]$_})",
                            "    # Check password complexity",
                            "    $hasUpper = $pw -cmatch '[A-Z]'",
                            "    $hasLower = $pw -cmatch '[a-z]'",
                            "    $hasDigit = $pw -cmatch '[0-9]'",
                            "    $hasSpec = $pw -match '[^A-Za-z0-9]'",
                            "  } until($hasUpper -and $hasLower -and $hasDigit -and $hasSpec)",
                            "  return $pw",
                            "}",
                            'Write-Output "========== SECURE CREDENTIALS ==========" ',
                            "# Check PowerShell version",
                            "$isModernPS = $PSVersionTable.PSVersion.Major -ge 5",
                            "# Process each user",
                            "foreach ($u in $users) {",
                            "  # Generate secure random password",
                            "  $pw = New-ComplexPassword",
                            "  if ($isModernPS) {",
                            "    # Modern PowerShell approach",
                            "    try {",
                            "      # Verify user exists",
                            "      $user = Get-LocalUser -Name $u -ErrorAction Stop",
                            "      # Reset password",
                            "      $sec = ConvertTo-SecureString $pw -AsPlainText -Force",
                            "      Set-LocalUser -Name $u -Password $sec -ErrorAction Stop",
                            "      # Output new password",
                            '      Write-Output "Username: $u | Password: $pw"',
                            "    } catch {",
                            '      Write-Output "ERROR: Failed to reset password for $u: $_"',
                            "    }",
                            "  } else {",
                            "    # Legacy approach for older PowerShell versions",
                            "    try {",
                            "      # Check if user exists",
                            "      $userExists = net user | Where-Object { $_ -match $u }",
                            "      if (-not $userExists) {",
                            '        Write-Output "ERROR: User $u not found"',
                            "        continue",
                            "      }",
                            "      # Reset password using net user",
                            '      $cmd = "net user $u $pw"',
                            "      Invoke-Expression $cmd",
                            "      if ($LASTEXITCODE -eq 0) {",
                            '        Write-Output "Username: $u | Password: $pw"',
                            "      } else {",
                            '        Write-Output "ERROR: Failed to reset password for $u using net user command"',
                            "      }",
                            "    } catch {",
                            '      Write-Output "ERROR: Failed to reset password for $u: $_"',
                            "    }",
                            "  }",
                            "}",
                            'Write-Output "========================================="',
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc08", "Reset-Local-User-Passwords-Windows", payload08)

        # 9. CHECK LOCAL-USER EXPIRATION – WINDOWS
        payload09 = {
            "schemaVersion": "2.2",
            "description": "Report Windows local-user password expiry",
            "mainSteps": [
                {
                    "name": "CheckExpiry",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "# Get IP address with compatibility for older systems",
                            "Try {",
                            "  $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.*' } | Select-Object -First 1).IPAddress",
                            "} Catch {",
                            "  # Fallback method for older systems",
                            "  $ip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null -and $_.IPAddress[0] -notlike '169.*' } | Select-Object -First 1).IPAddress[0]",
                            "}",
                            "$hostname = $env:COMPUTERNAME",
                            "# Get users with compatibility for older PowerShell",
                            "$isModernPS = $PSVersionTable.PSVersion.Major -ge 5",
                            "if ($isModernPS) {",
                            "  # Modern approach",
                            "  Get-LocalUser | ForEach-Object {",
                            "    $u = $_",
                            "    $info = net user $u.Name",
                            "    if ($info -match 'Password expires\\s+(?<d>\\S.+)') { $d = $matches['d'] } else { $d = 'Never' }",
                            '    Write-Output ("$ip | $hostname | $($u.Name) | $d | $($u.Enabled)") ',
                            "  }",
                            "} else {",
                            "  # Legacy approach for older PowerShell",
                            "  $users = (net user).Where({ $_ -match '^[a-zA-Z0-9]' -and $_ -notmatch 'command completed successfully' })",
                            "  foreach ($rawUser in $users) {",
                            "    # Split the line which may contain multiple usernames",
                            "    foreach ($username in $rawUser.Trim() -split '\\s+') {",
                            "      if ($username) {",
                            "        $info = net user $username",
                            "        $enabled = if ($info -match 'Account active\\s+Yes') { 'True' } else { 'False' }",
                            "        if ($info -match 'Password expires\\s+(?<d>\\S.+)') { $d = $matches['d'] } else { $d = 'Never' }",
                            '        Write-Output ("$ip | $hostname | $username | $d | $enabled")',
                            "      }",
                            "    }",
                            "  }",
                            "}",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc09", "Check-Local-User-Expiration-Windows", payload09)
        # 10. CREATE LOCAL USER – LINUX
        payload10 = {
            "schemaVersion": "2.2",
            "description": "Create a local Linux user with secure credential storage in Parameter Store",
            "parameters": {
                "username": {"type": "String", "description": "Username to create"},
                "group": {
                    "type": "String",
                    "default": "",
                    "description": "Optional secondary group",
                },
                "parameterPrefix": {
                    "type": "String",
                    "default": "/ec2/user-passwords/",
                    "description": "SSM parameter path prefix",
                },
                "expirationHours": {
                    "type": "String",
                    "default": "24",
                    "description": "Hours until password expires from Parameter Store",
                },
            },
            "mainSteps": [
                {
                    "name": "CreateUser",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "onFailure": "Abort",
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            "# Input validation",
                            "user='{{ username }}'",
                            "if [[ ! $user =~ ^[a-z][-a-z0-9]*$ ]]; then",
                            '  echo "ERROR: Invalid username format. Must start with a letter and contain only lowercase letters, numbers, and hyphens."',
                            "  exit 1",
                            "fi",
                            "grp='{{ group }}'",
                            "param_prefix='{{ parameterPrefix }}'",
                            "expiry_hours='{{ expirationHours }}'",
                            "# Check if user already exists",
                            'if id "$user" &>/dev/null; then echo "User $user already exists. No changes made."; exit 0; fi',
                            "# Generate secure password with better entropy",
                            "if command -v openssl >/dev/null 2>&1; then",
                            "  # OpenSSL method (preferred)",
                            "  pw=$(openssl rand -base64 16)",
                            "elif command -v dd >/dev/null 2>&1 && [ -f /dev/urandom ]; then",
                            "  # Fallback to /dev/urandom if openssl not available",
                            "  pw=$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | base64 | head -n 1 | cut -c1-16)",
                            "else",
                            "  # Last resort fallback",
                            "  pw=$(date +%s | sha256sum | base64 | head -c 16)",
                            "fi",
                            "# Create user - handle different passwd encryption methods for compatibility",
                            'echo "Creating user $user..."',
                            "if command -v openssl >/dev/null 2>&1; then",
                            '  encrypted_pw=$(openssl passwd -1 "$pw")',
                            "elif command -v mkpasswd >/dev/null 2>&1; then",
                            '  encrypted_pw=$(mkpasswd -m sha-512 "$pw")',
                            "else",
                            "  # Very old systems without OpenSSL/mkpasswd may need to create user first then set password",
                            '  useradd -m "$user" || { echo "ERROR: Failed to create user $user"; exit 1; }',
                            '  echo "$user:$pw" | chpasswd',
                            '  if [ $? -ne 0 ]; then echo "ERROR: Failed to set password for $user"; exit 1; fi',
                            '  echo "User created and password set."',
                            "  has_password_set=true",
                            "fi",
                            "# Create user with password if we have an encrypted password",
                            'if [[ -z "${has_password_set:-}" ]]; then',
                            '  useradd -m -p "$encrypted_pw" "$user" || { echo "ERROR: Failed to create user $user"; exit 1; }',
                            "fi",
                            "# Add to secondary group if specified",
                            'if [[ -n "$grp" ]]; then',
                            '  echo "Adding user to group $grp..."',
                            '  groupadd -f "$grp" || echo "WARNING: Failed to create group $grp"',
                            '  usermod -aG "$grp" "$user" || echo "WARNING: Failed to add user $user to group $grp"',
                            "fi",
                            "# Get instance metadata with IMDSv2 support",
                            'echo "Determining instance information..."',
                            'TOKEN=""',
                            "if command -v curl >/dev/null 2>&1; then",
                            "  # Try IMDSv2 first",
                            '  TOKEN=$(curl -s -f -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null || echo "")',
                            '  if [[ -n "$TOKEN" ]]; then',
                            '    instance_id=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
                            '    region=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
                            "  else",
                            "    # Fallback to IMDSv1",
                            "    instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)",
                            "    region=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)",
                            "  fi",
                            "elif command -v wget >/dev/null 2>&1; then",
                            "  # Use wget if curl is not available",
                            "  instance_id=$(wget -q -O - http://169.254.169.254/latest/meta-data/instance-id)",
                            "  region=$(wget -q -O - http://169.254.169.254/latest/meta-data/placement/region)",
                            "else",
                            '  echo "WARNING: Cannot determine instance metadata - neither curl nor wget available"',
                            '  instance_id="unknown-instance"',
                            "  # Attempt to get region from AWS config or environment",
                            '  region=$(aws configure get region 2>/dev/null || echo "${AWS_REGION:-us-east-1}")',
                            "fi",
                            "timestamp=$(date +%s)",
                            'param_name="${param_prefix}${instance_id}_${user}_${timestamp}"',
                            "# Store password securely in Parameter Store with expiration",
                            'echo "Storing password in Parameter Store..."',
                            "# Creating expiry date - with compatibility for different date commands",
                            'expiry_date=""',
                            'if date --version 2>&1 | grep -q "GNU coreutils"; then',
                            "  # GNU date (Linux)",
                            '  expiry_date="$(date -d "+${expiry_hours} hours" +%Y-%m-%dT%H:%M:%S%:z)"',
                            "elif date -v+1d > /dev/null 2>&1; then",
                            "  # BSD date (macOS)",
                            '  expiry_date="$(date -v+${expiry_hours}H +%Y-%m-%dT%H:%M:%S%z)"',
                            "else",
                            "  # Fallback - no expiration policy will be used",
                            '  echo "WARNING: Could not create compatible date format for expiration policy"',
                            "fi",
                            "# Try to create Advanced parameter with expiration policy if we have a valid date",
                            'if [[ -n "$expiry_date" ]]; then',
                            '  aws ssm put-parameter --region "$region" --name "$param_name" --type "SecureString" --value "$pw" --tier Advanced --policies "[{\\"Type\\":\\"Expiration\\",\\"Version\\":\\"1.0\\",\\"Attributes\\":{\\"Timestamp\\":\\"$expiry_date\\"}}]" || SSM_ADVANCED_FAILED=true',
                            "else",
                            "  SSM_ADVANCED_FAILED=true",
                            "fi",
                            "# Fallback to standard parameter if Advanced fails or not available",
                            'if [[ -n "${SSM_ADVANCED_FAILED:-}" ]]; then',
                            '  echo "WARNING: Could not create parameter with expiration policy. Falling back to standard parameter."',
                            '  if ! aws ssm put-parameter --region "$region" --name "$param_name" --type "SecureString" --value "$pw"; then',
                            '    echo "CRITICAL: Failed to store password in Parameter Store. Password will only be available in SSM output."',
                            '    echo "Password for $user: $pw"',
                            "    exit 1",
                            "  fi",
                            "fi",
                            'echo "User $user created successfully."',
                            'echo "IMPORTANT: The password is stored in AWS Parameter Store for ${expiry_hours} hours."',
                            'echo "Retrieve password with:"',
                            'echo "aws ssm get-parameter --name "$param_name" --with-decryption --query Parameter.Value --output text"',
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc10", "Create-Local-User-Linux", payload10)

        # 11. DELETE LOCAL USERS – LINUX
        payload11 = {
            "schemaVersion": "2.2",
            "description": "Remove one or more local Linux users",
            "parameters": {
                "usernames": {"type": "String", "description": "Comma-separated list"},
                "deleteHome": {
                    "type": "String",
                    "default": "true",
                    "allowedValues": ["true", "false"],
                    "description": "Delete home directory",
                },
            },
            "mainSteps": [
                {
                    "name": "DeleteUsers",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "onFailure": "Continue",
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            "IFS=',' read -ra USERS <<< '{{ usernames }}'",
                            "DELETE_HOME='{{ deleteHome }}'",
                            'USERDEL_OPTS=""',
                            '[[ "$DELETE_HOME" == "true" ]] && USERDEL_OPTS="-r"',
                            'for u in "${USERS[@]}"; do',
                            '  u=$(echo "$u" | xargs)',
                            '  if [[ -z "$u" ]]; then continue; fi',
                            "  # Check if user exists",
                            '  if id "$u" &>/dev/null; then',
                            "    # Stop any user processes before deletion",
                            '    pkill -9 -u "$u" 2>/dev/null || true',
                            "    # Delete user with appropriate options",
                            '    if [[ -n "$USERDEL_OPTS" ]]; then',
                            '      userdel $USERDEL_OPTS "$u" && echo "Deleted $u (including home directory)"',
                            "    else",
                            '      userdel "$u" && echo "Deleted $u (preserved home directory)"',
                            "    fi",
                            "  else",
                            '    echo "User $u not found"',
                            "  fi",
                            "done",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc11", "Delete-Local-Users-Linux", payload11)

        # 12. CREATE PASSWORD-LESS LINUX USER
        payload12 = {
            "schemaVersion": "2.2",
            "description": "Create Linux user with SSH key + sudo NOPASSWD (securely stores private key in Parameter Store)",
            "parameters": {
                "username": {"type": "String", "description": "Username to create"},
                "secondaryGroup": {
                    "type": "String",
                    "default": "",
                    "description": "Optional secondary group",
                },
                "parameterPrefix": {
                    "type": "String",
                    "default": "/ec2/ssh-keys/",
                    "description": "SSM parameter path prefix",
                },
                "expirationHours": {
                    "type": "String",
                    "default": "24",
                    "description": "Hours until key expires from Parameter Store",
                },
                "keyType": {
                    "type": "String",
                    "default": "ed25519",
                    "allowedValues": ["ed25519", "rsa"],
                    "description": "SSH key type (ed25519 recommended, rsa for compatibility)",
                },
            },
            "mainSteps": [
                {
                    "name": "CreateUserSSH",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "onFailure": "Abort",
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            "# Input validation",
                            "user='{{ username }}'",
                            "if [[ ! $user =~ ^[a-z][-a-z0-9]*$ ]]; then",
                            '  echo "ERROR: Invalid username format. Must start with a letter and contain only lowercase letters, numbers, and hyphens."',
                            "  exit 1",
                            "fi",
                            "sec='{{ secondaryGroup }}'",
                            "param_prefix='{{ parameterPrefix }}'",
                            "expiry_hours='{{ expirationHours }}'",
                            "key_type='{{ keyType }}'",
                            "# Check if user already exists",
                            'if id "$user" &>/dev/null; then echo "User $user already exists. No changes made."; exit 0; fi',
                            "# Create user with sudo access",
                            'echo "Creating user $user with sudo access..."',
                            'useradd -m -s /bin/bash "$user" || { echo "ERROR: Failed to create user $user"; exit 1; }',
                            "# Add to sudo group - handle both sudo and wheel group depending on distro",
                            'if grep -q "^sudo:" /etc/group; then',
                            '  usermod -aG sudo "$user" || echo "WARNING: Failed to add user to sudo group"',
                            'elif grep -q "^wheel:" /etc/group; then',
                            '  usermod -aG wheel "$user" || echo "WARNING: Failed to add user to wheel group"',
                            "else",
                            '  echo "WARNING: Neither sudo nor wheel group found. User may not have admin privileges."',
                            "fi",
                            "# Add to secondary group if specified",
                            'if [[ -n "$sec" ]]; then',
                            '  echo "Adding user to group $sec..."',
                            '  groupadd -f "$sec" || echo "WARNING: Failed to create group $sec"',
                            '  usermod -aG "$sec" "$user" || echo "WARNING: Failed to add user to group $sec"',
                            "fi",
                            "# Configure SSH key generation command based on key type and compatibility",
                            'KEY_CMD=""',
                            'SSH_PATH="/home/$user/.ssh"',
                            'KEY_PATH="$SSH_PATH/id_$key_type"',
                            'if [[ "$key_type" == "ed25519" ]]; then',
                            "  # Check if OpenSSH supports ed25519 (version 6.5+)",
                            '  if ssh -Q key 2>&1 | grep -q ed25519 || ssh -V 2>&1 | grep -E "OpenSSH_(6\\.[5-9]|[7-9]|[1-9][0-9])"; then',
                            "    KEY_CMD=\"ssh-keygen -q -t ed25519 -N '' -f $KEY_PATH\"",
                            "  else",
                            '    echo "WARNING: OpenSSH version does not support ed25519 keys, falling back to RSA"',
                            '    key_type="rsa"',
                            '    KEY_PATH="$SSH_PATH/id_rsa"',
                            "    KEY_CMD=\"ssh-keygen -q -t rsa -b 4096 -N '' -f $KEY_PATH\"",
                            "  fi",
                            "else",
                            "  # RSA is universally supported",
                            "  KEY_CMD=\"ssh-keygen -q -t rsa -b 4096 -N '' -f $KEY_PATH\"",
                            "fi",
                            "# Generate SSH key pair",
                            'echo "Generating SSH key pair..."',
                            'su - "$user" -c "mkdir -p ~/.ssh && $KEY_CMD" || { echo "ERROR: Failed to generate SSH key"; exit 1; }',
                            "# Set up authorized_keys",
                            "cat $KEY_PATH.pub >> $SSH_PATH/authorized_keys",
                            "chmod 700 $SSH_PATH && chmod 600 $SSH_PATH/authorized_keys",
                            "# Configure sudo without password (with compatibility for different sudo versions)",
                            'echo "Configuring sudo without password..."',
                            "if [[ -d /etc/sudoers.d ]]; then",
                            "  # Modern sudo with drop-in directory",
                            '  echo "$user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$user',
                            "  chmod 440 /etc/sudoers.d/$user",
                            "else",
                            "  # Older systems without sudoers.d directory",
                            "  cp /etc/sudoers /etc/sudoers.bak",
                            '  echo "$user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
                            "  # Validate sudoers file",
                            "  if command -v visudo >/dev/null 2>&1; then",
                            "    if ! visudo -c -f /etc/sudoers; then",
                            '      echo "ERROR: Failed to modify sudoers file. Restoring backup."',
                            "      cp /etc/sudoers.bak /etc/sudoers",
                            "      exit 1",
                            "    fi",
                            "  fi",
                            "fi",
                            "# Get instance metadata with IMDSv2 support",
                            'TOKEN=""',
                            "if command -v curl >/dev/null 2>&1; then",
                            "  # Try IMDSv2 first",
                            '  TOKEN=$(curl -s -f -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null || echo "")',
                            '  if [[ -n "$TOKEN" ]]; then',
                            '    instance_id=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
                            '    region=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
                            "  else",
                            "    # Fallback to IMDSv1",
                            "    instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)",
                            "    region=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)",
                            "  fi",
                            "elif command -v wget >/dev/null 2>&1; then",
                            "  # Use wget if curl is not available",
                            "  instance_id=$(wget -q -O - http://169.254.169.254/latest/meta-data/instance-id)",
                            "  region=$(wget -q -O - http://169.254.169.254/latest/meta-data/placement/region)",
                            "else",
                            '  echo "WARNING: Cannot determine instance metadata - neither curl nor wget available"',
                            '  instance_id="unknown-instance"',
                            "  # Attempt to get region from AWS config or environment",
                            '  region=$(aws configure get region 2>/dev/null || echo "${AWS_REGION:-us-east-1}")',
                            "fi",
                            "timestamp=$(date +%s)",
                            'param_name="${param_prefix}${instance_id}_${user}_${timestamp}"',
                            "# Store private key securely in Parameter Store with expiration",
                            'echo "Storing SSH key in Parameter Store..."',
                            "# Get private key",
                            "private_key=$(cat $KEY_PATH)",
                            "# Creating expiry date - with compatibility for different date commands",
                            'expiry_date=""',
                            'if date --version 2>&1 | grep -q "GNU coreutils"; then',
                            "  # GNU date (Linux)",
                            '  expiry_date="$(date -d "+${expiry_hours} hours" +%Y-%m-%dT%H:%M:%S%:z)"',
                            "elif date -v+1d > /dev/null 2>&1; then",
                            "  # BSD date (macOS)",
                            '  expiry_date="$(date -v+${expiry_hours}H +%Y-%m-%dT%H:%M:%S%z)"',
                            "else",
                            "  # Fallback - no expiration policy will be used",
                            '  echo "WARNING: Could not create compatible date format for expiration policy"',
                            "fi",
                            "# Try to create Advanced parameter with expiration policy if we have a valid date",
                            'if [[ -n "$expiry_date" ]]; then',
                            '  aws ssm put-parameter --region "$region" --name "$param_name" --type "SecureString" --value "$private_key" --tier Advanced --policies "[{\\"Type\\":\\"Expiration\\",\\"Version\\":\\"1.0\\",\\"Attributes\\":{\\"Timestamp\\":\\"$expiry_date\\"}}]" || SSM_ADVANCED_FAILED=true',
                            "else",
                            "  SSM_ADVANCED_FAILED=true",
                            "fi",
                            "# Fallback to standard parameter if Advanced fails or not available",
                            'if [[ -n "${SSM_ADVANCED_FAILED:-}" ]]; then',
                            '  echo "WARNING: Could not create parameter with expiration policy. Falling back to standard parameter."',
                            '  if ! aws ssm put-parameter --region "$region" --name "$param_name" --type "SecureString" --value "$private_key"; then',
                            '    echo "CRITICAL: Failed to store SSH key in Parameter Store."',
                            "    exit 1",
                            "  fi",
                            "fi",
                            'echo "User $user created successfully with SSH key access and sudo privileges."',
                            'echo "IMPORTANT: The private key is stored in AWS Parameter Store for ${expiry_hours} hours."',
                            'echo "Retrieve private key with:"',
                            'echo "aws ssm get-parameter --name "$param_name" --with-decryption --query Parameter.Value --output text > ~/.ssh/id_${key_type}_${user}"',
                            'echo "chmod 600 ~/.ssh/id_${key_type}_${user}"',
                            'echo "ssh -i ~/.ssh/id_${key_type}_${user} $user@$(hostname -f)"',
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc12", "Create-Passwordless-User-Linux", payload12)

        # 13. UPDATE SPECIFIC LINUX PACKAGES
        pkgs_doc = {
            "schemaVersion": "2.2",
            "description": "Upgrade specific packages (latest or security-only)",
            "parameters": {
                "packages": {"type": "String", "description": "Comma-separated list"},
                "updateType": {
                    "type": "String",
                    "default": "latest",
                    "allowedValues": ["latest", "security"],
                },
                "cves": {"type": "String", "default": ""},
            },
            "mainSteps": [
                {
                    "name": "UpdatePkgs",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "onFailure": "Abort",
                    "inputs": {
                        "timeoutSeconds": 1800,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            "IFS=',' read -ra PKGS <<< '{{ packages }}'",
                            "IFS=',' read -ra CVES <<< '{{ cves }}'",
                            "mode='{{ updateType }}'",
                            'command_exists() { command -v "$1" >/dev/null 2>&1; }',
                            "# Update with appropriate package manager, with compatibility for all major systems",
                            "if command_exists dnf; then",
                            '  echo "Using dnf package manager..."',
                            "  if [[ $mode == latest ]]; then",
                            '    if [[ ${#PKGS[@]} -gt 0 && -n "${PKGS[0]}" ]]; then',
                            '      echo "Updating packages to latest versions with dnf..."',
                            '      dnf -y update "${PKGS[@]}"',
                            "    else",
                            '      echo "No packages specified for upgrade."',
                            "    fi",
                            "  else",  # security mode
                            '    if [[ ${#CVES[@]} -gt 0 && -n "${CVES[0]}" ]]; then',
                            '      echo "Applying security patches for specified CVEs with dnf..."',
                            '      for c in "${CVES[@]}"; do',
                            '        dnf -y --security update --cve "$c" || echo "Warning: CVE update for $c failed or not applicable"',
                            "      done",
                            "    else",
                            '      echo "No CVEs specified for security update."',
                            "    fi",
                            "  fi",
                            "elif command_exists yum; then",
                            '  echo "Using yum package manager..."',
                            "  if [[ $mode == latest ]]; then",
                            '    if [[ ${#PKGS[@]} -gt 0 && -n "${PKGS[0]}" ]]; then',
                            '      echo "Updating packages to latest versions with yum..."',
                            '      yum -y update "${PKGS[@]}"',
                            "    else",
                            '      echo "No packages specified for upgrade."',
                            "    fi",
                            "  else",  # security mode
                            "    # Check if yum supports the security plugin",
                            "    if yum -h | grep -q security; then",
                            '      if [[ ${#CVES[@]} -gt 0 && -n "${CVES[0]}" ]]; then',
                            '        echo "Applying security patches for specified CVEs with yum..."',
                            '        for c in "${CVES[@]}"; do',
                            '          yum -y --security update --cve "$c" || echo "Warning: CVE update for $c failed or not applicable"',
                            "        done",
                            "      else",
                            '        echo "No CVEs specified for security update."',
                            "      fi",
                            "    else",
                            '      echo "Warning: yum security plugin not available, cannot update by CVE"',
                            '      if [[ ${#PKGS[@]} -gt 0 && -n "${PKGS[0]}" ]]; then',
                            '        echo "Updating packages (which may include security fixes)..."',
                            '        yum -y update "${PKGS[@]}"',
                            "      fi",
                            "    fi",
                            "  fi",
                            "elif command_exists apt-get; then",
                            '  echo "Using apt package manager..."',
                            "  export DEBIAN_FRONTEND=noninteractive",
                            "  apt-get update -y",
                            "  if [[ $mode == latest ]]; then",
                            '    if [[ ${#PKGS[@]} -gt 0 && -n "${PKGS[0]}" ]]; then',
                            '      echo "Updating packages to latest versions with apt-get..."',
                            '      apt-get install -y --only-upgrade "${PKGS[@]}"',
                            "    else",
                            '      echo "No packages specified for upgrade."',
                            "    fi",
                            "  else",  # security mode
                            '    echo "Warning: apt-get doesn\'t directly support CVE patching like yum/zypper."',
                            "    # Check if we have the debian-security source available",
                            "    has_security=false",
                            "    if grep -q security /etc/apt/sources.list; then",
                            "      has_security=true",
                            "    fi",
                            '    if [[ ${#PKGS[@]} -gt 0 && -n "${PKGS[0]}" ]]; then',
                            "      if [[ $has_security == true ]]; then",
                            '        echo "Upgrading packages from security sources..."',
                            '        apt-get -y upgrade -o Dir::Etc::SourceList=/etc/apt/sources.list.d/security.sources "${PKGS[@]}" || apt-get install -y --only-upgrade "${PKGS[@]}"',
                            "      else",
                            '        echo "Updating specified packages to latest available versions (which may include security fixes)."',
                            '        apt-get install -y --only-upgrade "${PKGS[@]}"',
                            "      fi",
                            "    else",
                            '      echo "No specific packages specified for security update."',
                            "    fi",
                            "  fi",
                            "elif command_exists zypper; then",
                            '  echo "Using zypper package manager..."',
                            "  if [[ $mode == latest ]]; then",
                            '    if [[ ${#PKGS[@]} -gt 0 && -n "${PKGS[0]}" ]]; then',
                            '      echo "Updating packages to latest versions with zypper..."',
                            '      zypper -n update "${PKGS[@]}"',
                            "    else",
                            '      echo "No packages specified for upgrade."',
                            "    fi",
                            "  else",  # security mode
                            '    if [[ ${#CVES[@]} -gt 0 && -n "${CVES[0]}" ]]; then',
                            '      echo "Applying security patches for specified CVEs with zypper..."',
                            '      for c in "${CVES[@]}"; do',
                            '        zypper -n patch --cve "$c" || echo "Warning: CVE patch for $c failed or not applicable"',
                            "      done",
                            "    else",
                            '      echo "No CVEs specified for security update."',
                            "    fi",
                            "  fi",
                            "else",
                            '  echo "ERROR: No supported package manager found (dnf, yum, apt-get, zypper)."',
                            "  exit 1",
                            "fi",
                            'echo "Package update operation completed."',
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc13", "Upgrade-Packages-Linux", pkgs_doc)

        # 14. DISK CLEANUP – WINDOWS
        win_cleanup_doc = {
            "schemaVersion": "2.2",
            "description": "Automated disk cleanup & component cleanup",
            "mainSteps": [
                {
                    "name": "Cleanup",
                    "action": "aws:runPowerShellScript",
                    "precondition": {"StringEquals": ["platformType", "Windows"]},
                    "onFailure": "Abort",
                    "inputs": {
                        "timeoutSeconds": 3600,
                        "runCommand": [
                            "# Cleanup temp directories with error handling and progress display",
                            'Write-Output "Starting Windows disk cleanup..."',
                            "# Temp folder cleanup",
                            'Write-Output "Cleaning user temp folders..."',
                            "Try {",
                            "  Get-ChildItem $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | ",
                            "    Where-Object { ($_.CreationTime -lt (Get-Date).AddDays(-1)) } | ",
                            "    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue",
                            "} Catch {",
                            '  Write-Output "Some temp files could not be removed: $_"',
                            "}",
                            "# Windows temp folder cleanup",
                            'Write-Output "Cleaning Windows temp folder..."',
                            "Try {",
                            "  Get-ChildItem 'C:\\Windows\\Temp' -Recurse -Force -ErrorAction SilentlyContinue | ",
                            "    Where-Object { ($_.CreationTime -lt (Get-Date).AddDays(-1)) } | ",
                            "    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue",
                            "} Catch {",
                            '  Write-Output "Some Windows temp files could not be removed: $_"',
                            "}",
                            "# Empty recycle bin",
                            'Write-Output "Emptying recycle bin..."',
                            "Try {",
                            "  if ($PSVersionTable.PSVersion.Major -ge 5) {",
                            "    # Modern approach",
                            "    Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
                            "  } else {",
                            "    # Legacy approach using shell.application",
                            "    $shell = New-Object -ComObject Shell.Application",
                            "    $recycleBin = $shell.Namespace(0xA)",
                            "    $recycleBin.items() | ForEach { Remove-Item $_.Path -Recurse -Confirm:$false }",
                            "  }",
                            '  Write-Output "Recycle bin emptied successfully"',
                            "} Catch {",
                            '  Write-Output "Could not empty recycle bin: $_"',
                            "}",
                            "# Windows component cleanup",
                            'Write-Output "Starting component store cleanup (this may take a while)..."',
                            "Try {",
                            "  $dismResult = Start-Process -FilePath 'Dism.exe' -ArgumentList '/online', '/Cleanup-Image', '/StartComponentCleanup', '/ResetBase' -Wait -PassThru -NoNewWindow",
                            "  if ($dismResult.ExitCode -ne 0) {",
                            '    Write-Output "DISM cleanup returned exit code $($dismResult.ExitCode) - this is not necessarily an error"',
                            "  } else {",
                            '    Write-Output "Component store cleanup completed successfully"',
                            "  }",
                            "} Catch {",
                            '  Write-Output "DISM cleanup encountered an error: $_"',
                            "}",
                            "# Disk optimization",
                            'Write-Output "Analyzing volume C: for optimization..."',
                            "Try {",
                            "  if ($PSVersionTable.PSVersion.Major -ge 5) {",
                            "    # Use Optimize-Volume for newer systems",
                            "    # Use Optimize-Volume for newer systems",
                            "    Optimize-Volume -DriveLetter C -Analyze -ErrorAction SilentlyContinue",
                            "    # TRIM is important for SSDs",
                            "    Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue",
                            '    Write-Output "Volume optimization operations completed"',
                            "  } else {",
                            "    # For older PowerShell versions, use defrag.exe command line",
                            "    $defragProcess = Start-Process -FilePath 'defrag.exe' -ArgumentList 'C: /A' -Wait -PassThru -NoNewWindow",
                            '    Write-Output "Disk analysis completed with exit code $($defragProcess.ExitCode)"',
                            "  }",
                            "} Catch {",
                            '  Write-Output "Volume optimization encountered an error: $_"',
                            "}",
                            "# Check available disk space after cleanup",
                            "Try {",
                            "  $drive = Get-PSDrive C",
                            "  $freeSpaceMB = [math]::Round($drive.Free / 1MB, 2)",
                            "  $totalSpaceMB = [math]::Round(($drive.Used + $drive.Free) / 1MB, 2)",
                            "  $usedPercentage = [math]::Round(($drive.Used / ($drive.Used + $drive.Free)) * 100, 2)",
                            '  Write-Output "Cleanup complete. Drive C: has $freeSpaceMB MB free of $totalSpaceMB MB total ($usedPercentage% used)"',
                            "} Catch {",
                            '  Write-Output "Could not retrieve disk space information"',
                            "}",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(f"{name}-doc14", "Disk-Cleanup-Windows", win_cleanup_doc)

        # 15. CHECK LOCAL-USER EXPIRATION – LINUX
        linux_exp_doc = {
            "schemaVersion": "2.2",
            "description": "List Linux local users & password expiry (skip system/excluded)",
            "parameters": {
                "excludedUsers": {"type": "String", "default": ""},
                "minimumUid": {
                    "type": "String",
                    "default": "1000",
                    "description": "Minimum UID to check",
                },
            },
            "mainSteps": [
                {
                    "name": "CheckExpiry",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "onFailure": "Continue",
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": [
                            "#!/usr/bin/env bash",
                            "set -euo pipefail",
                            "# Split excluded users by comma",
                            "IFS=',' read -ra EX <<< '{{ excludedUsers }}'",
                            "MIN_UID={{ minimumUid }}",
                            "# Get host info with fallbacks for older systems",
                            "if command -v hostname >/dev/null 2>&1; then",
                            "  if hostname -I >/dev/null 2>&1; then",
                            "    HOST=$(hostname); IP=$(hostname -I | awk '{print $1}')",
                            "  else",
                            "    HOST=$(hostname); IP=$(hostname -i 2>/dev/null || echo 'unknown')",
                            "  fi",
                            "else",
                            "  HOST=$(cat /etc/hostname 2>/dev/null || echo 'unknown')",
                            "  IP=$(ip addr show 2>/dev/null | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -n1 || echo 'unknown')",
                            "fi",
                            "# Function to check if user is in excluded list",
                            "is_excluded() {",
                            '  local user="$1"',
                            '  for ex_user in "${EX[@]}"; do',
                            '    if [[ "$user" == "$ex_user" ]]; then',
                            "      return 0 # True, user is excluded",
                            "    fi",
                            "  done",
                            "  return 1 # False, user is not excluded",
                            "}",
                            "# Use getent to get all users, filter by UID threshold",
                            'echo "$IP | $HOST | USERNAME | PASSWORD EXPIRY | ACCOUNT EXPIRY | LAST PASSWORD CHANGE"',
                            "getent passwd | awk -F: -v minuid=$MIN_UID '$3>=minuid {print $1\":\"$3}' | while IFS=: read U ID; do",
                            "  # Skip excluded users",
                            '  if is_excluded "$U"; then continue; fi',
                            "  # Check password expiry with compatibility for different systems",
                            "  if command -v chage >/dev/null 2>&1; then",
                            '    CHAGE_OUTPUT=$(chage -l "$U" 2>/dev/null)',
                            "    if [ $? -eq 0 ]; then",
                            "      PW_EXP=$(echo \"$CHAGE_OUTPUT\" | grep -i 'Password expires' | sed 's/^[^:]*: *//')",
                            "      ACC_EXP=$(echo \"$CHAGE_OUTPUT\" | grep -i 'Account expires' | sed 's/^[^:]*: *//')",
                            "      LAST_CHG=$(echo \"$CHAGE_OUTPUT\" | grep -i 'Last password change' | sed 's/^[^:]*: *//')",
                            "      # If password or account never expires, set it explicitly",
                            '      [ "$PW_EXP" = \'never\' ] || [ -z "$PW_EXP" ] && PW_EXP="Never"',
                            '      [ "$ACC_EXP" = \'never\' ] || [ -z "$ACC_EXP" ] && ACC_EXP="Never"',
                            '      echo "$IP | $HOST | $U | $PW_EXP | $ACC_EXP | $LAST_CHG"',
                            "    else",
                            '      echo "$IP | $HOST | $U | Error getting info | Error getting info | Error getting info"',
                            "    fi",
                            "  else",
                            "    # Very old systems without chage",
                            '    echo "$IP | $HOST | $U | Unknown (chage not available) | Unknown | Unknown"',
                            "  fi",
                            "done",
                        ],
                    },
                },
            ],
        }

        _make_ssm_doc(
            f"{name}-doc15", "Check-Local-User-Expiration-Linux", linux_exp_doc
        )

        # ===================================================================
        # FINISH
        # ===================================================================
        # Register component outputs
        self.register_outputs(
            {
                "document_count": 15,
                "document_names": [
                    "NewRelic-Agent-Install",
                    "NewRelic-Agent-Upgrade",
                    "NewRelic-Agent-Uninstall",
                    "Upgrade-Agent-GCP",
                    "Zabbix-Agent-Uninstall",
                    "TrendMicroDeepSecurity-Agent-Uninstall",
                    "Create-Local-User-Windows",
                    "Reset-Local-User-Passwords-Windows",
                    "Check-Local-User-Expiration-Windows",
                    "Create-Local-User-Linux",
                    "Delete-Local-Users-Linux",
                    "Create-Passwordless-User-Linux",
                    "Upgrade-Packages-Linux",
                    "Disk-Cleanup-Windows",
                    "Check-Local-User-Expiration-Linux",
                ],
            }
        )
