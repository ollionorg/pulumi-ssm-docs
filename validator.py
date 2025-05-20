# -----------------------------------------------------------------------------
# SSM Document Validator Module
#
# This module provides validation functionality for AWS SSM documents.
# It ensures documents conform to AWS best practices and required formatting.
# -----------------------------------------------------------------------------

import pulumi
from typing import Any, Dict, List


class SsmDocumentValidator:
    """
    Validator for AWS SSM documents.

    This class provides comprehensive validation for AWS Systems Manager documents,
    ensuring they conform to AWS-recommended best practices, schema requirements,
    and structural integrity checks.
    """

    def validate_document(self, payload: dict, doc_name: str) -> bool:
        """
        Validate an SSM document against AWS requirements and best practices.

        Args:
            payload: The document content as a dictionary
            doc_name: The name of the document for error reporting

        Returns:
            bool: True if validation passes

        Raises:
            ValueError: If validation fails with specific error details
        """
        try:
            errors = []
            warnings = []

            # Core validation functions
            self._validate_basic_fields(payload, errors, warnings)
            self._validate_parameters(payload, errors, warnings)
            self._validate_on_failure(payload, warnings, default="Abort")

            # Schema-specific validation based on version
            schema_version = payload.get("schemaVersion", "")
            if schema_version == "2.2":
                self._validate_schema_2_2(payload, errors, warnings)
            elif schema_version in ["0.3", "1.0", "1.2", "2.0"]:
                self._validate_older_schemas(payload, schema_version, errors)

            # Process validation results
            return self._process_validation_results(doc_name, errors, warnings)

        except Exception as e:
            if isinstance(e, ValueError) and "failed schema validation" in str(e):
                raise
            error_message = (
                f"Error during validation of SSM document '{doc_name}': {str(e)}"
            )
            pulumi.log.error(error_message)
            raise ValueError(error_message)

    def _process_validation_results(self, doc_name, errors, warnings):
        """
        Process validation findings and report results.

        Args:
            doc_name: Name of the document
            errors: List of validation errors
            warnings: List of validation warnings

        Returns:
            bool: True if validation passes (no errors)

        Raises:
            ValueError: If validation errors exist
        """
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

    def _validate_basic_fields(self, payload, errors, warnings):
        """
        Validate basic document fields and structure.

        Args:
            payload: The document content dictionary
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
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
            warnings.append(
                "Missing 'description' field. Add a description to document"
            )
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

    def _validate_parameters(self, payload, errors, warnings):
        """
        Validate parameter definitions in the document.

        Args:
            payload: The document content dictionary
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
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
            self._validate_parameter_type(
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
            self._validate_parameter_default(param_name, param_props, errors)

    def _validate_parameter_type(
        self, param_name, param_props, valid_types, errors, warnings
    ):
        """
        Validate parameter type and related properties.

        Args:
            param_name: Name of the parameter
            param_props: Parameter properties dictionary
            valid_types: List of valid parameter types
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
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

    def _validate_parameter_default(self, param_name, param_props, errors):
        """
        Validate parameter default values.

        Args:
            param_name: Name of the parameter
            param_props: Parameter properties dictionary
            errors: List to append any validation errors to
        """
        if "default" in param_props and "type" in param_props:
            param_type = param_props["type"]
            default_val = param_props["default"]

            if (param_type == "Boolean" and not isinstance(default_val, bool)) or (
                param_type == "Integer" and not isinstance(default_val, int)
            ):
                errors.append(
                    f"Parameter '{param_name}' default value doesn't match type {param_type}"
                )

    def _validate_schema_2_2(self, payload, errors, warnings):
        """
        Validate schema version 2.2 specific structure.

        Args:
            payload: The document content dictionary
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
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
        self._validate_steps(payload["mainSteps"], errors, warnings)

    def _validate_steps(self, steps, errors, warnings):
        """
        Validate steps in a document.

        Args:
            steps: List of document steps to validate
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
        step_names = set()

        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"Step {i+1} must be an object")
                continue

            # Check required fields
            if "action" not in step:
                errors.append(f"Step {i+1} missing required field 'action'")

            # Validate step name
            self._validate_step_name(step, i, step_names, errors)

            # Validate step onFailure property
            self._validate_step_failure_handling(step, i, warnings)

            # Validate action-specific details
            if "action" in step and step["action"].startswith("aws:"):
                self._validate_aws_action(step, i, errors, warnings)

    def _validate_step_name(self, step, index, step_names, errors):
        """
        Validate a step name.

        Args:
            step: The step definition to validate
            index: The index of the step in the steps array
            step_names: Set of already seen step names to check for duplicates
            errors: List to append any validation errors to
        """
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

    def _validate_step_failure_handling(self, step, index, warnings):
        """
        Validate step onFailure configuration.

        Args:
            step: The step definition to validate
            index: The index of the step in the steps array
            warnings: List to append any validation warnings to
        """
        step_name = step.get("name", f"step {index+1}")

        if "onFailure" not in step:
            warnings.append(
                f"Best practice: Specify 'onFailure' behavior for step '{step_name}'"
            )
        elif step["onFailure"] not in ["Abort", "Continue"]:
            # Check if it's a step reference
            if not (
                step["onFailure"].startswith("step:") and len(step["onFailure"]) > 5
            ):
                warnings.append(
                    f"Step '{step_name}' has potentially invalid onFailure value: '{step['onFailure']}'"
                )

    def _validate_aws_action(self, step, index, errors, warnings):
        """
        Validate AWS built-in actions.

        Args:
            step: The step definition to validate
            index: The index of the step in the steps array
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
        step_name = step.get("name", f"step {index+1}")
        action = step["action"]

        # Check for required inputs for specific actions
        if action in [
            "aws:runShellScript",
            "aws:runPowerShellScript",
            "aws:runDocument",
        ]:
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
                self._validate_shell_script(step, step_name, errors, warnings)
            elif action == "aws:runPowerShellScript":
                self._validate_powershell_script(step, step_name, errors, warnings)

    def _validate_shell_script(self, step, step_name, errors, warnings):
        """
        Validate shell script steps.

        Args:
            step: The step definition to validate
            step_name: Name of the step for error reporting
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
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

    def _validate_powershell_script(self, step, step_name, errors, warnings):
        """
        Validate PowerShell script steps.

        Args:
            step: The step definition to validate
            step_name: Name of the step for error reporting
            errors: List to append any validation errors to
            warnings: List to append any validation warnings to
        """
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

    def _validate_older_schemas(self, payload, schema_version, errors):
        """
        Validate older schema versions (0.3, 1.0, 1.2, 2.0).

        Args:
            payload: The document content dictionary
            schema_version: The schema version to validate against
            errors: List to append any validation errors to
        """
        if schema_version in ["0.3", "1.0"] and "runtimeConfig" not in payload:
            errors.append(
                f"Document with schemaVersion {schema_version} requires 'runtimeConfig' field"
            )

        if schema_version in ["1.2", "2.0"] and "mainSteps" not in payload:
            errors.append(
                f"Document with schemaVersion {schema_version} requires 'mainSteps' field"
            )

    def _validate_on_failure(
        self, payload: Dict[str, Any], warnings, default: str = "Abort"
    ):
        """
        Check if all steps have onFailure property defined.

        Args:
            payload: The document content dictionary
            warnings: List to append any validation warnings to
            default: The default onFailure value to recommend
        """
        for i, step in enumerate(payload.get("mainSteps", [])):
            if "onFailure" not in step:
                step_name = step.get("name", f"step {i+1}")
                warnings.append(
                    f"Step '{step_name}' missing 'onFailure' property. Recommended to add: 'onFailure': '{default}'"
                )
