# Multi-Region AWS SSM Documents via Pulumi

This repository provides a Pulumi-based solution to deploy and manage AWS Systems Manager (SSM) Documents across one or more AWS regions. It includes validation logic to ensure SSM document payloads comply with approved schemas, and automatically shares these documents with specified AWS accounts.

Information and Known issues: <https://ollion.atlassian.net/wiki/x/CYA3-w>

---

## Table of Contents

* [Overview](#overview)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Configuration](#configuration)
* [Usage](#usage)
* [SSM Documents Provided](#ssm-documents-provided)
* [Code Structure](#code-structure)
* [Testing](#testing)
* [Contributing](#contributing)
  * [Adding New SSM Documents](#adding-new-ssm-documents)
* [License](#license)

---

## Overview

This repository provides a modular, extensible framework for deploying AWS Systems Manager (SSM) Documents across multiple AWS regions using Pulumi ESC with OIDC authentication. The solution follows modern software engineering principles with a clean separation of concerns across multiple components:

* **Templating**: Standardized document templates with consistent structure and behavior
* **Validation**: Comprehensive validation against AWS SSM schema requirements
* **Script Library**: Reusable, cross-platform script templates for common operations
* **Deployment**: Pulumi component resources for managing multi-region deployments

The project seamlessly integrates with Pulumi ESC by separating:

* **Environment**: Stacks managed via ESC environments
* **Secrets**: Sensitive values stored and retrieved through ESC secret management
* **Config**: Declarative settings in `Pulumi.<stack>.yaml` for region selection and account sharing

On each run, the project deploys a suite of SSM Documents—ranging from agent management to user administration tools—to your configured regions, sharing them with specified AWS accounts.

## Prerequisites

* **Pulumi CLI** <https://www.pulumi.com/docs/iac/download-install/>
* **ESC CLI** <https://www.pulumi.com/docs/esc/download-install/>
* **Python** >= 3.7
* **AWS Credentials** configured locally (via `~/.aws/credentials`, environment variables, or IAM role)
* **AWS OIDC Provider** configured for Pulumi ESC

This repository includes a CloudFormation template (`CloudFormation template/Pulumi-OIDC.yaml`) to quickly set up the required AWS OIDC integration for Pulumi ESC, which you can deploy via the AWS Console or CLI.

## Installation

1. **Clone the repository**:

   ```bash
   git clone <repo-url> && cd <repo-dir>
   ```

2. **Install Python dependencies**:

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Log in to Pulumi ESC**:

   ```bash
   esc login
   ```

## Configuration

Define your stack configuration in `Pulumi.<stack>.yaml` at the project root:

```yaml
config:
  enabled_regions:
    - us-east-1
    - eu-central-1
    - ap-southeast-2

  accountIds:
    - "1234567890"
```

**Important configuration details:**

* The **default region** is determined by your Pulumi/AWS environment settings and is where the Pulumi program runs
* The **enabled_regions** list specifies all AWS regions where the SSM documents will be deployed
* The **accountIds** list contains AWS account IDs that the documents will be shared with (in addition to the account where they're being deployed)

For example, if your Pulumi is running in account `987654321` and you've specified the configuration above:

1. SSM documents will be deployed to `us-east-1`, `eu-central-1`, and `ap-southeast-2` in account `987654321`
2. Each document will be shared with account `1234567890`, allowing that account to use the documents without creating its own copies

Secrets can be managed using `pulumi env set` and referenced in your configuration as needed.

## Usage

Deploy all configured SSM Documents:

```bash
# List current environment
pulumi env ls

# Run in selected environment
pulumi env run <environment-name> -- pulumi up --yes
```

Destroy all deployed resources:

```bash
pulumi env run <environment-name> -- pulumi destroy --yes
```

## SSM Documents Provided

The following SSM Documents are automatically created in every region listed under `enabled_regions`. Each name includes a region-specific `<code>` suffix (e.g., `apse2` for `ap-southeast-2`).

| Document Name                                | Description                                                    | Parameters                                                                                                                                                         |
| -------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NewRelic-Agent-Install-<code>`              | Install & configure the New Relic Infrastructure Agent         | `apiKey`, `accountId`, `region`, `displayName`, `enableLogForwarding`, `enableProcessMetrics`                                                                      |
| `NewRelic-Agent-Upgrade-<code>`              | Upgrade New Relic Infrastructure Agent (Linux & Windows)       | None                                                                                                                                                               |
| `NewRelic-Agent-Uninstall-<code>`            | Remove New Relic Infrastructure Agent                          | None                                                                                                                                                               |
| `Create-Local-User-Windows-<code>`           | Create a local Windows user with secure random password        | `username`, `fullName`, `userDescription`, `group`                                                                                                                 |
| `Reset-Local-User-Passwords-Windows-<code>`  | Reset Windows local-user passwords (logs new passwords)        | `userNames`: Comma-separated list of Windows usernames                                                                                                             |
| `Check-Local-User-Expiration-Windows-<code>` | Report Windows local-user password expiry                      | None                                                                                                                                                               |
| `Create-Local-User-Linux-<code>`             | Create a Linux user and store password in Parameter Store      | `username`, `group`, `parameterPrefix`, `expirationHours`                                                                                                          |
| `Delete-Local-Users-Linux-<code>`            | Remove one or more Linux users                                 | `usernames`: Comma-separated list, `deleteHome`: `true`/`false`                                                                                                    |
| `Create-Passwordless-User-Linux-<code>`      | Create Linux user with SSH key + sudo NOPASSWD                 | `username`, `secondaryGroup`, `parameterPrefix`, `expirationHours`, `keyType`: `ed25519`/`rsa`                                                                     |
| `Upgrade-Packages-Linux-<code>`              | Upgrade specific packages (latest or security-only)            | `packages`: Comma-separated list, `updateType`: `latest`/`security`, `cves`: Comma-separated CVE IDs                                                               |
| `Disk-Cleanup-Windows-<code>`                | Automated disk cleanup & component cleanup on Windows          | None                                                                                                                                                               |
| `Check-Local-User-Expiration-Linux-<code>`   | List Linux local users & password expiry                       | `excludedUsers`: Comma-separated list, `minimumUid`: Minimum UID to check                                                                                          |

## Code Structure

```text
├── __main__.py                # Entry point: orchestrates multi-region deployment
├── validator.py               # SSM Document validation logic
├── script_library.py          # Reusable script templates for documents
├── document_templates.py      # Standardized SSM document payload definitions
├── ssm_component.py           # Pulumi component for SSM document deployment
├── CloudFormation template/   # Templates for infrastructure setup
│   └── Pulumi-OIDC.yaml       # CloudFormation template for AWS OIDC setup
├── requirements.txt           # Python dependencies
└── Pulumi.<stack>.yaml        # Stack configuration: enabled_regions, accountIds
```

## Testing

To validate changes:

* Run a Pulumi dry run:

  ```bash
  pulumi preview  # or pulumi up --dry-run
  ```

* Ensure SSM document payloads pass schema validation during the run.

## Contributing

We welcome contributions! Please follow these guidelines:

1. Fork this repository.
2. Create a feature branch:

   ```bash
   git checkout -b feature/your-feature
   ```

3. Implement your changes and update documentation as needed.
4. Commit with a descriptive message:

   ```bash
   git commit -m "feat: add new SSM document for X"
   ```

5. Push your branch to your fork:

   ```bash
   git push origin feature/your-feature
   ```

6. Open a Pull Request against the `main` branch, describing your changes.

### Adding New SSM Documents

To add a new SSM document to the deployment, follow these steps:

1. **Create Script Templates (if needed)**
   * Open `script_library.py`
   * Add a new static method to the `SsmScriptLibrary` class with your script content
   * Ensure your script handles different OS versions and includes proper error handling
   * Example:

     ```python
     @staticmethod
     def my_new_script() -> List[str]:
         """
         Description of what this script does.
         
         Returns:
             List[str]: Script commands as a line-by-line list
         """
         return [
             "#!/usr/bin/env bash",
             "set -euo pipefail",
             "# Your script commands here",
             "echo 'Hello from my new script'",
         ]
     ```

2. **Define Document Template**
   * Open `document_templates.py`
   * Add a new static method to the `SsmDocumentTemplates` class
   * Create your document payload with appropriate schema, parameters and steps
   * Reference your script template from `SsmScriptLibrary` if needed
   * Example:

     ```python
     @staticmethod
     def my_new_document() -> Dict[str, Any]:
         """
         Create an SSM document for my new operation.
         
         Description of what this document does.
         
         Returns:
             Dict[str, Any]: A complete SSM document template as a dictionary
         """
         return {
             "schemaVersion": "2.2",
             "description": "My new SSM document",
             "parameters": {
                 "myParam": {
                     "type": "String",
                     "description": "Description of parameter"
                 }
             },
             "mainSteps": [
                 {
                     "name": "RunMyScript",
                     "action": "aws:runShellScript",
                     "precondition": {"StringEquals": ["platformType", "Linux"]},
                     "inputs": {
                         "timeoutSeconds": 300,
                         "runCommand": SsmScriptLibrary.my_new_script()
                     }
                 }
             ]
         }
     ```

3. **Register Document in Component**
   * Open `ssm_component.py`
   * Find the `_create_documents` method in the `SsmDocs` class
   * Add your document to the `document_templates` list:

     ```python
     document_templates = [
         # Existing documents...
         ("My-New-Document", SsmDocumentTemplates.my_new_document),
     ]
     ```

4. **Update Documentation**
   * Add your document to the SSM Documents table in this README.md:

     ```markdown
     | `My-New-Document-<code>` | Description of what your document does | `myParam`: Description of parameter |
     ```

5. **Test Your Addition**
   * Run `pulumi preview` to ensure your document passes validation
   * Check for any issues in the validator output
   * Test the deployed document in AWS if possible

Your new SSM document will now be automatically deployed to all configured regions along with the existing documents.

## License

This project is released under the MIT License.
