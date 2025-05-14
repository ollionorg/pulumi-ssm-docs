# Multi-Region AWS SSM Documents via Pulumi

This repository provides a Pulumi-based solution to deploy and manage AWS Systems Manager (SSM) Documents across one or more AWS regions. It includes validation logic to ensure SSM document payloads comply with approved schemas, and automatically shares these documents with specified AWS accounts.

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
* [License](#license)

---

## Overview

This repository is a part of Automation package that deploys AWS Systems Manager (SSM) Documents across multiple AWS regions using Pulumi ESC with OIDC authentication. It adheres to ESC best practices by separating:

* **Environment**: Stacks managed via ESC environments.
* **Secrets**: Sensitive values stored and retrieved through ESC secret management.
* **Config**: Declarative settings in `Pulumi.<stack>.yaml` for region selection and account sharing.

On each run, the project discovers available AWS regions (with a fallback list), filters them according to `enabled_regions` in your stack YAML, and then instantiates a suite of SSM Documents—ranging from agent installers/upgraders/uninstallers to Linux and Windows user-management utilities. All payload definitions live in `ssm_docs.py` and are validated against AWS SSM schema v2.2 (and earlier) before publishing.

Documents are automatically shared with any AWS accounts listed under `accountIds`.

Refer to the ESC examples for end-to-end workflows: [https://github.com/pulumi/esc-examples](https://github.com/pulumi/esc-examples)

## Prerequisites

* **Pulumi CLI** (v3.x)
* **Python** >= 3.7
* **AWS Credentials** configured locally (via `~/.aws/credentials`, environment variables, or IAM role)
* **AWS OIDC Provider** configured for Pulumi ESC:

  * Create an AWS IAM OIDC identity provider for your ESC OIDC issuer and configure trust policies. See AWS docs: [https://docs.aws.amazon.com/IAM/latest/UserGuide/id\_roles\_providers\_create\_oidc.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
  * Follow Pulumi ESC AWS OIDC setup guide: [https://www.pulumi.com/docs/esc/environments/configuring-oidc/aws/](https://www.pulumi.com/docs/esc/environments/configuring-oidc/aws/)

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
3. **Log in once to Pulumi ESC with OIDC** (if not already authenticated):

   ```bash
   pulumi login pulumi-esc://<your-esc-endpoint> --oidc
   ```
4. **Setup ESC environment, secrets, and config**:

   * **Environment**: Create or select your ESC environment:

     ```bash
     esc env create <org>/<project>/<stack>
     ```
   * **Secrets**: Add sensitive values:

     ```bash
     esc secret set <org>/<project>/<stack>:<key> <value>
     ```
   * **Config**: Define declarative settings in `Pulumi.<stack>.yaml` under `config:` (see next section).

## Configuration

Define your stack configuration in `Pulumi.<stack>.yaml` at the project root:

```yaml
config:
  enabled_regions:
    - us-east-1
    - eu-central-1
    - ap-southeast-1
    - ap-southeast-2

  accountIds:
    - "1234567890"
```

Secrets can be flagged alongside values or stored via `esc secret set` and referenced here as needed.

## Usage

Deploy all configured SSM Documents:

```bash
pulumi up
```

Or, using Pulumi ESC:

```bash
esc run <org>/<project>/<stack> -- pulumi up --yes
```

Destroy all deployed resources:

```bash
pulumi destroy
```

Or via Pulumi ESC:

```bash
esc run <org>/<project>/<stack> -- pulumi destroy --yes
```

## SSM Documents Provided

The following SSM Documents are automatically created in every region listed under `enabled_regions`. Each name includes a region-specific `<code>` suffix (e.g., `apse1` for `ap-southeast-1`).

| Document Name                                   | Description                                                    | Parameters                                                                                                                                                        |
| ----------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NewRelic-Agent-Install-<code>`                 | Install & configure the New Relic Infrastructure Agent.        | None                                                                                                                                                              |
| `NewRelic-Agent-Upgrade-<code>`                 | Upgrade New Relic Infrastructure Agent (Linux & Windows).      | None                                                                                                                                                              |
| `NewRelic-Agent-Uninstall-<code>`               | Remove New Relic Infrastructure Agent.                         | None                                                                                                                                                              |
| `Upgrade-Agent-GCP-<code>`                      | Upgrade New Relic & Google guest agents (Linux & Windows).     | None                                                                                                                                                              |
| `Zabbix-Agent-Uninstall-<code>`                 | Remove Zabbix Agent (Linux & Windows).                         | None                                                                                                                                                              |
| `TrendMicroDeepSecurity-Agent-Uninstall-<code>` | Remove Trend Micro Deep-Security Agent.                        | `password` (String): Self-protect password.                                                                                                                       |
| `Create-Local-User-Windows-<code>`              | Create a local Windows user (logs password in output).         | `username` (String)<br>`fullName` (String, optional)<br>`userDescription` (String)<br>`group` (String).                                                           |
| `Reset-Local-User-Passwords-Windows-<code>`     | Reset Windows local-user passwords (logs new passwords).       | `userNames` (String): Comma-separated list of Windows usernames.                                                                                                  |
| `Check-Local-User-Expiration-Windows-<code>`    | Report Windows local-user password expiry.                     | None                                                                                                                                                              |
| `Create-Local-User-Linux-<code>`                | Create a Linux user and store its password in Parameter Store. | `username` (String)<br>`group` (String, optional)<br>`parameterPrefix` (String)<br>`expirationHours` (String).                                                    |
| `Delete-Local-Users-Linux-<code>`               | Remove one or more Linux users.                                | `usernames` (String): Comma-separated list<br>`deleteHome` (String): `true`/`false`.                                                                              |
| `Create-Passwordless-User-Linux-<code>`         | Create Linux user with SSH key + sudo NOPASSWD (stores key).   | `username` (String)<br>`secondaryGroup` (String, optional)<br>`parameterPrefix` (String)<br>`expirationHours` (String)<br>`keyType` (String): `ed25519` or `rsa`. |
| `Upgrade-Packages-Linux-<code>`                 | Upgrade specific packages (latest or security-only).           | `packages` (String): Comma-separated list<br>`updateType` (String): `latest`/`security`<br>`cves` (String, optional).                                             |
| `Disk-Cleanup-Windows-<code>`                   | Automated disk cleanup & component cleanup on Windows.         | None                                                                                                                                                              |

## Code Structure

```text
├── __main__.py         # Entry point: discovers/filter regions, instantiates SsmDocs component per region
├── ssm_docs.py         # Defines SsmDocs component and validation logic for SSM Document payloads
├── requirements.txt    # Python dependencies
└── Pulumi.<stack>.yaml  # Stack configuration: enabled_regions, accountIds, imports, values, and secrets
```

## Testing

There are currently no automated test suites included. To validate changes:

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

**Before submitting:**

* Run a Pulumi preview to validate your changes:

  ```bash
  pulumi preview
  ```

## License

This project is released under the MIT License.
