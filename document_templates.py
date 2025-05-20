# -----------------------------------------------------------------------------
# SSM Document Templates
#
# Comprehensive library of standardized AWS Systems Manager document templates
# designed for common administrative tasks across cloud environments.
# -----------------------------------------------------------------------------

from typing import Dict, Any, List
from script_library import SsmScriptLibrary


class SsmDocumentTemplates:
    """
    Collection of standardized SSM document templates.

    This class provides a library of well-structured, validated AWS Systems Manager
    document templates that follow AWS best practices and handle cross-platform
    compatibility. These templates can be used to perform common administrative
    and operational tasks across Windows and Linux environments.
    """

    @staticmethod
    def new_relic_agent_install() -> Dict[str, Any]:
        """
        Create an SSM document template for New Relic agent installation.

        This document template handles New Relic Infrastructure agent installation
        on both Windows and Linux systems. It configures the agent with the provided
        parameters and ensures the service is running after installation.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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

    @staticmethod
    def new_relic_agent_upgrade() -> Dict[str, Any]:
        """
        Create an SSM document template for upgrading New Relic agent.

        This document template handles upgrading the New Relic Infrastructure agent
        on both Windows and Linux systems. It provides platform-specific upgrade
        logic and handles service restarts.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
            "schemaVersion": "2.2",
            "description": "Upgrade New Relic Infrastructure Agent (Linux & Windows)",
            "mainSteps": [
                {
                    "name": "UpgradeLinux",
                    "action": "aws:runShellScript",
                    "precondition": {"StringEquals": ["platformType", "Linux"]},
                    "inputs": {
                        "timeoutSeconds": 300,
                        "runCommand": SsmScriptLibrary.linux_upgrade_steps(),
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

    @staticmethod
    def new_relic_agent_uninstall() -> Dict[str, Any]:
        """
        Create an SSM document template for uninstalling New Relic agent.

        This document template handles removing the New Relic Infrastructure agent
        from both Windows and Linux systems, cleaning up files and configurations.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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

    @staticmethod
    def create_local_user_windows() -> Dict[str, Any]:
        """
        Create an SSM document template for creating a local Windows user.

        This document template creates a local user with a secure random password on
        Windows systems, adds the user to a specified group, and outputs the credentials
        securely in the command output logs.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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
                        "runCommand": SsmScriptLibrary.create_local_windows_user_script(),
                    },
                },
            ],
        }

    @staticmethod
    def reset_local_user_passwords_windows() -> Dict[str, Any]:
        """
        Create an SSM document template for resetting Windows user passwords.

        This document template resets passwords for multiple local users on Windows
        systems, using secure random password generation and handling cross-platform
        compatibility. Outputs new credentials in the command output logs.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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
                        "runCommand": SsmScriptLibrary.reset_windows_passwords_script(),
                    },
                },
            ],
        }

    @staticmethod
    def check_user_expiration_windows() -> Dict[str, Any]:
        """
        Create an SSM document template for checking Windows user password expiration.

        This document template generates a report of all local users on a Windows system,
        including their password expiration dates and account status.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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

    @staticmethod
    def windows_disk_cleanup() -> Dict[str, Any]:
        """
        Create an SSM document template for Windows disk cleanup.

        This document template provides comprehensive disk cleanup operations for
        Windows systems, including temporary file removal, component store cleanup,
        and disk optimization. Works across different Windows versions.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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
                        "runCommand": SsmScriptLibrary.windows_disk_cleanup_script(),
                    },
                },
            ],
        }

    @staticmethod
    def delete_local_users_linux() -> Dict[str, Any]:
        """
        Create an SSM document template for deleting Linux users.

        This document template safely removes one or more local users from a Linux
        system, with options to delete or preserve home directories. Works across
        different Linux distributions.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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
                        "runCommand": SsmScriptLibrary.linux_delete_users_script(),
                    },
                },
            ],
        }

    @staticmethod
    def check_user_expiration_linux() -> Dict[str, Any]:
        """
        Create an SSM document template for checking Linux user password expiration.

        This document template generates a report of local users on a Linux system,
        including their password and account expiration dates. Provides options to
        exclude system users and specific accounts.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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
                        "runCommand": SsmScriptLibrary.check_linux_user_expiry_script(),
                    },
                },
            ],
        }

    @staticmethod
    def upgrade_packages_linux() -> Dict[str, Any]:
        """
        Create an SSM document template for upgrading specific Linux packages.

        This document template updates specified packages on Linux systems with
        options for latest versions or security-only updates. Supports CVE-specific
        patching where available and works across distributions.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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
                        "runCommand": SsmScriptLibrary.upgrade_linux_packages_script(),
                    },
                },
            ],
        }

    @staticmethod
    def create_passwordless_user_linux() -> Dict[str, Any]:
        """
        Create an SSM document template for setting up a passwordless SSH user on Linux.

        This document template creates a Linux user with SSH key-based authentication
        and sudo access without password. The private key is stored securely in
        SSM Parameter Store with expiration.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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

    @staticmethod
    def create_local_user_linux() -> Dict[str, Any]:
        """
        Create an SSM document template for creating a local Linux user.

        This document template creates a local user on a Linux system with a secure
        random password. The password is stored securely in SSM Parameter Store
        with expiration. Works across different Linux distributions.

        Returns:
            Dict[str, Any]: A complete SSM document template as a dictionary
        """
        return {
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
