# -----------------------------------------------------------------------------
# SSM Script Library
#
# Library of standardized script templates for AWS Systems Manager documents.
# These templates provide consistent, well-tested, and compatible scripts
# for common administrative tasks across different platforms.
# -----------------------------------------------------------------------------

from typing import List


class SsmScriptLibrary:
    """
    Library of reusable script templates for SSM documents.

    This class provides standardized, well-tested script templates that handle
    compatibility across different OS versions, system configurations, and
    runtime environments. Scripts follow security best practices and include
    appropriate error handling.
    """

    @staticmethod
    def make_powershell_download_cmd(url: str, dest: str) -> List[str]:
        """
        Create PowerShell commands to download a file with backward compatibility.

        Creates a PowerShell command sequence that handles different PowerShell
        versions when downloading files from URLs. Includes fallback mechanisms
        for older PowerShell versions.

        Args:
            url: The source URL to download from
            dest: The destination path to save the file

        Returns:
            List[str]: List of PowerShell commands
        """
        return [
            "$ver = $PSVersionTable.PSVersion.Major",
            f"$cmd = \"Invoke-WebRequest '{url}' -OutFile {dest}\"",
            "if ($ver -lt 6) { $cmd += ' -UseBasicParsing' }",
            "Invoke-Expression $cmd",
        ]

    @staticmethod
    def linux_upgrade_steps() -> List[str]:
        """
        Generate commands to upgrade agents on Linux systems.

        Provides a shell script that handles different package managers and service
        control systems across various Linux distributions, ensuring compatibility
        with RHEL/CentOS, Debian/Ubuntu, SUSE, and other common distributions.

        Returns:
            List[str]: Shell script commands as a line-by-line list
        """
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

    @staticmethod
    def create_local_windows_user_script() -> List[str]:
        """
        Generate PowerShell script to create a local Windows user.

        Creates a secure script that works across different PowerShell versions
        to create a local Windows user with appropriate group membership. Includes
        password generation with complexity requirements and error handling.

        Returns:
            List[str]: PowerShell script commands as a line-by-line list
        """
        return [
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
        ]

    @staticmethod
    def reset_windows_passwords_script() -> List[str]:
        """
        Generate PowerShell script to reset Windows user passwords.

        Creates a secure script that resets passwords for one or more Windows users
        with compatibility across different PowerShell versions. Includes secure
        password generation and proper error handling.

        Returns:
            List[str]: PowerShell script commands as a line-by-line list
        """
        return [
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
        ]

    @staticmethod
    def windows_disk_cleanup_script() -> List[str]:
        """
        Generate PowerShell script for Windows disk cleanup.

        Creates a comprehensive disk cleanup script that removes temporary files,
        cleans up the component store, and optimizes disk usage. Works across
        different Windows versions with appropriate error handling.

        Returns:
            List[str]: PowerShell script commands as a line-by-line list
        """
        return [
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
        ]

    @staticmethod
    def linux_delete_users_script() -> List[str]:
        """
        Generate shell script to delete Linux users.

        Creates a script that safely removes one or more Linux users with
        options to delete or preserve home directories. Handles different
        user management systems across various Linux distributions.

        Returns:
            List[str]: Shell script commands as a line-by-line list
        """
        return [
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
        ]

    @staticmethod
    def check_linux_user_expiry_script() -> List[str]:
        """
        Generate shell script to check Linux user password expiration.

        Creates a script that reports password and account expiration details
        for Linux users, with options to exclude system users and specific
        accounts. Works across different Linux distributions.

        Returns:
            List[str]: Shell script commands as a line-by-line list
        """
        return [
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
        ]

    @staticmethod
    def upgrade_linux_packages_script() -> List[str]:
        """
        Generate shell script to upgrade specific Linux packages.

        Creates a script to update packages across different Linux distributions,
        with options for latest versions or security-only updates. Supports
        CVE-specific patching where available.

        Returns:
            List[str]: Shell script commands as a line-by-line list
        """
        return [
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
        ]
